# ============================================================================
# security/netblock.py — L4(iptables/ipset) 차단 요청 장부에 "막아라/풀어라"를 적는 함수
#
# 담당: 역할 C (C0-2 구현).
# 함수 모양은 docs/track-d/contracts.md 계약서 K7이 기준이다.
#
# 이 파일은 network_blocks 표에 원하는 상태만 기록한다. 실제 방화벽 반영은 같은 Docker 단지의
# fw-agent가 내부 API로 목록을 가져가서 한다(앱이 방화벽 권한을 갖지 않게 하기 위해).
# 모든 함수는 여러 번 불려도 결과가 같고(멱등), 허용 목록·주소 형식을 스스로 검사한다 —
# 판단하는 쪽(플레이북)이 잘못된 주소를 넘겨도 여기서 한 번 더 막는다.
#
# import 규칙(계약서 K7): config, db, security.lockdown만 쓴다. lockdown은 release() 안에서(C2-2)
# 함수 안 import로 이 파일을 부르므로, 여기서 lockdown을 모듈째 import해도
# 순환이 생기지 않는다. lockdown.is_ip_allowlisted(...)처럼 모듈 이름을 거쳐 부르는 것은
# 테스트에서 monkeypatch로 바꿔 끼울 수 있게 하기 위해서다.
#
# 사용하는 DB 함수(C1-1에서 db/network_blocks.py에 만들었다):
#   db.get_network_block / db.insert_network_block / db.update_network_block_if_status /
#   db.count_recent_net_blocked_events
# ============================================================================

from datetime import datetime, timedelta, timezone
import ipaddress

import config
import db
from security import lockdown


# 계약서 K12 network_blocks.reason 값. 표의 check 제약과 같게 둬서, DB까지 가서 오류가 나기 전에
# 여기서 False로 거절한다(플레이북은 False를 '이미 막혀 있음/거절'로 기록하고 다음 단계로 넘어간다).
_VALID_REASONS = {"NET_FLOOD", "KILL_CHAIN", "ADMIN_MANUAL"}
# SPOOFABLE = 위조될 수 있는 증거(SYN 등, 출발지 주소를 속일 수 있음) → 반드시 TTL.
# CONNECTED = 3-way handshake가 끝난 연결의 증거(주소 위조 불가) → 영구 차단 가능.
_VALID_EVIDENCES = {"SPOOFABLE", "CONNECTED"}

# 이 상태의 행은 지금 '막혀 있거나 곧 막힐' 행이다. 새 요청은 더 강할 때만 덮어쓴다.
_ACTIVE_STATUSES = ("PENDING_APPLY", "APPLIED")
# 이 상태의 행은 같은 ip_address(기본 키) 행을 재사용해 PENDING_APPLY로 되돌린다.
_REUSABLE_STATUSES = ("PENDING_REMOVE", "REMOVED", "FAILED")

# gateway·app·shipper가 쓰는 core 대역(docker-compose.yml, 계약서 K2). 설정값과 상관없이 고정으로 막는다 —
# 이 대역이 ipset에 들어가면 정문(gateway)이 앱의 응답 패킷을 버려 사이트 전체가 멈춘다(guide57).
# Scapy 측정기(netwatch/l4_detector/detector_core.py)의 CORE_NETWORK와 같은 값이다.
CORE_NETWORK = ipaddress.ip_network("172.30.0.0/24")


def _edge_network() -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """NET_EDGE_SUBNET을 대역으로 바꾼다. 비었거나 형식이 틀리면 None."""
    if not config.NET_EDGE_SUBNET:
        return None
    try:
        return ipaddress.ip_network(config.NET_EDGE_SUBNET, strict=False)
    except ValueError:
        return None


def is_infrastructure_ip(ip: str) -> bool:
    """우리 단지의 기반 주소이거나 사람이 쓰지 않는 특수 주소인지(guide57, 계약서 K7).

    SYN·ICMP는 출발지를 마음대로 적어 보낼 수 있다. 공격자가 출발지를 app(core 대역)이나 gateway(.10)로
    꾸며 폭주를 보내면, 예전에는 그 주소가 그대로 NET-01 차단 대상이 되어 우리 서비스가 스스로 막힐 수
    있었다. 그래서 어떤 증거가 오든 이 주소들은 막지 않는다.
    - core 대역 172.30.0.0/24 (고정)
    - NET_EDGE_SUBNET의 .1(호스트 브라우저·Docker 게이트웨이)과 .10(gateway edge)
    - 루프백·멀티캐스트·예약·미지정(0.0.0.0)·링크로컬 — 실제 공격자일 수 없는 주소
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version == 4 and address in CORE_NETWORK:
        return True
    if (
        address.is_loopback
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address.is_link_local
    ):
        return True
    edge = _edge_network()
    if edge is not None and address.version == edge.version:
        base = int(edge.network_address)
        if int(address) in (base + 1, base + 10):
            return True
    return False


def is_outside_edge_subnet(ip: str) -> bool:
    """NET_EDGE_SUBNET이 설정돼 있는데 ip가 그 밖이면 True(설정이 없으면 항상 False).

    이 PC의 센서는 자기 edge 대역만 본다. 그 밖의 출발지가 edge로 들어왔다면 위조된 주소다(guide57).
    """
    edge = _edge_network()
    if edge is None:
        return False
    try:
        return ipaddress.ip_address(ip) not in edge
    except ValueError:
        return True


def _now_utc() -> datetime:
    """지금 시각(UTC). 테스트에서 시각을 고정하고 싶을 때 이 함수만 바꿔 끼우면 된다."""
    return datetime.now(timezone.utc)


def _isoformat_utc(dt: datetime) -> str:
    """DB에 넣을 UTC ISO 8601 문자열("...+00:00"). 다른 db/*.py와 같은 형식이다."""
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    """DB에서 읽은 시각 문자열을 UTC datetime으로 바꾼다. 비었거나 해석이 안 되면 None.

    문자열 그대로 비교하지 않는 이유: Supabase는 "…+00:00", 다른 경로는 "…Z", 소수점 초가
    붙거나 빠지는 등 같은 시각을 여러 표기로 돌려줄 수 있다. 문자열 비교는 이런 표기 차이에서
    '더 늦은 만료'를 잘못 판단해, 더 약한 요청이 기존 차단을 덮어쓰게 만들 수 있다.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        # 시간대가 없는 값은 이 프로젝트 규칙(시각은 UTC)에 따라 UTC로 본다.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_stronger(new_expires: datetime | None, cur_expires_raw: str | None) -> bool:
    """새 요청이 기존 차단보다 '더 강한지'(계약서 K7 멱등 규칙).

    더 강함 = 기존이 영구가 아니고, (새 요청이 영구이거나 새 만료 시각이 더 늦음).
    기존 만료 값이 있는데 해석할 수 없으면 더 강한 것으로 본다 — 깨진 값을 올바른 값으로
    바로잡는 쪽이, 깨진 값 때문에 차단 연장을 영영 못 하는 것보다 안전하다.
    """
    if cur_expires_raw is None:
        return False  # 기존이 영구면 어떤 요청도 더 강하지 않다.
    if new_expires is None:
        return True  # 기존은 TTL, 새 요청은 영구.
    cur_expires = _parse_iso(cur_expires_raw)
    if cur_expires is None:
        return True
    return new_expires > cur_expires


def request_block(
    ip: str,
    reason: str,
    evidence: str,
    ttl_seconds: int | None = None,
    requested_by: str = "playbook",
) -> bool:
    """network_blocks에 '막아라'를 기록한다. 실제로 바뀌었을 때만 True.

    reason은 계약서 K12 값, evidence는 'SPOOFABLE' 또는 'CONNECTED'.
    TTL 계산(기본 × 2^반복, 상한)은 이 함수만 한다 — 플레이북은 ttl_seconds를 넘기지 않는다(K7).
    """
    # 1. 입력 검증 — 거절할 때마다 이유를 한 줄 남긴다(플레이북 결과가 SKIPPED/False일 때
    #    서버 로그에서 왜 그랬는지 바로 찾을 수 있게).
    if not ip or "/" in ip:
        # 대역 차단은 같은 NAT 뒤 정상 사용자까지 막으므로 받지 않는다.
        print(f"[netblock] 거부: 잘못된 IP 형식 또는 대역 ('{ip}')")
        return False

    try:
        parsed_ip = ipaddress.ip_address(ip)
        if parsed_ip.version == 6:
            # fw-agent의 lw_block은 hash:ip(IPv4) 집합이다. 앱의 IPv6 키(/64 대역, guide42)는
            # 대역이라 위 '/' 규칙과도 맞지 않는다.
            print(f"[netblock] 거부: IPv6 차단 미지원 ('{ip}')")
            return False
    except ValueError:
        print(f"[netblock] 거부: IP 해석 실패 ('{ip}')")
        return False

    if is_infrastructure_ip(ip):
        # 위조된 출발지로 우리 core·gateway 주소를 막게 만드는 공격을 여기서 끊는다(guide57).
        print(f"[netblock] 거부: 인프라·특수 주소 ('{ip}')")
        return False

    if evidence not in _VALID_EVIDENCES:
        print(f"[netblock] 거부: 잘못된 evidence ('{evidence}')")
        return False

    if reason not in _VALID_REASONS:
        print(f"[netblock] 거부: 잘못된 reason ('{reason}')")
        return False

    if lockdown.is_ip_allowlisted(ip):
        # 관리자 PC·Docker 게이트웨이(172.28.0.1 등)를 정문에서 막으면 시연 중 화면에 들어갈 수
        # 없다. 앱 잠금(L7)과 같은 목록을 써서 두 계층의 예외가 어긋나지 않게 한다.
        print(f"[netblock] 거부: 허용 목록 IP ('{ip}')")
        return False

    if ttl_seconds is not None and (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int)):
        print(f"[netblock] 거부: ttl_seconds가 정수가 아님 ({ttl_seconds!r})")
        return False

    if ttl_seconds is not None and ttl_seconds <= 0:
        # 0을 그대로 두면 fw-agent에서 ipset timeout 0(= 만료 없음)이 되어 영구 차단으로 바뀐다.
        print(f"[netblock] 거부: ttl_seconds가 0 이하 ({ttl_seconds})")
        return False

    # 2. TTL 및 expires_at 계산
    now = _now_utc()
    expires_dt: datetime | None = None

    if evidence == "SPOOFABLE":
        # 위조 가능한 증거는 영구 차단 금지(상위 계획서 P2). 남의 주소를 사칭한 SYN만으로
        # 그 주소의 주인이 영원히 막히면 안 되기 때문이다.
        if ttl_seconds is None:
            # 최근 NET_BLOCK_REPEAT_DAYS일 동안 실제로 막혔던 횟수(NET_BLOCKED 이벤트)만큼 2배씩.
            # '요청' 횟수가 아니라 '실제 적용' 횟수를 세므로, 거절·실패한 요청은 늘리지 않는다.
            since_dt = now - timedelta(days=config.NET_BLOCK_REPEAT_DAYS)
            recent_count = db.count_recent_net_blocked_events(ip, _isoformat_utc(since_dt))
            calculated_ttl = config.NET_BLOCK_DEFAULT_TTL_SECONDS * (2 ** recent_count)
            ttl = min(calculated_ttl, config.NET_BLOCK_MAX_TTL_SECONDS)
        else:
            ttl = min(ttl_seconds, config.NET_BLOCK_MAX_TTL_SECONDS)
        expires_dt = now + timedelta(seconds=ttl)
    else:  # CONNECTED
        if ttl_seconds is None:
            expires_dt = None  # 영구(expires_at=NULL). CR-01 킬체인 전용(K7 block_l4).
        else:
            # 계약서는 CONNECTED+TTL의 상한을 정하지 않았지만, 일부러 TTL을 준 요청은 '임시'라는
            # 뜻이므로 SPOOFABLE과 같은 상한을 둔다. 영구가 필요하면 ttl_seconds=None으로 부른다.
            ttl = min(ttl_seconds, config.NET_BLOCK_MAX_TTL_SECONDS)
            expires_dt = now + timedelta(seconds=ttl)

    expires_at = _isoformat_utc(expires_dt) if expires_dt is not None else None
    now_iso = _isoformat_utc(now)

    # 3. DB 기존 행 조회 및 상태 전이
    # Supabase REST에는 트랜잭션이 없으므로 '읽은 상태 그대로일 때만 갱신'(조건부 UPDATE)과
    # 기본 키(ip_address) 충돌로 동시 요청을 정리한다(AGENTS.md 10번).
    existing = db.get_network_block(ip)

    if existing is None:
        new_row = {
            "ip_address": ip,
            "status": "PENDING_APPLY",
            "reason": reason,
            "evidence": evidence,
            "expires_at": expires_at,
            "requested_by": requested_by,
            "requested_at": now_iso,
            "applied_at": None,
            "removed_at": None,
            "last_error": None,
        }
        inserted = db.insert_network_block(new_row)
        if inserted:
            return True
        # 동시 요청으로 insert 실패 시(다른 스레드가 먼저 넣음) 한 번 다시 읽어 아래 규칙으로 처리
        existing = db.get_network_block(ip)
        if existing is None:
            return False

    current_status = existing.get("status")

    if current_status in _ACTIVE_STATUSES:
        # 이미 막혀 있으면 더 강한 요청일 때만 갱신(멱등). 같은 SYN Flood 경보가 몇 초 간격으로
        # 여러 번 와도 TTL이 매번 늘어나거나 fw-agent가 같은 IP를 반복 처리하지 않게 한다.
        if not _is_stronger(expires_dt, existing.get("expires_at")):
            return False

        # 한 번이라도 연결 완성 증거가 있었으면 그 사실을 잃지 않는다.
        merged_evidence = "CONNECTED" if (existing.get("evidence") == "CONNECTED" or evidence == "CONNECTED") else evidence
        update_fields = {
            "status": "PENDING_APPLY",  # fw-agent가 새 TTL로 다시 add하게 한다
            "reason": reason,
            "evidence": merged_evidence,
            "expires_at": expires_at,
            "requested_by": requested_by,
            "requested_at": now_iso,
            "applied_at": None,
            "removed_at": None,
            "last_error": None,
        }
        return _update_with_version(ip, current_status, existing, _with_retry_reset(existing, update_fields))

    if current_status in _REUSABLE_STATUSES:
        # 해제됐거나 실패한 행은 같은 행을 새 요청으로 재사용한다(기본 키가 ip_address라 새 행을
        # 만들 수 없다). 과거 기록은 security_events의 NET_BLOCKED 이력으로 남아 있다.
        update_fields = {
            "status": "PENDING_APPLY",
            "reason": reason,
            "evidence": evidence,
            "expires_at": expires_at,
            "requested_by": requested_by,
            "requested_at": now_iso,
            "applied_at": None,
            "removed_at": None,
            "last_error": None,
        }
        return _update_with_version(ip, current_status, existing, _with_retry_reset(existing, update_fields))

    # 알 수 없는 상태(표 제약상 나오면 안 됨)는 건드리지 않는다.
    print(f"[netblock] 거부: 알 수 없는 기존 상태 ('{ip}', status={current_status!r})")
    return False


def _with_retry_reset(existing: dict, fields: dict) -> dict:
    """새 차단 요청이면 적용 재시도 횟수(guide57)를 처음부터 센다. 칸이 없는 DB에서는 그대로 둔다."""
    if "apply_attempts" not in existing:
        return fields
    return {**fields, "apply_attempts": 0, "failed_at": None}


def _update_with_version(ip: str, current_status: str, existing: dict, fields: dict) -> bool:
    """읽은 행 그대로일 때만 바꾸고, version 칸이 있으면 1 올린다(요청 번호).

    fw-agent는 GET /blocks에서 받은 version을 ACK에 그대로 돌려준다. 요청이 바뀔 때마다 번호가
    달라지므로, 60초 차단에 대한 늦은 ACK가 그 사이 바뀐 영구 차단을 "적용 완료"로 만들지 못한다
    (10/26 강사 피드백 4). guide56 실행 전 DB(version 칸 없음)에서는 예전처럼 상태만 조건으로 쓴다.
    """
    if "version" not in existing:
        return db.update_network_block_if_status(ip, [current_status], fields)
    version = int(existing.get("version") or 0)
    return db.update_network_block_if_status(
        ip, [current_status], {**fields, "version": version + 1}, expected_version=version,
    )


def request_unblock(ip: str, actor: str) -> bool:
    """PENDING_APPLY/APPLIED인 행을 PENDING_REMOVE로 바꾼다. 바뀌었을 때만 True.

    실제 ipset del은 fw-agent가 다음 폴링(2초)에서 하고 ack REMOVED를 보낸다. 이미 해제됐거나
    행이 없으면 False(멱등) — 관리자 해제(lockdown.release, C2-2)가 L4 차단이 없는 IP에 대해
    불러도 오류가 아니다. actor(예: "admin:alice")는 누가 풀었는지 서버 로그로 남기려고 받는다.
    """
    if not ip or "/" in ip:
        print(f"[netblock] request_unblock 거부: 잘못된 IP 형식 ('{ip}'), actor='{actor}'")
        return False

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[netblock] request_unblock 거부: IP 해석 실패 ('{ip}'), actor='{actor}'")
        return False

    # version 칸(guide56)이 있으면 해제도 "새 요청"으로 보고 1 올린다 — 그래야 해제 직전에 읽힌 옛 차단
    # 요청의 늦은 ACK(FAILED 등)가 이 해제 요청을 덮어쓰지 못한다. 읽기가 실패하면 예전 방식으로 바꾼다.
    try:
        row = db.get_network_block(ip)
    except Exception:
        row = None
    if row is not None and "version" in row:
        if row.get("status") not in _ACTIVE_STATUSES:
            res = False
        else:
            res = _update_with_version(ip, row["status"], row, {"status": "PENDING_REMOVE"})
    else:
        res = db.update_network_block_if_status(
            ip, list(_ACTIVE_STATUSES), {"status": "PENDING_REMOVE"}
        )
    print(f"[netblock] request_unblock 요청 처리 (ip='{ip}', actor='{actor}', result={res})")
    return res
