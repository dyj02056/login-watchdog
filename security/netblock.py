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
# ============================================================================

from datetime import datetime, timedelta, timezone
import ipaddress

import config
import db
from security import lockdown


_VALID_REASONS = {"NET_FLOOD", "KILL_CHAIN", "ADMIN_MANUAL"}
_VALID_EVIDENCES = {"SPOOFABLE", "CONNECTED"}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def request_block(
    ip: str,
    reason: str,
    evidence: str,
    ttl_seconds: int | None = None,
    requested_by: str = "playbook",
) -> bool:
    """network_blocks에 '막아라'를 기록한다. 실제로 바뀌었을 때만 True.

    reason은 계약서 K12 값, evidence는 'SPOOFABLE' 또는 'CONNECTED'.
    """
    # 1. 입력 검증
    if not ip or "/" in ip:
        print(f"[netblock] 거부: 잘못된 IP 형식 또는 대역 ('{ip}')")
        return False

    try:
        parsed_ip = ipaddress.ip_address(ip)
        if parsed_ip.version == 6:
            print(f"[netblock] 거부: IPv6 차단 미지원 ('{ip}')")
            return False
    except ValueError:
        print(f"[netblock] 거부: IP 해석 실패 ('{ip}')")
        return False

    if evidence not in _VALID_EVIDENCES:
        print(f"[netblock] 거부: 잘못된 evidence ('{evidence}')")
        return False

    if reason not in _VALID_REASONS:
        print(f"[netblock] 거부: 잘못된 reason ('{reason}')")
        return False

    if lockdown.is_ip_allowlisted(ip):
        print(f"[netblock] 거부: 허용 목록 IP ('{ip}')")
        return False

    if ttl_seconds is not None and ttl_seconds <= 0:
        print(f"[netblock] 거부: ttl_seconds가 0 이하 ({ttl_seconds})")
        return False

    # 2. TTL 및 expires_at 계산
    now = _now_utc()
    expires_at: str | None = None

    if evidence == "SPOOFABLE":
        if ttl_seconds is None:
            since_dt = now - timedelta(days=config.NET_BLOCK_REPEAT_DAYS)
            recent_count = db.count_recent_net_blocked_events(ip, _isoformat_utc(since_dt))
            calculated_ttl = config.NET_BLOCK_DEFAULT_TTL_SECONDS * (2 ** recent_count)
            ttl = min(calculated_ttl, config.NET_BLOCK_MAX_TTL_SECONDS)
        else:
            ttl = min(ttl_seconds, config.NET_BLOCK_MAX_TTL_SECONDS)
        expires_at = _isoformat_utc(now + timedelta(seconds=ttl))
    else:  # CONNECTED
        if ttl_seconds is None:
            expires_at = None
        else:
            ttl = min(ttl_seconds, config.NET_BLOCK_MAX_TTL_SECONDS)
            expires_at = _isoformat_utc(now + timedelta(seconds=ttl))

    now_iso = _isoformat_utc(now)

    # 3. DB 기존 행 조회 및 상태 전이
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
        # 동시 요청으로 insert 실패 시 재조회 후 update 수행
        existing = db.get_network_block(ip)
        if existing is None:
            return False

    current_status = existing.get("status")

    if current_status in ("PENDING_APPLY", "APPLIED"):
        cur_expires = existing.get("expires_at")
        # 더 강한 요청인지 판단: 기존이 영구가 아닌 상황에서 (새 요청이 영구이거나 새 expires_at이 더 늦음)
        is_stronger = False
        if cur_expires is not None:
            if expires_at is None:
                is_stronger = True
            elif expires_at > cur_expires:
                is_stronger = True

        if not is_stronger:
            return False

        merged_evidence = "CONNECTED" if (existing.get("evidence") == "CONNECTED" or evidence == "CONNECTED") else evidence
        update_fields = {
            "status": "PENDING_APPLY",
            "reason": reason,
            "evidence": merged_evidence,
            "expires_at": expires_at,
            "requested_by": requested_by,
            "requested_at": now_iso,
            "applied_at": None,
            "removed_at": None,
            "last_error": None,
        }
        return db.update_network_block_if_status(ip, [current_status], update_fields)

    if current_status in ("PENDING_REMOVE", "REMOVED", "FAILED"):
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
        return db.update_network_block_if_status(ip, [current_status], update_fields)

    return False


def request_unblock(ip: str, actor: str) -> bool:
    """PENDING_APPLY/APPLIED인 행을 PENDING_REMOVE로 바꾼다. 바뀌었을 때만 True."""
    if not ip or "/" in ip:
        print(f"[netblock] request_unblock 거부: 잘못된 IP 형식 ('{ip}'), actor='{actor}'")
        return False

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[netblock] request_unblock 거부: IP 해석 실패 ('{ip}'), actor='{actor}'")
        return False

    res = db.update_network_block_if_status(
        ip, ["PENDING_APPLY", "APPLIED"], {"status": "PENDING_REMOVE"}
    )
    print(f"[netblock] request_unblock 요청 처리 (ip='{ip}', actor='{actor}', result={res})")
    return res