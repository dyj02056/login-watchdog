# ============================================================================
# security/net_ingest.py — 네트워크 경보를 보안 이벤트로 올리고, 실제 L4 차단(NET_BLOCKED)을 기록한다
#
# HIGH 경보는 기존 미해결 이벤트의 bump 경로를, MEDIUM은 공통 기록 경로를 사용한다.
# 함수 모양은 docs/track-d/contracts.md 계약서 K5·K6이 기준이다.
#
# 역할 C(차단 목록 창구)가 fw-agent의 반영 보고를 받을 때 아래 두 함수를 부른다. C는
# "from security import net_ingest" 후 net_ingest.record_net_blocked(...)처럼 모듈 이름을 거쳐
# 부른다 — 그래야 테스트에서 이 함수를 가짜로 바꿔 끼울 수 있다(B1-2 머지 전에는 C의 테스트가 이 방식으로 먼저 돌았다).
# ============================================================================

import config
import db
from notify import alert
from security import correlate, netblock
from security.soar._events import _record_event


CATEGORY_MAP = {
    "SYN_FLOOD": ("NET_SYN_FLOOD", "HIGH"),
    "PORT_SCAN": ("NET_PORT_SCAN", "MEDIUM"),
    "SCANNER_UA": ("NET_SCANNER_UA", "MEDIUM"),
    "WEB_ATTACK": ("NET_WEB_ATTACK", "HIGH"),
    "LOGIN_BURST": ("NET_LOGIN_BURST", "MEDIUM"),
    # guide57 L3 경보. ICMP도 출발지를 위조할 수 있어 MEDIUM으로만 올리고 교차 규칙(correlate.CROSS_LAYER_RULES)에는
    # 넣지 않는다 — 사건 묶음에는 기존 상관분석으로 참고 근거로만 붙고, IP 잠금 판단(app_severity_max)에는 쓰이지 않는다.
    "ICMP_FLOOD": ("NET_ICMP_FLOOD", "MEDIUM"),
}

# 처음 저장할 때 Slack으로 알리는 L3 경보(guide57, 계약서 K5). SPOOFED_SRC·GLOBAL_SYN_FLOOD는 막을 출발지가
# 없거나 가짜라 보안 이벤트로 올리지 않으므로(CATEGORY_MAP에 없음), 알림이 관리자에게 닿는 유일한 길이다.
NOTICE_CATEGORIES = {"ICMP_FLOOD", "SPOOFED_SRC", "GLOBAL_SYN_FLOOD"}


def _untrusted_source(ip: str) -> bool:
    """보안 이벤트로 올리면 안 되는 출발지인지(guide57, 계약서 K5).

    우리 인프라 주소(core·gateway 등)나 이 PC의 edge 대역 밖 주소가 경보 출발지로 왔다면 위조된 것이다.
    이걸 올리면 사건·플레이북을 거쳐 우리 주소를 막거나 남의 주소에 오명을 남기므로, 원본 기록
    (network_events)에만 남긴다.
    """
    return netblock.is_infrastructure_ip(ip) or netblock.is_outside_edge_subnet(ip)


def promote(row: dict) -> bool:
    """K5에 정의된 경보만 NET 출처로 기록하고 OTHER는 원본 기록에만 남긴다."""
    mapped = CATEGORY_MAP.get(row["category"])
    if mapped is None:
        return False
    if _untrusted_source(row["src_ip"]):
        print(f"[net_ingest] 승격 안 함: 인프라·대역 밖 출발지 ({row['src_ip']}, {row['category']})")
        return False
    event_type, severity = mapped
    if severity == "HIGH":
        db.insert_security_event_or_bump(
            event_type, severity, row["src_ip"], None, row["packet_count"], "NET_ALERT",
            source="NET", layer=row["layer"],
        )
        correlate.check_and_correlate(row["src_ip"], event_type, severity, source="NET")
    else:
        _record_event(
            event_type, severity, row["src_ip"], None, row["packet_count"], "NET_ALERT",
            source="NET", layer=row["layer"],
        )
    return True


def notify_network(row: dict) -> None:
    """L3 경보를 종류 단위 쿨다운으로 Slack에 알린다(guide57).

    위조 출발지 폭주는 출발지가 수천 개라 출발지마다 알리면 채널이 넘친다. 그래서 쿨다운 키를
    slack:net:<PC>:<종류>로 잡아 종류당 AGENT_ALERT_COOLDOWN_SECONDS에 한 통만 보낸다.
    알림 실패가 경보 저장을 깨면 안 되므로 호출하는 쪽에서 예외를 삼킨다.
    """
    category = row.get("category")
    if category not in NOTICE_CATEGORIES:
        return
    key = f"slack:net:{config.LW_NODE_NAME or '-'}:{category}"
    if not db.try_acquire_cooldown(key, config.AGENT_ALERT_COOLDOWN_SECONDS):
        return
    summary = (
        f"출발지 {row.get('src_ip')} · 패킷 {row.get('packet_count')}개 · "
        f"{row.get('signature')} · 관측 {row.get('observed_at')}"
    )
    alert.send_network_notice(category, summary)


def record_net_blocked(ip: str, reason: str) -> None:
    """fw-agent가 APPLIED를 보고한 순간 부른다. NET_BLOCKED(CRITICAL)를 기록한다.

    같은 IP에 미해결 NET_BLOCKED가 이미 있으면 새로 만들지 않는다(멱등).
    교차 계층 규칙의 입력으로 쓰지 않는다(계약서 K6).
    reason은 로그·알림용이며 이벤트 칸에는 넣지 않는다.
    """
    if db.get_unresolved_security_event(ip, "NET_BLOCKED"):
        return
    _record_event("NET_BLOCKED", "CRITICAL", ip, None, 1, "L4_BLOCKED", source="NET", layer="L4")


def resolve_net_blocked(ip: str) -> None:
    """fw-agent가 REMOVED를 보고했거나 TTL이 만료됐을 때 부른다.

    그 IP의 미해결 NET_BLOCKED만 해결 처리한다(다른 이벤트는 건드리지 않음).
    """
    db.resolve_net_blocked_events(ip)
