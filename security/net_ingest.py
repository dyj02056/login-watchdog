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

import db
from security import correlate
from security.soar._events import _record_event


CATEGORY_MAP = {
    "SYN_FLOOD": ("NET_SYN_FLOOD", "HIGH"),
    "PORT_SCAN": ("NET_PORT_SCAN", "MEDIUM"),
    "SCANNER_UA": ("NET_SCANNER_UA", "MEDIUM"),
    "WEB_ATTACK": ("NET_WEB_ATTACK", "HIGH"),
    "LOGIN_BURST": ("NET_LOGIN_BURST", "MEDIUM"),
}


def promote(row: dict) -> bool:
    """K5에 정의된 경보만 NET 출처로 기록하고 OTHER는 원본 기록에만 남긴다."""
    mapped = CATEGORY_MAP.get(row["category"])
    if mapped is None:
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
