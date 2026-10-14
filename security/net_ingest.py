# ============================================================================
# security/net_ingest.py — 네트워크 경보를 보안 이벤트로 올리고, 실제 L4 차단(NET_BLOCKED)을 기록한다
#
# 담당: 역할 B (B1-2에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# 함수 모양은 docs/track-d/contracts.md 계약서 K5·K6이 기준이다.
#
# 역할 C(차단 목록 창구)가 fw-agent의 반영 보고를 받을 때 아래 두 함수를 부른다. C는
# "from security import net_ingest" 후 net_ingest.record_net_blocked(...)처럼 모듈 이름을 거쳐
# 부른다 — 그래야 B1-2가 머지되기 전에도 테스트에서 이 함수를 가짜로 바꿔 끼울 수 있다.
# ============================================================================


def record_net_blocked(ip: str, reason: str) -> None:
    """fw-agent가 APPLIED를 보고한 순간 부른다. NET_BLOCKED(CRITICAL)를 기록한다.

    같은 IP에 미해결 NET_BLOCKED가 이미 있으면 새로 만들지 않는다(멱등).
    교차 계층 규칙의 입력으로 쓰지 않는다. B1-2에서 구현한다(계약서 K6).
    """
    raise NotImplementedError("B1-2에서 구현 — 계약서 K6")


def resolve_net_blocked(ip: str) -> None:
    """fw-agent가 REMOVED를 보고했거나 TTL이 만료됐을 때 부른다.

    그 IP의 미해결 NET_BLOCKED만 해결 처리한다(다른 이벤트는 건드리지 않음).
    B1-2에서 구현한다(계약서 K6).
    """
    raise NotImplementedError("B1-2에서 구현 — 계약서 K6")
