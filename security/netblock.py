# ============================================================================
# security/netblock.py — L4(iptables/ipset) 차단 요청 장부에 "막아라/풀어라"를 적는 함수
#
# 담당: 역할 C (C0-2에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# 함수 모양은 docs/track-d/contracts.md 계약서 K7이 기준이다.
#
# 이 파일은 network_blocks 표에 원하는 상태만 기록한다. 실제 방화벽 반영은 같은 Docker 단지의
# fw-agent가 내부 API로 목록을 가져가서 한다(앱이 방화벽 권한을 갖지 않게 하기 위해).
# 모든 함수는 여러 번 불려도 결과가 같고(멱등), 허용 목록·주소 형식을 스스로 검사한다 —
# 판단하는 쪽(플레이북)이 잘못된 주소를 넘겨도 여기서 한 번 더 막는다.
# ============================================================================


def request_block(
    ip: str,
    reason: str,
    evidence: str,
    ttl_seconds: int | None = None,
    requested_by: str = "playbook",
) -> bool:
    """network_blocks에 '막아라'를 기록한다. 실제로 바뀌었을 때만 True.

    reason은 계약서 K12 값, evidence는 'SPOOFABLE' 또는 'CONNECTED'.
    C0-2에서 구현한다(계약서 K7).
    """
    raise NotImplementedError("C0-2에서 구현 — 계약서 K7")


def request_unblock(ip: str, actor: str) -> bool:
    """PENDING_APPLY/APPLIED인 행을 PENDING_REMOVE로 바꾼다. 바뀌었을 때만 True.

    C0-2에서 구현한다(계약서 K7).
    """
    raise NotImplementedError("C0-2에서 구현 — 계약서 K7")
