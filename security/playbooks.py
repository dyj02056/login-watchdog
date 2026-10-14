# ============================================================================
# security/playbooks.py — Track D 대응 절차서(플레이북): 규칙이 맞으면 조치를 순서대로 실행한다
#
# 담당: 역할 B (B2-2에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# 플레이북·단계 이름은 docs/track-d/contracts.md 계약서 K12, 넘겨받는 ctx 모양은 K8이 기준이다.
#
# 판단(B)과 실행(C)을 나눈다: 이 파일은 "어떤 조치를 어떤 순서로"만 정하고, 실제 차단·메일·알림은
# 역할 C의 조치 함수가 스스로 검증하며 실행한다.
# 기존 복합 공격 알림(security/correlate.py의 PLAYBOOKS["CRITICAL_MULTI_STAGE"])은 옮기지 않는다 —
# 이 파일은 Track D 플레이북만 담당한다(계약서 K12).
# ============================================================================


def run(playbook: str, trigger_ref: str, ctx: dict) -> list[dict]:
    """플레이북의 단계를 순서대로 실행하고 단계별 결과를 돌려준다.

    trigger_ref는 "incident:<사건 id>:<규칙 ID>"(계약서 K12), 결과 항목은
    {"step", "status": "OK" | "FAILED" | "SKIPPED", "error"}. B2-2에서 구현한다.
    """
    raise NotImplementedError("B2-2에서 구현 — 계약서 K8·K12")
