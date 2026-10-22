# ============================================================================
# db/playbook_runs.py — playbook_runs 표: 플레이북 단계별 실행 결과 (계약서 K11)
#
# 담당: 역할 B (B2-2). 단계별 기록으로 부분 실패를 확인할 수 있게 한다.
#
# 새 DB 함수는 이 파일에 만들고, 이름을 아래 __all__ 목록에 추가한다. 그러면
# db/__init__.py가 "from .playbook_runs import *"로 자동으로 다시 내보내므로, 다른 파일에서
# 바로 db.함수이름(...)으로 쓸 수 있다 — 세 사람이 공용 파일(db/__init__.py)을 고치지
# 않아도 되게 하려는 장치다(team-plan 01 3.2).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고(import db 후 db.get_client()).
# ============================================================================

import db

__all__ = ["insert_playbook_run"]


def insert_playbook_run(
    playbook: str, trigger_ref: str, step: str, status: str, error: str | None = None,
) -> None:
    """단계 결과를 기록하며 장애 격리는 실행기에 맡겨 다음 조치를 보장한다."""
    db.get_client().table("playbook_runs").insert({
        "playbook": playbook, "trigger_ref": trigger_ref,
        "step": step, "status": status, "error": error,
    }).execute()
