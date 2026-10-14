# ============================================================================
# db/agent_heartbeats.py — agent_heartbeats 표: fw-agent·shipper 생존 신호, PC별 저장 (계약서 K9·K11)
#
# 담당: 역할 C (C1-1부터). Track D 뼈대 PR(I0-1)이 만든 빈 모듈이다.
#
# 새 DB 함수는 이 파일에 만들고, 이름을 아래 __all__ 목록에 추가한다. 그러면
# db/__init__.py가 "from .agent_heartbeats import *"로 자동으로 다시 내보내므로, 다른 파일에서
# 바로 db.함수이름(...)으로 쓸 수 있다 — 세 사람이 공용 파일(db/__init__.py)을 고치지
# 않아도 되게 하려는 장치다(team-plan 01 3.2).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고(import db 후 db.get_client()).
# ============================================================================

import db  # noqa: F401  (함수를 추가하면 db.get_client()로 쓴다)

__all__: list[str] = []
