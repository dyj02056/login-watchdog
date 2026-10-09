# ============================================================================
# security/soar/_events.py — 보안 이벤트 기록 + 상관분석 훅 (아래 조치 함수들이 공유)
#
# 예전 soar.py(497줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from security import soar` 후 `soar.enforce_lockout(...)`으로
# 쓴다(security/soar/__init__.py가 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import db
from security import correlate


def _record_event(
    event_type: str,
    severity: str,
    ip: str,
    path: str | None,
    count: int,
    action: str,
    username: str | None = None,
) -> None:
    """security_events에 이벤트를 기록하고, 곧바로 상관분석 훅(security/correlate.py)을
    호출한다 (Track C guide27).

    security/soar/ 안에서 직접 db.insert_security_event()를 부르는 곳을 여기 하나로
    모아둔 이유: correlate.check_and_correlate()를 매번 손으로 챙겨 부르게
    하면, 새 조치 함수를 추가할 때 상관분석 훅을 빠뜨리기 쉽다.
    """
    if username is not None:
        db.insert_security_event(event_type, severity, ip, path, count, action, username=username)
    else:
        db.insert_security_event(event_type, severity, ip, path, count, action)
    correlate.check_and_correlate(ip, event_type, severity)
