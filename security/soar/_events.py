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
    source: str = "APP",
    layer: str | None = None,
) -> None:
    """security_events에 이벤트를 기록하고, 곧바로 상관분석 훅(security/correlate.py)을
    호출한다 (Track C guide27).

    security/soar/ 안에서 직접 db.insert_security_event()를 부르는 곳을 여기 하나로
    모아둔 이유: correlate.check_and_correlate()를 매번 손으로 챙겨 부르게
    하면, 새 조치 함수를 추가할 때 상관분석 훅을 빠뜨리기 쉽다.
    """
    # APP 기본 호출은 예전 인자 모양을 유지하고, NET 출처와 계층은 명시적으로 전달한다.
    options = {}
    if username is not None:
        options["username"] = username
    if source != "APP" or layer is not None:
        options.update(source=source, layer=layer)
    db.insert_security_event(event_type, severity, ip, path, count, action, **options)
    # 실제 차단 기록은 탐지의 결과이므로 새 상관분석을 유발하지 않는다(계약서 K6).
    if event_type == "NET_BLOCKED":
        return
    if source == "APP":
        correlate.check_and_correlate(ip, event_type, severity)
    else:
        correlate.check_and_correlate(ip, event_type, severity, source=source)
