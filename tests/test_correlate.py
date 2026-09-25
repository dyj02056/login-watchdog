# ============================================================================
# test_correlate.py — correlate.py(형사 역할)가 "사건으로 묶어야 하는가"를
# 올바르게 판단하는지 확인하는 단위 테스트 (Track C guide27, SIEM 상관분석)
#
# 여기서는 db.py가 진짜로 뭘 저장하는지가 아니라, correlate.py가 db.py의
# 함수들을 올바른 조건에서, 올바른 값으로 부르는지만 확인한다 — test_soar.py와
# 같은 스타일.
# ============================================================================

import config
import correlate
import db


def test_check_and_correlate_does_nothing_when_fewer_than_two_distinct_types(monkeypatch):
    # 이 이벤트 하나뿐(다른 유형과 겹치지 않음)이면 사건을 만들면 안 된다.
    monkeypatch.setattr(db, "get_recent_distinct_event_types", lambda ip, window_minutes: ["BRUTE_FORCE"])
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("서로 다른 유형이 2개 미만인데 record_incident가 호출되면 안 된다")
    ))

    correlate.check_and_correlate("9.9.9.9", "BRUTE_FORCE", "CRITICAL")  # 예외가 안 나면 통과


def test_check_and_correlate_records_incident_when_two_or_more_distinct_types(monkeypatch):
    monkeypatch.setattr(
        db, "get_recent_distinct_event_types", lambda ip, window_minutes: ["BRUTE_FORCE", "WEB_SCANNING"]
    )
    calls = []
    monkeypatch.setattr(
        db, "record_incident", lambda ip, event_types, severity: calls.append((ip, event_types, severity))
    )

    correlate.check_and_correlate("9.9.9.9", "BRUTE_FORCE", "CRITICAL")

    assert calls == [("9.9.9.9", ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")]


def test_check_and_correlate_uses_configured_window(monkeypatch):
    seen_windows = []
    monkeypatch.setattr(
        db,
        "get_recent_distinct_event_types",
        lambda ip, window_minutes: seen_windows.append(window_minutes) or [],
    )
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: None)

    correlate.check_and_correlate("9.9.9.9", "WEB_SCANNING", "MEDIUM")

    assert seen_windows == [config.INCIDENT_CORRELATION_WINDOW_MINUTES]
