# ============================================================================
# test_correlate.py — correlate.py(형사 역할)가 "사건으로 묶어야 하는가"를
# 올바르게 판단하는지 확인하는 단위 테스트 (Track C guide27, SIEM 상관분석)
#
# 여기서는 db.py가 진짜로 뭘 저장하는지가 아니라, correlate.py가 db.py의
# 함수들을 올바른 조건에서, 올바른 값으로 부르는지만 확인한다 — test_soar.py와
# 같은 스타일.
# ============================================================================

import alert
import config
import correlate
import db

# 대부분의 테스트는 record_incident()의 반환값 자체가 아니라 "누가 어떤 값으로
# 불렸는가"만 보므로, _maybe_escalate()가 더 진행하지 않도록 escalated=True인
# 무해한 사건을 기본값으로 돌려준다. 에스컬레이션 자체를 확인하는 테스트는
# 이 값을 따로 오버라이드한다.
_NON_ESCALATING_INCIDENT = {
    "id": 1,
    "event_types": ["BRUTE_FORCE", "WEB_SCANNING"],
    "severity_max": "CRITICAL",
    "escalated": True,
}


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

    def fake_record_incident(ip, event_types, severity):
        calls.append((ip, event_types, severity))
        return _NON_ESCALATING_INCIDENT

    monkeypatch.setattr(db, "record_incident", fake_record_incident)

    correlate.check_and_correlate("9.9.9.9", "BRUTE_FORCE", "CRITICAL")

    assert calls == [("9.9.9.9", ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")]


def test_check_and_correlate_uses_configured_window(monkeypatch):
    seen_windows = []
    monkeypatch.setattr(
        db,
        "get_recent_distinct_event_types",
        lambda ip, window_minutes: seen_windows.append(window_minutes) or [],
    )
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: _NON_ESCALATING_INCIDENT)

    correlate.check_and_correlate("9.9.9.9", "WEB_SCANNING", "MEDIUM")

    assert seen_windows == [config.INCIDENT_CORRELATION_WINDOW_MINUTES]


# ============================================================================
# _maybe_escalate / PLAYBOOKS — SOAR 플레이북 고도화 (Track C guide28)
# ============================================================================

def test_check_and_correlate_runs_playbook_when_incident_crosses_escalation_threshold(monkeypatch):
    monkeypatch.setattr(
        db, "get_recent_distinct_event_types",
        lambda ip, window_minutes: ["BRUTE_FORCE", "HTTP_FLOOD", "WEB_SCANNING"],
    )
    monkeypatch.setattr(
        db,
        "record_incident",
        lambda ip, event_types, severity: {
            "id": 42,
            "event_types": event_types,
            "severity_max": "CRITICAL",
            "escalated": False,
        },
    )
    alert_calls = []
    monkeypatch.setattr(
        alert,
        "send_incident_escalation_alert",
        lambda ip, event_types, severity_max: alert_calls.append((ip, event_types, severity_max)),
    )
    marked = []
    monkeypatch.setattr(db, "mark_incident_escalated", lambda incident_id: marked.append(incident_id))

    correlate.check_and_correlate("9.9.9.9", "WEB_SCANNING", "CRITICAL")

    assert alert_calls == [("9.9.9.9", ["BRUTE_FORCE", "HTTP_FLOOD", "WEB_SCANNING"], "CRITICAL")]
    assert marked == [42]


def test_check_and_correlate_skips_playbook_when_already_escalated(monkeypatch):
    # 같은 사건에 이벤트가 하나 더 붙어도, 이미 에스컬레이션 알림을 보낸
    # 사건이면 재알림하면 안 된다(알림 피로 방지).
    monkeypatch.setattr(
        db, "get_recent_distinct_event_types",
        lambda ip, window_minutes: ["BRUTE_FORCE", "HTTP_FLOOD", "WEB_SCANNING"],
    )
    monkeypatch.setattr(
        db,
        "record_incident",
        lambda ip, event_types, severity: {
            "id": 42,
            "event_types": event_types,
            "severity_max": "CRITICAL",
            "escalated": True,
        },
    )
    monkeypatch.setattr(alert, "send_incident_escalation_alert", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("이미 escalated된 사건인데 다시 알림을 보내면 안 된다")
    ))
    monkeypatch.setattr(db, "mark_incident_escalated", lambda incident_id: (_ for _ in ()).throw(
        AssertionError("이미 escalated된 사건인데 mark_incident_escalated가 또 호출되면 안 된다")
    ))

    correlate.check_and_correlate("9.9.9.9", "WEB_SCANNING", "CRITICAL")  # 예외가 안 나면 통과


def test_check_and_correlate_skips_playbook_when_severity_not_critical(monkeypatch):
    monkeypatch.setattr(
        db, "get_recent_distinct_event_types",
        lambda ip, window_minutes: ["WEB_SCANNING", "UNAUTHORIZED_ACCESS", "PAGE_ACCESS"],
    )
    monkeypatch.setattr(
        db,
        "record_incident",
        lambda ip, event_types, severity: {
            "id": 7,
            "event_types": event_types,
            "severity_max": "MEDIUM",
            "escalated": False,
        },
    )
    monkeypatch.setattr(alert, "send_incident_escalation_alert", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("CRITICAL이 아닌데 에스컬레이션 알림이 나가면 안 된다")
    ))

    correlate.check_and_correlate("9.9.9.9", "WEB_SCANNING", "MEDIUM")  # 예외가 안 나면 통과


def test_check_and_correlate_skips_playbook_when_below_min_event_types(monkeypatch):
    monkeypatch.setattr(
        db, "get_recent_distinct_event_types", lambda ip, window_minutes: ["BRUTE_FORCE", "WEB_SCANNING"]
    )
    monkeypatch.setattr(
        db,
        "record_incident",
        lambda ip, event_types, severity: {
            "id": 8,
            "event_types": event_types,
            "severity_max": "CRITICAL",
            "escalated": False,
        },
    )
    monkeypatch.setattr(alert, "send_incident_escalation_alert", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("유형이 config.INCIDENT_ESCALATION_MIN_EVENT_TYPES 미만인데 알림이 나가면 안 된다")
    ))

    correlate.check_and_correlate("9.9.9.9", "BRUTE_FORCE", "CRITICAL")  # 예외가 안 나면 통과
