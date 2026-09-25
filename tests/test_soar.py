# ============================================================================
# test_soar.py — soar.py(집행관 역할)가 db.py / alert.py를 올바른 순서와
# 조건으로 호출하는지 확인하는 단위 테스트
#
# 여기서 확인하고 싶은 건 "정말로 Slack에 메시지가 갔는가"가 아니라
# "soar.py가 db.create_lockout과 alert.send_lockout_alert를 올바르게,
# 올바른 값으로, 올바른 순서로 호출하는가"이다. 그래서 진짜 함수 대신
# "호출된 사실을 기록만 해두는 가짜 함수"로 바꿔치기해서 확인한다.
# ============================================================================

import alert
import correlate
import db
import soar


def test_enforce_lockout_creates_lockout_then_sends_alert(monkeypatch):
    calls = []  # 호출된 순서를 기록해둘 리스트

    def fake_create_lockout(ip, failure_count):
        calls.append(("create_lockout", ip, failure_count))

    def fake_send_lockout_alert(ip, failure_count, locked_at, distinct_usernames, is_admin=False):
        calls.append(("send_lockout_alert", ip, failure_count, distinct_usernames, is_admin))

    def fake_insert_security_event(event_type, severity, ip, path, count, action):
        calls.append(("insert_security_event", event_type, severity, ip, path, count, action))

    monkeypatch.setattr(db, "create_lockout", fake_create_lockout)
    monkeypatch.setattr(alert, "send_lockout_alert", fake_send_lockout_alert)
    monkeypatch.setattr(db, "insert_security_event", fake_insert_security_event)
    # 이 테스트는 "잠그기 → 알리기 → 이벤트 기록" 순서만 확인하는 것이 목적이라,
    # Track C에서 추가된 상관분석 훅(correlate.py)은 여기서는 아무 일도 안 하게
    # 막아둔다 — 훅 자체의 동작은 test_correlate.py와
    # test_record_event_calls_correlate_with_the_recorded_event에서 따로 확인한다.
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)

    soar.enforce_lockout("9.9.9.9", 6, 2)

    # 세 함수가 다 호출됐는지, 그리고 "잠그기 → 알리기 → 이벤트 기록" 순서가 지켜졌는지,
    # distinct_usernames가 그대로 alert.py까지 전달됐는지, distinct_usernames가 2개
    # 이상이라 PASSWORD_SPRAYING으로 분류됐는지 확인.
    assert calls == [
        ("create_lockout", "9.9.9.9", 6),
        ("send_lockout_alert", "9.9.9.9", 6, 2, False),
        ("insert_security_event", "PASSWORD_SPRAYING", "CRITICAL", "9.9.9.9", None, 6, "LOCKED"),
    ]


def test_enforce_lockout_records_brute_force_when_single_username(monkeypatch):
    monkeypatch.setattr(db, "create_lockout", lambda ip, failure_count: None)
    monkeypatch.setattr(
        alert, "send_lockout_alert", lambda ip, failure_count, locked_at, distinct_usernames, is_admin=False: None
    )
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    events = []
    monkeypatch.setattr(
        db,
        "insert_security_event",
        lambda event_type, severity, ip, path, count, action: events.append(event_type),
    )

    soar.enforce_lockout("9.9.9.9", 6, 1)  # distinct_usernames == 1 → 계정 하나 집중 공격

    assert events == ["BRUTE_FORCE"]


def test_enforce_lockout_records_admin_brute_force_when_is_admin(monkeypatch):
    monkeypatch.setattr(db, "create_lockout", lambda ip, failure_count: None)
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    alert_calls = []
    monkeypatch.setattr(
        alert,
        "send_lockout_alert",
        lambda ip, failure_count, locked_at, distinct_usernames, is_admin=False: alert_calls.append(is_admin),
    )
    events = []
    monkeypatch.setattr(
        db,
        "insert_security_event",
        lambda event_type, severity, ip, path, count, action: events.append(event_type),
    )

    # distinct_usernames가 2개 이상이어도 is_admin=True면 Password Spraying이 아니라
    # 관리자 로그인 무차별 대입으로 분류되어야 한다.
    soar.enforce_lockout("9.9.9.9", 6, 2, is_admin=True)

    assert events == ["ADMIN_BRUTE_FORCE"]
    assert alert_calls == [True]


def test_enforce_account_lockout_creates_lockout_then_alerts_then_records_event(monkeypatch):
    calls = []

    def fake_create_account_lockout(username, failure_count):
        calls.append(("create_account_lockout", username, failure_count))

    def fake_send_account_lockout_alert(username, failure_count, locked_at, distinct_ip_count):
        calls.append(("send_account_lockout_alert", username, failure_count, distinct_ip_count))

    def fake_insert_security_event(event_type, severity, ip, path, count, action, username=None):
        calls.append(("insert_security_event", event_type, severity, ip, path, count, action, username))

    monkeypatch.setattr(db, "create_account_lockout", fake_create_account_lockout)
    monkeypatch.setattr(alert, "send_account_lockout_alert", fake_send_account_lockout_alert)
    monkeypatch.setattr(db, "insert_security_event", fake_insert_security_event)
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)

    soar.enforce_account_lockout("victim", 9, 4, "9.9.9.9")

    # "잠그기 → 알리기 → 이벤트 기록" 순서, 그리고 이벤트에는 username이 채워지고
    # ip_address 칸에는 잠금을 유발한 마지막 시도의 IP(참고용)가 남는지 확인.
    assert calls == [
        ("create_account_lockout", "victim", 9),
        ("send_account_lockout_alert", "victim", 9, 4),
        (
            "insert_security_event",
            "DISTRIBUTED_BRUTE_FORCE",
            "CRITICAL",
            "9.9.9.9",
            None,
            9,
            "ACCOUNT_LOCKED",
            "victim",
        ),
    ]


def test_try_release_expired_account_lockouts_releases_each_expired_username(monkeypatch):
    expired = [{"username": "victim1"}, {"username": "victim2"}]
    released = []
    resolved = []

    monkeypatch.setattr(db, "list_expired_active_account_lockouts", lambda: expired)
    monkeypatch.setattr(db, "release_account_lockout", lambda username: released.append(username))
    monkeypatch.setattr(
        db, "resolve_security_events_for_username", lambda username: resolved.append(username)
    )

    soar.try_release_expired_account_lockouts()

    assert released == ["victim1", "victim2"]
    assert resolved == ["victim1", "victim2"]


def test_try_release_expired_account_lockouts_does_nothing_when_none_expired(monkeypatch):
    monkeypatch.setattr(db, "list_expired_active_account_lockouts", lambda: [])
    monkeypatch.setattr(db, "release_account_lockout", lambda username: (_ for _ in ()).throw(
        AssertionError("풀어줄 게 없는데 release_account_lockout이 호출되면 안 된다")
    ))
    monkeypatch.setattr(
        db,
        "resolve_security_events_for_username",
        lambda username: (_ for _ in ()).throw(
            AssertionError("풀어줄 게 없는데 resolve_security_events_for_username이 호출되면 안 된다")
        ),
    )

    soar.try_release_expired_account_lockouts()  # 예외가 안 나면 통과


def test_try_release_expired_lockouts_releases_each_expired_ip(monkeypatch):
    expired = [{"ip_address": "1.1.1.1"}, {"ip_address": "2.2.2.2"}]
    released = []
    resolved = []
    closed = []

    monkeypatch.setattr(db, "list_expired_active_lockouts", lambda: expired)
    monkeypatch.setattr(db, "release_lockout", lambda ip: released.append(ip))
    monkeypatch.setattr(db, "resolve_security_events_for_ip", lambda ip: resolved.append(ip))
    monkeypatch.setattr(db, "close_open_incident_for_ip", lambda ip: closed.append(ip))

    soar.try_release_expired_lockouts()

    # 만료된 IP 두 개가 각각 한 번씩, 빠짐없이 풀렸는지, 그리고 각 IP의 CRITICAL
    # 이벤트와 열린 사건(security_incidents, Track C guide27)도 함께 정리됐는지 확인.
    assert released == ["1.1.1.1", "2.2.2.2"]
    assert resolved == ["1.1.1.1", "2.2.2.2"]
    assert closed == ["1.1.1.1", "2.2.2.2"]


def test_try_release_expired_lockouts_does_nothing_when_none_expired(monkeypatch):
    monkeypatch.setattr(db, "list_expired_active_lockouts", lambda: [])
    monkeypatch.setattr(db, "release_lockout", lambda ip: (_ for _ in ()).throw(
        AssertionError("풀어줄 게 없는데 release_lockout이 호출되면 안 된다")
    ))
    monkeypatch.setattr(db, "resolve_security_events_for_ip", lambda ip: (_ for _ in ()).throw(
        AssertionError("풀어줄 게 없는데 resolve_security_events_for_ip가 호출되면 안 된다")
    ))
    monkeypatch.setattr(db, "close_open_incident_for_ip", lambda ip: (_ for _ in ()).throw(
        AssertionError("풀어줄 게 없는데 close_open_incident_for_ip가 호출되면 안 된다")
    ))

    soar.try_release_expired_lockouts()  # 예외가 안 나면 통과


def test_manual_release_returns_true_when_ip_is_locked(monkeypatch):
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [{"ip_address": "5.5.5.5"}])
    released_ip = {}
    monkeypatch.setattr(db, "release_lockout", lambda ip: released_ip.setdefault("ip", ip))
    resolved_ip = {}
    monkeypatch.setattr(db, "resolve_security_events_for_ip", lambda ip: resolved_ip.setdefault("ip", ip))
    closed_ip = {}
    monkeypatch.setattr(db, "close_open_incident_for_ip", lambda ip: closed_ip.setdefault("ip", ip))

    result = soar.manual_release("5.5.5.5")

    assert result is True
    assert released_ip["ip"] == "5.5.5.5"
    assert resolved_ip["ip"] == "5.5.5.5"
    assert closed_ip["ip"] == "5.5.5.5"


def test_manual_release_returns_false_when_ip_not_locked(monkeypatch):
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [{"ip_address": "5.5.5.5"}])
    monkeypatch.setattr(db, "release_lockout", lambda ip: (_ for _ in ()).throw(
        AssertionError("잠긴 적 없는 IP인데 release_lockout이 호출되면 안 된다")
    ))

    result = soar.manual_release("6.6.6.6")  # 잠긴 목록(5.5.5.5)에 없는 IP

    assert result is False


# ============================================================================
# notify_web_scanning / notify_unauthorized_access / notify_page_access —
# MEDIUM 관찰 알림이 이제 security_events에도 함께 기록되는지 확인
# ============================================================================

def test_notify_web_scanning_sends_alert_then_records_medium_event(monkeypatch):
    calls = []
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    monkeypatch.setattr(alert, "send_web_scanning_alert", lambda ip, count, path: calls.append(("alert", ip, count, path)))
    monkeypatch.setattr(
        db,
        "insert_security_event",
        lambda event_type, severity, ip, path, count, action: calls.append(
            ("event", event_type, severity, ip, path, count, action)
        ),
    )

    soar.notify_web_scanning("9.9.9.9", 11, "/no-such-page")

    assert calls == [
        ("alert", "9.9.9.9", 11, "/no-such-page"),
        ("event", "WEB_SCANNING", "MEDIUM", "9.9.9.9", "/no-such-page", 11, "ALERTED"),
    ]


def test_notify_unauthorized_access_sends_alert_then_records_medium_event(monkeypatch):
    calls = []
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    monkeypatch.setattr(
        alert, "send_unauthorized_access_alert", lambda ip, count, path: calls.append(("alert", ip, count, path))
    )
    monkeypatch.setattr(
        db,
        "insert_security_event",
        lambda event_type, severity, ip, path, count, action: calls.append(
            ("event", event_type, severity, ip, path, count, action)
        ),
    )

    soar.notify_unauthorized_access("9.9.9.9", 11, "/api/status")

    assert calls == [
        ("alert", "9.9.9.9", 11, "/api/status"),
        ("event", "UNAUTHORIZED_ACCESS", "MEDIUM", "9.9.9.9", "/api/status", 11, "ALERTED"),
    ]


def test_notify_page_access_sends_alert_then_records_medium_event(monkeypatch):
    calls = []
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    monkeypatch.setattr(alert, "send_page_access_alert", lambda ip, count, path: calls.append(("alert", ip, count, path)))
    monkeypatch.setattr(
        db,
        "insert_security_event",
        lambda event_type, severity, ip, path, count, action: calls.append(
            ("event", event_type, severity, ip, path, count, action)
        ),
    )

    soar.notify_page_access("9.9.9.9", 21, "/board")

    assert calls == [
        ("alert", "9.9.9.9", 21, "/board"),
        ("event", "PAGE_ACCESS", "MEDIUM", "9.9.9.9", "/board", 21, "ALERTED"),
    ]


# ============================================================================
# record_rejection — HIGH 이벤트 기록 + 상태 기반 중복 방지
# ============================================================================

def test_record_rejection_inserts_event_when_none_unresolved(monkeypatch):
    monkeypatch.setattr(db, "get_unresolved_security_event", lambda ip, event_type: None)
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    calls = []
    monkeypatch.setattr(
        db,
        "insert_security_event_or_bump",
        lambda event_type, severity, ip, path, count, action: calls.append(
            (event_type, severity, ip, path, count, action)
        ),
    )

    soar.record_rejection("SIGNUP_RATE_LIMIT", "9.9.9.9", "/signup", 5)

    assert calls == [("SIGNUP_RATE_LIMIT", "HIGH", "9.9.9.9", "/signup", 5, "REJECTED")]


def test_record_rejection_bumps_count_when_already_unresolved(monkeypatch):
    # 봇이 60초 창 안에 계속 거부당해도, 이미 처리되지 않은 이벤트가 있으면 매번
    # 새로 기록하지 않는다 — 그렇지 않으면 security_events가 HIGH로 도배된다.
    # 대신 이미 열려있는 사건이 몇 번이나 반복됐는지 알 수 있도록 count를 올린다.
    monkeypatch.setattr(
        db, "get_unresolved_security_event", lambda ip, event_type: {"id": 7, "count": 5}
    )
    monkeypatch.setattr(db, "insert_security_event_or_bump", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("이미 미해결 이벤트가 있는데 insert_security_event_or_bump가 또 호출되었다")
    ))
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    bump_calls = []
    monkeypatch.setattr(
        db, "update_security_event_count", lambda event_id, count: bump_calls.append((event_id, count))
    )

    soar.record_rejection("SIGNUP_RATE_LIMIT", "9.9.9.9", "/signup", 5)

    assert bump_calls == [(7, 6)]


# ============================================================================
# _record_event / record_rejection — 상관분석 훅(correlate.py) 연동
# (Track C guide27) — 위 테스트들이 correlate를 아예 꺼둔 채로 기존 동작만
# 확인했다면, 여기서는 반대로 "훅이 정말 불리는지, 올바른 값으로 불리는지"만
# 확인한다.
# ============================================================================

def test_record_event_calls_correlate_with_the_recorded_event(monkeypatch):
    monkeypatch.setattr(db, "create_lockout", lambda ip, failure_count: None)
    monkeypatch.setattr(
        alert, "send_lockout_alert", lambda ip, failure_count, locked_at, distinct_usernames, is_admin=False: None
    )
    monkeypatch.setattr(db, "insert_security_event", lambda *args, **kwargs: None)
    correlate_calls = []
    monkeypatch.setattr(
        correlate, "check_and_correlate", lambda ip, event_type, severity: correlate_calls.append((ip, event_type, severity))
    )

    soar.enforce_lockout("9.9.9.9", 6, 1)  # distinct_usernames == 1 → BRUTE_FORCE

    assert correlate_calls == [("9.9.9.9", "BRUTE_FORCE", "CRITICAL")]


def test_record_rejection_calls_correlate_when_inserting_new_event(monkeypatch):
    monkeypatch.setattr(db, "get_unresolved_security_event", lambda ip, event_type: None)
    monkeypatch.setattr(db, "insert_security_event_or_bump", lambda *args, **kwargs: None)
    correlate_calls = []
    monkeypatch.setattr(
        correlate, "check_and_correlate", lambda ip, event_type, severity: correlate_calls.append((ip, event_type, severity))
    )

    soar.record_rejection("SIGNUP_RATE_LIMIT", "9.9.9.9", "/signup", 5)

    assert correlate_calls == [("9.9.9.9", "SIGNUP_RATE_LIMIT", "HIGH")]


def test_record_rejection_calls_correlate_even_when_bumping_existing_event(monkeypatch):
    # 이미 열린 사건의 count만 올리는 경로(새로 삽입하지 않음)에서도 상관분석은
    # 똑같이 확인해야 한다 — 반복되는 거부도 여전히 "이 IP가 지금 뭔가 하고
    # 있다"는 신호이기 때문.
    monkeypatch.setattr(db, "get_unresolved_security_event", lambda ip, event_type: {"id": 7, "count": 5})
    monkeypatch.setattr(db, "update_security_event_count", lambda event_id, count: None)
    correlate_calls = []
    monkeypatch.setattr(
        correlate, "check_and_correlate", lambda ip, event_type, severity: correlate_calls.append((ip, event_type, severity))
    )

    soar.record_rejection("SIGNUP_RATE_LIMIT", "9.9.9.9", "/signup", 5)

    assert correlate_calls == [("9.9.9.9", "SIGNUP_RATE_LIMIT", "HIGH")]
