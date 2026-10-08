# ============================================================================
# test_admin_account_lockout.py — 관리자 계정 단위 잠금(guide38)
#
# /admin/login은 IP 단위 잠금만 있어서 IP를 나눠 쓰는 분산 브루트포스에 무방비였다. 이 파일은
#   - detector/db: admin_login_log를 15분 창·아이디 기준으로 세는지, 잠금 표 조회·해제
#   - 로그인 흐름: 기준 초과 시 잠금 / 잠긴 계정은 비밀번호 확인 없이 거절 / 허용 목록 IP는
#     계정 잠금을 건너뜀 / 없는 아이디도 같은 문구 / IP 잠금이 먼저 / 이미 잠긴 계정은 재잠금 안 함
#   - soar: 잠금·Slack·이벤트·이력, 영구 승격 안 함, 해제 시 관리자 이벤트만 정리
#   - 회원 "alice"와 관리자 "alice"의 이벤트 정리가 서로 섞이지 않는지
#   - API·대시보드 응답·CLI(--admin)
# 를 확인한다.
# ============================================================================

import os
import sys
import types

import pytest

import alert
import config
import correlate
import db
import detector
import lockdown
import soar

from tests.admin_session import login_admin_session, stub_admin_role
from tests.test_app import get_csrf_token  # noqa: E402

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)
import unlock_account  # noqa: E402

LOCKED_MESSAGE = "잠긴 계정입니다"


# ---------------------------------------------------------------------------
# db / detector
# ---------------------------------------------------------------------------

class _Recorder:
    """체이닝 호출을 전부 기록하고 execute()에서 정해둔 결과를 돌려주는 가짜 클라이언트."""

    def __init__(self, data=None, count=None):
        self.calls = []
        self._data = data if data is not None else []
        self._count = count

    def __getattr__(self, method):
        def call(*args, **kwargs):
            self.calls.append((method, args, kwargs))
            return self

        return call

    def execute(self):
        return types.SimpleNamespace(data=self._data, count=self._count)


def test_count_admin_failures_by_username_uses_admin_log_and_fifteen_minute_window(monkeypatch):
    fake = _Recorder(count=9)
    monkeypatch.setattr(db, "get_client", lambda: fake)

    assert db.count_recent_admin_failures_by_username("boss") == 9

    assert ("table", ("admin_login_log",), {}) in fake.calls
    assert ("eq", ("username", "boss"), {}) in fake.calls
    assert ("eq", ("success", False), {}) in fake.calls
    assert config.ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS == 900


def test_count_distinct_admin_ips_by_username(monkeypatch):
    rows = [{"ip_address": "1.1.1.1"}, {"ip_address": "2.2.2.2"}, {"ip_address": "1.1.1.1"}]
    monkeypatch.setattr(db, "get_client", lambda: _Recorder(data=rows))

    assert db.count_recent_distinct_admin_ips_by_username("boss") == 2


def test_create_admin_account_lockout_upserts_into_its_own_table(monkeypatch):
    fake = _Recorder()
    monkeypatch.setattr(db, "get_client", lambda: fake)

    db.create_admin_account_lockout("boss", 9)

    assert ("table", ("admin_account_lockouts",), {}) in fake.calls  # 회원 표(account_lockouts)가 아니다
    upsert = next(call for call in fake.calls if call[0] == "upsert")
    assert upsert[1][0]["username"] == "boss" and upsert[1][0]["active"] is True


def test_release_admin_account_lockout_reports_whether_anything_was_released(monkeypatch):
    monkeypatch.setattr(db, "get_client", lambda: _Recorder(data=[{"username": "boss"}]))
    assert db.release_admin_account_lockout("boss") is True

    monkeypatch.setattr(db, "get_client", lambda: _Recorder(data=[]))
    assert db.release_admin_account_lockout("boss") is False


@pytest.mark.parametrize("failures, suspicious", [(8, False), (9, True)])
def test_admin_account_is_suspicious_only_above_threshold(monkeypatch, failures, suspicious):
    monkeypatch.setattr(db, "count_recent_admin_failures_by_username", lambda username: failures)
    assert detector.is_admin_account_suspicious("boss") == (suspicious, failures)


def test_resolving_admin_events_filters_by_admin_event_type(monkeypatch):
    fake = _Recorder()
    monkeypatch.setattr(db, "get_client", lambda: fake)

    db.resolve_security_events_for_username("alice", [db.ADMIN_ACCOUNT_LOCK_EVENT_TYPE])

    assert ("in_", ("event_type", ["ADMIN_DISTRIBUTED_BRUTE_FORCE"]), {}) in fake.calls


def test_resolving_member_events_leaves_admin_events_of_the_same_name(monkeypatch):
    fake = _Recorder()
    monkeypatch.setattr(db, "get_client", lambda: fake)

    db.resolve_security_events_for_username("alice")

    assert ("neq", ("event_type", "ADMIN_DISTRIBUTED_BRUTE_FORCE"), {}) in fake.calls


# ---------------------------------------------------------------------------
# /admin/login 흐름
# ---------------------------------------------------------------------------

@pytest.fixture
def admin_login(client, monkeypatch):
    """IP는 수상하지 않은 상태에서 관리자 로그인을 시도하는 준비물. 기록을 env에 모은다."""
    env = types.SimpleNamespace(verify_calls=[], logged=[], account_locks=[], failures=0, locked=False)
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(detector, "is_admin_suspicious", lambda ip: (False, 1))
    monkeypatch.setattr(config, "PERMANENT_LOCK_IP_ALLOWLIST", set())  # 테스트 클라이언트(127.0.0.1)를 허용 목록에서 뺀다

    def verify(username, password):
        env.verify_calls.append(username)
        return password == "correct"

    monkeypatch.setattr(db, "verify_admin_credentials", verify)
    monkeypatch.setattr(db, "log_admin_attempt", lambda username, success, ip: env.logged.append((username, success)))
    monkeypatch.setattr(db, "get_admin_id_by_username", lambda username: 1)
    monkeypatch.setattr(db, "count_recent_admin_failures_by_username", lambda username: env.failures)
    monkeypatch.setattr(db, "count_recent_distinct_admin_ips_by_username", lambda username: 4)
    monkeypatch.setattr(
        db, "get_active_admin_account_lockout", lambda username: {"username": username} if env.locked else None
    )
    monkeypatch.setattr(
        soar, "enforce_admin_account_lockout",
        lambda username, count, distinct_ips, ip: env.account_locks.append((username, count, distinct_ips, ip)),
    )

    def post(username="boss", password="wrong"):
        token = get_csrf_token(client, "/admin/login")
        return client.post("/admin/login", data={"username": username, "password": password, "csrf_token": token})

    env.post = post
    return env


def test_failures_spread_across_ips_lock_the_admin_account(admin_login):
    admin_login.failures = 9  # IP별로는 수상하지 않지만 이 아이디의 총 실패가 기준(8)을 넘었다

    response = admin_login.post()

    assert admin_login.account_locks == [("boss", 9, 4, "127.0.0.1")]
    assert LOCKED_MESSAGE in response.get_data(as_text=True)


def test_failures_at_threshold_do_not_lock(admin_login):
    admin_login.failures = 8

    response = admin_login.post()

    assert admin_login.account_locks == []
    assert "아이디 또는 비밀번호가 올바르지 않습니다" in response.get_data(as_text=True)


def test_locked_admin_account_rejects_even_the_correct_password_without_checking_it(admin_login, client):
    admin_login.locked = True

    response = admin_login.post(password="correct")

    assert LOCKED_MESSAGE in response.get_data(as_text=True)
    assert admin_login.verify_calls == []  # 비밀번호를 맞춰볼 기회 자체가 없다
    assert admin_login.logged == []
    with client.session_transaction() as sess:
        assert "admin_username" not in sess


def test_unknown_admin_username_gets_the_same_lock_message(admin_login):
    # 아이디 존재 여부와 무관하게 실패 기록으로 잠그므로, 응답으로 관리자 아이디를 알아낼 수 없다.
    admin_login.locked = True

    response = admin_login.post(username="no_such_admin")

    assert LOCKED_MESSAGE in response.get_data(as_text=True)


def test_allowlisted_ip_can_still_log_in_while_the_account_is_locked(admin_login, monkeypatch, client):
    admin_login.locked = True
    monkeypatch.setattr(config, "PERMANENT_LOCK_IP_ALLOWLIST", {"127.0.0.1"})

    response = admin_login.post(password="correct")

    assert response.status_code == 302
    assert response.headers["Location"] == "/admin/dashboard"
    with client.session_transaction() as sess:
        assert sess["admin_username"] == "boss"


def test_failure_from_allowlisted_ip_does_not_relock_an_already_locked_account(admin_login, monkeypatch):
    admin_login.locked = True
    admin_login.failures = 12
    monkeypatch.setattr(config, "PERMANENT_LOCK_IP_ALLOWLIST", {"127.0.0.1"})

    admin_login.post()

    assert admin_login.account_locks == []  # 실패할 때마다 Slack 알림이 반복되지 않는다


def test_ip_lock_is_checked_before_the_account_lock(admin_login, monkeypatch):
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(
        db, "get_active_admin_account_lockout",
        lambda username: pytest.fail("IP가 잠겼는데 계정 잠금까지 조회했다"),
    )

    assert LOCKED_MESSAGE in admin_login.post().get_data(as_text=True)


def test_ip_threshold_takes_priority_over_account_threshold(admin_login, monkeypatch):
    ip_locks = []
    admin_login.failures = 9
    monkeypatch.setattr(detector, "is_admin_suspicious", lambda ip: (True, 6))
    monkeypatch.setattr(detector, "count_distinct_admin_usernames", lambda ip: 1)
    monkeypatch.setattr(soar, "enforce_lockout", lambda *a, **k: ip_locks.append(a))

    admin_login.post()

    assert len(ip_locks) == 1
    assert admin_login.account_locks == []


def test_member_account_lock_does_not_affect_admin_login(admin_login, monkeypatch, client):
    # 회원 "boss"가 잠겨 있어도(account_lockouts) 관리자 "boss"는 영향을 받지 않는다.
    monkeypatch.setattr(db, "get_active_account_lockout", lambda username: {"username": username})

    response = admin_login.post(password="correct")

    assert response.status_code == 302


# ---------------------------------------------------------------------------
# soar
# ---------------------------------------------------------------------------

def test_enforce_admin_account_lockout_locks_alerts_records_and_never_promotes(monkeypatch):
    calls = []
    monkeypatch.setattr(db, "create_admin_account_lockout", lambda u, c: calls.append(("lock", u, c)))
    monkeypatch.setattr(
        alert, "send_account_lockout_alert",
        lambda u, c, at, ips, is_admin=False: calls.append(("alert", u, c, ips, is_admin)),
    )
    monkeypatch.setattr(
        db, "insert_security_event",
        lambda event_type, severity, ip, path, count, action, username=None: calls.append(
            ("event", event_type, severity, ip, count, action, username)
        ),
    )
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    monkeypatch.setattr(db, "insert_lock_history", lambda *a, **k: calls.append(("history",) + a))
    monkeypatch.setattr(
        lockdown, "after_temporary_lock", lambda *a, **k: pytest.fail("관리자 계정을 영구 승격 대상으로 넘겼다")
    )

    soar.enforce_admin_account_lockout("boss", 9, 4, "9.9.9.9")

    assert calls == [
        ("lock", "boss", 9),
        ("alert", "boss", 9, 4, True),
        ("event", "ADMIN_DISTRIBUTED_BRUTE_FORCE", "CRITICAL", "9.9.9.9", 9, "ACCOUNT_LOCKED", "boss"),
        ("history", "admin_account", "boss", "TEMPORARY", "THRESHOLD", "ADMIN_DISTRIBUTED_BRUTE_FORCE"),
    ]


def test_expired_admin_account_lockouts_are_released_with_only_admin_events(monkeypatch):
    released, resolved = [], []
    monkeypatch.setattr(db, "list_expired_active_admin_account_lockouts", lambda: [{"username": "boss"}])
    monkeypatch.setattr(db, "release_admin_account_lockout", lambda u: released.append(u) or True)
    monkeypatch.setattr(
        db, "resolve_security_events_for_username", lambda u, event_types=None: resolved.append((u, event_types))
    )

    soar.try_release_expired_admin_account_lockouts()

    assert released == ["boss"]
    assert resolved == [("boss", ["ADMIN_DISTRIBUTED_BRUTE_FORCE"])]


def test_manual_release_admin_account_returns_false_when_not_locked(monkeypatch):
    monkeypatch.setattr(db, "get_active_admin_account_lockout", lambda u: None)
    monkeypatch.setattr(db, "release_admin_account_lockout", lambda u: pytest.fail("잠기지 않았는데 해제했다"))

    assert soar.manual_release_admin_account("boss") is False


def test_admin_account_alert_names_the_target_as_an_admin_account(monkeypatch):
    sent = []
    monkeypatch.setattr(alert, "_send_slack_message", sent.append)
    from datetime import datetime, timezone

    alert.send_account_lockout_alert("boss", 9, datetime.now(timezone.utc), 4, is_admin=True)
    alert.send_account_lockout_alert("alice", 9, datetime.now(timezone.utc), 4)

    assert "관리자 계정: boss" in sent[0]
    assert "대상 계정: alice" in sent[1]


# ---------------------------------------------------------------------------
# API / 대시보드
# ---------------------------------------------------------------------------

def _post_unlock_admin(client, body):
    with client.session_transaction() as sess:
        login_admin_session(sess, "root")
    token = get_csrf_token(client, "/admin/dashboard")
    return client.post("/api/unlock-admin-account", json=body, headers={"X-CSRFToken": token})


def test_super_admin_can_unlock_an_admin_account(client, monkeypatch):
    stub_admin_role(monkeypatch, "super_admin")
    checked = []
    monkeypatch.setattr(db, "has_permission", lambda role, action: checked.append(action) or True)
    monkeypatch.setattr(soar, "manual_release_admin_account", lambda u: u == "boss")

    response = _post_unlock_admin(client, {"username": "boss"})

    assert response.get_json() == {"success": True}
    assert checked == ["unlock_admin_account"]


def test_security_admin_cannot_unlock_an_admin_account(client, monkeypatch):
    stub_admin_role(monkeypatch, "security_admin")
    monkeypatch.setattr(db, "has_permission", lambda role, action: False)
    monkeypatch.setattr(soar, "manual_release_admin_account", lambda u: pytest.fail("권한 없이 해제됐다"))

    assert _post_unlock_admin(client, {"username": "boss"}).status_code == 403


def test_unlock_admin_account_requires_username(client, monkeypatch):
    stub_admin_role(monkeypatch, "super_admin")
    monkeypatch.setattr(db, "has_permission", lambda role, action: True)

    assert _post_unlock_admin(client, {}).status_code == 400


def test_api_status_includes_active_admin_account_lockouts(client, monkeypatch):
    lockouts = [{"username": "boss", "failure_count": 9, "unlock_at": "t", "locked_at": "t"}]
    expired_checked = []
    monkeypatch.setattr(db, "list_active_admin_account_lockouts", lambda: lockouts)
    monkeypatch.setattr(soar, "try_release_expired_admin_account_lockouts", lambda: expired_checked.append(1))
    for name, value in {
        "list_recent_attempts": ([], 0), "list_active_lockouts": [], "list_active_account_lockouts": [],
        "list_admin_login_log": ([], 0), "list_users": ([], 0), "get_signup_enabled": True,
        "list_posts": ([], 0), "list_comments_admin": ([], 0), "list_security_events": ([], 0),
        "list_security_incidents": ([], 0), "list_pending_requests": ([], 0),
    }.items():
        monkeypatch.setattr(db, name, lambda *a, _v=value, **k: _v)
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(soar, "try_release_expired_account_lockouts", lambda: None)
    monkeypatch.setattr(db, "has_permission", lambda role, action: False)
    with client.session_transaction() as sess:
        login_admin_session(sess, "root")

    response = client.get("/api/status")

    assert response.get_json()["active_admin_account_lockouts"] == lockouts
    assert expired_checked == [1]  # 폴링할 때 만료된 관리자 계정 잠금도 정리한다


# ---------------------------------------------------------------------------
# CLI: scripts/unlock_account.py --admin
# ---------------------------------------------------------------------------

def test_cli_admin_unlocks_through_soar(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(soar, "manual_release_admin_account", lambda u: calls.append(u) or True)
    monkeypatch.setattr(db, "release_account_lockout", lambda u: pytest.fail("회원 계정 잠금을 건드렸다"))
    monkeypatch.setattr(sys, "argv", ["unlock_account.py", "--admin", "--username", "boss"])

    unlock_account.main()

    assert calls == ["boss"]
    assert "관리자 계정 boss" in capsys.readouterr().out


def test_cli_admin_lists_without_changes_when_no_target_given(monkeypatch, capsys):
    monkeypatch.setattr(
        db, "list_active_admin_account_lockouts",
        lambda: [{"username": "boss", "failure_count": 9, "locked_at": "t1", "unlock_at": "t2"}],
    )
    monkeypatch.setattr(soar, "manual_release_admin_account", lambda u: pytest.fail("조회만 해야 한다"))
    monkeypatch.setattr(sys, "argv", ["unlock_account.py", "--admin"])

    unlock_account.main()

    assert "boss" in capsys.readouterr().out


def test_cli_admin_rejects_permanent_option(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["unlock_account.py", "--admin", "--permanent", "--username", "boss"])

    with pytest.raises(SystemExit):
        unlock_account.main()
