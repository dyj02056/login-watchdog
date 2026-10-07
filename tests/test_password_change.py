# ============================================================================
# test_password_change.py — 비밀번호 변경 + 세션 무효화 (guide35)
#
# 확인하는 것
#   - 회원 화면 문지기가 세션 세대 번호(session_version)를 DB 값과 비교해 다른 기기의 세션을 끊는가
#   - 비밀번호 변경이 현재 비밀번호를 확인하고, 틀리면 로그인 실패와 같은 기준으로 기록·잠금하는가
#   - 바꾸면 세대 번호가 올라가 이 기기는 유지되고 이전 세션은 끊기며, 알림 메일이 나가는가
#   - db.update_user_password가 조건부 UPDATE로 번호를 올리는가
# test_app.py와 같은 방식(Flask 테스트 클라이언트 + monkeypatch)을 쓴다.
# ============================================================================

import types

import pytest

import config
import db
import detector
import mailer
import soar

from tests.test_app import get_csrf_token  # noqa: E402


# ---------------------------------------------------------------------------
# 공용 준비물
# ---------------------------------------------------------------------------

class Account:
    """메모리 위의 회원 한 명 — 비밀번호와 세션 세대 번호를 들고 있다."""

    def __init__(self):
        self.password = "old-password-1"
        self.version = 0
        self.failures = []
        self.notices = []
        self.updates = []


@pytest.fixture
def account(monkeypatch):
    acc = Account()
    user = {"id": 7, "username": "alice", "email": "alice@example.com", "name": "", "session_version": 0}
    monkeypatch.setattr(db, "get_user_by_id", lambda uid: user if uid == 7 else None)
    monkeypatch.setattr(db, "get_user_session_version", lambda uid: acc.version if uid == 7 else None)
    monkeypatch.setattr(db, "verify_user_credentials", lambda u, p: u == "alice" and p == acc.password)
    monkeypatch.setattr(db, "log_attempt", lambda ip, u, success: acc.failures.append((ip, u, success)))

    def update(uid, new_password):
        acc.password = new_password
        acc.version += 1
        acc.updates.append(new_password)
        return acc.version

    monkeypatch.setattr(db, "update_user_password", update)
    monkeypatch.setattr(mailer, "send_password_changed_notice", lambda to: acc.notices.append(to) or mailer.SENT)
    monkeypatch.setattr(detector, "is_account_locked", lambda u: False)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(detector, "is_suspicious", lambda ip: (False, 1))
    monkeypatch.setattr(detector, "is_account_suspicious", lambda u: (False, 1))
    return acc


def _log_in(client, version=0):
    with client.session_transaction() as sess:
        sess["username"] = "alice"
        sess["user_id"] = 7
        if version is not None:
            sess["session_version"] = version


def _change(client, current, new, confirm=None, extra=None):
    token = get_csrf_token(client, "/dashboard/profile")
    data = {
        "current_password": current,
        "new_password": new,
        "new_password_confirm": new if confirm is None else confirm,
        "csrf_token": token,
    }
    data.update(extra or {})
    return client.post("/dashboard/password", data=data)


def _flashes(client):
    with client.session_transaction() as sess:
        return [message for _, message in sess.get("_flashes", [])]


# ---------------------------------------------------------------------------
# 회원 화면 문지기 — 세션 세대 번호
# ---------------------------------------------------------------------------

def test_session_with_current_version_can_use_member_pages(client, account):
    _log_in(client, version=0)

    assert client.get("/dashboard/profile").status_code == 200


def test_session_created_before_this_feature_has_no_version_and_is_treated_as_zero(client, account):
    _log_in(client, version=None)  # 기능 도입 전에 로그인한 세션

    assert client.get("/dashboard/profile").status_code == 200


def test_session_with_outdated_version_is_logged_out(client, account):
    account.version = 2  # 다른 기기에서 비밀번호가 바뀌었다
    _log_in(client, version=1)

    response = client.get("/dashboard")

    assert response.status_code == 302 and response.headers["Location"] == "/login"
    with client.session_transaction() as sess:
        assert "username" not in sess and "user_id" not in sess and "session_version" not in sess
    assert any("로그아웃되었습니다" in m for m in _flashes(client))


def test_board_pages_are_protected_by_the_same_check(client, account):
    account.version = 1
    _log_in(client, version=0)

    response = client.get("/board")

    assert response.status_code == 302 and response.headers["Location"] == "/login"


def test_deleted_member_session_is_logged_out(client, account, monkeypatch):
    monkeypatch.setattr(db, "get_user_session_version", lambda uid: None)
    _log_in(client)

    assert client.get("/dashboard/profile").headers["Location"] == "/login"


def test_logout_keeps_the_admin_session_in_the_same_browser(client, account):
    _log_in(client)
    with client.session_transaction() as sess:
        sess["admin_username"] = "boss"

    token = get_csrf_token(client, "/dashboard/profile")
    client.post("/dashboard/logout", data={"csrf_token": token})

    with client.session_transaction() as sess:
        assert "username" not in sess and "session_version" not in sess
        assert sess["admin_username"] == "boss"


def test_login_stores_the_current_session_version(client, monkeypatch):
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(soar, "try_release_expired_account_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(detector, "is_account_locked", lambda u: False)
    monkeypatch.setattr(db, "verify_user_credentials", lambda u, p: True)
    monkeypatch.setattr(db, "log_attempt", lambda *a: None)
    monkeypatch.setattr(db, "get_user_by_username", lambda u: {"id": 7, "username": u, "session_version": 4})

    token = get_csrf_token(client, "/login")
    client.post("/login", data={"username": "alice", "password": "x", "csrf_token": token})

    with client.session_transaction() as sess:
        assert sess["session_version"] == 4


# ---------------------------------------------------------------------------
# 비밀번호 변경 — 성공
# ---------------------------------------------------------------------------

def test_successful_change_bumps_version_keeps_this_session_and_notifies(client, account):
    _log_in(client)

    response = _change(client, "old-password-1", "new-password-2")

    assert response.status_code == 302 and response.headers["Location"] == "/dashboard/profile"
    assert account.updates == ["new-password-2"]
    assert account.notices == ["alice@example.com"]
    assert any("다른 기기의 로그인은 모두 해제" in m for m in _flashes(client))
    with client.session_transaction() as sess:
        assert sess["session_version"] == 1  # 이 기기는 새 번호를 받아 로그인 유지
    assert client.get("/dashboard/profile").status_code == 200


def test_other_devices_are_logged_out_after_the_change(client, flask_app, account):
    other_device = flask_app.test_client()
    _log_in(other_device, version=0)  # 변경 전에 다른 기기에서 로그인해 둔 세션(탈취된 세션일 수도 있다)
    _log_in(client, version=0)

    _change(client, "old-password-1", "new-password-2")

    assert other_device.get("/dashboard").headers["Location"] == "/login"
    assert client.get("/dashboard/profile").status_code == 200


def test_mail_failure_does_not_undo_the_change(client, account, monkeypatch):
    monkeypatch.setattr(mailer, "send_password_changed_notice", lambda to: mailer.FAILED)
    _log_in(client)

    _change(client, "old-password-1", "new-password-2")

    assert account.password == "new-password-2"


# ---------------------------------------------------------------------------
# 비밀번호 변경 — 입력 검증 (본인 확인과 무관한 실수는 실패 횟수에 넣지 않는다)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "current, new, confirm, expected",
    [
        ("old-password-1", "short", None, "최소"),
        ("old-password-1", "new-password-2", "different-3", "일치하지 않습니다"),
        ("old-password-1", "old-password-1", None, "현재 비밀번호와 같습니다"),
        ("", "new-password-2", None, "모두 입력"),
    ],
)
def test_invalid_new_password_is_rejected_before_checking_the_current_one(client, account, current, new, confirm, expected):
    _log_in(client)

    _change(client, current, new, confirm)

    assert account.updates == [] and account.failures == []
    assert any(expected in m for m in _flashes(client))


# ---------------------------------------------------------------------------
# 비밀번호 변경 — 현재 비밀번호 확인 (세션 탈취 대비 + 잠금 우회 방지)
# ---------------------------------------------------------------------------

def test_wrong_current_password_is_recorded_as_a_login_failure(client, account):
    _log_in(client)

    _change(client, "wrong-guess", "new-password-2")

    assert account.updates == [] and account.notices == []
    assert account.failures == [("127.0.0.1", "alice", False)]
    assert any("현재 비밀번호가 올바르지 않습니다" in m for m in _flashes(client))


def test_repeated_wrong_guesses_lock_the_account_and_end_the_session(client, account, monkeypatch):
    monkeypatch.setattr(detector, "is_account_suspicious", lambda u: (True, 9))
    monkeypatch.setattr(detector, "count_distinct_ips_by_username", lambda u: 1)
    locked = []
    monkeypatch.setattr(soar, "enforce_account_lockout", lambda *a: locked.append(a))
    _log_in(client)

    response = _change(client, "wrong-guess", "new-password-2")

    assert locked == [("alice", 9, 1, "127.0.0.1")]
    assert response.headers["Location"] == "/login"
    with client.session_transaction() as sess:
        assert "username" not in sess


def test_ip_threshold_also_applies_but_an_already_locked_ip_is_not_locked_again(client, account, monkeypatch):
    monkeypatch.setattr(detector, "is_suspicious", lambda ip: (True, 6))
    monkeypatch.setattr(detector, "count_distinct_usernames", lambda ip: 1)
    ip_locks = []
    monkeypatch.setattr(soar, "enforce_lockout", lambda *a: ip_locks.append(a))
    _log_in(client)

    _change(client, "wrong-guess", "new-password-2")
    assert ip_locks == [("127.0.0.1", 6, 1)]

    # 영구 잠금 예외로 들어온 회원처럼 이미 잠긴 IP라면 5분 잠금 알림을 또 보내지 않는다
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    _log_in(client)
    _change(client, "wrong-guess", "new-password-2")
    assert len(ip_locks) == 1


def test_locked_account_cannot_change_password(client, account, monkeypatch):
    monkeypatch.setattr(detector, "is_account_locked", lambda u: True)
    monkeypatch.setattr(db, "verify_user_credentials", lambda *a: (_ for _ in ()).throw(AssertionError("확인하면 안 된다")))
    _log_in(client)

    response = _change(client, "old-password-1", "new-password-2")

    assert response.headers["Location"] == "/login" and account.updates == []


def test_honeypot_submission_is_dropped(client, account, monkeypatch):
    bots = []
    monkeypatch.setattr(soar, "notify_bot_detected", lambda ip, path: bots.append(path))
    _log_in(client)

    _change(client, "old-password-1", "new-password-2", extra={"website": "spam"})

    assert account.updates == [] and bots == ["/dashboard/password"]


def test_change_requires_csrf_and_login(client, account):
    _log_in(client)
    assert client.post("/dashboard/password", data={"current_password": "x"}).status_code == 400  # CSRF 없음

    anonymous = client.application.test_client()
    token = get_csrf_token(anonymous, "/login")
    response = anonymous.post("/dashboard/password", data={"csrf_token": token})
    assert response.headers["Location"] == "/login"


def test_profile_page_shows_the_password_form(client, account):
    _log_in(client)

    html = client.get("/dashboard/profile").get_data(as_text=True)

    assert 'action="/dashboard/password"' in html
    assert 'type="password"' in html and 'name="current_password"' in html


# ---------------------------------------------------------------------------
# db.update_user_password — 조건부 UPDATE로 세대 번호를 올린다
# ---------------------------------------------------------------------------

class _Chain:
    def __init__(self, responses, log):
        self._responses = responses  # 순서대로 돌려줄 execute() 결과
        self._log = log

    def table(self, name):
        return self

    def __getattr__(self, method):
        def call(*args, **kwargs):
            self._log.append((method, args, kwargs))
            return self

        return call

    def execute(self):
        return types.SimpleNamespace(data=self._responses.pop(0))


def test_update_user_password_increments_version_conditionally(monkeypatch):
    log = []
    responses = [[{"session_version": 3}], [{"id": 7}]]
    monkeypatch.setattr(db, "get_client", lambda: _Chain(responses, log))

    assert db.update_user_password(7, "new-password-2") == 4

    update = next(entry for entry in log if entry[0] == "update")[1][0]
    assert update["session_version"] == 4
    assert update["password_hash"] != "new-password-2"  # 평문이 아니라 해시로 저장
    assert ("eq", ("session_version", 3), {}) in log  # 읽은 값 그대로일 때만 올린다


def test_update_user_password_retries_when_another_change_won_the_race(monkeypatch):
    log = []
    responses = [[{"session_version": 3}], [], [{"session_version": 4}], [{"id": 7}]]
    monkeypatch.setattr(db, "get_client", lambda: _Chain(responses, log))

    assert db.update_user_password(7, "new-password-2") == 5


@pytest.mark.real_lockdown  # 공용 기본 stub을 끄고 실제 함수를 확인한다
def test_get_user_session_version_returns_none_for_missing_user(monkeypatch):
    monkeypatch.setattr(db, "get_client", lambda: _Chain([[]], []))
    assert db.get_user_session_version(99) is None


# ---------------------------------------------------------------------------
# 메일 문구
# ---------------------------------------------------------------------------

def test_recovery_done_notice_points_to_the_profile_page(monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "_send_mail", lambda to, subject, body: sent.append(body) or mailer.SENT)
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://login-watchdog.vercel.app")

    mailer.send_recovery_done_notice("a@b.com", "account")

    assert "https://login-watchdog.vercel.app/dashboard/profile" in sent[0]
    assert "다른 기기의 로그인은 모두 해제" in sent[0]


def test_password_changed_notice_is_sent_to_the_account_email(monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "_send_mail", lambda to, subject, body: sent.append((to, subject)) or mailer.SENT)

    mailer.send_password_changed_notice("a@b.com")

    assert sent == [("a@b.com", "[로그인 워치독] 비밀번호가 변경되었습니다")]
