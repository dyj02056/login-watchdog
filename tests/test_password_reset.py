# ============================================================================
# test_password_reset.py — 비밀번호 찾기(재설정) (guide41)
#
#   - 요청: 인증된(VERIFIED) 계정에만 메일, 아이디 없음·미인증·반송·한도는 메일 없이 같은 화면,
#     IP 빈도 제한, 허니팟, 프로필에서 넘어올 때 아이디 미리 채우기
#   - 재설정: GET은 소비 안 함, 형식이 틀리면 링크가 닳지 않음, 성공하면 세션 세대 번호가 올라
#     다른 기기 로그아웃 + 알림, 재사용·이메일 변경 후의 옛 링크는 무효
#   - 용도 분리: 재설정 토큰은 /email/confirm에서, 인증 토큰은 /password/reset에서 쓰이지 않는다
# ============================================================================

import re
import types

import pytest

import config
import db
import email_verification
import mailer
import soar

from tests.test_app import get_csrf_token  # noqa: E402

VERIFIED_USER = {
    "id": 7, "username": "alice", "email": "alice@example.com", "name": "",
    "email_status": "VERIFIED", "session_version": 0,
}


@pytest.fixture
def store(monkeypatch):
    s = types.SimpleNamespace(
        users={7: dict(VERIFIED_USER)}, tokens=[], mails=[], activity=(0, None), ip_count=0,
        passwords=[], statuses=[], version=0,
    )
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://watchdog.test")
    monkeypatch.setattr(config, "RECOVERY_MIN_RESPONSE_SECONDS", 0)
    monkeypatch.setattr(db, "get_user_by_username", lambda u: next((x for x in s.users.values() if x["username"] == u), None))
    monkeypatch.setattr(db, "get_user_by_id", lambda uid: s.users.get(uid))
    monkeypatch.setattr(db, "get_email_token_activity", lambda uid, purpose, hours=24: s.activity)
    monkeypatch.setattr(db, "count_email_tokens_by_ip", lambda ip, purpose, hours=1: s.ip_count)

    def create(user_id, purpose, email, token_hash, ip, expires_iso):
        row = {"id": len(s.tokens) + 1, "user_id": user_id, "purpose": purpose, "email": email,
               "token_hash": token_hash, "status": "PENDING"}
        s.tokens.append(row)
        return row

    monkeypatch.setattr(db, "create_email_token", create)
    monkeypatch.setattr(
        db, "get_pending_email_token",
        lambda h: next((t for t in s.tokens if t["token_hash"] == h and t["status"] == "PENDING"), None),
    )

    def consume(token_id):
        for t in s.tokens:
            if t["id"] == token_id and t["status"] == "PENDING":
                t["status"] = "USED"
                return dict(t)
        return None

    monkeypatch.setattr(db, "consume_email_token", consume)
    monkeypatch.setattr(
        db, "revoke_email_token", lambda tid: [t.update(status="REVOKED") for t in s.tokens if t["id"] == tid]
    )
    monkeypatch.setattr(db, "set_user_email_status", lambda uid, status: s.statuses.append((uid, status)))

    def update_password(uid, new_password):
        s.passwords.append((uid, new_password))
        s.version += 1
        return s.version

    monkeypatch.setattr(db, "update_user_password", update_password)
    monkeypatch.setattr(db, "get_user_session_version", lambda uid: s.version if uid == 7 else None)
    monkeypatch.setattr(mailer, "send_password_reset_email", lambda to, link: s.mails.append(("reset", to, link)) or mailer.SENT)
    monkeypatch.setattr(mailer, "send_password_reset_notice", lambda to: s.mails.append(("notice", to, "")) or mailer.SENT)
    s.token = lambda: next(m for m in reversed(s.mails) if m[0] == "reset")[2].split("t=", 1)[1]
    return s


# ---------------------------------------------------------------------------
# 요청 (email_verification.request_password_reset)
# ---------------------------------------------------------------------------

def test_verified_account_gets_a_reset_link_and_only_the_hash_is_stored(store):
    email_verification.request_password_reset("alice", "1.1.1.1")

    kind, to, link = store.mails[0]
    assert (kind, to) == ("reset", "alice@example.com")
    assert link.startswith("https://watchdog.test/password/reset?t=")
    assert store.tokens[0]["purpose"] == "PASSWORD_RESET"
    assert store.tokens[0]["token_hash"] != store.token()


@pytest.mark.parametrize("username, status", [
    ("ghost", "VERIFIED"),         # 없는 아이디
    ("alice", "UNKNOWN"),          # 미인증 — 확인된 적 없는 주소로는 계정을 되찾는 메일을 보내지 않는다
    ("alice", "UNDELIVERABLE"),
    ("bad name!", "VERIFIED"),     # 아이디 형식 아님
])
def test_no_mail_unless_the_account_has_a_verified_email(store, username, status):
    store.users[7]["email_status"] = status

    email_verification.request_password_reset(username, "1.1.1.1")

    assert store.mails == [] and store.tokens == []


def test_daily_limit_per_account(store):
    store.activity = (config.PASSWORD_RESET_MAX_PER_DAY, None)

    email_verification.request_password_reset("alice", "1.1.1.1")

    assert store.mails == []


def test_refused_reset_mail_marks_the_email_undeliverable(store, monkeypatch):
    monkeypatch.setattr(mailer, "send_password_reset_email", lambda to, link: mailer.REFUSED)

    email_verification.request_password_reset("alice", "1.1.1.1")

    assert store.statuses == [(7, "UNDELIVERABLE")]
    assert store.tokens[0]["status"] == "REVOKED"


# ---------------------------------------------------------------------------
# 화면: /password/forgot
# ---------------------------------------------------------------------------

def _flash(html):
    return re.findall(r"<li>(.*?)</li>", html)


def _forgot(client, username, extra=None):
    csrf = get_csrf_token(client, "/password/forgot")
    data = {"username": username, "csrf_token": csrf}
    data.update(extra or {})
    return client.post("/password/forgot", data=data).get_data(as_text=True)


def test_forgot_response_is_identical_whether_or_not_mail_is_sent(client, store):
    sent = _flash(_forgot(client, "alice"))
    store.users[7]["email_status"] = "UNKNOWN"
    unverified = _flash(_forgot(client, "alice"))
    unknown = _flash(_forgot(client, "ghost"))

    assert sent == unverified == unknown
    assert len(store.mails) == 1  # 실제 메일은 인증된 계정의 첫 요청에만


def test_forgot_is_limited_per_ip(client, store):
    store.ip_count = config.PASSWORD_RESET_MAX_PER_IP_PER_HOUR

    html = _forgot(client, "alice")

    assert "요청이 너무 많습니다" in html and store.mails == []


def test_forgot_honeypot_is_dropped(client, store, monkeypatch):
    bots = []
    monkeypatch.setattr(soar, "notify_bot_detected", lambda ip, path: bots.append(path))

    _forgot(client, "alice", extra={"website": "spam"})

    assert bots == ["/password/forgot"] and store.mails == []


def test_forgot_form_prefills_only_a_valid_username(client, store):
    assert 'value="alice"' in client.get("/password/forgot?username=alice").get_data(as_text=True)
    assert 'value="&lt;b&gt;"' not in client.get("/password/forgot?username=<b>").get_data(as_text=True)


def test_forgot_submit_has_its_own_rate_limit(client, store, monkeypatch):
    monkeypatch.setattr(soar, "record_rejection", lambda *a, **k: None)
    csrf = get_csrf_token(client, "/password/forgot")
    statuses = [
        client.post("/password/forgot", data={"username": "ghost", "csrf_token": csrf}).status_code
        for _ in range(config.PASSWORD_RESET_RATE_LIMIT_PER_MINUTE + 1)
    ]

    assert statuses[:-1] == [200] * config.PASSWORD_RESET_RATE_LIMIT_PER_MINUTE
    assert statuses[-1] == 429


# ---------------------------------------------------------------------------
# 화면: /password/reset
# ---------------------------------------------------------------------------

def _reset(client, token, password, confirm=None):
    csrf = get_csrf_token(client, "/password/forgot")
    return client.post(
        "/password/reset",
        data={"t": token, "new_password": password, "new_password_confirm": password if confirm is None else confirm,
              "csrf_token": csrf},
    )


def test_opening_the_reset_link_does_not_consume_it(client, store, monkeypatch):
    email_verification.request_password_reset("alice", "1.1.1.1")
    monkeypatch.setattr(db, "consume_email_token", lambda tid: pytest.fail("GET에서 토큰을 소비했다"))

    html = client.get(f"/password/reset?t={store.token()}").get_data(as_text=True)

    assert "a***e" in html and 'name="new_password"' in html


def test_invalid_reset_link_shows_invalid(client, store):
    assert "만료되었거나 이미 사용된 링크" in client.get("/password/reset?t=nope").get_data(as_text=True)


@pytest.mark.parametrize("password, confirm, message", [
    ("short", None, "최소"),
    ("new-password-2", "different-3", "일치하지 않습니다"),
])
def test_bad_new_password_does_not_use_up_the_link(client, store, password, confirm, message):
    email_verification.request_password_reset("alice", "1.1.1.1")

    html = _reset(client, store.token(), password, confirm).get_data(as_text=True)

    assert message in html and 'name="new_password"' in html
    assert store.tokens[0]["status"] == "PENDING" and store.passwords == []


def test_successful_reset_changes_the_password_notifies_and_logs_out_other_devices(client, flask_app, store):
    email_verification.request_password_reset("alice", "1.1.1.1")
    other_device = flask_app.test_client()
    with other_device.session_transaction() as sess:
        sess["username"], sess["user_id"], sess["session_version"] = "alice", 7, 0

    response = _reset(client, store.token(), "new-password-2")

    assert response.headers["Location"] == "/login"
    assert store.passwords == [(7, "new-password-2")]
    assert store.mails[-1] == ("notice", "alice@example.com", "")
    assert store.tokens[0]["status"] == "USED"
    # 세션 세대 번호가 올라갔으므로 다른 기기의 로그인은 끊긴다(guide35의 문지기)
    assert other_device.get("/dashboard/profile").headers["Location"] == "/login"
    assert "비밀번호가 재설정되었습니다" in client.get("/login").get_data(as_text=True)


def test_reset_link_cannot_be_used_twice(client, store):
    email_verification.request_password_reset("alice", "1.1.1.1")
    token = store.token()
    _reset(client, token, "new-password-2")

    html = _reset(client, token, "new-password-3").get_data(as_text=True)

    assert "만료되었거나 이미 사용된 링크" in html
    assert store.passwords == [(7, "new-password-2")]


def test_reset_link_sent_to_an_old_email_is_invalid_after_the_email_changed(client, store):
    email_verification.request_password_reset("alice", "1.1.1.1")
    store.users[7]["email"] = "changed@example.com"

    assert "만료되었거나 이미 사용된 링크" in client.get(f"/password/reset?t={store.token()}").get_data(as_text=True)
    _reset(client, store.token(), "new-password-2")
    assert store.passwords == []


# ---------------------------------------------------------------------------
# 용도 분리
# ---------------------------------------------------------------------------

def test_reset_token_is_rejected_by_the_email_confirm_page_without_being_used(client, store):
    email_verification.request_password_reset("alice", "1.1.1.1")
    token = store.token()

    assert "만료되었거나 이미 사용된 링크" in client.get(f"/email/confirm?t={token}").get_data(as_text=True)
    csrf = get_csrf_token(client, "/password/forgot")
    client.post("/email/confirm", data={"t": token, "csrf_token": csrf})

    assert store.tokens[0]["status"] == "PENDING"  # 재설정 링크는 그대로 쓸 수 있다
    assert _reset(client, token, "new-password-2").headers["Location"] == "/login"


def test_email_verification_token_cannot_reset_a_password(client, store, monkeypatch):
    store.users[7]["email_status"] = "UNKNOWN"
    links = []
    monkeypatch.setattr(mailer, "send_email_verification", lambda to, link: links.append(link) or mailer.SENT)
    email_verification.send_verification(store.users[7], "1.1.1.1")
    token = links[0].split("t=", 1)[1]

    assert "만료되었거나 이미 사용된 링크" in client.get(f"/password/reset?t={token}").get_data(as_text=True)
    _reset(client, token, "new-password-2")
    assert store.passwords == []


# ---------------------------------------------------------------------------
# 연결 링크
# ---------------------------------------------------------------------------

def test_login_form_links_to_password_forgot(client):
    assert 'href="/password/forgot"' in client.get("/login").get_data(as_text=True)


@pytest.fixture
def logged_in(client, store, monkeypatch):
    monkeypatch.setattr(db, "get_pending_email_token_for_user", lambda uid, purpose: None)
    with client.session_transaction() as sess:
        sess["username"], sess["user_id"], sess["session_version"] = "alice", 7, 0


def test_profile_links_to_reset_with_the_username_when_verified(client, store, logged_in):
    html = client.get("/dashboard/profile").get_data(as_text=True)

    assert 'href="/password/forgot?username=alice"' in html


def test_profile_asks_for_email_verification_first_when_unverified(client, store, logged_in):
    store.users[7]["email_status"] = "UNKNOWN"

    html = client.get("/dashboard/profile").get_data(as_text=True)

    assert "/password/forgot" not in html and "먼저 위에서 이메일 인증" in html


# ---------------------------------------------------------------------------
# db
# ---------------------------------------------------------------------------

def test_count_email_tokens_by_ip_filters_ip_and_purpose(monkeypatch):
    calls = []

    class Fake:
        def __getattr__(self, method):
            def call(*args, **kwargs):
                calls.append((method, args))
                return self
            return call

        def execute(self):
            return types.SimpleNamespace(data=[], count=2)

    monkeypatch.setattr(db, "get_client", lambda: Fake())

    assert db.count_email_tokens_by_ip("1.1.1.1", "PASSWORD_RESET", 1) == 2
    assert ("eq", ("requested_ip", "1.1.1.1")) in calls and ("eq", ("purpose", "PASSWORD_RESET")) in calls
