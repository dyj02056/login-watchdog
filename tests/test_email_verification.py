# ============================================================================
# test_email_verification.py — 이메일 인증 + 이메일 변경 보호 (guide40)
#
#   - email_verification: 인증 링크 발송(한도·반송·설정 없음), 변경 요청(빈 주소 / 이미 쓰는 주소를
#     화면상 똑같이), 확인(인증 / 변경 / 만료·재사용 / 옛 주소 링크 / 그사이 선점)
#   - 화면: /email/confirm(GET은 소비 안 함), 프로필(이름만 바로 저장, 이메일은 비밀번호+링크),
#     인증 메일 다시 보내기, 대시보드 배너, 회원가입 직후 발송
#   - db: 토큰 생성·소비, 이메일 변경, 인증 표시 조건
# ============================================================================

import re
import types
from datetime import datetime, timedelta, timezone

import pytest

import config
import db
from notify import mailer
from security import detector, soar
from services import email_verification

from tests.test_app import get_csrf_token  # noqa: E402

UNKNOWN_USER = {"id": 7, "username": "alice", "email": "alice@example.com", "name": "", "email_status": "UNKNOWN"}


# ---------------------------------------------------------------------------
# 메모리 위의 토큰 저장소 + 메일함
# ---------------------------------------------------------------------------

class Store:
    def __init__(self):
        self.users = {7: dict(UNKNOWN_USER), 8: {**UNKNOWN_USER, "id": 8, "username": "bob", "email": "bob@example.com"}}
        self.tokens = []
        self.mails = []          # (종류, 받는 주소, 링크 또는 내용)
        self.activity = (0, None)
        self.statuses = []

    def link_token(self):
        return self.mails[-1][2].split("t=", 1)[1]


@pytest.fixture
def store(monkeypatch):
    s = Store()
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://watchdog.test")
    monkeypatch.setattr(db, "get_email_token_activity", lambda uid, purpose, hours=24: s.activity)

    def create(user_id, purpose, email, token_hash, ip, expires_iso):
        for t in s.tokens:
            if t["user_id"] == user_id and t["purpose"] == purpose and t["status"] == "PENDING":
                t["status"] = "REVOKED"
        row = {"id": len(s.tokens) + 1, "user_id": user_id, "purpose": purpose, "email": email,
               "token_hash": token_hash, "requested_ip": ip, "status": "PENDING", "expires_at": expires_iso}
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
        db, "revoke_email_token",
        lambda token_id: [t.update(status="REVOKED") for t in s.tokens if t["id"] == token_id and t["status"] == "PENDING"],
    )
    monkeypatch.setattr(
        db, "get_pending_email_token_for_user",
        lambda uid, purpose: next(
            (t for t in s.tokens if t["user_id"] == uid and t["purpose"] == purpose and t["status"] == "PENDING"), None
        ),
    )
    monkeypatch.setattr(db, "get_user_by_id", lambda uid: s.users.get(uid))
    monkeypatch.setattr(
        db, "is_email_taken",
        lambda email, exclude_user_id=None: any(
            u["email"] == email and u["id"] != exclude_user_id for u in s.users.values()
        ),
    )

    def change(uid, new_email):
        if any(u["email"] == new_email and u["id"] != uid for u in s.users.values()):
            return False
        s.users[uid].update(email=new_email, email_status="VERIFIED")
        return True

    monkeypatch.setattr(db, "change_user_email", change)

    def mark(uid, email):
        if s.users[uid]["email"] != email:
            return False
        s.users[uid]["email_status"] = "VERIFIED"
        return True

    monkeypatch.setattr(db, "mark_user_email_verified", mark)
    monkeypatch.setattr(db, "set_user_email_status", lambda uid, status: s.statuses.append((uid, status)))

    monkeypatch.setattr(mailer, "send_email_verification", lambda to, link: s.mails.append(("verify", to, link)) or mailer.SENT)
    monkeypatch.setattr(
        mailer, "send_email_change_confirmation", lambda to, link: s.mails.append(("change", to, link)) or mailer.SENT
    )
    monkeypatch.setattr(mailer, "send_email_in_use_notice", lambda to: s.mails.append(("in_use", to, "")) or mailer.SENT)
    monkeypatch.setattr(
        mailer, "send_email_changed_notice", lambda old, masked: s.mails.append(("changed", old, masked)) or mailer.SENT
    )
    return s


# ---------------------------------------------------------------------------
# email_verification — 발송
# ---------------------------------------------------------------------------

def test_verification_link_uses_public_base_url_and_stores_only_the_hash(store):
    assert email_verification.send_verification(store.users[7], "1.1.1.1") == email_verification.SENT

    kind, to, link = store.mails[0]
    assert (kind, to) == ("verify", "alice@example.com")
    assert link.startswith("https://watchdog.test/email/confirm?t=")
    token = store.link_token()
    assert store.tokens[0]["token_hash"] != token and len(store.tokens[0]["token_hash"]) == 64


def test_already_verified_email_gets_no_mail(store):
    store.users[7]["email_status"] = "VERIFIED"

    assert email_verification.send_verification(store.users[7], "1.1.1.1") == email_verification.ALREADY_VERIFIED
    assert store.mails == [] and store.tokens == []


@pytest.mark.parametrize("activity", [
    (5, None),                                                       # 하루 한도
    (1, (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()),  # 쿨다운
])
def test_verification_is_rate_limited(store, activity):
    store.activity = activity

    assert email_verification.send_verification(store.users[7], "1.1.1.1") == email_verification.RATE_LIMITED
    assert store.mails == []


def test_refused_recipient_marks_the_email_undeliverable_and_revokes_the_token(store, monkeypatch):
    monkeypatch.setattr(mailer, "send_email_verification", lambda to, link: mailer.REFUSED)

    assert email_verification.send_verification(store.users[7], "1.1.1.1") == email_verification.UNAVAILABLE
    assert store.statuses == [(7, "UNDELIVERABLE")]
    assert store.tokens[0]["status"] == "REVOKED"


def test_temporary_mail_failure_does_not_mark_undeliverable(store, monkeypatch):
    monkeypatch.setattr(mailer, "send_email_verification", lambda to, link: mailer.FAILED)

    assert email_verification.send_verification(store.users[7], "1.1.1.1") == email_verification.UNAVAILABLE
    assert store.statuses == [] and store.tokens[0]["status"] == "REVOKED"


def test_no_mail_in_production_without_public_base_url(store, monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "")
    monkeypatch.setattr(config, "IS_PRODUCTION", True)
    monkeypatch.setattr(mailer, "report_failure", lambda *a: None)

    assert email_verification.send_verification(store.users[7], "1.1.1.1") == email_verification.UNAVAILABLE
    assert store.tokens == [] and store.mails == []


def test_email_change_request_mails_the_new_address_but_changes_nothing_yet(store):
    assert email_verification.request_email_change(store.users[7], "new@example.com", "1.1.1.1") == email_verification.SENT

    assert store.mails[0][:2] == ("change", "new@example.com")
    assert store.users[7]["email"] == "alice@example.com"  # 링크를 눌러야 바뀐다


def test_email_change_to_a_taken_address_looks_the_same_but_sends_only_a_notice(store):
    result = email_verification.request_email_change(store.users[7], "bob@example.com", "1.1.1.1")

    assert result == email_verification.SENT  # 화면 응답은 빈 주소일 때와 같다
    assert store.mails == [("in_use", "bob@example.com", "")]
    assert store.tokens[0]["status"] == "REVOKED"  # 확인 링크는 존재하지 않는다


# ---------------------------------------------------------------------------
# email_verification — 확인
# ---------------------------------------------------------------------------

def test_confirming_a_verification_link_marks_the_email_verified(store):
    email_verification.send_verification(store.users[7], "1.1.1.1")

    result, _ = email_verification.confirm(store.link_token())

    assert result == email_verification.CONFIRMED_VERIFIED
    assert store.users[7]["email_status"] == "VERIFIED"


def test_link_cannot_be_used_twice(store):
    email_verification.send_verification(store.users[7], "1.1.1.1")
    token = store.link_token()

    email_verification.confirm(token)
    assert email_verification.confirm(token)[0] == email_verification.CONFIRM_INVALID


def test_old_verification_link_cannot_verify_a_changed_email(store):
    email_verification.send_verification(store.users[7], "1.1.1.1")
    store.users[7]["email"] = "changed@example.com"

    assert email_verification.confirm(store.link_token())[0] == email_verification.CONFIRM_STALE
    assert store.users[7]["email_status"] == "UNKNOWN"


def test_confirming_an_email_change_switches_the_email_and_notifies_the_old_one(store):
    email_verification.request_email_change(store.users[7], "new@example.com", "1.1.1.1")

    result, _ = email_verification.confirm(store.link_token())

    assert result == email_verification.CONFIRMED_CHANGED
    assert store.users[7]["email"] == "new@example.com" and store.users[7]["email_status"] == "VERIFIED"
    assert store.mails[-1] == ("changed", "alice@example.com", "n*w@example.com")


def test_email_taken_before_the_link_was_clicked_is_not_applied(store):
    email_verification.request_email_change(store.users[7], "new@example.com", "1.1.1.1")
    store.users[8]["email"] = "new@example.com"  # 그사이 다른 회원이 차지

    assert email_verification.confirm(store.link_token())[0] == email_verification.CONFIRM_TAKEN
    assert store.users[7]["email"] == "alice@example.com"
    assert not any(kind == "changed" for kind, _, _ in store.mails)


def test_unknown_token_is_invalid(store):
    assert email_verification.confirm("no-such-token")[0] == email_verification.CONFIRM_INVALID
    assert email_verification.confirm("")[0] == email_verification.CONFIRM_INVALID


@pytest.mark.parametrize("email, masked", [
    ("alice@example.com", "a***e@example.com"),
    ("ab@example.com", "a*@example.com"),
    ("a@example.com", "a*@example.com"),
])
def test_mask_email(email, masked):
    assert email_verification.mask_email(email) == masked


# ---------------------------------------------------------------------------
# 화면: /email/confirm
# ---------------------------------------------------------------------------

def test_opening_the_link_does_not_consume_it(client, store, monkeypatch):
    email_verification.send_verification(store.users[7], "1.1.1.1")
    monkeypatch.setattr(db, "consume_email_token", lambda token_id: pytest.fail("GET에서 토큰을 소비했다"))

    html = client.get(f"/email/confirm?t={store.link_token()}").get_data(as_text=True)

    assert "a***e@example.com" in html  # 확인할 주소는 가려서 보여준다
    assert store.tokens[0]["status"] == "PENDING"


def test_link_page_for_unknown_token_shows_invalid(client, store):
    assert "만료되었거나 이미 사용된 링크" in client.get("/email/confirm?t=nope").get_data(as_text=True)


def test_confirm_button_applies_once(client, store):
    email_verification.request_email_change(store.users[7], "new@example.com", "1.1.1.1")
    token = store.link_token()

    csrf = get_csrf_token(client, f"/email/confirm?t={token}")

    def submit():
        return client.post("/email/confirm", data={"t": token, "csrf_token": csrf}).get_data(as_text=True)

    assert "이메일이 변경되었습니다" in submit()
    assert store.users[7]["email"] == "new@example.com"
    assert "만료되었거나 이미 사용된 링크" in submit()


# ---------------------------------------------------------------------------
# 화면: 회원 프로필 / 대시보드
# ---------------------------------------------------------------------------

@pytest.fixture
def member(client, store, monkeypatch):
    env = types.SimpleNamespace(password="old-password-1", failures=[], names=[], change_calls=[])
    monkeypatch.setattr(db, "verify_user_credentials", lambda u, p: u == "alice" and p == env.password)
    monkeypatch.setattr(db, "log_attempt", lambda ip, u, success: env.failures.append((u, success)))
    monkeypatch.setattr(db, "update_user_name", lambda uid, name: env.names.append((uid, name)))
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(detector, "is_suspicious", lambda ip: (False, 1))
    monkeypatch.setattr(detector, "is_account_suspicious", lambda u: (False, 1))
    with client.session_transaction() as sess:
        sess["username"] = "alice"
        sess["user_id"] = 7
        sess["session_version"] = 0
    return env


def _flash(response_html):
    return re.findall(r"<li>(.*?)</li>", response_html)


def _change_email(client, new_email, password, extra=None):
    csrf = get_csrf_token(client, "/dashboard/profile")
    data = {"new_email": new_email, "current_password": password, "csrf_token": csrf}
    data.update(extra or {})
    client.post("/dashboard/email/change", data=data)
    return client.get("/dashboard/profile").get_data(as_text=True)


def test_profile_form_only_saves_the_name_even_if_an_email_is_sent(client, store, member):
    csrf = get_csrf_token(client, "/dashboard/profile")
    client.post("/dashboard/profile", data={"name": "앨리스", "email": "attacker@evil.test", "csrf_token": csrf})

    assert member.names == [(7, "앨리스")]
    assert store.users[7]["email"] == "alice@example.com" and store.mails == []


def test_email_change_needs_the_current_password_and_counts_failures(client, store, member):
    html = _change_email(client, "new@example.com", "wrong-password")

    assert "현재 비밀번호가 올바르지 않습니다" in html
    assert member.failures == [("alice", False)]
    assert store.mails == [] and store.tokens == []


def test_wrong_password_that_crosses_the_threshold_locks_and_logs_out(client, store, member, monkeypatch):
    locks = []
    monkeypatch.setattr(detector, "is_account_suspicious", lambda u: (True, 9))
    monkeypatch.setattr(detector, "count_distinct_ips_by_username", lambda u: 1)
    monkeypatch.setattr(soar, "enforce_account_lockout", lambda *a: locks.append(a))
    csrf = get_csrf_token(client, "/dashboard/profile")

    response = client.post(
        "/dashboard/email/change", data={"new_email": "n@example.com", "current_password": "bad", "csrf_token": csrf}
    )

    assert response.headers["Location"] == "/login" and len(locks) == 1
    with client.session_transaction() as sess:
        assert "username" not in sess


def test_email_change_response_is_the_same_for_free_and_taken_addresses(client, store, member):
    free = _flash(_change_email(client, "new@example.com", member.password))
    store.activity = (0, None)
    taken = _flash(_change_email(client, "bob@example.com", member.password))

    assert free == taken and "확인 메일을 보냈습니다" in free[0]
    assert [kind for kind, _, _ in store.mails] == ["change", "in_use"]


def test_pending_email_change_is_shown_on_the_profile(client, store, member):
    html = _change_email(client, "new@example.com", member.password)

    assert "확인 대기 중" in html and "n*w@example.com" in html
    assert "alice@example.com" in html  # 아직 바뀌지 않았다


@pytest.mark.parametrize("new_email, message", [
    ("not-an-email", "올바른 이메일 형식이 아닙니다"),
    ("ALICE@example.com", "지금 쓰고 있는 이메일과 같습니다"),
])
def test_email_change_input_is_validated_before_the_password(client, store, member, new_email, message):
    html = _change_email(client, new_email, member.password)

    assert message in html
    assert member.failures == [] and store.mails == []


def test_email_change_honeypot_is_dropped(client, store, member, monkeypatch):
    bots = []
    monkeypatch.setattr(soar, "notify_bot_detected", lambda ip, path: bots.append(path))

    _change_email(client, "new@example.com", member.password, extra={"website": "spam"})

    assert bots == ["/dashboard/email/change"] and store.mails == []


def test_resend_from_the_dashboard_returns_to_the_dashboard(client, store, member):
    csrf = get_csrf_token(client, "/dashboard")
    response = client.post("/dashboard/email/verify/resend", data={"next": "dashboard", "csrf_token": csrf})

    assert response.headers["Location"] == "/dashboard"
    assert store.mails[0][:2] == ("verify", "alice@example.com")
    assert "a***e@example.com" in client.get("/dashboard").get_data(as_text=True)


def test_dashboard_banner_depends_on_the_email_status(client, store, member):
    assert "이메일 인증이 필요합니다" in client.get("/dashboard").get_data(as_text=True)

    store.users[7]["email_status"] = "UNDELIVERABLE"
    assert "메일이 전달되지 않습니다" in client.get("/dashboard").get_data(as_text=True)

    store.users[7]["email_status"] = "VERIFIED"
    html = client.get("/dashboard").get_data(as_text=True)
    assert "이메일 인증이 필요합니다" not in html and "메일이 전달되지 않습니다" not in html


def test_profile_shows_the_verified_badge_without_a_resend_button(client, store, member):
    store.users[7]["email_status"] = "VERIFIED"

    html = client.get("/dashboard/profile").get_data(as_text=True)

    assert "인증됨" in html and "/dashboard/email/verify/resend" not in html


# ---------------------------------------------------------------------------
# 회원가입 직후 발송
# ---------------------------------------------------------------------------

@pytest.fixture
def signup_env(monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(detector, "is_signup_rate_limited", lambda ip: (False, 0))
    monkeypatch.setattr(db, "log_signup_attempt", lambda ip: None)
    monkeypatch.setattr(
        db, "create_user",
        lambda username, email, password: {"id": 9, "username": username, "email": email, "email_status": "UNKNOWN"},
    )


def _signup(client):
    csrf = get_csrf_token(client, "/signup")
    client.post("/signup", data={"username": "newbie", "email": "n@example.com", "password": "password123",
                                 "password_confirm": "password123", "csrf_token": csrf})
    return client.get("/login").get_data(as_text=True)


def test_signup_sends_a_verification_mail_to_the_new_account(client, signup_env, monkeypatch):
    sent = []
    monkeypatch.setattr(email_verification, "send_verification", lambda user, ip: sent.append(user) or email_verification.SENT)

    html = _signup(client)

    assert sent[0]["id"] == 9 and sent[0]["email"] == "n@example.com"
    assert "인증 메일을 보냈습니다" in html


def test_signup_succeeds_even_if_the_verification_mail_breaks(client, signup_env, monkeypatch):
    reported = []
    monkeypatch.setattr(email_verification, "send_verification", lambda user, ip: 1 / 0)
    monkeypatch.setattr(mailer, "report_failure", lambda category, detail: reported.append(category))

    html = _signup(client)

    assert "회원가입이 완료되었습니다" in html and "대시보드에서" in html
    assert reported == [mailer.FAIL_INTERNAL]


# ---------------------------------------------------------------------------
# db
# ---------------------------------------------------------------------------

class _Recorder:
    """체이닝 호출을 기록하고, execute()마다 미리 정한 결과를 순서대로 돌려주는 가짜 클라이언트."""

    def __init__(self, responses=None):
        self.calls = []
        self._responses = list(responses or [])

    def __getattr__(self, method):
        def call(*args, **kwargs):
            self.calls.append((method, args, kwargs))
            return self

        return call

    def execute(self):
        return types.SimpleNamespace(data=self._responses.pop(0) if self._responses else [], count=0)


def test_create_email_token_revokes_the_previous_pending_token_first(monkeypatch):
    fake = _Recorder(responses=[[], [{"id": 3}]])
    monkeypatch.setattr(db, "get_client", lambda: fake)

    assert db.create_email_token(7, "EMAIL_VERIFY", "a@b.c", "h", "1.1.1.1", "2026-01-01T00:00:00+00:00") == {"id": 3}

    methods = [c[0] for c in fake.calls]
    assert methods.index("update") < methods.index("insert")
    assert ("update", ({"status": "REVOKED"},), {}) in fake.calls


def test_consume_email_token_is_conditional(monkeypatch):
    fake = _Recorder(responses=[[{"id": 3, "status": "USED"}]])
    monkeypatch.setattr(db, "get_client", lambda: fake)

    assert db.consume_email_token(3)["status"] == "USED"
    assert ("eq", ("status", "PENDING"), {}) in fake.calls
    assert any(c[0] == "gt" and c[1][0] == "expires_at" for c in fake.calls)


def test_mark_user_email_verified_only_for_the_same_email(monkeypatch):
    fake = _Recorder(responses=[[]])
    monkeypatch.setattr(db, "get_client", lambda: fake)

    assert db.mark_user_email_verified(7, "old@example.com") is False
    assert ("eq", ("email", "old@example.com"), {}) in fake.calls


def test_change_user_email_refuses_an_address_taken_by_someone_else(monkeypatch):
    fake = _Recorder(responses=[[{"id": 8}]])
    monkeypatch.setattr(db, "get_client", lambda: fake)

    assert db.change_user_email(7, "bob@example.com") is False
    assert not any(c[0] == "update" for c in fake.calls)


def test_change_user_email_sets_the_new_address_as_verified(monkeypatch):
    fake = _Recorder(responses=[[], [{"id": 7}]])
    monkeypatch.setattr(db, "get_client", lambda: fake)

    assert db.change_user_email(7, "new@example.com") is True
    update = next(c for c in fake.calls if c[0] == "update")[1][0]
    assert update["email"] == "new@example.com" and update["email_status"] == "VERIFIED"


def test_create_user_returns_the_new_row(monkeypatch):
    fake = _Recorder(responses=[[], [], [{"id": 9, "email": "n@example.com"}]])
    monkeypatch.setattr(db, "get_client", lambda: fake)

    assert db.create_user("newbie", "n@example.com", "password123") == {"id": 9, "email": "n@example.com"}


def test_create_user_returns_none_for_a_taken_username(monkeypatch):
    monkeypatch.setattr(db, "get_client", lambda: _Recorder(responses=[[{"id": 1}]]))

    assert db.create_user("alice", "x@example.com", "password123") is None


def test_dashboard_user_list_includes_the_email_status(monkeypatch):
    fake = _Recorder(responses=[[]])
    monkeypatch.setattr(db, "get_client", lambda: fake)

    db.list_users(1, 10)

    select = next(c for c in fake.calls if c[0] == "select")
    assert "email_status" in select[1][0]
