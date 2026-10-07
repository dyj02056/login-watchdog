# ============================================================================
# test_recovery.py — 이메일 복구(guide34-a): mailer, /recovery 4개 엔드포인트, 영구 잠금 상태의
# 로그인/가입 판정(예외 통과·회수)을 검증한다.
#
# 진짜 SMTP/Supabase 대신 (1) smtplib.SMTP를 가짜로, (2) db 함수를 메모리 저장소로
# 바꿔치기해서 "복구 요청 → 메일 → 링크/코드 → 해제" 전체 흐름을 코드로 재현한다.
# 이 파일은 영구 잠금 기본 stub(autouse)을 꺼야 해서 real_lockdown 마커를 단다.
# ============================================================================

import smtplib
from datetime import datetime, timedelta, timezone

import pytest

import alert
import config
import db
import detector
import helpers
import lockdown
import mailer
import soar

from tests.test_app import get_csrf_token  # noqa: E402

pytestmark = pytest.mark.real_lockdown


# ===========================================================================
# mailer
# ===========================================================================

class _FakeSMTP:
    """smtplib.SMTP를 흉내내고, 어떤 일이 있었는지 기록한다."""

    instances = []
    send_error = None

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.events = []
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.events.append("starttls")

    def login(self, user, password):
        self.events.append(("login", user, password))

    def send_message(self, message):
        if _FakeSMTP.send_error:
            raise _FakeSMTP.send_error
        self.events.append(("send", message["To"], message["Subject"], message.get_content()))


@pytest.fixture
def fake_smtp(monkeypatch):
    _FakeSMTP.instances = []
    _FakeSMTP.send_error = None
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setattr(config, "MAIL_BACKEND", "smtp")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(config, "SMTP_PORT", 587)
    monkeypatch.setattr(config, "SMTP_USER", "")
    monkeypatch.setattr(config, "SMTP_STARTTLS", True)
    return _FakeSMTP


def test_smtp_backend_sends_with_timeout_starttls_and_includes_link_and_code(fake_smtp):
    result = mailer.send_recovery_email("a@b.com", "http://x/recovery/verify?t=TOKEN", "123456", "account")

    assert result == mailer.SENT
    smtp = fake_smtp.instances[0]
    assert (smtp.host, smtp.port, smtp.timeout) == ("smtp.test", 587, config.SMTP_TIMEOUT_SECONDS)
    assert smtp.events[0] == "starttls"
    sent = next(e for e in smtp.events if e[0] == "send")
    assert sent[1] == "a@b.com"
    assert "http://x/recovery/verify?t=TOKEN" in sent[3] and "123456" in sent[3]


def test_smtp_without_starttls_and_credentials_skips_both_for_mailpit(fake_smtp, monkeypatch):
    monkeypatch.setattr(config, "SMTP_STARTTLS", False)

    mailer.send_recovery_email("a@b.com", "l", "1", "ip")

    assert [e for e in fake_smtp.instances[0].events if e == "starttls" or e[0] == "login"] == []


def test_smtp_logs_in_when_credentials_are_configured(fake_smtp, monkeypatch):
    monkeypatch.setattr(config, "SMTP_USER", "me")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "pw")

    mailer.send_recovery_email("a@b.com", "l", "1", "ip")

    assert ("login", "me", "pw") in fake_smtp.instances[0].events


def test_permanent_recipient_refusal_is_reported_as_refused(fake_smtp):
    fake_smtp.send_error = smtplib.SMTPRecipientsRefused({"a@b.com": (550, b"no such user")})
    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.REFUSED


def test_temporary_refusal_and_network_errors_are_failed_not_refused(fake_smtp):
    fake_smtp.send_error = smtplib.SMTPRecipientsRefused({"a@b.com": (450, b"try later")})
    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.FAILED

    fake_smtp.send_error = ConnectionRefusedError("down")
    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.FAILED


def test_smtp_backend_without_host_fails_without_raising(monkeypatch):
    monkeypatch.setattr(config, "MAIL_BACKEND", "smtp")
    monkeypatch.setattr(config, "SMTP_HOST", "")
    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.FAILED


def test_console_backend_prints_in_development_but_is_refused_in_production(monkeypatch, capsys):
    monkeypatch.setattr(config, "MAIL_BACKEND", "console")
    monkeypatch.setattr(config, "IS_PRODUCTION", False)
    assert mailer.send_recovery_email("a@b.com", "http://link", "654321", "account") == mailer.SENT
    assert "http://link" in capsys.readouterr().out

    monkeypatch.setattr(config, "IS_PRODUCTION", True)
    assert mailer.send_recovery_email("a@b.com", "http://link", "654321", "account") == mailer.FAILED
    assert "http://link" not in capsys.readouterr().out  # 운영 로그에 토큰이 남으면 안 된다


# ===========================================================================
# 메모리 저장소로 바꿔치기한 db — 복구 흐름 전체를 재현한다
# ===========================================================================

class Store:
    def __init__(self):
        self.users = {
            "alice": {"id": 1, "username": "alice", "email": "alice@example.com", "email_status": "UNKNOWN"},
        }
        self.account_locks = {}   # username -> row (active 영구 잠금)
        self.ip_locks = {}        # ip -> row
        self.requests = []        # recovery_requests 행들
        self.exemptions = []
        self.events = []
        self.mails = []           # (kind, to, link, code)
        self.done_notices = []
        self.released_accounts = []
        self.probation = []
        self.history_released = []
        self.email_status_changes = []
        self.recoverable_changes = []
        self.ip_count = 0
        self.user_count = 0
        self.latest_time = None
        self.mail_result = mailer.SENT
        self.next_id = 1

    def lock_account(self, username, recoverable="SELF"):
        self.account_locks[username] = {"lock_type": "PERMANENT", "recoverable": recoverable, "active": True}

    def lock_ip(self, ip, recoverable="EXEMPTION"):
        self.ip_locks[ip] = {"lock_type": "PERMANENT", "recoverable": recoverable, "active": True}

    def pending(self):
        return [r for r in self.requests if r["status"] == "PENDING"]


@pytest.fixture
def store(monkeypatch):
    s = Store()
    monkeypatch.setattr(config, "RECOVERY_MIN_RESPONSE_SECONDS", 0)

    monkeypatch.setattr(db, "get_user_by_username", lambda username: s.users.get(username))
    monkeypatch.setattr(db, "get_user_by_id", lambda uid: next((u for u in s.users.values() if u["id"] == uid), None))
    monkeypatch.setattr(db, "expire_old_recovery_requests", lambda: None)
    monkeypatch.setattr(db, "count_recovery_requests_by_ip", lambda ip, hours=1: s.ip_count)
    monkeypatch.setattr(db, "get_recovery_activity", lambda uid, hours=24: (s.user_count, s.latest_time))
    monkeypatch.setattr(db, "get_active_account_lockout", lambda u: s.account_locks.get(u))
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: s.ip_locks.get(ip))

    def create_request(user_id, kind, value, token_hash, code_hash, device_hash, requested_ip, expires_iso):
        for r in s.requests:
            if (r["user_id"], r["target_kind"], r["target_value"]) == (user_id, kind, value) and r["status"] == "PENDING":
                r["status"] = "REVOKED"
        row = {
            "id": s.next_id, "user_id": user_id, "target_kind": kind, "target_value": value,
            "token_hash": token_hash, "code_hash": code_hash, "device_hash": device_hash,
            "requested_ip": requested_ip, "status": "PENDING", "code_attempts": 0,
            "expires_at": expires_iso, "created_at": datetime.now(timezone.utc).isoformat(),
        }
        s.next_id += 1
        s.requests.append(row)
        return row

    monkeypatch.setattr(db, "create_recovery_request", create_request)
    monkeypatch.setattr(
        db, "get_pending_recovery_by_token_hash",
        lambda h: next((r for r in s.pending() if r["token_hash"] == h), None),
    )
    monkeypatch.setattr(
        db, "get_latest_pending_recovery_for_user",
        lambda uid: next((r for r in reversed(s.pending()) if r["user_id"] == uid), None),
    )

    def consume(request_id):
        for r in s.requests:
            if r["id"] == request_id and r["status"] == "PENDING":
                r["status"] = "VERIFIED"
                return dict(r)
        return None  # 이미 소비됨 — DB의 조건부 UPDATE가 0행을 돌려주는 것과 같다

    monkeypatch.setattr(db, "consume_recovery_request", consume)

    def bump(request_id, current, max_attempts):
        for r in s.requests:
            if r["id"] == request_id:
                r["code_attempts"] = current + 1
                if current + 1 >= max_attempts:
                    r["status"] = "REVOKED"
                return current + 1

    monkeypatch.setattr(db, "increment_recovery_code_attempts", bump)

    def revoke(request_id):
        for r in s.requests:
            if r["id"] == request_id and r["status"] == "PENDING":
                r["status"] = "REVOKED"
                return True
        return False

    monkeypatch.setattr(db, "revoke_recovery_request", revoke)
    monkeypatch.setattr(db, "set_user_email_status", lambda uid, status: s.email_status_changes.append((uid, status)))
    monkeypatch.setattr(db, "insert_security_event", lambda *a, **k: s.events.append((a, k)))
    monkeypatch.setattr(db, "set_account_lockout_recoverable", lambda u, r: s.recoverable_changes.append((u, r)))

    # lockdown.apply_recovery가 부르는 db
    def release_account(username, only_recoverable=None):
        row = s.account_locks.get(username)
        if not row or not row["active"]:
            return False
        if only_recoverable and row["recoverable"] != only_recoverable:
            return False
        row["active"] = False
        s.released_accounts.append(username)
        return True

    monkeypatch.setattr(db, "release_permanent_account_lockout", release_account)
    monkeypatch.setattr(db, "resolve_security_events_for_username", lambda u: None)
    monkeypatch.setattr(db, "mark_lock_released", lambda *a, **k: s.history_released.append(a))
    monkeypatch.setattr(db, "set_account_probation", lambda u, until: s.probation.append((u, until)))
    monkeypatch.setattr(
        db, "insert_ip_exemption",
        lambda ip, uid, dev, via, exp: s.exemptions.append({"ip": ip, "user_id": uid, "device_hash": dev, "via": via}),
    )
    monkeypatch.setattr(alert, "send_recovery_completed_alert", lambda *a: None)

    def fake_send_recovery_email(to, link, code, kind):
        s.mails.append((kind, to, link, code))
        return s.mail_result

    monkeypatch.setattr(mailer, "send_recovery_email", fake_send_recovery_email)
    monkeypatch.setattr(mailer, "send_recovery_done_notice", lambda to, kind: s.done_notices.append((to, kind)))
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "http://watchdog.test")
    return s


def _request_recovery(client, username="alice", extra=None):
    token = get_csrf_token(client, "/recovery")
    data = {"username": username, "csrf_token": token}
    data.update(extra or {})
    return client.post("/recovery/request", data=data)


def _token_from(store):
    link = store.mails[-1][2]
    return link.split("t=", 1)[1]


GENERIC = "등록된 이메일이 있다면 안내 메일을 보냈습니다"


# ===========================================================================
# POST /recovery/request
# ===========================================================================

def test_request_for_permanently_locked_account_sends_mail_and_stores_only_hashes(client, store):
    store.lock_account("alice")

    response = _request_recovery(client)

    assert response.status_code == 200 and GENERIC in response.get_data(as_text=True)
    kind, to, link, code = store.mails[0]
    assert (kind, to) == ("account", "alice@example.com")
    assert link.startswith("http://watchdog.test/recovery/verify?t=")  # Host 헤더가 아니라 PUBLIC_BASE_URL
    token = link.split("t=", 1)[1]
    stored = store.requests[0]
    assert token not in str(stored) and code not in str(stored)  # 원문은 저장하지 않는다
    assert stored["token_hash"] == helpers.hash_secret(token)
    assert stored["code_hash"] == helpers.hash_secret(code)
    assert len(code) == 6 and code.isdigit()


def test_request_sets_device_cookie_httponly_and_stores_its_hash(client, store):
    store.lock_account("alice")

    response = _request_recovery(client)

    cookie = next(h for h in response.headers.getlist("Set-Cookie") if h.startswith("lw_dev="))
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    raw = cookie.split(";")[0].split("=", 1)[1]
    assert store.requests[0]["device_hash"] == helpers.hash_secret(raw)


@pytest.mark.parametrize(
    "scenario",
    ["unknown_user", "not_locked", "admin_only", "undeliverable_email", "ip_not_locked"],
)
def test_ineligible_requests_get_the_same_response_and_no_mail(client, store, scenario):
    if scenario == "admin_only":
        store.lock_account("alice", recoverable="ADMIN_ONLY")
    elif scenario == "undeliverable_email":
        store.lock_account("alice")
        store.users["alice"]["email_status"] = "UNDELIVERABLE"
    username = "ghost" if scenario == "unknown_user" else "alice"

    response = _request_recovery(client, username)

    assert response.status_code == 200 and GENERIC in response.get_data(as_text=True)
    assert store.mails == [] and store.requests == []
    assert any(h.startswith("lw_dev=") for h in response.headers.getlist("Set-Cookie"))  # 응답 모양도 같다


def test_ip_permanent_lock_with_exemption_recovery_issues_ip_kind_request(client, store):
    store.lock_ip("127.0.0.1")

    _request_recovery(client)

    assert store.mails[0][0] == "ip"
    assert store.requests[0]["target_value"] == "127.0.0.1"


def test_ip_permanent_lock_with_admin_only_recovery_sends_no_mail(client, store):
    store.lock_ip("127.0.0.1", recoverable="ADMIN_ONLY")

    _request_recovery(client)

    assert store.mails == []


def test_ip_rate_limit_blocks_with_a_distinct_message_and_no_mail(client, store):
    store.lock_account("alice")
    store.ip_count = config.RECOVERY_MAX_PER_IP_PER_HOUR

    response = _request_recovery(client)

    assert "요청이 너무 많습니다" in response.get_data(as_text=True)
    assert store.mails == []


def test_per_user_daily_limit_and_cooldown_suppress_mail_silently(client, store):
    store.lock_account("alice")
    store.user_count = config.RECOVERY_MAX_PER_USER_PER_DAY
    response = _request_recovery(client)
    assert GENERIC in response.get_data(as_text=True) and store.mails == []

    store.user_count = 0
    store.latest_time = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()  # 쿨다운 60초 안
    _request_recovery(client)
    assert store.mails == []

    store.latest_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    _request_recovery(client)
    assert len(store.mails) == 1


def test_new_request_revokes_the_previous_pending_one(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    _request_recovery(client)

    assert [r["status"] for r in store.requests] == ["REVOKED", "PENDING"]


def test_honeypot_request_is_dropped_but_looks_normal(client, store, monkeypatch):
    store.lock_account("alice")
    bots = []
    monkeypatch.setattr(soar, "notify_bot_detected", lambda ip, path: bots.append((ip, path)))

    response = _request_recovery(client, extra={"website": "http://spam"})

    assert GENERIC in response.get_data(as_text=True)
    assert store.mails == [] and bots == [("127.0.0.1", "/recovery/request")]


def test_permanent_recipient_refusal_flags_account_and_escalates_to_admin_only(client, store):
    store.lock_account("alice")
    store.mail_result = mailer.REFUSED

    response = _request_recovery(client)

    assert GENERIC in response.get_data(as_text=True)  # 사용자에게는 항상 같은 안내
    assert store.email_status_changes == [(1, "UNDELIVERABLE")]
    assert store.recoverable_changes == [("alice", "ADMIN_ONLY")]
    # MEDIUM 이벤트로만 기록한다(요청 IP가 HIGH 사건에 묶이는 부작용 방지)
    (args, kwargs) = store.events[0]
    assert args[:2] == ("EMAIL_UNDELIVERABLE", "MEDIUM") and kwargs == {"username": "alice"}
    assert store.requests[0]["status"] == "REVOKED"  # 못 보낸 요청은 쓸 수 없게 취소


def test_transient_mail_failure_revokes_request_but_does_not_flag_the_email(client, store):
    store.lock_account("alice")
    store.mail_result = mailer.FAILED

    _request_recovery(client)

    assert store.email_status_changes == [] and store.recoverable_changes == []
    assert store.requests[0]["status"] == "REVOKED"


def test_production_without_public_base_url_sends_no_mail(client, store, monkeypatch):
    store.lock_account("alice")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "")
    monkeypatch.setattr(config, "IS_PRODUCTION", True)

    _request_recovery(client)

    assert store.mails == []


# ===========================================================================
# GET /recovery/verify — 토큰을 소비하지 않는다
# ===========================================================================

def test_get_verify_shows_confirmation_without_consuming_the_token(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    token = _token_from(store)

    first = client.get(f"/recovery/verify?t={token}")
    second = client.get(f"/recovery/verify?t={token}")  # 메일 보안 스캐너가 먼저 열어도

    html = first.get_data(as_text=True)
    assert first.status_code == 200 and "a***e" in html and "127.0.0.1" in html and "alice" not in html
    assert "해제" in html and second.status_code == 200
    assert store.pending()[0]["status"] == "PENDING"  # 여전히 쓸 수 있다
    assert store.released_accounts == []


def test_get_verify_with_unknown_or_missing_token(client, store):
    assert "만료되었거나" in client.get("/recovery/verify?t=nope").get_data(as_text=True)
    assert "6자리 코드" in client.get("/recovery/verify").get_data(as_text=True)


# ===========================================================================
# POST /recovery/verify — 계정 해제
# ===========================================================================

def _confirm(client, token):
    csrf = get_csrf_token(client, "/recovery/verify")
    return client.post("/recovery/verify", data={"t": token, "csrf_token": csrf})


def test_confirming_account_recovery_releases_lock_starts_probation_and_notifies(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    token = _token_from(store)

    response = _confirm(client, token)

    assert "복구 완료" in response.get_data(as_text=True)
    assert store.released_accounts == ["alice"]
    assert store.history_released[0][:3] == ("account", "alice", "EMAIL_RECOVERY")
    assert store.probation and store.probation[0][0] == "alice"
    assert store.done_notices == [("alice@example.com", "account")]


def test_probation_ends_after_configured_hours(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    _confirm(client, _token_from(store))

    until = datetime.fromisoformat(store.probation[0][1])
    expected = datetime.now(timezone.utc) + timedelta(hours=config.RECOVERY_PROBATION_HOURS)
    assert abs((until - expected).total_seconds()) < 60


def test_token_is_one_time_use(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    token = _token_from(store)

    assert "복구 완료" in _confirm(client, token).get_data(as_text=True)
    second = _confirm(client, token)

    assert "만료되었거나" in second.get_data(as_text=True)
    assert store.released_accounts == ["alice"]  # 한 번만 해제됐다


def test_concurrent_consume_losing_the_race_does_nothing(client, store, monkeypatch):
    # 조회 시점엔 PENDING이었지만, 소비 직전에 다른 요청이 먼저 소비한 상황(조건부 UPDATE가 0행)
    store.lock_account("alice")
    _request_recovery(client)
    token = _token_from(store)
    monkeypatch.setattr(db, "consume_recovery_request", lambda request_id: None)

    response = _confirm(client, token)

    assert "만료되었거나" in response.get_data(as_text=True)
    assert store.released_accounts == [] and store.done_notices == []


def test_recovery_cannot_release_a_lock_that_became_admin_only(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    store.account_locks["alice"]["recoverable"] = "ADMIN_ONLY"  # 요청 후 관리자 전용으로 올라감

    response = _confirm(client, _token_from(store))

    assert "복구할 수 없습니다" in response.get_data(as_text=True)
    assert store.released_accounts == [] and store.done_notices == []


def test_expired_request_is_not_confirmable(client, store, monkeypatch):
    store.lock_account("alice")
    _request_recovery(client)
    token = _token_from(store)
    store.requests[0]["status"] = "EXPIRED"

    assert "만료되었거나" in _confirm(client, token).get_data(as_text=True)


# ===========================================================================
# IP 복구 — 요청한 기기에서만 완료된다
# ===========================================================================

def test_ip_recovery_from_the_requesting_device_issues_exemption_bound_to_user_and_device(client, store):
    store.lock_ip("127.0.0.1")
    _request_recovery(client)  # 이 client가 요청 기기(lw_dev 쿠키를 받는다)
    token = _token_from(store)

    response = _confirm(client, token)

    assert "복구 완료" in response.get_data(as_text=True)
    assert store.exemptions == [
        {"ip": "127.0.0.1", "user_id": 1, "device_hash": store.requests[0]["device_hash"], "via": "EMAIL_RECOVERY"}
    ]
    assert store.released_accounts == []  # IP 자체는 계속 잠겨 있다(예외만 발급)
    assert store.ip_locks["127.0.0.1"]["active"] is True


def test_ip_recovery_link_opened_on_another_device_is_rejected_and_not_consumed(client, flask_app, store):
    store.lock_ip("127.0.0.1")
    _request_recovery(client)
    token = _token_from(store)
    other_device = flask_app.test_client()  # 쿠키가 없는 다른 기기(예: 공격자가 엮은 피해자의 폰)

    get_page = other_device.get(f"/recovery/verify?t={token}")
    assert "요청한 기기" in get_page.get_data(as_text=True)

    csrf = get_csrf_token(other_device, "/recovery/verify")
    response = other_device.post("/recovery/verify", data={"t": token, "csrf_token": csrf})

    assert "요청한 기기" in response.get_data(as_text=True)
    assert store.exemptions == []
    assert store.pending()[0]["status"] == "PENDING"  # 소비되지 않았으니 요청 기기에서 다시 쓸 수 있다
    # 요청 기기에서는 같은 링크로 정상 완료된다
    assert "복구 완료" in _confirm(client, token).get_data(as_text=True)


def test_ip_recovery_attacker_device_cannot_use_a_different_cookie(client, flask_app, store):
    store.lock_ip("127.0.0.1")
    _request_recovery(client)
    token = _token_from(store)
    attacker = flask_app.test_client()
    attacker.set_cookie("lw_dev", "attacker-cookie-value")

    csrf = get_csrf_token(attacker, "/recovery/verify")
    attacker.post("/recovery/verify", data={"t": token, "csrf_token": csrf})

    assert store.exemptions == []


# ===========================================================================
# 6자리 코드 경로
# ===========================================================================

def _submit_code(client, username, code):
    csrf = get_csrf_token(client, "/recovery/verify")
    return client.post("/recovery/verify", data={"username": username, "code": code, "csrf_token": csrf})


def test_correct_code_completes_account_recovery(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    code = store.mails[0][3]

    response = _submit_code(client, "alice", code)

    assert "복구 완료" in response.get_data(as_text=True)
    assert store.released_accounts == ["alice"]


def test_wrong_code_counts_attempts_and_revokes_after_the_limit(client, store):
    store.lock_account("alice")
    _request_recovery(client)
    real_code = store.mails[0][3]
    wrong = "000000" if real_code != "000000" else "111111"

    for attempt in range(1, config.RECOVERY_MAX_CODE_ATTEMPTS):
        response = _submit_code(client, "alice", wrong)
        assert f"남은 시도 {config.RECOVERY_MAX_CODE_ATTEMPTS - attempt}회" in response.get_data(as_text=True)

    final = _submit_code(client, "alice", wrong)
    assert "다시 요청" in final.get_data(as_text=True)
    assert store.requests[0]["status"] == "REVOKED"

    # 한도를 넘어 취소된 뒤에는 맞는 코드도 소용없다
    assert "복구 완료" not in _submit_code(client, "alice", real_code).get_data(as_text=True)
    assert store.released_accounts == []


def test_code_for_ip_recovery_from_another_device_is_not_checked_and_not_counted(client, flask_app, store):
    store.lock_ip("127.0.0.1")
    _request_recovery(client)
    code = store.mails[0][3]
    other_device = flask_app.test_client()

    response = _submit_code(other_device, "alice", code)

    assert "요청한 기기" in response.get_data(as_text=True)
    assert store.requests[0]["code_attempts"] == 0  # 코드가 맞는지 알려주는 창구가 되지 않는다
    assert store.exemptions == []


def test_code_for_unknown_user_gives_generic_failure(client, store):
    response = _submit_code(client, "ghost", "123456")
    assert "올바르지 않거나 만료" in response.get_data(as_text=True)


# ===========================================================================
# 로그인/가입 판정 — 영구 잠금 + 예외
# ===========================================================================

@pytest.fixture
def login_env(monkeypatch):
    env = {"verify_calls": [], "revoked": [], "failures": 0, "exemption": None}
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(soar, "try_release_expired_account_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_account_locked", lambda username: False)
    monkeypatch.setattr(detector, "get_account_lock_state", lambda username: "NONE")
    monkeypatch.setattr(db, "log_attempt", lambda *a: None)
    monkeypatch.setattr(db, "get_user_by_username", lambda username: {"id": 1, "username": username})
    monkeypatch.setattr(
        db, "verify_user_credentials",
        lambda username, password: env["verify_calls"].append(username) or (password == "right"),
    )
    monkeypatch.setattr(db, "get_active_ip_exemption", lambda ip, uid, dev: env["exemption"] if dev else None)
    monkeypatch.setattr(db, "count_recent_failures", lambda ip: env["failures"])
    monkeypatch.setattr(db, "revoke_ip_exemption", lambda i, reason: env["revoked"].append((i, reason)) or True)
    return env


def _login(client, password="wrong"):
    token = get_csrf_token(client, "/login")
    return client.post("/login", data={"username": "alice", "password": password, "csrf_token": token})


def test_permanently_locked_ip_without_exemption_is_blocked_with_recovery_link(client, login_env, monkeypatch):
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "PERMANENT")

    response = _login(client, "right")

    html = response.get_data(as_text=True)
    assert "차단되어 있습니다" in html and "/recovery" in html
    assert login_env["verify_calls"] == []  # 비밀번호 확인 자체를 건너뛴다


def test_temporary_lock_keeps_the_original_message_without_recovery_link(client, login_env, monkeypatch):
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "TEMPORARY")

    html = _login(client, "right").get_data(as_text=True)

    assert "잠긴 계정입니다" in html and "/recovery" not in html


def test_permanently_locked_account_shows_recovery_link(client, login_env, monkeypatch):
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(detector, "is_account_locked", lambda username: True)
    monkeypatch.setattr(detector, "get_account_lock_state", lambda username: "PERMANENT")

    html = _login(client, "right").get_data(as_text=True)

    assert "영구 잠금된 계정" in html and "/recovery" in html
    assert login_env["verify_calls"] == []


def test_exempted_user_with_device_cookie_passes_through_the_permanent_ip_lock(client, login_env, monkeypatch):
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "PERMANENT")
    login_env["exemption"] = {"id": 9}
    client.set_cookie("lw_dev", "my-device-cookie")

    response = _login(client, "right")

    assert response.status_code == 302 and response.headers["Location"] == "/dashboard"
    assert login_env["verify_calls"] == ["alice"]


def test_same_exemption_without_the_device_cookie_is_blocked(client, login_env, monkeypatch):
    # NAT 안의 공격자: 피해자의 아이디는 알지만 기기 쿠키(lw_dev)가 없다
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "PERMANENT")
    login_env["exemption"] = {"id": 9}

    html = _login(client, "right").get_data(as_text=True)

    assert "차단되어 있습니다" in html and login_env["verify_calls"] == []


def test_exempted_user_failing_repeatedly_loses_the_exemption_without_new_ip_lockout(client, login_env, monkeypatch):
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "PERMANENT")
    monkeypatch.setattr(
        soar, "enforce_lockout", lambda *a, **k: (_ for _ in ()).throw(AssertionError("이미 영구 잠금인 IP에 5분 잠금 알림이 또 나가면 안 된다"))
    )
    login_env["exemption"] = {"id": 9}
    login_env["failures"] = config.IP_EXEMPTION_MAX_FAILURES
    client.set_cookie("lw_dev", "my-device-cookie")

    html = _login(client, "wrong").get_data(as_text=True)

    assert "아이디 또는 비밀번호가 올바르지 않습니다" in html
    assert login_env["revoked"] and login_env["revoked"][0][0] == 9


def test_exempted_user_failing_once_keeps_the_exemption(client, login_env, monkeypatch):
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "PERMANENT")
    login_env["exemption"] = {"id": 9}
    login_env["failures"] = 1
    client.set_cookie("lw_dev", "my-device-cookie")

    _login(client, "wrong")

    assert login_env["revoked"] == []


def test_signup_is_rejected_from_a_permanently_locked_ip(client, monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "PERMANENT")
    monkeypatch.setattr(
        db, "create_user", lambda *a: (_ for _ in ()).throw(AssertionError("영구 잠긴 IP에서 가입되면 안 된다"))
    )

    token = get_csrf_token(client, "/signup")
    response = client.post(
        "/signup",
        data={"username": "newbie", "email": "n@e.com", "password": "password123",
              "password_confirm": "password123", "csrf_token": token},
    )

    assert "회원가입을 할 수 없습니다" in response.get_data(as_text=True)


def test_signup_from_a_temporarily_locked_ip_is_not_blocked_by_permanent_check(client, monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "TEMPORARY")
    monkeypatch.setattr(detector, "is_signup_rate_limited", lambda ip: (False, 0))
    monkeypatch.setattr(db, "log_signup_attempt", lambda ip: None)
    created = []
    monkeypatch.setattr(db, "create_user", lambda *a: created.append(a) or True)

    token = get_csrf_token(client, "/signup")
    client.post(
        "/signup",
        data={"username": "newbie", "email": "n@e.com", "password": "password123",
              "password_confirm": "password123", "csrf_token": token},
    )

    assert created


def test_admin_login_from_a_permanently_locked_ip_is_blocked_with_no_recovery_link(client, monkeypatch):
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: "PERMANENT")
    monkeypatch.setattr(
        db, "verify_admin_credentials", lambda *a: (_ for _ in ()).throw(AssertionError("확인하면 안 된다"))
    )

    token = get_csrf_token(client, "/admin/login")
    response = client.post(
        "/admin/login", data={"username": "boss", "password": "pw", "csrf_token": token}
    )

    html = response.get_data(as_text=True)
    assert "차단되어 있습니다" in html and "/recovery" not in html


# ===========================================================================
# 응답 시간 평탄화 — 없는 아이디와 실제 메일 발송의 응답 시점이 같아야 한다
# ===========================================================================

def test_response_time_is_fixed_regardless_of_how_long_the_work_takes(monkeypatch):
    import time

    from routes import recovery

    monkeypatch.setattr(config, "RECOVERY_MIN_RESPONSE_SECONDS", 0.4)

    def timed(work):
        started = time.monotonic()
        recovery._run_with_fixed_response_time(work, started)
        return time.monotonic() - started

    fast = timed(lambda: None)                      # 없는 아이디처럼 바로 끝나는 처리
    slow = timed(lambda: time.sleep(0.15))          # 실제 메일 발송처럼 시간이 걸리는 처리

    assert 0.4 <= fast < 0.55 and 0.4 <= slow < 0.55
    assert abs(fast - slow) < 0.1


def test_background_mode_responds_on_time_and_finishes_the_work_afterwards(monkeypatch):
    import time

    from routes import recovery

    monkeypatch.setattr(config, "RECOVERY_MIN_RESPONSE_SECONDS", 0.1)
    monkeypatch.setattr(config, "RECOVERY_BACKGROUND_WORK", True)  # 상시 실행 서버 모드
    done = []

    started = time.monotonic()
    recovery._run_with_fixed_response_time(lambda: (time.sleep(0.3), done.append(True)), started)
    assert time.monotonic() - started < 0.25 and done == []   # 응답은 먼저 나가고
    time.sleep(0.4)
    assert done == [True]                                     # 처리는 뒤에서 마무리된다


def test_default_mode_finishes_the_work_before_responding_even_if_it_is_slow(monkeypatch):
    # Vercel 같은 서버리스는 응답을 보내는 순간 함수를 멈추므로, 기본 모드는 메일 발송까지
    # 끝낸 뒤에 응답해야 한다(백그라운드로 미루면 끊길 수 있다).
    import time

    from routes import recovery

    monkeypatch.setattr(config, "RECOVERY_MIN_RESPONSE_SECONDS", 0.1)
    monkeypatch.setattr(config, "RECOVERY_BACKGROUND_WORK", False)
    done = []

    recovery._run_with_fixed_response_time(lambda: (time.sleep(0.25), done.append(True)), time.monotonic())

    assert done == [True]  # 응답 시점에 이미 끝나 있다


@pytest.mark.parametrize("background", [False, True])
def test_errors_during_work_never_leak_as_a_500(monkeypatch, capsys, background):
    # 예외가 500으로 새면 "이 아이디는 처리 중 오류가 났다"는 신호가 되어 계정 존재 여부가 드러난다.
    import time

    from routes import recovery

    monkeypatch.setattr(config, "RECOVERY_MIN_RESPONSE_SECONDS", 0.05)
    monkeypatch.setattr(config, "RECOVERY_BACKGROUND_WORK", background)

    recovery._run_with_fixed_response_time(lambda: 1 / 0, time.monotonic())  # 예외가 안 나면 통과

    time.sleep(0.05)
    assert "복구 요청 처리 중 오류" in capsys.readouterr().out


def test_missing_public_base_url_in_production_reports_a_config_failure(client, store, monkeypatch):
    store.lock_account("alice")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "")
    monkeypatch.setattr(config, "IS_PRODUCTION", True)
    reports = []
    monkeypatch.setattr(mailer, "report_failure", lambda category, detail: reports.append(category))

    _request_recovery(client)

    assert store.mails == [] and reports == [mailer.FAIL_CONFIG]


# ===========================================================================
# mailer 보강 — 배포(Gmail SMTP)용
# ===========================================================================

def test_ssl_port_uses_smtp_ssl_without_starttls(fake_smtp, monkeypatch):
    used = []

    class _FakeSMTPSSL(_FakeSMTP):
        def __init__(self, host, port, timeout=None):
            super().__init__(host, port, timeout)
            used.append("ssl")

    monkeypatch.setattr(smtplib, "SMTP_SSL", _FakeSMTPSSL)
    monkeypatch.setattr(config, "SMTP_USE_SSL", True)
    monkeypatch.setattr(config, "SMTP_PORT", 465)

    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.SENT

    assert used == ["ssl"]
    assert "starttls" not in fake_smtp.instances[-1].events  # SSL이면 STARTTLS는 건너뛴다


def test_message_has_date_message_id_and_from_headers(fake_smtp, monkeypatch):
    monkeypatch.setattr(config, "MAIL_FROM", "로그인 워치독 <watchdog@gmail.com>")
    captured = {}
    original = _FakeSMTP.send_message

    def capture(self, message):
        captured["message"] = message
        return original(self, message)

    monkeypatch.setattr(_FakeSMTP, "send_message", capture)

    mailer.send_recovery_email("a@b.com", "l", "1", "account")

    message = captured["message"]
    assert message["Date"] and ("GMT" in message["Date"] or "+0000" in message["Date"])  # UTC 기준 시각
    assert message["Message-ID"].endswith("@gmail.com>")
    assert "watchdog@gmail.com" in message["From"]


def test_authentication_failure_is_classified_and_alerted_without_secrets(fake_smtp, monkeypatch, capsys):
    monkeypatch.setattr(config, "SMTP_USER", "me@gmail.com")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "super-secret-app-password")
    mailer._last_alert_at.clear()
    alerts = []
    monkeypatch.setattr(alert, "send_mail_failure_alert", lambda category, detail: alerts.append((category, detail)))

    def failing_login(self, user, password):
        raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")

    monkeypatch.setattr(_FakeSMTP, "login", failing_login)

    assert mailer.send_recovery_email("a@b.com", "http://link", "123456", "account") == mailer.FAILED

    assert alerts[0][0] == mailer.FAIL_AUTH
    everything = str(alerts) + capsys.readouterr().out
    assert "super-secret-app-password" not in everything  # 비밀번호는 로그/알림에 남지 않는다
    assert "http://link" not in everything and "123456" not in everything  # 토큰·코드도 마찬가지


def test_connection_failure_is_classified_as_connect(fake_smtp, monkeypatch):
    mailer._last_alert_at.clear()
    alerts = []
    monkeypatch.setattr(alert, "send_mail_failure_alert", lambda category, detail: alerts.append(category))
    fake_smtp.send_error = TimeoutError("timed out")

    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.FAILED

    assert alerts == [mailer.FAIL_CONNECT]


def test_same_failure_is_alerted_only_once_per_cooldown(fake_smtp, monkeypatch):
    mailer._last_alert_at.clear()
    alerts = []
    monkeypatch.setattr(alert, "send_mail_failure_alert", lambda category, detail: alerts.append(category))
    fake_smtp.send_error = ConnectionRefusedError("down")

    for _ in range(3):
        mailer.send_recovery_email("a@b.com", "l", "1", "account")

    assert alerts == [mailer.FAIL_CONNECT]  # 알림 폭주 방지

    mailer._last_alert_at[mailer.FAIL_CONNECT] -= config.MAIL_FAILURE_ALERT_COOLDOWN_SECONDS + 1
    mailer.send_recovery_email("a@b.com", "l", "1", "account")
    assert alerts == [mailer.FAIL_CONNECT, mailer.FAIL_CONNECT]


def test_permanent_refusal_and_success_do_not_raise_failure_alerts(fake_smtp, monkeypatch):
    mailer._last_alert_at.clear()
    monkeypatch.setattr(
        alert, "send_mail_failure_alert", lambda *a: (_ for _ in ()).throw(AssertionError("설정 문제가 아니다"))
    )

    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.SENT
    fake_smtp.send_error = smtplib.SMTPRecipientsRefused({"a@b.com": (550, b"no such user")})
    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.REFUSED


def test_console_backend_in_production_is_a_reported_config_failure(monkeypatch):
    mailer._last_alert_at.clear()
    alerts = []
    monkeypatch.setattr(alert, "send_mail_failure_alert", lambda category, detail: alerts.append(category))
    monkeypatch.setattr(config, "MAIL_BACKEND", "console")
    monkeypatch.setattr(config, "IS_PRODUCTION", True)

    assert mailer.send_recovery_email("a@b.com", "l", "1", "account") == mailer.FAILED

    assert alerts == [mailer.FAIL_CONFIG]


def test_configuration_warnings_list_missing_production_settings(monkeypatch):
    monkeypatch.setattr(config, "IS_PRODUCTION", False)
    assert mailer.configuration_warnings() == []  # 개발 환경은 console이 기본이라 경고하지 않는다

    monkeypatch.setattr(config, "IS_PRODUCTION", True)
    monkeypatch.setattr(config, "MAIL_BACKEND", "console")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "")
    warnings = mailer.configuration_warnings()
    assert any("MAIL_BACKEND" in w for w in warnings) and any("PUBLIC_BASE_URL" in w for w in warnings)

    monkeypatch.setattr(config, "MAIL_BACKEND", "smtp")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setattr(config, "SMTP_USER", "me@gmail.com")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "")
    monkeypatch.setattr(config, "PUBLIC_BASE_URL", "https://login-watchdog.vercel.app")
    assert any("SMTP_PASSWORD" in w for w in mailer.configuration_warnings())

    monkeypatch.setattr(config, "SMTP_PASSWORD", "x")
    assert mailer.configuration_warnings() == []


def test_send_test_mail_reports_result_without_alerting_slack(fake_smtp, monkeypatch):
    monkeypatch.setattr(
        alert, "send_mail_failure_alert", lambda *a: (_ for _ in ()).throw(AssertionError("테스트 메일은 알리지 않는다"))
    )
    assert mailer.send_test_mail("a@b.com")[0] == mailer.SENT

    fake_smtp.send_error = ConnectionRefusedError("down")
    result, category, detail = mailer.send_test_mail("a@b.com")
    assert (result, category) == (mailer.FAILED, mailer.FAIL_CONNECT) and "SMTP_HOST" in detail
