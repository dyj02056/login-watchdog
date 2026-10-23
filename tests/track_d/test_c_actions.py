# ============================================================================
# tests/track_d/test_c_actions.py — 조치 함수 3개 단위 테스트 (계약서 K8, C2-1)
#
# 실제 Supabase·메일 서버·Slack에 접속하지 않도록 db.get_client, db.try_acquire_cooldown,
# mailer._send_mail, alert._send_slack_message를 가짜로 바꿔서 시험한다.
# ============================================================================

import db
from notify import alert, mailer


class DummyResponse:
    def __init__(self, data=None):
        self.data = data if data is not None else []


class FakeUsersTable:
    """users 표 한 행만 흉내 낸다. select는 현재 session_version을, update는 조건(eq)이 맞을
    때만 값을 바꾸고 바뀐 행을 돌려준다(Supabase 조건부 UPDATE와 같은 동작).

    race_count만큼은 update 직전에 "다른 요청"이 먼저 번호를 올린 것처럼 만들어
    경쟁에서 지는 상황을 재현한다."""

    def __init__(self, store):
        self.store = store
        self._op = None
        self._fields = None
        self._eq = []

    def select(self, *args, **kwargs):
        self._op = "select"
        return self

    def update(self, fields):
        self._op = "update"
        self._fields = fields
        return self

    def eq(self, column, value):
        self._eq.append((column, value))
        return self

    def limit(self, n):
        return self

    def execute(self):
        row = self.store.get("row")
        if self._op == "select":
            return DummyResponse([{"session_version": row["session_version"]}] if row else [])
        self.store["update_calls"] += 1
        if row is None:
            return DummyResponse([])
        if self.store["race_count"] > 0:
            self.store["race_count"] -= 1
            row["session_version"] += 1  # 다른 요청이 먼저 올렸다
        if all(row.get(col) == val for col, val in self._eq):
            row.update(self._fields)
            return DummyResponse([dict(row)])
        return DummyResponse([])


class FakeClient:
    def __init__(self, store):
        self.store = store

    def table(self, name):
        assert name == "users"
        return FakeUsersTable(self.store)


def _install_fake_users(monkeypatch, row, race_count=0):
    store = {"row": row, "race_count": race_count, "update_calls": 0}
    monkeypatch.setattr(db, "get_client", lambda: FakeClient(store))
    return store


# ---------------------------------------------------------------------------
# db.bump_session_version
# ---------------------------------------------------------------------------

def test_bump_session_version_success(monkeypatch):
    store = _install_fake_users(monkeypatch, {"id": 7, "session_version": 3})
    assert db.bump_session_version(7) is True
    assert store["row"]["session_version"] == 4
    assert store["update_calls"] == 1
    # 비밀번호는 건드리지 않는다
    assert "password_hash" not in store["row"]


def test_bump_session_version_retries_after_race(monkeypatch):
    # 첫 시도는 다른 요청이 먼저 번호를 올려 0행 → 다시 읽어 두 번째에 성공
    store = _install_fake_users(monkeypatch, {"id": 7, "session_version": 3}, race_count=1)
    assert db.bump_session_version(7) is True
    assert store["row"]["session_version"] == 5
    assert store["update_calls"] == 2


def test_bump_session_version_missing_user(monkeypatch):
    store = _install_fake_users(monkeypatch, None)
    assert db.bump_session_version(999) is False
    assert store["update_calls"] == 0


def test_bump_session_version_gives_up_after_three_losses(monkeypatch):
    # 3번 다 지면 예외 대신 False
    store = _install_fake_users(monkeypatch, {"id": 7, "session_version": 0}, race_count=3)
    assert db.bump_session_version(7) is False
    assert store["update_calls"] == 3


# ---------------------------------------------------------------------------
# mailer.send_suspicious_login_notice
# ---------------------------------------------------------------------------

def test_suspicious_login_notice_sent_then_skipped(monkeypatch):
    acquired = set()
    cooldown_calls = []

    def fake_cooldown(key, seconds):
        cooldown_calls.append((key, seconds))
        if key in acquired:
            return False
        acquired.add(key)
        return True

    sent = []

    def fake_send_mail(to_address, subject, body):
        sent.append((to_address, subject, body))
        return mailer.SENT

    monkeypatch.setattr(db, "try_acquire_cooldown", fake_cooldown, raising=False)
    monkeypatch.setattr(mailer, "_send_mail", fake_send_mail)

    first = mailer.send_suspicious_login_notice("Victim@Example.com", "203.0.113.5", "2026-10-23T01:02:03+00:00")
    second = mailer.send_suspicious_login_notice("victim@example.com", "203.0.113.5", "2026-10-23T01:05:00+00:00")

    assert first == mailer.SENT
    assert second == mailer.SKIPPED == "SKIPPED"
    assert len(sent) == 1
    to_address, subject, body = sent[0]
    assert subject == "[login-watchdog] 의심스러운 로그인이 차단되었습니다"
    assert "203.0.113.5" in body and "2026-10-23T01:02:03+00:00" in body
    assert "비밀번호" in body
    # 대소문자만 다른 주소도 같은 쿨다운 키를 쓴다
    assert cooldown_calls[0][0] == cooldown_calls[1][0] == "mail:suspicious:victim@example.com"
    assert cooldown_calls[0][1] == mailer.config.SUSPICIOUS_LOGIN_MAIL_COOLDOWN_SECONDS


# ---------------------------------------------------------------------------
# alert.send_playbook_alert
# ---------------------------------------------------------------------------

def test_playbook_alert_marks_partial_failure(monkeypatch):
    messages = []
    monkeypatch.setattr(alert, "_send_slack_message", messages.append)

    alert.send_playbook_alert(
        "PB-CR-03",
        "203.0.113.5",
        ["CR-03"],
        [
            {"step": "bump_session", "status": "OK", "error": None},
            {"step": "block_l4", "status": "FAILED", "error": "fw-agent 응답 없음"},
            {"step": "notify_owner_email", "status": "SKIPPED", "error": None},
        ],
    )

    assert len(messages) == 1
    lines = messages[0].split("\n")
    assert lines[0].startswith("⚠ 일부 조치 실패")
    assert "✓ bump_session (OK)" in lines
    assert "✗ block_l4 (FAILED): fw-agent 응답 없음" in lines
    assert "– notify_owner_email (SKIPPED)" in lines


def test_playbook_alert_without_failure_has_no_warning(monkeypatch):
    messages = []
    monkeypatch.setattr(alert, "_send_slack_message", messages.append)

    alert.send_playbook_alert(
        "PB-NET-01", "203.0.113.9", ["NET-01"],
        [{"step": "block_l4_ttl", "status": "OK", "error": None}],
    )

    assert "일부 조치 실패" not in messages[0]
    assert "203.0.113.9" in messages[0]
