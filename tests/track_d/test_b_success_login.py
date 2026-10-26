"""CR-03은 비밀번호 확인 뒤, 회원 세션을 만들기 전에만 판단한다."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import config
import db
from db import network_events
from security import correlate, detector, playbooks, soar
from tests.test_app import get_csrf_token


IP = "127.0.0.1"
USERNAME = "victim_b"


class NetworkQuery:
    """조회 조건을 실제 행에 적용해 창·출처·유형 필터를 함께 검증한다."""

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def table(self, name):
        assert name == "security_events"
        return self

    def select(self, columns):
        self.calls.append(("select", (columns,), {}))
        return self

    def eq(self, column, value):
        self.calls.append(("eq", (column, value), {}))
        self.rows = [row for row in self.rows if row[column] == value]
        return self

    def in_(self, column, values):
        self.calls.append(("in_", (column, values), {}))
        self.rows = [row for row in self.rows if row[column] in values]
        return self

    def gte(self, column, value):
        self.calls.append(("gte", (column, value), {}))
        self.rows = [row for row in self.rows if row[column] >= value]
        return self

    def lte(self, column, value):
        self.calls.append(("lte", (column, value), {}))
        self.rows = [row for row in self.rows if row[column] <= value]
        return self

    def order(self, column, desc=False):
        self.calls.append(("order", (column,), {"desc": desc}))
        self.rows.sort(key=lambda row: row[column], reverse=desc)
        return self

    def limit(self, count):
        self.calls.append(("limit", (count,), {}))
        self.rows = self.rows[:count]
        return self

    def execute(self):
        return SimpleNamespace(data=self.rows)


@pytest.fixture
def login_ready(monkeypatch):
    """라우트 테스트가 실제 DB 없이 성공 자격 증명 경로에 도달하게 한다."""
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(soar, "try_release_expired_account_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(detector, "is_account_locked", lambda username: False)
    monkeypatch.setattr(db, "verify_user_credentials", lambda username, password: True)
    monkeypatch.setattr(db, "log_attempt", lambda ip, username, success: None)
    monkeypatch.setattr(db, "get_user_by_username", lambda username: {
        "id": 7, "username": username, "email": "victim@example.invalid",
        "session_version": 0,
    })


def _login(client):
    token = get_csrf_token(client, "/login")
    return client.post("/login", data={
        "username": USERNAME, "password": "test-password", "csrf_token": token,
    })


@pytest.mark.parametrize("event_type", ["NET_WEB_ATTACK", "NET_SCANNER_UA"])
def test_connected_evidence_blocks_session_and_runs_once(
    client, login_ready, monkeypatch, event_type
):
    monkeypatch.setattr(db, "list_recent_connected_net_events_for_login", lambda ip, minutes: [
        {"event_type": event_type, "severity": "MEDIUM"}
    ], raising=False)
    monkeypatch.setattr(db, "get_open_incident", lambda ip: None)
    calls = []

    def record(ip, types, severity, **kwargs):
        calls.append(("record", ip, types, severity, kwargs))
        return {"id": 12, "matched_rules": ["CR-03"], "rule_added": True}

    monkeypatch.setattr(db, "record_incident", record)
    monkeypatch.setattr(playbooks, "run", lambda *args: calls.append(("run", *args)))

    response = _login(client)

    assert response.status_code == 200
    assert "아이디 또는 비밀번호가 올바르지 않습니다." in response.get_data(as_text=True)
    with client.session_transaction() as session:
        assert "username" not in session
        assert "user_id" not in session
    assert calls[0] == (
        "record", IP, [event_type], "MEDIUM", {"source": "NET", "rule_id": "CR-03"}
    )
    _, playbook, trigger_ref, ctx = calls[1]
    assert (playbook, trigger_ref) == ("SUSPICIOUS_SUCCESS_LOGIN", "incident:12:CR-03")
    assert ctx == {
        "ip": IP, "incident_id": 12, "rule_id": "CR-03", "priority": "HIGH",
        "matched_rules": ["CR-03"], "evidence": "CONNECTED", "username": USERNAME,
        "user_id": 7, "user_email": "victim@example.invalid",
    }


@pytest.mark.parametrize("event_type", ["NET_SYN_FLOOD", "NET_PORT_SCAN"])
def test_spoofable_evidence_does_not_block_login(
    client, login_ready, monkeypatch, event_type
):
    query = NetworkQuery([{
        "ip_address": IP, "source": "NET", "event_type": event_type,
        "detected_at": datetime.now(timezone.utc).isoformat(), "severity": "MEDIUM",
    }])
    monkeypatch.setattr(db, "get_client", lambda: query)
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: pytest.fail(event_type))
    response = _login(client)
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["username"] == USERNAME


def test_outside_window_does_not_block_login(client, login_ready, monkeypatch):
    query = NetworkQuery([{
        "ip_address": IP, "source": "NET", "event_type": "NET_SCANNER_UA",
        "detected_at": (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat(),
        "severity": "MEDIUM",
    }])
    monkeypatch.setattr(db, "get_client", lambda: query)
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: pytest.fail("창 밖 증거"))
    response = _login(client)
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["username"] == USERNAME


def test_second_success_on_same_incident_does_not_rerun(
    client, login_ready, monkeypatch
):
    monkeypatch.setattr(db, "list_recent_connected_net_events_for_login", lambda ip, minutes: [
        {"event_type": "NET_SCANNER_UA", "severity": "MEDIUM"}
    ], raising=False)
    incident = {"id": 12, "matched_rules": []}
    monkeypatch.setattr(db, "get_open_incident", lambda ip: incident)
    monkeypatch.setattr(db.incidents, "_is_idle", lambda row: False)
    calls = []

    def record(ip, types, severity, **kwargs):
        incident["matched_rules"] = ["CR-03"]
        return {**incident, "rule_added": True}

    monkeypatch.setattr(db, "record_incident", record)
    monkeypatch.setattr(playbooks, "run", lambda *args: calls.append(args))
    for _ in range(2):
        response = _login(client)
        assert response.status_code == 200
        with client.session_transaction() as session:
            assert "username" not in session
    assert len(calls) == 1


def test_check_error_allows_normal_login(client, login_ready, monkeypatch, capsys):
    def fail(ip, minutes):
        raise RuntimeError("test-query-error")

    monkeypatch.setattr(db, "list_recent_connected_net_events_for_login", fail, raising=False)
    response = _login(client)
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["username"] == USERNAME
    assert capsys.readouterr().out.strip() == "[의심 로그인 검사 오류] RuntimeError"


def test_concurrent_rule_claim_still_blocks_without_rerunning(monkeypatch):
    monkeypatch.setattr(db, "list_recent_connected_net_events_for_login", lambda ip, minutes: [
        {"event_type": "NET_SCANNER_UA", "severity": "MEDIUM"}
    ], raising=False)
    monkeypatch.setattr(db, "get_open_incident", lambda ip: None)
    monkeypatch.setattr(db, "get_user_by_username", lambda username: {
        "id": 7, "email": "victim@example.invalid"
    })
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: {
        "id": 12, "matched_rules": ["CR-03"], "rule_added": False,
    })
    monkeypatch.setattr(playbooks, "run", lambda *a: pytest.fail("중복 실행"))
    assert correlate.check_success_login(IP, USERNAME) is True


def test_db_query_uses_ip_net_source_connected_types_and_utc_window(monkeypatch):
    query = NetworkQuery([])
    monkeypatch.setattr(db, "get_client", lambda: query)
    assert network_events.list_recent_connected_net_events_for_login(IP, 30) == []
    calls = {name: args for name, args, _ in query.calls}
    assert calls["eq"] == ("source", "NET")
    assert calls["in_"] == ("event_type", ["NET_WEB_ATTACK", "NET_SCANNER_UA"])
    assert ("eq", ("ip_address", IP), {}) in query.calls
    cutoff = datetime.fromisoformat(calls["gte"][1])
    upper = datetime.fromisoformat(calls["lte"][1])
    assert upper - cutoff == timedelta(minutes=config.NET_SUCCESS_LOGIN_LOOKBACK_MINUTES)
    assert cutoff.tzinfo == timezone.utc
    assert "list_recent_connected_net_events_for_login" in network_events.__all__
    assert db.list_recent_connected_net_events_for_login is network_events.list_recent_connected_net_events_for_login
