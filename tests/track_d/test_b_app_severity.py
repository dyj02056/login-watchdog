"""NET 위조 경보가 앱 등급을 올리거나 기존 앱 방어를 끄지 못하는지 검증한다."""

import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from postgrest.exceptions import APIError

import config
import db
from db import incidents
from notify import alert
from security import correlate, lockdown


pytestmark = pytest.mark.real_lockdown
IP = "203.0.113.25"


class IncidentDB:
    """조건부 갱신·유니크 충돌·페이지 조회를 메모리에서 재현해 외부 접속을 막는다."""

    def __init__(self):
        self.rows = []
        self.queries = []
        self.before_app_update = None
        self.raced_row = None

    def table(self, name):
        assert name == "security_incidents"
        query = IncidentQuery(self)
        self.queries.append(query)
        return query


class IncidentQuery:
    def __init__(self, client):
        self.client = client
        self.operation = "select"
        self.values = {}
        self.columns = "*"
        self.filters = []
        self.condition = None
        self.maximum = None
        self.bounds = None

    def select(self, columns, **kwargs):
        self.columns = columns
        return self

    def insert(self, values):
        self.operation, self.values = "insert", values
        return self

    def update(self, values):
        self.operation, self.values = "update", values
        return self

    def eq(self, key, value):
        self.filters.append((key, value))
        return self

    def or_(self, condition):
        self.condition = condition
        return self

    def order(self, key, desc=False):
        return self

    def range(self, start, end):
        self.bounds = (start, end)
        return self

    def limit(self, maximum):
        self.maximum = maximum
        return self

    def execute(self):
        if self.operation == "insert":
            if self.client.raced_row is not None:
                self.client.rows.append(self.client.raced_row.copy())
                self.client.raced_row = None
                raise APIError({"code": "23505", "message": "test-incident-conflict"})
            row = {**self.values, "id": len(self.client.rows) + 1}
            self.client.rows.append(row)
            return SimpleNamespace(data=[row.copy()])
        if "app_severity_max" in self.values and self.client.before_app_update is not None:
            callback = self.client.before_app_update
            self.client.before_app_update = None
            callback()
        rows = [row for row in self.client.rows if all(row.get(key) == value for key, value in self.filters)]
        if self.condition is not None:
            assert "app_severity_max.is.null" in self.condition
            match = re.search(r"app_severity_max\.in\.\(([^)]+)\)", self.condition)
            allowed = match.group(1).split(",") if match else []
            rows = [row for row in rows if row.get("app_severity_max") is None or row["app_severity_max"] in allowed]
        count = len(rows)
        if self.operation == "update":
            for row in rows:
                row.update(self.values)
        if self.maximum is not None:
            rows = rows[:self.maximum]
        if self.bounds is not None:
            rows = rows[self.bounds[0]:self.bounds[1] + 1]
        if self.columns != "*":
            columns = [key.strip() for key in self.columns.split(",")]
            rows = [{key: row.get(key) for key in columns} for row in rows]
        return SimpleNamespace(data=[row.copy() for row in rows], count=count)


@pytest.fixture
def environment(monkeypatch):
    fake = IncidentDB()
    actions = []
    monkeypatch.setattr(db, "get_client", lambda: fake)
    monkeypatch.setattr(lockdown, "is_ip_allowlisted", lambda ip: False)
    monkeypatch.setattr(lockdown, "is_permanent_ip", lambda ip: False)
    monkeypatch.setattr(lockdown, "promote_ip", lambda *a, **k: actions.append(("promote", a, k)) or True)
    monkeypatch.setattr(db, "get_pending_request", lambda *a: None)
    monkeypatch.setattr(db, "insert_pending_request", lambda *a: actions.append(("pending", a)))
    monkeypatch.setattr(alert, "send_pending_approval_alert", lambda *a: actions.append(("alert", a)))
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_ON_HIGH", False)
    monkeypatch.setattr(config, "INCIDENT_MERGE_IDLE_MINUTES", 30)
    return SimpleNamespace(db=fake, actions=actions)


@pytest.mark.parametrize("source", ["APP", "NET"])
@pytest.mark.parametrize("severity", ["MEDIUM", "HIGH", "CRITICAL"])
def test_new_incident_tracks_app_severity_and_rules(environment, source, severity):
    result = incidents.record_incident(IP, ["TEST_EVENT"], severity, source=source)
    expected_app = severity if source == "APP" else None
    assert result == {
        "id": 1, "event_types": ["TEST_EVENT"], "severity_max": severity,
        "app_severity_max": expected_app, "matched_rules": [], "escalated": False,
    }
    assert environment.db.rows[0]["app_severity_max"] == expected_app
    assert environment.db.rows[0]["severity_max"] == severity


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
@pytest.mark.parametrize("automatic", [False, True])
def test_net_only_never_triggers_permanent_lock(environment, monkeypatch, severity, automatic):
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_ON_HIGH", automatic)
    result = incidents.record_incident(IP, ["NET_SYN_FLOOD", "NET_PORT_SCAN"], severity, source="NET")
    lockdown.consider_incident_promotion(IP, result)
    assert result["app_severity_max"] is None
    assert environment.actions == []


@pytest.mark.parametrize("net_severity", ["MEDIUM", "HIGH", "CRITICAL"])
@pytest.mark.parametrize("automatic", [False, True])
def test_app_high_with_net_keeps_t4_decision(environment, monkeypatch, net_severity, automatic):
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_ON_HIGH", automatic)
    incidents.record_incident(IP, ["SIGNUP_RATE_LIMIT", "WEB_SCANNING"], "HIGH")
    result = incidents.record_incident(IP, ["NET_SYN_FLOOD"], net_severity, source="NET")
    lockdown.consider_incident_promotion(IP, result)
    assert result["app_severity_max"] == "HIGH"
    if automatic:
        assert environment.actions == [("promote", (IP, "SIEM_HIGH", "EXEMPTION"), {"incident_id": 1})]
    else:
        assert [action[0] for action in environment.actions] == ["pending", "alert"]
        assert environment.actions[0][1][:4] == ("SIEM_HIGH_INCIDENT", "PERMANENT_LOCK_IP", "ip", IP)


def test_app_critical_triggers_t3_after_net_event(environment):
    incidents.record_incident(IP, ["NET_SYN_FLOOD", "NET_PORT_SCAN"], "HIGH", source="NET")
    result = incidents.record_incident(IP, ["BRUTE_FORCE"], "CRITICAL")
    lockdown.consider_incident_promotion(IP, result)
    assert environment.actions == [("promote", (IP, "SIEM_CRITICAL", "EXEMPTION"), {"incident_id": 1})]


@pytest.mark.parametrize("app_severity", [None, "MEDIUM", "HIGH", "CRITICAL"])
@pytest.mark.parametrize("net_severity", ["MEDIUM", "HIGH", "CRITICAL"])
def test_net_merge_preserves_app_grade_and_rules(environment, app_severity, net_severity):
    incidents.record_incident(IP, ["NET_PORT_SCAN"], "MEDIUM", source="NET")
    environment.db.rows[0].update(app_severity_max=app_severity, matched_rules=["CR-01"], escalated=True)
    result = incidents.record_incident(IP, ["NET_SYN_FLOOD"], net_severity, source="NET")
    assert result["app_severity_max"] == app_severity
    assert result["matched_rules"] == ["CR-01"]
    assert result["escalated"] is True
    assert environment.db.rows[0]["app_severity_max"] == app_severity
    assert not any("app_severity_max" in query.values for query in environment.db.queries if query.operation == "update")


@pytest.mark.parametrize("initial,incoming,expected", [
    (None, "MEDIUM", "MEDIUM"), (None, "HIGH", "HIGH"), (None, "CRITICAL", "CRITICAL"),
    ("MEDIUM", "HIGH", "HIGH"), ("HIGH", "MEDIUM", "HIGH"),
    ("HIGH", "CRITICAL", "CRITICAL"), ("CRITICAL", "HIGH", "CRITICAL"),
    ("CRITICAL", "CRITICAL", "CRITICAL"),
])
def test_app_merge_uses_maximum_app_grade(environment, initial, incoming, expected):
    incidents.record_incident(IP, ["NET_TEST"], "CRITICAL", source="NET")
    environment.db.rows[0].update(app_severity_max=initial, matched_rules=["CR-03"])
    result = incidents.record_incident(IP, ["APP_TEST"], incoming)
    assert result["severity_max"] == "CRITICAL"
    assert result["app_severity_max"] == expected
    assert environment.db.rows[0]["app_severity_max"] == expected
    assert result["matched_rules"] == ["CR-03"]


@pytest.mark.parametrize("missing", [False, True])
def test_missing_or_null_app_grade_does_not_fall_back_to_overall(environment, missing):
    incident = {"id": 1, "event_types": ["NET_TEST"], "severity_max": "CRITICAL"}
    if not missing:
        incident["app_severity_max"] = None
    lockdown.consider_incident_promotion(IP, incident)
    assert environment.actions == []


def test_net_critical_does_not_turn_app_medium_into_permanent_lock(environment):
    incidents.record_incident(IP, ["WEB_SCANNING"], "MEDIUM")
    result = incidents.record_incident(IP, ["NET_TEST"], "CRITICAL", source="NET")
    lockdown.consider_incident_promotion(IP, result)
    assert (result["severity_max"], result["app_severity_max"]) == ("CRITICAL", "MEDIUM")
    assert environment.actions == []


def test_concurrent_higher_app_grade_cannot_be_downgraded(environment):
    incidents.record_incident(IP, ["NET_TEST"], "CRITICAL", source="NET")
    environment.db.before_app_update = lambda: environment.db.rows[0].update(
        app_severity_max="CRITICAL", matched_rules=["CR-01"]
    )
    result = incidents.record_incident(IP, ["SIGNUP_RATE_LIMIT"], "HIGH")
    assert result["app_severity_max"] == "CRITICAL"
    assert result["matched_rules"] == ["CR-01"]
    assert environment.db.rows[0]["app_severity_max"] == "CRITICAL"


@pytest.mark.parametrize("source,expected", [("NET", None), ("APP", "HIGH")])
def test_idle_incident_does_not_leak_app_grade_into_new_incident(environment, source, expected):
    incidents.record_incident(IP, ["BRUTE_FORCE"], "CRITICAL")
    environment.db.rows[0].update(
        last_event_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        matched_rules=["CR-01"],
    )
    result = incidents.record_incident(IP, ["NEW_TEST"], "HIGH", source=source)
    assert result["id"] == 2
    assert result["app_severity_max"] == expected
    assert result["matched_rules"] == []
    assert environment.db.rows[0]["status"] == "IDLE"


@pytest.mark.parametrize("source,expected", [("NET", "HIGH"), ("APP", "CRITICAL")])
def test_insert_conflict_merges_app_metadata(environment, source, expected):
    now = datetime.now(timezone.utc).isoformat()
    environment.db.raced_row = {
        "id": 7, "ip_address": IP, "event_types": ["EXISTING_TEST"], "status": "OPEN",
        "severity_max": "HIGH", "app_severity_max": "HIGH", "matched_rules": ["CR-03"],
        "escalated": False, "last_event_at": now,
    }
    result = incidents.record_incident(IP, ["INCOMING_TEST"], "CRITICAL", source=source)
    assert result["id"] == 7
    assert result["severity_max"] == "CRITICAL"
    assert result["app_severity_max"] == expected
    assert result["matched_rules"] == ["CR-03"]
    assert len(environment.db.rows) == 1


def test_open_and_list_queries_return_app_metadata(environment):
    incidents.record_incident(IP, ["APP_TEST"], "HIGH")
    environment.db.rows[0]["matched_rules"] = ["CR-01"]
    opened = incidents.get_open_incident(IP)
    assert opened["app_severity_max"] == "HIGH"
    assert opened["matched_rules"] == ["CR-01"]
    rows, count = incidents.list_security_incidents()
    assert count == 1
    assert rows[0]["app_severity_max"] == "HIGH"
    assert rows[0]["matched_rules"] == ["CR-01"]


def test_real_correlate_path_uses_app_grade(environment, monkeypatch):
    monkeypatch.setattr(correlate, "_maybe_escalate", lambda *a: None)
    monkeypatch.setattr(db, "get_recent_distinct_event_types", lambda *a: ["APP_TEST", "NET_TEST"])
    correlate.check_and_correlate(IP, "APP_TEST", "HIGH")
    environment.actions.clear()
    correlate.check_and_correlate(IP, "NET_TEST", "CRITICAL", source="NET")
    assert environment.db.rows[0]["severity_max"] == "CRITICAL"
    assert environment.db.rows[0]["app_severity_max"] == "HIGH"
    assert [action[0] for action in environment.actions] == ["pending", "alert"]
