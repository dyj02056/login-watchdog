"""B2-1 교차 계층 규칙은 DB·플레이북을 가짜로 바꿔 판단 경계만 검증한다."""

from datetime import datetime, timedelta, timezone

import config
import db
from db import incidents, network_events
from security import correlate, playbooks


IP = "172.28.12.103"


def _event(event_type, severity="MEDIUM", path=None, minutes_ago=0):
    return {
        "event_type": event_type,
        "severity": severity,
        "path": path,
        "detected_at": (
            datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
        ).isoformat(),
        "source": "NET" if event_type.startswith("NET_") else "APP",
        "layer": "L4" if event_type.startswith("NET_") else "L7",
    }


def _install_rule_fakes(monkeypatch, rows):
    state = {"incident": None, "runs": [], "windows": []}

    def recent(ip, window_minutes):
        assert ip == IP
        state["windows"].append(window_minutes)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        return [
            row for row in rows
            if datetime.fromisoformat(row["detected_at"]) >= cutoff
        ]

    def get_open(ip):
        assert ip == IP
        return state["incident"]

    def record(ip, event_types, severity, source="APP", rule_id=None):
        assert ip == IP
        assert source == "NET"
        if state["incident"] is None:
            state["incident"] = {
                "id": 41,
                "event_types": list(event_types),
                "severity_max": severity,
                "app_severity_max": None,
                "matched_rules": [],
                "escalated": False,
            }
        incident = state["incident"]
        incident["event_types"] = sorted(set(incident["event_types"]) | set(event_types))
        if rule_id and rule_id not in incident["matched_rules"]:
            incident["matched_rules"].append(rule_id)
        return incident

    monkeypatch.setattr(
        db, "list_recent_security_events_for_correlation", recent, raising=False
    )
    monkeypatch.setattr(db, "get_open_incident", get_open)
    monkeypatch.setattr(db, "record_incident", record)
    monkeypatch.setattr(
        playbooks,
        "run",
        lambda name, trigger_ref, ctx: state["runs"].append(
            (name, trigger_ref, ctx)
        ) or [],
        raising=False,
    )
    return state


def test_net01_runs_ttl_playbook_and_uses_spoofable_evidence(monkeypatch):
    state = _install_rule_fakes(monkeypatch, [])

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    name, trigger_ref, ctx = state["runs"][0]
    assert (name, trigger_ref) == ("NET_FLOOD_TTL", "incident:41:NET-01")
    assert ctx == {
        "ip": IP,
        "incident_id": 41,
        "rule_id": "NET-01",
        "priority": "HIGH",
        "matched_rules": ["NET-01"],
        "evidence": "SPOOFABLE",
        "username": None,
        "user_id": None,
        "user_email": None,
    }


def test_net01_does_not_match_without_syn_flood(monkeypatch):
    state = _install_rule_fakes(monkeypatch, [])
    correlate.check_cross_layer(IP, "NET_PORT_SCAN")
    assert state["runs"] == []


def test_cr01_requires_recon_before_app_intrusion(monkeypatch):
    rows = [
        _event("NET_PORT_SCAN", minutes_ago=2),
        _event("BRUTE_FORCE", severity="HIGH", minutes_ago=1),
    ]
    state = _install_rule_fakes(monkeypatch, rows)

    correlate.check_cross_layer(IP, "BRUTE_FORCE")

    name, trigger_ref, ctx = state["runs"][0]
    assert (name, trigger_ref) == ("KILL_CHAIN", "incident:41:CR-01")
    assert ctx["priority"] == "CRITICAL"
    assert ctx["evidence"] == "CONNECTED"
    assert state["windows"] == [config.NET_CORRELATION_WINDOW_MINUTES]


def test_cr01_reverse_order_does_not_match(monkeypatch):
    rows = [
        _event("BRUTE_FORCE", severity="HIGH", minutes_ago=2),
        _event("NET_PORT_SCAN", minutes_ago=1),
    ]
    state = _install_rule_fakes(monkeypatch, rows)
    correlate.check_cross_layer(IP, "NET_PORT_SCAN")
    assert state["runs"] == []


def test_cr01_does_not_count_event_outside_window(monkeypatch):
    rows = [
        _event("NET_SCANNER_UA", minutes_ago=config.NET_CORRELATION_WINDOW_MINUTES + 1),
        _event("WEB_SCANNING", minutes_ago=0),
    ]
    state = _install_rule_fakes(monkeypatch, rows)
    correlate.check_cross_layer(IP, "WEB_SCANNING")
    assert state["runs"] == []


def test_cr01_missing_app_intrusion_does_not_match(monkeypatch):
    state = _install_rule_fakes(monkeypatch, [_event("NET_PORT_SCAN")])
    correlate.check_cross_layer(IP, "NET_PORT_SCAN")
    assert state["runs"] == []


def test_cr02_matches_global_http_flood(monkeypatch):
    rows = [
        _event("NET_SYN_FLOOD", severity="HIGH", minutes_ago=1),
        _event("HTTP_FLOOD", severity="HIGH", path="/login"),
    ]
    state = _install_rule_fakes(monkeypatch, rows)

    correlate.check_cross_layer(IP, "HTTP_FLOOD")

    name, trigger_ref, ctx = state["runs"][0]
    assert (name, trigger_ref) == ("NET_FLOOD", "incident:41:CR-02")
    assert ctx["evidence"] == "SPOOFABLE"
    assert state["windows"] == [config.NET_FLOOD_WINDOW_MINUTES]


def test_cr02_excludes_route_specific_http_flood(monkeypatch):
    rows = [
        _event("NET_SYN_FLOOD", severity="HIGH", minutes_ago=1),
        _event("HTTP_FLOOD", severity="HIGH", path="/recovery/verify"),
    ]
    state = _install_rule_fakes(monkeypatch, rows)
    correlate.check_cross_layer(IP, "HTTP_FLOOD")
    assert state["runs"] == []


def test_cr02_missing_syn_flood_does_not_match(monkeypatch):
    state = _install_rule_fakes(
        monkeypatch, [_event("HTTP_FLOOD", severity="HIGH", path="/login")]
    )
    correlate.check_cross_layer(IP, "HTTP_FLOOD")
    assert state["runs"] == []


def test_same_rule_runs_only_once_per_incident(monkeypatch):
    state = _install_rule_fakes(monkeypatch, [])
    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")
    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")
    assert len(state["runs"]) == 1


def test_record_incident_merges_rule_id_without_duplicates(monkeypatch):
    existing = {
        "id": 7,
        "event_types": ["NET_PORT_SCAN"],
        "severity_max": "MEDIUM",
        "app_severity_max": None,
        "matched_rules": ["NET-01"],
        "escalated": False,
    }
    monkeypatch.setattr(incidents, "get_open_incident", lambda ip: existing)
    updates = []
    monkeypatch.setattr(
        incidents, "_update_incident", lambda *args: updates.append(args)
    )

    result = incidents.record_incident(
        IP,
        ["NET_PORT_SCAN", "BRUTE_FORCE"],
        "HIGH",
        source="NET",
        rule_id="CR-01",
    )

    assert result["matched_rules"] == ["NET-01", "CR-01"]
    assert updates == [
        (7, ["BRUTE_FORCE", "NET_PORT_SCAN"], "HIGH", ["NET-01", "CR-01"])
    ]


def test_record_incident_stores_rule_id_when_opening(monkeypatch):
    monkeypatch.setattr(incidents, "get_open_incident", lambda ip: None)
    inserted = []

    def insert(ip, event_types, severity, rule_id=None):
        inserted.append((ip, event_types, severity, rule_id))
        return 8

    monkeypatch.setattr(incidents, "_insert_incident", insert)

    result = incidents.record_incident(
        IP, ["NET_SYN_FLOOD"], "HIGH", source="NET", rule_id="NET-01"
    )

    assert inserted == [(IP, ["NET_SYN_FLOOD"], "HIGH", "NET-01")]
    assert result["matched_rules"] == ["NET-01"]


def test_rule_match_opens_incident_with_rule_id(monkeypatch):
    state = _install_rule_fakes(monkeypatch, [])
    assert state["incident"] is None
    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")
    assert state["incident"]["matched_rules"] == ["NET-01"]
    assert state["incident"]["event_types"] == ["NET_SYN_FLOOD"]


def test_single_type_still_checks_net01(monkeypatch):
    state = _install_rule_fakes(monkeypatch, [])
    monkeypatch.setattr(
        db, "get_recent_distinct_event_types", lambda ip, window: ["NET_SYN_FLOOD"]
    )

    correlate.check_and_correlate(IP, "NET_SYN_FLOOD", "HIGH", source="NET")

    assert [run[0] for run in state["runs"]] == ["NET_FLOOD_TTL"]


def test_net_blocked_skips_cross_layer_rules(monkeypatch):
    monkeypatch.setattr(db, "get_recent_distinct_event_types", lambda ip, window: [])
    monkeypatch.setattr(
        correlate,
        "check_cross_layer",
        lambda *args: (_ for _ in ()).throw(AssertionError("규칙을 검사하면 안 된다")),
    )
    correlate.check_and_correlate(IP, "NET_BLOCKED", "CRITICAL", source="NET")


def test_cross_layer_failure_does_not_break_existing_correlation(monkeypatch):
    monkeypatch.setattr(db, "get_recent_distinct_event_types", lambda ip, window: [])
    monkeypatch.setattr(
        correlate,
        "check_cross_layer",
        lambda *args: (_ for _ in ()).throw(RuntimeError("test failure")),
    )
    correlate.check_and_correlate(IP, "BRUTE_FORCE", "HIGH")


class _CorrelationQuery:
    def __init__(self):
        self.calls = []

    def table(self, name):
        self.calls.append(("table", name))
        return self

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return self
        return call

    def execute(self):
        return type("Result", (), {"data": []})()


def test_correlation_query_filters_ip_utc_window_and_orders_oldest(monkeypatch):
    query = _CorrelationQuery()
    monkeypatch.setattr(db, "get_client", lambda: query)

    assert network_events.list_recent_security_events_for_correlation(IP, 15) == []

    assert ("table", "security_events") in query.calls
    assert ("eq", ("ip_address", IP), {}) in query.calls
    gte = next(call for call in query.calls if call[0] == "gte")
    assert gte[1][0] == "detected_at"
    assert datetime.fromisoformat(gte[1][1]).tzinfo is not None
    assert ("order", ("detected_at",), {}) in query.calls


def test_new_query_is_exported():
    name = "list_recent_security_events_for_correlation"
    assert name in network_events.__all__
    assert name in db.__all__
    assert getattr(db, name) is getattr(network_events, name)
