# ============================================================================
# tests/track_d/test_c_status_api.py — Track D 대시보드 API (/api/status, /api/stats) 테스트 [C2-3]
# ============================================================================

from datetime import datetime, timedelta, timezone
import pytest

import config
import db
from notify import alert
from tests.admin_session import login_admin_session


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    monkeypatch.setattr(config, "LW_NODE_NAME", "node-a")
    monkeypatch.setattr(config, "FW_AGENT_STALE_SECONDS", 30)
    monkeypatch.setattr(config, "SHIPPER_STALE_SECONDS", 120)
    monkeypatch.setattr(config, "AGENT_ALERT_COOLDOWN_SECONDS", 600)
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "")


def test_api_status_contains_track_d_keys(client, monkeypatch):
    with client.session_transaction() as sess:
        login_admin_session(sess, "admin")

    monkeypatch.setattr(db, "list_recent_network_events", lambda limit=50: [{"src_ip": "10.0.0.1", "category": "SYN_FLOOD"}], raising=False)
    monkeypatch.setattr(db, "list_network_blocks_for_dashboard", lambda: [{"ip_address": "10.0.0.1", "status": "APPLIED"}], raising=False)
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {}, raising=False)

    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "network_events" in data
    assert "network_blocks" in data
    assert "agent_status" in data
    assert len(data["network_events"]) == 1
    assert len(data["network_blocks"]) == 1


def test_api_status_edge_subnet_filter(client, monkeypatch):
    with client.session_transaction() as sess:
        login_admin_session(sess, "admin")

    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "192.168.1.0/24")
    monkeypatch.setattr(
        db,
        "list_recent_network_events",
        lambda limit=50: [
            {"src_ip": "192.168.1.10", "category": "SYN_FLOOD"},
            {"src_ip": "10.0.0.1", "category": "PORT_SCAN"},
        ],
        raising=False,
    )
    monkeypatch.setattr(
        db,
        "list_network_blocks_for_dashboard",
        lambda: [
            {"ip_address": "192.168.1.20", "status": "APPLIED"},
            {"ip_address": "10.0.0.2", "status": "APPLIED"},
        ],
        raising=False,
    )

    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["network_events"]) == 1
    assert data["network_events"][0]["src_ip"] == "192.168.1.10"
    assert len(data["network_blocks"]) == 1
    assert data["network_blocks"][0]["ip_address"] == "192.168.1.20"


def test_build_agent_status_calculations_and_alerts(client, monkeypatch):
    with client.session_transaction() as sess:
        login_admin_session(sess, "admin")

    now_dt = datetime.now(timezone.utc)
    recent_iso = (now_dt - timedelta(seconds=10)).isoformat()
    stale_iso = (now_dt - timedelta(seconds=200)).isoformat()

    beats = {
        "fw-agent": {"agent": "fw-agent", "last_seen_at": recent_iso, "detail": {"ok": True}},
        "shipper": {"agent": "shipper", "last_seen_at": stale_iso, "detail": {"ok": True}},
    }
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: beats, raising=False)
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, sec: True, raising=False)

    alerts = []
    monkeypatch.setattr(alert, "send_component_alert", lambda comp, msg: alerts.append((comp, msg)))

    res = client.get("/api/status")
    assert res.status_code == 200
    status = res.get_json()["agent_status"]

    assert status["fw-agent"]["stale"] is False
    assert status["shipper"]["stale"] is True
    assert len(alerts) == 1
    assert alerts[0][0] == "shipper"


def test_agent_status_empty_node_name(client, monkeypatch):
    with client.session_transaction() as sess:
        login_admin_session(sess, "admin")

    monkeypatch.setattr(config, "LW_NODE_NAME", "")
    alerts = []
    monkeypatch.setattr(alert, "send_component_alert", lambda comp, msg: alerts.append((comp, msg)))

    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["agent_status"] == {}
    assert len(alerts) == 0


def test_agent_status_stale_cooldown_false_no_alert(client, monkeypatch):
    with client.session_transaction() as sess:
        login_admin_session(sess, "admin")

    stale_iso = (datetime.now(timezone.utc) - timedelta(seconds=200)).isoformat()
    beats = {
        "shipper": {"agent": "shipper", "last_seen_at": stale_iso, "detail": {}},
    }
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: beats, raising=False)
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, sec: False, raising=False)

    alerts = []
    monkeypatch.setattr(alert, "send_component_alert", lambda comp, msg: alerts.append((comp, msg)))

    res = client.get("/api/status")
    assert res.status_code == 200
    assert res.get_json()["agent_status"]["shipper"]["stale"] is True
    assert len(alerts) == 0