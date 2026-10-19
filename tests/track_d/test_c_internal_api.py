# ============================================================================
# tests/track_d/test_c_internal_api.py — 내부 API (/api/internal/*) 단위 테스트 [작업 C1-2]
# ============================================================================

from datetime import datetime, timedelta, timezone
import pytest

import config
import db
from security import net_ingest
from notify import alert


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    monkeypatch.setattr(config, "NET_AGENT_SECRET", "agent-secret")
    monkeypatch.setattr(config, "NET_INGEST_SECRET", "ingest-secret")
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "")
    monkeypatch.setattr(config, "LW_NODE_NAME", "node-a")
    monkeypatch.setattr(config, "FW_AGENT_STALE_SECONDS", 30)
    monkeypatch.setattr(config, "SHIPPER_STALE_SECONDS", 120)
    monkeypatch.setattr(config, "AGENT_ALERT_COOLDOWN_SECONDS", 600)


def test_internal_api_unauthorized(client):
    res = client.get("/api/internal/blocks")
    assert res.status_code == 401
    assert res.get_json()["error"] == "unauthorized"


def test_list_blocks_shipper_disallowed(client, signed_headers):
    headers = signed_headers("shipper", "ingest-secret", b"")
    res = client.get("/api/internal/blocks", headers=headers)
    assert res.status_code == 401


def test_list_blocks_success(client, signed_headers, monkeypatch):
    now_iso = datetime.now(timezone.utc).isoformat()
    future_iso = (datetime.now(timezone.utc) + timedelta(seconds=3600)).isoformat()

    monkeypatch.setattr(db, "list_expired_network_blocks", lambda now: [])
    desired_blocks = [
        {"ip_address": "10.0.0.1", "status": "PENDING_APPLY", "expires_at": future_iso},
        {"ip_address": "10.0.0.2", "status": "APPLIED", "expires_at": None},
    ]
    monkeypatch.setattr(db, "list_desired_network_blocks", lambda: desired_blocks)

    headers = signed_headers("fw-agent", "agent-secret", b"")
    res = client.get("/api/internal/blocks", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["blocks"]) == 2
    assert data["blocks"][0]["ip"] == "10.0.0.1"
    assert data["blocks"][0]["ttl_seconds"] is not None
    assert data["blocks"][1]["ttl_seconds"] is None


def test_ack_block_applied(client, signed_headers, monkeypatch):
    recorded = []
    monkeypatch.setattr(db, "update_network_block_if_status", lambda ip, st, f: True)
    monkeypatch.setattr(db, "get_network_block", lambda ip: {"reason": "NET_FLOOD"})
    monkeypatch.setattr(net_ingest, "record_net_blocked", lambda ip, reason: recorded.append((ip, reason)))

    body = b'{"ip":"10.0.0.1","status":"APPLIED"}'
    headers = signed_headers("fw-agent", "agent-secret", body)
    headers["Content-Type"] = "application/json"
    res = client.post("/api/internal/blocks/ack", data=body, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["changed"] is True
    assert recorded == [("10.0.0.1", "NET_FLOOD")]


def test_ack_block_idempotent_second_call(client, signed_headers, monkeypatch):
    monkeypatch.setattr(db, "update_network_block_if_status", lambda ip, st, f: False)

    body = b'{"ip":"10.0.0.1","status":"APPLIED"}'
    headers = signed_headers("fw-agent", "agent-secret", body)
    headers["Content-Type"] = "application/json"
    res = client.post("/api/internal/blocks/ack", data=body, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["changed"] is False


def test_ack_block_out_of_subnet(client, signed_headers, monkeypatch):
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "192.168.1.0/24")

    body = b'{"ip":"10.0.0.1","status":"APPLIED"}'
    headers = signed_headers("fw-agent", "agent-secret", body)
    headers["Content-Type"] = "application/json"
    res = client.post("/api/internal/blocks/ack", data=body, headers=headers)
    assert res.status_code == 400
    assert res.get_json()["field"] == "ip"


def test_heartbeat_mismatched_agent(client, signed_headers):
    body = b'{"agent":"shipper","detail":{}}'
    headers = signed_headers("fw-agent", "agent-secret", body)
    headers["Content-Type"] = "application/json"
    res = client.post("/api/internal/heartbeat", data=body, headers=headers)
    assert res.status_code == 400
    assert res.get_json()["field"] == "agent"


def test_heartbeat_stalled_triggers_alert(client, signed_headers, monkeypatch):
    monkeypatch.setattr(db, "upsert_agent_heartbeat", lambda a, n, d: None)
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, sec: True)
    alerts = []
    monkeypatch.setattr(alert, "send_component_alert", lambda comp, msg: alerts.append((comp, msg)))
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {})

    body = b'{"agent":"shipper","detail":{},"stalled":true}'
    headers = signed_headers("shipper", "ingest-secret", body)
    headers["Content-Type"] = "application/json"
    res = client.post("/api/internal/heartbeat", data=body, headers=headers)
    assert res.status_code == 200
    assert len(alerts) == 1
    assert alerts[0][0] == "shipper"


def test_heartbeat_detects_other_stale(client, signed_headers, monkeypatch):
    stale_time = (datetime.now(timezone.utc) - timedelta(seconds=200)).isoformat()
    monkeypatch.setattr(db, "upsert_agent_heartbeat", lambda a, n, d: None)
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, sec: True)
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {
        "shipper": {"agent": "shipper", "last_seen_at": stale_time}
    })
    alerts = []
    monkeypatch.setattr(alert, "send_component_alert", lambda comp, msg: alerts.append((comp, msg)))

    body = b'{"agent":"fw-agent","detail":{}}'
    headers = signed_headers("fw-agent", "agent-secret", body)
    headers["Content-Type"] = "application/json"
    res = client.post("/api/internal/heartbeat", data=body, headers=headers)
    assert res.status_code == 200
    assert len(alerts) == 1
    assert alerts[0][0] == "shipper"