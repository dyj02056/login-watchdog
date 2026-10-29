# ============================================================================
# tests/track_d/test_i_guide57_app.py — guide57 앱 쪽 수신·알림 보완
#
#   - heartbeat: fw-agent 규칙 빠짐(rules_ok·l3_ok)·목록 연속 실패(poll_failures),
#     shipper 파일별 정지(stalled_sensors)·Suricata 패킷 누락(kernel_drops) 알림
#   - 수집 창구: L3 경보 3종 접수, 종류 단위 쿨다운 알림, ICMP_FLOOD만 MEDIUM 승격·교차 규칙 미사용
# ============================================================================

import json

import pytest

import config
import db
from notify import alert
from security import correlate, net_ingest


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    monkeypatch.setattr(config, "NET_AGENT_SECRET", "agent-secret")
    monkeypatch.setattr(config, "NET_INGEST_SECRET", "test-ingest-secret")
    monkeypatch.setattr(config, "LW_NODE_NAME", "node-a")
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "172.28.13.0/24")
    monkeypatch.setattr(config, "FW_AGENT_POLL_FAIL_ALERT_COUNT", 15)
    monkeypatch.setattr(config, "AGENT_ALERT_COOLDOWN_SECONDS", 600)
    monkeypatch.setattr(db, "upsert_agent_heartbeat", lambda a, n, d: None, raising=False)
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {}, raising=False)


@pytest.fixture
def cooldowns(monkeypatch):
    """쿨다운 표 흉내 — 같은 키는 처음 한 번만 True."""
    taken = []

    def acquire(key, seconds):
        if key in taken:
            return False
        taken.append(key)
        return True

    monkeypatch.setattr(db, "try_acquire_cooldown", acquire, raising=False)
    return taken


@pytest.fixture
def component_alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(alert, "send_component_alert", lambda comp, msg: sent.append((comp, msg)))
    return sent


def _beat(client, signed_headers, sender, secret, payload):
    body = json.dumps(payload).encode()
    headers = signed_headers(sender, secret, body)
    headers["Content-Type"] = "application/json"
    return client.post("/api/internal/heartbeat", data=body, headers=headers)


def _fw(client, signed_headers, detail):
    return _beat(client, signed_headers, "fw-agent", "agent-secret", {"agent": "fw-agent", "detail": detail})


def _shipper(client, signed_headers, detail, stalled=False):
    return _beat(client, signed_headers, "shipper", "test-ingest-secret",
                 {"agent": "shipper", "stalled": stalled, "detail": detail})


# ---------------------------------------------------------------------------
# heartbeat — fw-agent
# ---------------------------------------------------------------------------

def test_missing_rules_alert_once(client, signed_headers, cooldowns, component_alerts):
    detail = {"poll_failures": 0, "ipset_size": 1, "rules_ok": False, "raw_ok": True, "l3_ok": False}
    assert _fw(client, signed_headers, detail).status_code == 200
    assert _fw(client, signed_headers, detail).status_code == 200
    assert len(component_alerts) == 1
    component, message = component_alerts[0]
    assert component == "fw-agent"
    assert "INPUT" in message and "LW_L3" in message
    assert "slack:rules:node-a" in cooldowns


def test_healthy_or_old_fw_agent_detail_does_not_alert(client, signed_headers, cooldowns, component_alerts):
    _fw(client, signed_headers, {"poll_failures": 0, "ipset_size": 1, "rules_ok": True, "raw_ok": True, "l3_ok": True})
    _fw(client, signed_headers, {"poll_failures": 0, "ipset_size": 1})  # guide57 이전 fw-agent
    assert component_alerts == []


def test_poll_failures_alert_at_threshold(client, signed_headers, cooldowns, component_alerts):
    _fw(client, signed_headers, {"poll_failures": 14, "ipset_size": 0})
    assert component_alerts == []
    _fw(client, signed_headers, {"poll_failures": 15, "ipset_size": 0})
    assert len(component_alerts) == 1 and "15번" in component_alerts[0][1]
    assert "slack:pollfail:node-a" in cooldowns


# ---------------------------------------------------------------------------
# heartbeat — shipper
# ---------------------------------------------------------------------------

def test_single_stalled_sensor_alerts_with_name(client, signed_headers, cooldowns, component_alerts):
    _shipper(client, signed_headers, {"eve_bytes": 1, "l4_bytes": 1, "queue": 0, "stalled_seconds": 0,
                                      "stalled_sensors": ["l4"]})
    assert len(component_alerts) == 1
    assert "l4-detector" in component_alerts[0][1]
    assert "slack:stalled:node-a:shipper" in cooldowns


def test_all_stalled_does_not_double_alert(client, signed_headers, cooldowns, component_alerts):
    _shipper(client, signed_headers, {"eve_bytes": 1, "l4_bytes": 1, "queue": 0, "stalled_seconds": 130,
                                      "stalled_sensors": ["eve", "l4"]}, stalled=True)
    assert len(component_alerts) == 1  # 기존 "센서 로그가 2분 넘게" 알림 한 통만


def test_kernel_drop_ratio_alert(client, signed_headers, cooldowns, component_alerts):
    base = {"eve_bytes": 1, "l4_bytes": 1, "queue": 0, "stalled_seconds": 0, "stalled_sensors": []}
    _shipper(client, signed_headers, {**base, "kernel_packets": 1000, "kernel_drops": 50})
    assert component_alerts == []  # 정확히 5%는 넘지 않음
    _shipper(client, signed_headers, {**base, "kernel_packets": 1000, "kernel_drops": 51})
    assert len(component_alerts) == 1 and "놓쳤습니다" in component_alerts[0][1]


def test_detail_check_failure_keeps_200(client, signed_headers, monkeypatch):
    def boom(key, seconds):
        raise RuntimeError("db down")

    monkeypatch.setattr(db, "try_acquire_cooldown", boom, raising=False)
    res = _fw(client, signed_headers, {"poll_failures": 99, "ipset_size": 0, "rules_ok": False})
    assert res.status_code == 200 and res.get_json() == {"ok": True}


# ---------------------------------------------------------------------------
# 수집 창구 — L3 경보
# ---------------------------------------------------------------------------

def _event(category, src_ip, layer, signature_id, event_id="b" * 64):
    return {
        "event_id": event_id, "sensor": "scapy" if signature_id >= 9100000 else "suricata", "layer": layer,
        "src_ip": src_ip, "dst_port": None, "proto": None, "category": category,
        "signature_id": signature_id, "signature": "x (sources=12)", "sensor_severity": 1,
        "packet_count": 40, "window_start": "2026-10-29T01:00:00Z", "observed_at": "2026-10-29T01:00:05.000Z",
    }


def _ingest(client, signed_headers, event):
    body = json.dumps(event).encode()
    return client.post("/api/internal/net-events", data=body, content_type="application/json",
                       headers=signed_headers("shipper", "test-ingest-secret", body))


@pytest.fixture
def stored(monkeypatch):
    rows = []
    monkeypatch.setattr(db, "insert_network_event", lambda row: rows.append(row) or True, raising=False)
    monkeypatch.setattr(db, "mark_network_event_promoted", lambda event_id: None, raising=False)
    return rows


@pytest.fixture
def notices(monkeypatch):
    sent = []
    monkeypatch.setattr(alert, "send_network_notice", lambda category, summary: sent.append((category, summary)))
    return sent


@pytest.mark.parametrize(("category", "src_ip", "layer", "sid"), [
    ("SPOOFED_SRC", "10.0.0.99", "L3", 9100003),
    ("GLOBAL_SYN_FLOOD", "0.0.0.0", "L4", 9100004),
])
def test_notice_only_categories_are_stored_and_alerted_but_not_promoted(
    client, signed_headers, cooldowns, stored, notices, monkeypatch, category, src_ip, layer, sid,
):
    def fail(*args, **kwargs):
        raise AssertionError("알림 전용 경보는 보안 이벤트가 되면 안 된다")

    monkeypatch.setattr(db, "insert_security_event_or_bump", fail, raising=False)
    monkeypatch.setattr(net_ingest, "_record_event", fail)
    res = _ingest(client, signed_headers, _event(category, src_ip, layer, sid))
    assert res.get_json() == {"status": "stored", "promoted": False}
    assert stored[0]["category"] == category
    assert [n[0] for n in notices] == [category]
    assert f"slack:net:node-a:{category}" in cooldowns


def test_icmp_flood_is_promoted_as_medium_without_cross_layer_rule(client, signed_headers, cooldowns, stored, notices, monkeypatch):
    recorded = []
    monkeypatch.setattr(net_ingest, "_record_event", lambda *a, **k: recorded.append((a, k)))
    res = _ingest(client, signed_headers, _event("ICMP_FLOOD", "172.28.13.150", "L3", 9000005))
    assert res.get_json() == {"status": "stored", "promoted": True}
    (args, kwargs), = recorded
    assert args[:3] == ("NET_ICMP_FLOOD", "MEDIUM", "172.28.13.150")
    assert kwargs["layer"] == "L3"
    assert [n[0] for n in notices] == ["ICMP_FLOOD"]
    # 교차 규칙(차단·영구 잠금으로 이어지는 길)에는 들어가지 않는다.
    used = set()
    for rule in correlate.CROSS_LAYER_RULES:
        used |= {rule.get("single")} | set(rule.get("first_any", ())) | set(rule.get("then_any", ())) | set(rule.get("all", ()))
    assert "NET_ICMP_FLOOD" not in used


def test_network_notice_cooldown_is_per_category(client, signed_headers, cooldowns, stored, notices):
    _ingest(client, signed_headers, _event("SPOOFED_SRC", "10.0.0.1", "L3", 9100003, event_id="c" * 64))
    _ingest(client, signed_headers, _event("SPOOFED_SRC", "10.0.0.2", "L3", 9100003, event_id="d" * 64))
    _ingest(client, signed_headers, _event("GLOBAL_SYN_FLOOD", "0.0.0.0", "L4", 9100004, event_id="e" * 64))
    assert [n[0] for n in notices] == ["SPOOFED_SRC", "GLOBAL_SYN_FLOOD"]


def test_notice_failure_does_not_block_ingest(client, signed_headers, stored, monkeypatch):
    def boom(key, seconds):
        raise RuntimeError("db down")

    monkeypatch.setattr(db, "try_acquire_cooldown", boom, raising=False)
    res = _ingest(client, signed_headers, _event("SPOOFED_SRC", "10.0.0.1", "L3", 9100003))
    assert res.status_code == 200 and len(stored) == 1


def test_existing_categories_do_not_send_network_notice(client, signed_headers, cooldowns, stored, notices, monkeypatch):
    monkeypatch.setattr(net_ingest, "promote", lambda row: False)
    _ingest(client, signed_headers, _event("PORT_SCAN", "172.28.13.150", "L4", 9100002))
    assert notices == []
