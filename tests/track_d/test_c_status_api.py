# ============================================================================
# tests/track_d/test_c_status_api.py — Track D 관제 데이터 (/api/status·/api/stats) 테스트 [C2-3]
#
# /api/status는 기존 조회 17개 + Track D 조회 3개를 한꺼번에 보낸다. 실제 DB에 닿지 않도록
# 기존 조회는 모두 빈 값 가짜로 바꾸고(tests/test_dashboard_speed.py와 같은 방식), Track D 함수만
# 테스트마다 원하는 값으로 끼운다. 계약서 K10의 응답 모양을 기준으로 확인한다.
# ============================================================================

from datetime import datetime, timedelta, timezone

import pytest

import config
import db
from db import stats as db_stats
from notify import alert
from security import soar
from tests.admin_session import login_admin_session

# /api/status가 원래 부르는 조회와 그 빈 값(tests/test_dashboard_speed.py의 FULL_STATUS_QUERIES와 같음).
_BASE_STATUS_QUERIES = {
    "list_recent_attempts": ([], 0), "list_active_lockouts": [], "list_active_account_lockouts": [],
    "list_active_admin_account_lockouts": [], "list_admin_login_log": ([], 0), "list_users": ([], 0),
    "get_signup_enabled": True, "list_posts": ([], 0), "list_comments_admin": ([], 0),
    "list_security_events": ([], 0), "list_security_incidents": ([], 0), "list_pending_requests": ([], 0),
    "list_recent_recovery_requests": [], "list_active_ip_exemptions": [], "list_role_permissions": [],
}


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    monkeypatch.setattr(config, "LW_NODE_NAME", "node-a")
    monkeypatch.setattr(config, "FW_AGENT_STALE_SECONDS", 30)
    monkeypatch.setattr(config, "SHIPPER_STALE_SECONDS", 120)
    monkeypatch.setattr(config, "AGENT_ALERT_COOLDOWN_SECONDS", 600)
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "")
    # 응답 보관(캐시)이 켜져 있으면 앞 테스트의 응답이 그대로 돌아올 수 있다.
    monkeypatch.setattr(config, "ADMIN_STATUS_CACHE_SECONDS", 0)
    for name, value in _BASE_STATUS_QUERIES.items():
        monkeypatch.setattr(db, name, lambda *a, _v=value, **k: _v)
    monkeypatch.setattr(db, "has_permission", lambda role, action: False)
    for name in ("try_release_expired_lockouts", "try_release_expired_account_lockouts",
                 "try_release_expired_admin_account_lockouts"):
        monkeypatch.setattr(soar, name, lambda: None)


@pytest.fixture
def admin_client(client):
    with client.session_transaction() as sess:
        login_admin_session(sess, "admin")
    return client


@pytest.fixture
def alerts(monkeypatch):
    sent = []
    monkeypatch.setattr(alert, "send_component_alert", lambda comp, msg: sent.append((comp, msg)))
    return sent


def test_api_status_contains_track_d_keys_in_contract_shape(admin_client, monkeypatch):
    monkeypatch.setattr(db, "list_recent_network_events", lambda limit=50: [
        {"id": 1, "observed_at": "2026-10-20T03:12:44Z", "src_ip": "10.0.0.1", "layer": "L4",
         "category": "SYN_FLOOD", "signature": "LW SYN flood suspected", "packet_count": 143, "promoted": True},
    ])
    monkeypatch.setattr(db, "list_network_blocks_for_dashboard", lambda: [
        {"ip_address": "10.0.0.1", "reason": "NET_FLOOD", "evidence": "SPOOFABLE", "status": "APPLIED",
         "expires_at": "2026-10-20T04:12:44Z", "requested_by": "playbook:NET_FLOOD_TTL",
         "applied_at": "2026-10-20T03:12:46Z", "last_error": None, "requested_at": "x", "removed_at": None},
    ])

    data = admin_client.get("/api/status").get_json()

    assert len(data["network_events"]) == 1
    # 계약서 K10: 차단 항목은 ip(DB 칸 이름 ip_address가 아님)와 정해진 8개 칸만 담는다.
    assert data["network_blocks"] == [{
        "ip": "10.0.0.1", "reason": "NET_FLOOD", "evidence": "SPOOFABLE", "status": "APPLIED",
        "expires_at": "2026-10-20T04:12:44Z", "requested_by": "playbook:NET_FLOOD_TTL",
        "applied_at": "2026-10-20T03:12:46Z", "last_error": None,
    }]
    assert set(data["agent_status"]) == {"fw-agent", "shipper"}


def test_api_status_edge_subnet_filter(admin_client, monkeypatch):
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "192.168.1.0/24")
    monkeypatch.setattr(db, "list_recent_network_events", lambda limit=50: [
        {"src_ip": "192.168.1.10", "category": "SYN_FLOOD"},
        {"src_ip": "10.0.0.1", "category": "PORT_SCAN"},
    ])
    monkeypatch.setattr(db, "list_network_blocks_for_dashboard", lambda: [
        {"ip_address": "192.168.1.20", "status": "APPLIED"},
        {"ip_address": "10.0.0.2", "status": "APPLIED"},
    ])

    data = admin_client.get("/api/status").get_json()

    assert [e["src_ip"] for e in data["network_events"]] == ["192.168.1.10"]
    assert [b["ip"] for b in data["network_blocks"]] == ["192.168.1.20"]


def test_invalid_edge_subnet_setting_does_not_hide_everything(admin_client, monkeypatch):
    # 잘못된 설정 때문에 화면이 통째로 비면 "공격이 없다"고 오해하기 쉬우므로 거르지 않는다.
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "not-a-subnet")
    monkeypatch.setattr(db, "list_recent_network_events", lambda limit=50: [{"src_ip": "10.0.0.1"}])

    data = admin_client.get("/api/status").get_json()

    assert len(data["network_events"]) == 1


def test_agent_status_stale_calculation_and_single_alert(admin_client, monkeypatch, alerts):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {
        "fw-agent": {"agent": "fw-agent", "last_seen_at": (now - timedelta(seconds=10)).isoformat(), "detail": {"ok": True}},
        "shipper": {"agent": "shipper", "last_seen_at": (now - timedelta(seconds=200)).isoformat(), "detail": {}},
    })
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, sec: True)

    status = admin_client.get("/api/status").get_json()["agent_status"]

    assert status["fw-agent"]["stale"] is False
    assert status["fw-agent"]["detail"] == {"ok": True}
    assert status["shipper"]["stale"] is True
    assert [a[0] for a in alerts] == ["shipper"]


def test_agent_without_any_record_is_stale_but_not_alerted(admin_client, monkeypatch, alerts):
    # 한 번도 켠 적 없는 장비까지 알리면 단지를 안 켠 PC에서 화면을 열 때마다 알림이 쌓인다.
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, sec: True)

    status = admin_client.get("/api/status").get_json()["agent_status"]

    assert status["fw-agent"] == {"last_seen_at": None, "stale": True, "detail": {}}
    assert status["shipper"]["stale"] is True
    assert alerts == []


def test_agent_status_empty_node_name_gives_empty_object(admin_client, monkeypatch, alerts):
    monkeypatch.setattr(config, "LW_NODE_NAME", "")
    called = []
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: called.append(node) or {})

    data = admin_client.get("/api/status").get_json()

    assert data["agent_status"] == {}
    assert called == []  # Vercel처럼 장비가 없는 환경에서는 조회도 하지 않는다
    assert alerts == []


def test_agent_status_stale_cooldown_false_no_alert(admin_client, monkeypatch, alerts):
    stale_iso = (datetime.now(timezone.utc) - timedelta(seconds=200)).isoformat()
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {
        "shipper": {"agent": "shipper", "last_seen_at": stale_iso, "detail": {}},
    })
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, sec: False)

    data = admin_client.get("/api/status").get_json()

    assert data["agent_status"]["shipper"]["stale"] is True
    assert alerts == []


def test_alert_failure_does_not_break_status(admin_client, monkeypatch):
    stale_iso = (datetime.now(timezone.utc) - timedelta(seconds=200)).isoformat()
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {
        "shipper": {"agent": "shipper", "last_seen_at": stale_iso, "detail": {}},
    })

    def boom(key, sec):
        raise RuntimeError("test-cooldown-error")

    monkeypatch.setattr(db, "try_acquire_cooldown", boom)

    res = admin_client.get("/api/status")

    assert res.status_code == 200
    assert res.get_json()["agent_status"]["shipper"]["stale"] is True


def test_threat_stats_network_layer_comes_from_category_counts(monkeypatch):
    # db/stats.py: fetch_raw가 최근 RECENT_DAYS일 집계를 가져오고 build_threat_stats가 그대로 싣는다.
    counts = [{"category": "SYN_FLOOD", "layer": "L4", "count": 12}]
    seen = []
    monkeypatch.setattr(db_stats, "_fetch_rows", lambda *a, **k: [])
    monkeypatch.setattr(db_stats, "_count_since", lambda *a, **k: 0)
    monkeypatch.setattr(db_stats, "_summary_rows", lambda *a, **k: [])
    monkeypatch.setattr(db, "count_network_events_by_category", lambda since_iso: seen.append(since_iso) or counts)

    now = datetime(2026, 10, 20, 12, 0, tzinfo=db_stats.KST)
    raw = db_stats.fetch_raw(now)
    result = db_stats.build_threat_stats(raw, active_locks=0, pending_ai=0, locations={})

    assert result["network_layer"] == counts
    assert seen == [(now.replace(hour=0) - timedelta(days=db_stats.RECENT_DAYS)).isoformat()]
