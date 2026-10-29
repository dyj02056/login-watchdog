# ============================================================================
# tests/track_d/test_i_guide57_blocks.py — guide57 차단 장부 보완 (인프라 주소 보호·적용 실패 재시도)
#
# 확인하는 것:
#   - 우리 core·gateway·특수 주소는 어떤 증거로도 차단 요청·차단 목록·보안 이벤트가 되지 않는다.
#   - NET_EDGE_SUBNET 형식이 틀리면 /blocks가 503으로 멈춘다(빈 값은 예전처럼 거르지 않음).
#   - 적용 실패(PENDING_APPLY → FAILED)만 failed_at·알림을 남기고, 정해진 횟수까지 다시 시도한다.
# 실제 DB에는 접속하지 않고 db.* 함수를 메모리 장부로 바꿔 끼운다.
# ============================================================================

from datetime import datetime, timedelta, timezone
import json

import pytest

import config
import db
from notify import alert
from security import net_ingest, netblock


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    monkeypatch.setattr(config, "NET_AGENT_SECRET", "agent-secret")
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "172.28.13.0/24")
    monkeypatch.setattr(config, "LW_NODE_NAME", "node-a")
    monkeypatch.setattr(config, "NET_BLOCK_APPLY_MAX_RETRIES", 3)
    monkeypatch.setattr(config, "NET_BLOCK_APPLY_RETRY_SECONDS", 10)
    monkeypatch.setattr(config, "AGENT_ALERT_COOLDOWN_SECONDS", 600)
    monkeypatch.setattr(db, "try_acquire_cooldown", lambda key, seconds: True, raising=False)


class FakeBlocks:
    """network_blocks 표를 흉내 내는 메모리 장부. 조건부 UPDATE 규칙(상태·version)을 그대로 따른다."""

    def __init__(self, rows):
        self.rows = {row["ip_address"]: dict(row) for row in rows}
        self.updates = []

    def get(self, ip):
        row = self.rows.get(ip)
        return dict(row) if row else None

    def update(self, ip, from_statuses, fields, expected_version=None):
        row = self.rows.get(ip)
        if row is None or row["status"] not in from_statuses:
            return False
        if expected_version is not None and row.get("version") != expected_version:
            return False
        row.update(fields)
        self.updates.append((ip, dict(fields)))
        return True

    def failed_apply(self):
        return [dict(r) for r in self.rows.values() if r["status"] == "FAILED" and r.get("failed_at")]

    def desired(self):
        return [dict(r) for r in self.rows.values() if r["status"] in ("PENDING_APPLY", "APPLIED", "PENDING_REMOVE")]


def _install(monkeypatch, store):
    monkeypatch.setattr(db, "get_network_block", store.get, raising=False)
    monkeypatch.setattr(db, "update_network_block_if_status", store.update, raising=False)
    monkeypatch.setattr(db, "list_failed_apply_blocks", store.failed_apply, raising=False)
    monkeypatch.setattr(db, "list_desired_network_blocks", store.desired, raising=False)
    monkeypatch.setattr(db, "list_expired_network_blocks", lambda now_iso: [], raising=False)


def _iso(seconds_from_now):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)).isoformat()


# ---------------------------------------------------------------------------
# 인프라 주소 판별과 차단 요청 거절
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "172.30.0.10",   # gateway core
    "172.30.0.4",    # app
    "172.28.13.1",   # 호스트 브라우저·Docker 게이트웨이
    "172.28.13.10",  # gateway edge
    "0.0.0.0",
    "127.0.0.1",
    "224.0.0.1",
    "169.254.1.1",
    "240.0.0.1",
])
def test_infrastructure_ips_are_recognized(ip):
    assert netblock.is_infrastructure_ip(ip) is True


@pytest.mark.parametrize("ip", ["172.28.13.101", "172.28.13.140", "10.0.0.1", "8.8.8.8"])
def test_ordinary_ips_are_not_infrastructure(ip):
    assert netblock.is_infrastructure_ip(ip) is False


def test_core_network_is_infrastructure_even_without_edge_subnet(monkeypatch):
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "")
    assert netblock.is_infrastructure_ip("172.30.0.4") is True
    # 대역을 모르면 .10이 gateway인지 알 수 없으므로 일반 주소로 본다.
    assert netblock.is_infrastructure_ip("172.28.13.10") is False


def test_request_block_rejects_core_ip_before_touching_db(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)

    def fail(*args, **kwargs):
        raise AssertionError("인프라 주소는 DB까지 가면 안 된다")

    monkeypatch.setattr(db, "get_network_block", fail, raising=False)
    monkeypatch.setattr(db, "count_recent_net_blocked_events", fail, raising=False)
    assert netblock.request_block("172.30.0.4", "NET_FLOOD", "SPOOFABLE") is False
    assert netblock.request_block("172.28.13.10", "KILL_CHAIN", "CONNECTED") is False


def test_outside_edge_subnet():
    assert netblock.is_outside_edge_subnet("172.28.12.101") is True
    assert netblock.is_outside_edge_subnet("172.28.13.101") is False


def test_new_request_resets_retry_counters(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    monkeypatch.setattr(db, "count_recent_net_blocked_events", lambda ip, since: 0, raising=False)
    store = FakeBlocks([{
        "ip_address": "172.28.13.120", "status": "FAILED", "version": 2,
        "apply_attempts": 3, "failed_at": None, "expires_at": _iso(-10), "evidence": "SPOOFABLE",
    }])
    _install(monkeypatch, store)
    assert netblock.request_block("172.28.13.120", "NET_FLOOD", "SPOOFABLE") is True
    row = store.rows["172.28.13.120"]
    assert row["status"] == "PENDING_APPLY"
    assert row["apply_attempts"] == 0 and row["version"] == 3


# ---------------------------------------------------------------------------
# 보안 이벤트 승격에서 위조 출발지 거름
# ---------------------------------------------------------------------------

def _net_row(src_ip, category="SYN_FLOOD"):
    return {"src_ip": src_ip, "category": category, "packet_count": 100, "layer": "L4"}


@pytest.mark.parametrize("src_ip", ["172.30.0.4", "172.28.13.10", "172.28.12.101", "0.0.0.0"])
def test_promote_skips_untrusted_sources(monkeypatch, src_ip):
    def fail(*args, **kwargs):
        raise AssertionError("위조 출발지는 보안 이벤트가 되면 안 된다")

    monkeypatch.setattr(db, "insert_security_event_or_bump", fail, raising=False)
    monkeypatch.setattr(net_ingest, "_record_event", fail)
    assert net_ingest.promote(_net_row(src_ip)) is False


def test_promote_keeps_edge_sources(monkeypatch):
    calls = []
    monkeypatch.setattr(db, "insert_security_event_or_bump", lambda *a, **k: calls.append(a), raising=False)
    monkeypatch.setattr("security.correlate.check_and_correlate", lambda *a, **k: None)
    assert net_ingest.promote(_net_row("172.28.13.150")) is True
    assert calls and calls[0][0] == "NET_SYN_FLOOD"


# ---------------------------------------------------------------------------
# GET /api/internal/blocks — 설정 오류·인프라 주소 제외·적용 재시도
# ---------------------------------------------------------------------------

def _get_blocks(client, signed_headers):
    return client.get("/api/internal/blocks", headers=signed_headers("fw-agent", "agent-secret", b""))


def test_blocks_malformed_edge_subnet_returns_503(client, signed_headers, monkeypatch):
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "172.28.13.0/99")
    monkeypatch.setattr(db, "list_expired_network_blocks", lambda now: (_ for _ in ()).throw(AssertionError()), raising=False)
    res = _get_blocks(client, signed_headers)
    assert res.status_code == 503
    assert res.get_json() == {"error": "misconfigured"}


def test_blocks_never_returns_infrastructure_rows(client, signed_headers, monkeypatch):
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "")
    store = FakeBlocks([
        {"ip_address": "172.30.0.4", "status": "PENDING_APPLY", "expires_at": _iso(600)},
        {"ip_address": "172.28.13.150", "status": "APPLIED", "expires_at": _iso(600)},
    ])
    _install(monkeypatch, store)
    res = _get_blocks(client, signed_headers)
    assert res.status_code == 200
    assert [b["ip"] for b in res.get_json()["blocks"]] == ["172.28.13.150"]


def test_failed_apply_is_retried_after_interval(client, signed_headers, monkeypatch):
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "FAILED", "version": 4, "apply_attempts": 0,
        "failed_at": _iso(-30), "expires_at": _iso(600), "last_error": "ipset add failed",
    }])
    _install(monkeypatch, store)
    res = _get_blocks(client, signed_headers)
    blocks = res.get_json()["blocks"]
    assert blocks == [{"ip": "172.28.13.150", "status": "PENDING_APPLY", "ttl_seconds": blocks[0]["ttl_seconds"], "version": 5}]
    row = store.rows["172.28.13.150"]
    assert row["apply_attempts"] == 1 and row["failed_at"] is None


def test_failed_apply_waits_for_interval(client, signed_headers, monkeypatch):
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "FAILED", "version": 4, "apply_attempts": 0,
        "failed_at": _iso(-2), "expires_at": _iso(600), "last_error": "ipset add failed",
    }])
    _install(monkeypatch, store)
    assert _get_blocks(client, signed_headers).get_json()["blocks"] == []
    assert store.rows["172.28.13.150"]["status"] == "FAILED"


@pytest.mark.parametrize("error", ["allowlisted", "out_of_subnet"])
def test_failed_apply_by_agent_refusal_is_not_retried(client, signed_headers, monkeypatch, error):
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "FAILED", "version": 4, "apply_attempts": 0,
        "failed_at": _iso(-30), "expires_at": None, "last_error": error,
    }])
    _install(monkeypatch, store)
    _get_blocks(client, signed_headers)
    assert store.rows["172.28.13.150"]["status"] == "FAILED"


def test_expired_failed_apply_is_not_retried(client, signed_headers, monkeypatch):
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "FAILED", "version": 4, "apply_attempts": 0,
        "failed_at": _iso(-30), "expires_at": _iso(-1), "last_error": "x",
    }])
    _install(monkeypatch, store)
    _get_blocks(client, signed_headers)
    assert store.rows["172.28.13.150"]["status"] == "FAILED"


def test_retry_gives_up_once_with_alert(client, signed_headers, monkeypatch):
    sent = []
    monkeypatch.setattr(alert, "send_block_failed_alert", lambda ip, reason, error, gave_up=False: sent.append((ip, reason, gave_up)))
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "FAILED", "version": 4, "apply_attempts": 3,
        "failed_at": _iso(-30), "expires_at": None, "reason": "KILL_CHAIN", "last_error": "x",
    }])
    _install(monkeypatch, store)
    _get_blocks(client, signed_headers)
    _get_blocks(client, signed_headers)
    assert store.rows["172.28.13.150"]["status"] == "FAILED"
    assert store.rows["172.28.13.150"]["failed_at"] is None
    assert sent == [("172.28.13.150", "KILL_CHAIN", True)]


def test_retry_skipped_without_guide57_columns(client, signed_headers, monkeypatch):
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "FAILED", "version": 4,
        "failed_at": _iso(-30), "expires_at": None, "last_error": "x",
    }])
    _install(monkeypatch, store)
    _get_blocks(client, signed_headers)
    assert store.rows["172.28.13.150"]["status"] == "FAILED"


# ---------------------------------------------------------------------------
# POST /api/internal/blocks/ack — 적용 실패와 해제 실패 구분
# ---------------------------------------------------------------------------

def _ack(client, signed_headers, payload):
    body = json.dumps(payload).encode()
    headers = signed_headers("fw-agent", "agent-secret", body)
    headers["Content-Type"] = "application/json"
    return client.post("/api/internal/blocks/ack", data=body, headers=headers)


def test_apply_failure_records_failed_at_and_alerts(client, signed_headers, monkeypatch):
    sent = []
    monkeypatch.setattr(alert, "send_block_failed_alert", lambda ip, reason, error, gave_up=False: sent.append((ip, reason, error, gave_up)))
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "PENDING_APPLY", "version": 2, "reason": "KILL_CHAIN",
        "apply_attempts": 0, "failed_at": None,
    }])
    _install(monkeypatch, store)
    res = _ack(client, signed_headers, {"ip": "172.28.13.150", "status": "FAILED", "error": "ipset add failed", "version": 2})
    assert res.get_json() == {"changed": True}
    row = store.rows["172.28.13.150"]
    assert row["status"] == "FAILED" and row["failed_at"] and row["last_error"] == "ipset add failed"
    assert sent == [("172.28.13.150", "KILL_CHAIN", "ipset add failed", False)]


def test_remove_failure_does_not_mark_retry_or_alert(client, signed_headers, monkeypatch):
    monkeypatch.setattr(alert, "send_block_failed_alert", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    store = FakeBlocks([{
        "ip_address": "172.28.13.150", "status": "PENDING_REMOVE", "version": 2,
        "apply_attempts": 0, "failed_at": None,
    }])
    _install(monkeypatch, store)
    res = _ack(client, signed_headers, {"ip": "172.28.13.150", "status": "FAILED", "error": "ipset del failed", "version": 2})
    assert res.get_json() == {"changed": True}
    assert store.rows["172.28.13.150"]["failed_at"] is None


def test_apply_failure_without_failed_at_column_still_works(client, signed_headers, monkeypatch):
    monkeypatch.setattr(alert, "send_block_failed_alert", lambda *a, **k: None)
    store = FakeBlocks([{"ip_address": "172.28.13.150", "status": "PENDING_APPLY", "version": 2}])
    _install(monkeypatch, store)
    res = _ack(client, signed_headers, {"ip": "172.28.13.150", "status": "FAILED", "error": "x", "version": 2})
    assert res.get_json() == {"changed": True}
    assert "failed_at" not in store.rows["172.28.13.150"]
