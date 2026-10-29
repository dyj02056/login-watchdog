"""TTL 차단이 만료 처리되는 순간 공격이 계속되면 바로 다시 막는지 검증한다.

shipper는 1분 창의 첫 경보만 바로 보내고 추가분은 창이 끝난 뒤 보내므로(계약서 K4), 경보를 기다려
다시 막으면 TTL이 분 중간에 끝날 때 다음 분까지 차단이 풀려 있었다(10/29 Docker 실측 약 21~25초).
그래서 GET /blocks의 지연 만료가 이번 분·지난 분의 SYN Flood 경보를 보고 그 자리에서 다시 요청한다.
DB·플레이북은 모두 가짜로 바꿔 실제 DB에 접속하지 않는다.
"""

from datetime import datetime, timedelta, timezone

import pytest

import config
import db
from security import correlate, net_ingest


IP = "172.28.0.180"


def _iso(seconds_from_now):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)).isoformat()


def _incident(matched=("NET-01",), last_event_minutes_ago=1):
    return {
        "id": 88, "event_types": ["NET_BLOCKED", "NET_SYN_FLOOD"], "severity_max": "CRITICAL",
        "app_severity_max": None, "matched_rules": list(matched), "escalated": False,
        "last_event_at": _iso(-60 * last_event_minutes_ago),
    }


@pytest.fixture
def reblocks(monkeypatch):
    """재차단 요청(_reblock_if_ttl_expired)이 어떤 규칙으로 불렸는지 기록한다."""
    calls = []
    monkeypatch.setattr(
        correlate, "_reblock_if_ttl_expired",
        lambda ip, incident, rule: calls.append((ip, incident["id"], rule["id"])),
    )
    return calls


def _recent(monkeypatch, answer, seen=None):
    def has_recent(ip, category, since_iso):
        if seen is not None:
            seen.append((ip, category, since_iso))
        return answer

    monkeypatch.setattr(db, "has_recent_network_event", has_recent, raising=False)


# ---------------------------------------------------------------------------
# correlate.reblock_on_expiry
# ---------------------------------------------------------------------------

def test_ongoing_attack_reblocks_net01(monkeypatch, reblocks):
    seen = []
    _recent(monkeypatch, True, seen)
    monkeypatch.setattr(db, "get_open_incident", lambda ip: _incident())

    correlate.reblock_on_expiry(IP)

    assert reblocks == [(IP, 88, "NET-01")]
    # "이번 분이나 지난 분": 지난 분 정각 이후의 SYN_FLOOD 창을 찾는다.
    ip, category, since_iso = seen[0]
    since = datetime.fromisoformat(since_iso)
    expected = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=1)
    assert (ip, category) == (IP, "SYN_FLOOD")
    assert abs((since - expected).total_seconds()) <= 60


def test_both_ttl_rules_are_checked(monkeypatch, reblocks):
    _recent(monkeypatch, True)
    monkeypatch.setattr(db, "get_open_incident", lambda ip: _incident(matched=("NET-01", "CR-02")))

    correlate.reblock_on_expiry(IP)

    assert reblocks == [(IP, 88, "NET-01"), (IP, 88, "CR-02")]


def test_no_recent_alert_does_not_reblock(monkeypatch, reblocks):
    _recent(monkeypatch, False)

    def unexpected(ip):
        raise AssertionError("최근 경보가 없으면 사건을 조회할 필요가 없다")

    monkeypatch.setattr(db, "get_open_incident", unexpected)

    correlate.reblock_on_expiry(IP)

    assert reblocks == []


def test_without_open_or_with_idle_incident_does_not_reblock(monkeypatch, reblocks):
    _recent(monkeypatch, True)
    monkeypatch.setattr(db, "get_open_incident", lambda ip: None)
    correlate.reblock_on_expiry(IP)

    monkeypatch.setattr(
        db, "get_open_incident",
        lambda ip: _incident(last_event_minutes_ago=config.INCIDENT_MERGE_IDLE_MINUTES + 5),
    )
    correlate.reblock_on_expiry(IP)

    assert reblocks == []


def test_permanent_rule_is_not_reblocked(monkeypatch, reblocks):
    _recent(monkeypatch, True)
    monkeypatch.setattr(db, "get_open_incident", lambda ip: _incident(matched=("CR-01",)))

    correlate.reblock_on_expiry(IP)

    assert reblocks == []


def test_lookup_error_is_swallowed(monkeypatch, reblocks):
    def broken(ip, category, since_iso):
        raise RuntimeError("db down")

    monkeypatch.setattr(db, "has_recent_network_event", broken, raising=False)

    correlate.reblock_on_expiry(IP)  # 예외가 밖으로 나오면 안 된다

    assert reblocks == []


# ---------------------------------------------------------------------------
# GET /api/internal/blocks — 지연 만료와 같은 응답에 새 차단이 실리는지
# ---------------------------------------------------------------------------

@pytest.fixture
def agent_env(monkeypatch):
    monkeypatch.setattr(config, "NET_AGENT_SECRET", "agent-secret")
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "")
    monkeypatch.setattr(net_ingest, "resolve_net_blocked", lambda ip: None)
    monkeypatch.setattr(db, "update_network_block_if_status", lambda *args, **kwargs: True, raising=False)


def _get_blocks(client, signed_headers):
    return client.get("/api/internal/blocks", headers=signed_headers("fw-agent", "agent-secret", b""))


def test_expiry_reblock_is_in_same_response(client, signed_headers, monkeypatch, agent_env):
    state = {"desired": []}
    expired = {"ip_address": IP, "status": "APPLIED", "reason": "NET_FLOOD", "expires_at": _iso(-1)}
    monkeypatch.setattr(db, "list_expired_network_blocks", lambda now: [expired], raising=False)

    def fake_reblock(ip):
        # 재요청이 장부에 PENDING_APPLY(120초)를 적은 것처럼 둔다.
        state["desired"].append(
            {"ip_address": ip, "status": "PENDING_APPLY", "expires_at": _iso(120), "version": 2}
        )

    monkeypatch.setattr(correlate, "reblock_on_expiry", fake_reblock)
    monkeypatch.setattr(db, "list_desired_network_blocks", lambda: state["desired"], raising=False)

    res = _get_blocks(client, signed_headers)

    assert res.status_code == 200
    blocks = res.get_json()["blocks"]
    assert [(b["ip"], b["status"]) for b in blocks] == [(IP, "PENDING_APPLY")]
    # 가짜의 120초는 라우트의 '지금'보다 조금 뒤에 계산돼 올림하면 121이 될 수 있다.
    assert 115 <= blocks[0]["ttl_seconds"] <= 121


def test_admin_manual_expiry_is_not_reblocked(client, signed_headers, monkeypatch, agent_env):
    calls = []
    expired = {"ip_address": IP, "status": "APPLIED", "reason": "ADMIN_MANUAL", "expires_at": _iso(-1)}
    monkeypatch.setattr(db, "list_expired_network_blocks", lambda now: [expired], raising=False)
    monkeypatch.setattr(correlate, "reblock_on_expiry", calls.append)
    monkeypatch.setattr(db, "list_desired_network_blocks", lambda: [], raising=False)

    res = _get_blocks(client, signed_headers)

    assert res.status_code == 200
    assert calls == []


def test_expiry_lost_to_concurrent_change_is_not_reblocked(client, signed_headers, monkeypatch, agent_env):
    # 조건부 UPDATE가 실패했으면(다른 요청이 먼저 바꿈) 만료로 보지 않으므로 재요청도 하지 않는다.
    calls = []
    expired = {"ip_address": IP, "status": "APPLIED", "reason": "NET_FLOOD", "expires_at": _iso(-1)}
    monkeypatch.setattr(db, "list_expired_network_blocks", lambda now: [expired], raising=False)
    monkeypatch.setattr(db, "update_network_block_if_status", lambda *args, **kwargs: False, raising=False)
    monkeypatch.setattr(correlate, "reblock_on_expiry", calls.append)
    monkeypatch.setattr(db, "list_desired_network_blocks", lambda: [], raising=False)

    _get_blocks(client, signed_headers)

    assert calls == []


def test_has_recent_network_event_query(monkeypatch):
    # 조회 조건(IP·category·창 시작 시각)과 1건 제한을 확인한다.
    from db import network_events

    calls = []

    class Query:
        def __getattr__(self, name):
            def method(*args, **kwargs):
                calls.append((name, args))
                return self
            return method

        def execute(self):
            calls.append(("execute", ()))
            return type("Res", (), {"data": [{"event_id": "x"}]})()

    class Client:
        def table(self, name):
            calls.append(("table", (name,)))
            return Query()

    monkeypatch.setattr(db, "get_client", lambda: Client())

    assert network_events.has_recent_network_event(IP, "SYN_FLOOD", "2026-10-29T05:19:00+00:00") is True
    assert ("table", ("network_events",)) in calls
    assert ("eq", ("src_ip", IP)) in calls
    assert ("eq", ("category", "SYN_FLOOD")) in calls
    assert ("gte", ("window_start", "2026-10-29T05:19:00+00:00")) in calls
    assert ("limit", (1,)) in calls
