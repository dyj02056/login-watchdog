"""10/26 강사 피드백 3·4와 추가 상황(규칙 동시 기록·같은 IP 다른 계정)의 보완을 검사한다.

- 4: 차단 요청마다 version을 올리고, ACK에 같은 번호가 있어야 상태를 바꾼다.
- 3: 규칙은 기록됐지만 조치가 실패한 단계만, 다음 경보에서 이어서 실행한다(알림은 반복하지 않음).
- 규칙 동시 기록: append_matched_rule RPC를 먼저 쓰고, 함수가 없는 DB에서는 예전 방식으로 돌아간다.
- 같은 IP 다른 계정: 사건이 이미 처리됐어도 계정마다 세션 끊기를 한 번 실행한다.
실제 DB 없이 db.* 함수를 가짜로 바꾼다.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from postgrest.exceptions import APIError

import config
import db
from db import incidents
from security import correlate, netblock, playbooks
from tests.track_d.test_c_fw_agent import MockClient, fw_agent

IP = "172.28.0.120"


# ---------------------------------------------------------------------------
# 4. 요청 번호(version)
# ---------------------------------------------------------------------------

def test_stronger_request_bumps_version_with_condition(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    existing = {"ip_address": IP, "status": "PENDING_APPLY", "evidence": "SPOOFABLE",
                "expires_at": "2026-10-26T00:01:00+00:00", "version": 3}
    monkeypatch.setattr(db, "get_network_block", lambda ip: existing, raising=False)
    calls = []
    monkeypatch.setattr(db, "update_network_block_if_status",
                        lambda ip, st, f, expected_version=None: calls.append((st, f, expected_version)) or True,
                        raising=False)

    assert netblock.request_block(IP, "KILL_CHAIN", "CONNECTED", None, "playbook:KILL_CHAIN") is True

    statuses, fields, expected = calls[0]
    assert statuses == ["PENDING_APPLY"] and fields["version"] == 4 and expected == 3
    assert fields["expires_at"] is None


def test_unblock_bumps_version(monkeypatch):
    monkeypatch.setattr(db, "get_network_block", lambda ip: {"status": "APPLIED", "version": 5}, raising=False)
    calls = []
    monkeypatch.setattr(db, "update_network_block_if_status",
                        lambda ip, st, f, expected_version=None: calls.append((st, f, expected_version)) or True,
                        raising=False)

    assert netblock.request_unblock(IP, "admin:boss") is True
    assert calls == [(["APPLIED"], {"status": "PENDING_REMOVE", "version": 6}, 5)]


def test_unblock_without_version_column_keeps_old_query(monkeypatch):
    monkeypatch.setattr(db, "get_network_block", lambda ip: {"status": "APPLIED"}, raising=False)
    calls = []
    monkeypatch.setattr(db, "update_network_block_if_status", lambda ip, st, f: calls.append((st, f)) or True,
                        raising=False)

    assert netblock.request_unblock(IP, "admin:boss") is True
    assert calls == [(["PENDING_APPLY", "APPLIED"], {"status": "PENDING_REMOVE"})]


@pytest.fixture
def agent_env(monkeypatch):
    monkeypatch.setattr(config, "NET_AGENT_SECRET", "agent-secret")
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "")


def _ack(client, signed_headers, payload):
    body = json.dumps(payload).encode()
    headers = signed_headers("fw-agent", "agent-secret", body)
    headers["Content-Type"] = "application/json"
    return client.post("/api/internal/blocks/ack", data=body, headers=headers)


def test_ack_with_version_is_conditional(client, signed_headers, monkeypatch, agent_env):
    calls = []
    # 지금 행은 version 4(영구 차단 요청). 60초 차단(version 3)에 대한 늦은 ACK는 맞지 않아야 한다.
    monkeypatch.setattr(db, "update_network_block_if_status",
                        lambda ip, st, f, expected_version=None: calls.append(expected_version) or expected_version == 4)
    monkeypatch.setattr(db, "get_network_block", lambda ip: {"reason": "KILL_CHAIN"})
    monkeypatch.setattr("security.net_ingest.record_net_blocked", lambda ip, reason: None)

    stale = _ack(client, signed_headers, {"ip": IP, "status": "APPLIED", "error": None, "version": 3})
    fresh = _ack(client, signed_headers, {"ip": IP, "status": "APPLIED", "error": None, "version": 4})

    assert stale.get_json()["changed"] is False
    assert fresh.get_json()["changed"] is True
    assert calls == [3, 4]


@pytest.mark.parametrize("bad", ["3", True, -1, 1.5])
def test_ack_rejects_bad_version(client, signed_headers, agent_env, bad):
    res = _ack(client, signed_headers, {"ip": IP, "status": "APPLIED", "error": None, "version": bad})
    assert res.status_code == 400 and res.get_json()["field"] == "version"


def test_blocks_list_carries_version_only_when_present(client, signed_headers, monkeypatch, agent_env):
    monkeypatch.setattr(db, "list_expired_network_blocks", lambda now: [])
    monkeypatch.setattr(db, "list_desired_network_blocks", lambda: [
        {"ip_address": "10.0.0.1", "status": "APPLIED", "expires_at": None, "version": 7},
        {"ip_address": "10.0.0.2", "status": "APPLIED", "expires_at": None},
    ])
    res = client.get("/api/internal/blocks", headers=signed_headers("fw-agent", "agent-secret", b""))
    blocks = res.get_json()["blocks"]
    assert blocks[0]["version"] == 7 and "version" not in blocks[1]


def test_agent_echoes_version_in_ack():
    class VersionClient(MockClient):
        def ack(self, ip, status, error=None, version=None):
            self.acks.append((ip, status, error, version))
            return {"changed": True}

    client = VersionClient()
    backend = fw_agent.IptablesBackend(fw_agent.FakeRunner(), set_name="lw_block")
    fw_agent.process_blocks([{"ip": "1.2.3.4", "status": "PENDING_APPLY", "ttl_seconds": None, "version": 9}],
                            backend, client, allowlist=[])
    assert client.acks == [("1.2.3.4", "APPLIED", None, 9)]


def test_agent_ack_body_includes_version():
    sent = []

    class Session:
        def post(self, url, data=None, headers=None, timeout=None):
            sent.append(json.loads(data))
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"changed": True})

    fw_agent.AgentClient("http://app:5000", "test-agent-secret", session=Session()).ack("1.2.3.4", "APPLIED", version=2)
    assert sent == [{"ip": "1.2.3.4", "status": "APPLIED", "error": None, "version": 2}]


# ---------------------------------------------------------------------------
# 규칙 동시 기록 — RPC 우선, 없으면 예전 방식
# ---------------------------------------------------------------------------

class _RpcClient:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    def rpc(self, name, params):
        self.calls.append((name, params))
        return self

    def table(self, name):
        raise AssertionError("RPC가 되면 예전 UPDATE를 쓰지 않는다")

    def execute(self):
        if self.error:
            raise self.error
        return SimpleNamespace(data=self.result)


@pytest.mark.parametrize("result", [True, False])
def test_rule_append_uses_rpc(monkeypatch, result):
    rpc = _RpcClient(result=result)
    monkeypatch.setattr(db, "get_client", lambda: rpc)
    assert incidents._append_matched_rule_rpc(7, "CR-02", ["NET_SYN_FLOOD"], "HIGH") is result
    assert rpc.calls == [("append_matched_rule", {
        "p_incident_id": 7, "p_rule": "CR-02", "p_event_types": ["NET_SYN_FLOOD"], "p_severity_max": "HIGH",
    })]


def test_rule_append_falls_back_when_function_missing(monkeypatch):
    missing = APIError({"code": "PGRST202", "message": "Could not find the function"})
    monkeypatch.setattr(db, "get_client", lambda: _RpcClient(error=missing))
    assert incidents._append_matched_rule_rpc(7, "CR-02", ["NET_SYN_FLOOD"], "HIGH") is None


def test_rule_append_other_errors_are_raised(monkeypatch):
    monkeypatch.setattr(db, "get_client", lambda: _RpcClient(error=APIError({"code": "57014", "message": "x"})))
    with pytest.raises(APIError):
        incidents._append_matched_rule_rpc(7, "CR-02", ["NET_SYN_FLOOD"], "HIGH")


# ---------------------------------------------------------------------------
# 3. 실패한 단계만 이어서 실행
# ---------------------------------------------------------------------------

def test_playbook_only_steps_runs_subset(monkeypatch):
    done = []
    monkeypatch.setattr(db, "insert_playbook_run", lambda *a: done.append(a[2:4]), raising=False)
    monkeypatch.setattr("security.netblock.request_block", lambda *a, **k: True)
    ctx = dict(ip=IP, incident_id=1, rule_id="NET-01", priority="HIGH", matched_rules=["NET-01"],
               evidence="SPOOFABLE")
    results = playbooks.run("NET_FLOOD_TTL", "incident:1:NET-01", ctx, only_steps=["block_l4_ttl"])
    assert [r["step"] for r in results] == ["block_l4_ttl"]
    assert done == [("block_l4_ttl", "OK")]


@pytest.fixture
def retry_env(monkeypatch):
    state = SimpleNamespace(runs=[], history=[])
    incident = {"id": 41, "matched_rules": ["NET-01"], "last_event_at": None}
    monkeypatch.setattr(correlate, "_match_cross_layer_rule",
                        lambda ip, event_type, rule: [{"event_type": "NET_SYN_FLOOD"}] if rule["id"] == "NET-01" else [])
    monkeypatch.setattr(db, "get_open_incident", lambda ip: incident)
    monkeypatch.setattr(db.incidents, "_is_idle", lambda row: False)
    monkeypatch.setattr(db, "list_playbook_runs", lambda ref: state.history, raising=False)
    monkeypatch.setattr(playbooks, "run", lambda *a, **k: state.runs.append((a, k)) or [])
    return state


def test_failed_block_step_is_retried_on_next_alert(retry_env):
    retry_env.history = [
        {"step": "block_l4_ttl", "status": "FAILED"},
        {"step": "notify_slack", "status": "FAILED"},  # 알림은 반복하지 않는다
    ]
    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    (args, kwargs), = retry_env.runs
    assert args[:2] == ("NET_FLOOD_TTL", "incident:41:NET-01")
    assert kwargs == {"only_steps": ["block_l4_ttl"]}


def test_step_that_later_succeeded_is_not_retried(retry_env):
    retry_env.history = [
        {"step": "block_l4_ttl", "status": "FAILED"},
        {"step": "block_l4_ttl", "status": "OK"},
    ]
    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")
    assert retry_env.runs == []


def test_history_lookup_error_does_not_rerun(retry_env, monkeypatch):
    monkeypatch.setattr(db, "list_playbook_runs", lambda ref: (_ for _ in ()).throw(RuntimeError("db")))
    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")
    assert retry_env.runs == []


# ---------------------------------------------------------------------------
# 같은 IP, 다른 계정 — 계정마다 세션 끊기
# ---------------------------------------------------------------------------

@pytest.fixture
def login_env(monkeypatch):
    state = SimpleNamespace(runs=[], history={})
    monkeypatch.setattr(db, "list_recent_connected_net_events_for_login", lambda ip, minutes: [
        {"event_type": "NET_SCANNER_UA", "severity": "MEDIUM"}
    ], raising=False)
    monkeypatch.setattr(db, "get_open_incident", lambda ip: {"id": 12, "matched_rules": ["CR-03"]})
    monkeypatch.setattr(db.incidents, "_is_idle", lambda row: False)
    users = {"alice": {"id": 1, "email": "a@example.invalid"}, "bob": {"id": 2, "email": "b@example.invalid"}}
    monkeypatch.setattr(db, "get_user_by_username", lambda name: users.get(name))
    monkeypatch.setattr(db, "list_playbook_runs", lambda ref: state.history.get(ref, []), raising=False)
    monkeypatch.setattr(playbooks, "run", lambda *a, **k: state.runs.append((a, k)) or [])
    return state


def test_second_account_on_handled_ip_gets_sessions_cut(login_env):
    assert correlate.check_success_login(IP, "bob") is True

    (args, kwargs), = login_env.runs
    assert args[0] == "SUSPICIOUS_SUCCESS_LOGIN" and args[1] == "incident:12:CR-03:user:2"
    assert args[2]["user_id"] == 2 and kwargs == {"only_steps": ["invalidate_sessions"]}


def test_account_already_cut_is_not_repeated(login_env):
    login_env.history["incident:12:CR-03:user:2"] = [{"step": "invalidate_sessions", "status": "OK"}]
    assert correlate.check_success_login(IP, "bob") is True
    assert login_env.runs == []


def test_session_cut_error_still_blocks_login(login_env, monkeypatch):
    monkeypatch.setattr(db, "get_user_by_username", lambda name: (_ for _ in ()).throw(RuntimeError("db")))
    assert correlate.check_success_login(IP, "bob") is True


# ---------------------------------------------------------------------------
# guide56 SQL — schema.sql에도 같은 본문이 들어 있어야 새 DB가 한 번에 맞춰진다
# ---------------------------------------------------------------------------

def test_schema_contains_guide56():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    migration = (root / "docs" / "migrations" / "guide56_track_d_hardening.sql").read_text(encoding="utf-8")
    schema = (root / "docs" / "schema.sql").read_text(encoding="utf-8")
    assert migration.strip() in schema
    # 여러 번 실행해도 같은 결과가 되도록 if not exists / or replace만 쓴다.
    assert "add column if not exists version" in migration
    assert "create or replace function append_matched_rule" in migration
