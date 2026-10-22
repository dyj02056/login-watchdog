"""실제 차단·메일·DB 없이 실행 순서와 부분 실패, K7 인자를 검증한다."""

import importlib
from datetime import datetime
from types import SimpleNamespace

import pytest
import db
from db import playbook_runs
from security import playbooks, correlate


EXPECTED = {
    "NET_FLOOD_TTL": ["block_l4_ttl", "notify_slack"],
    "KILL_CHAIN": ["lock_ip_permanent", "block_l4", "notify_slack", "llm_postmortem"],
    "NET_FLOOD": ["block_l4_ttl", "notify_slack"],
    "SUSPICIOUS_SUCCESS_LOGIN": ["invalidate_sessions", "notify_owner_email", "notify_slack"],
    "SUBNET_REVIEW": ["require_approval", "notify_slack"],
    "ROTATION_EVASION": ["lock_account_permanent", "notify_owner_email", "notify_slack"],
    "WEB_ATTACK": ["lock_ip_permanent", "notify_slack"],
}


@pytest.fixture
def ctx():
    return dict(ip="172.28.12.103", incident_id=12, rule_id="CR-01",
                priority="CRITICAL", matched_rules=["CR-01"], evidence="CONNECTED",
                username="test-user", user_id=7, user_email="test@example.invalid",
                subnet="172.28.12.0/24", count=3, threshold=3)


@pytest.fixture
def fake(monkeypatch):
    state = SimpleNamespace(calls=[], records=[], values={}, failures=set())
    for path in set(playbooks.ACTIONS.values()):
        module, name = path.rsplit(".", 1)

        def action(*args, _path=path, **kwargs):
            state.calls.append((_path, args, kwargs))
            if _path in state.failures:
                raise RuntimeError("test-secret-must-not-be-recorded")
            return state.values.get(_path, True)

        monkeypatch.setattr(importlib.import_module(module), name, action, raising=False)
    monkeypatch.setattr(db, "insert_playbook_run",
                        lambda *args: state.records.append(args), raising=False)
    return state


@pytest.mark.parametrize("name", EXPECTED)
def test_registry_order_and_records(name, fake, ctx):
    assert playbooks.PLAYBOOKS == EXPECTED
    results = playbooks.run(name, "incident:12:CR-01", ctx)
    assert [call[0] for call in fake.calls] == [playbooks.ACTIONS[s] for s in EXPECTED[name]]
    assert results == [dict(step=s, status="OK", error=None) for s in EXPECTED[name]]
    assert fake.records == [(name, "incident:12:CR-01", r["step"], r["status"], r["error"])
                            for r in results]


@pytest.mark.parametrize("name", ["NET_FLOOD", "NET_FLOOD_TTL"])
def test_ttl_fixed_arguments(name, fake, ctx):
    playbooks.run(name, "incident:12:CR-02", ctx)
    assert fake.calls[0][1:] == ((ctx["ip"], "NET_FLOOD"), dict(
        evidence="SPOOFABLE", ttl_seconds=None, requested_by=f"playbook:{name}"))


def test_permanent_arguments_and_slack_snapshot(fake, ctx):
    results = playbooks.run("KILL_CHAIN", "incident:12:CR-01", ctx)
    assert fake.calls[0][1:] == ((ctx["ip"],), dict(
        reason="NETWORK_IDS", recoverable="ADMIN_ONLY", incident_id=12))
    assert fake.calls[1][1:] == ((ctx["ip"], "KILL_CHAIN"), dict(
        evidence="CONNECTED", ttl_seconds=None, requested_by="playbook:KILL_CHAIN"))
    assert fake.calls[2][1] == ("KILL_CHAIN", ctx["ip"], ["CR-01"], results[:2])


def test_web_attack_recovery(fake, ctx):
    playbooks.run("WEB_ATTACK", "incident:12:CR-06", ctx)
    assert fake.calls[0][2]["recoverable"] == "EXEMPTION"


def test_partial_failure_continues_and_hides_exception_secrets(fake, ctx):
    fake.failures.add(playbooks.ACTIONS["block_l4"])
    results = playbooks.run("KILL_CHAIN", "incident:12:CR-01", ctx)
    assert [r["status"] for r in results] == ["OK", "FAILED", "OK", "OK"]
    assert results[1]["error"] == "RuntimeError"
    assert len(fake.calls) == 4
    assert fake.calls[2][1][3] == results[:2]


def test_record_failure_does_not_stop_actions(monkeypatch, fake, ctx):
    def fail(*args):
        raise RuntimeError("test-record-error")
    monkeypatch.setattr(db, "insert_playbook_run", fail)
    assert len(playbooks.run("KILL_CHAIN", "incident:12:CR-01", ctx)) == 4
    assert len(fake.calls) == 4


def test_missing_function_skipped(monkeypatch, fake, ctx):
    monkeypatch.delattr(importlib.import_module("services.llm_client"), "summarize_incident")
    results = playbooks.run("KILL_CHAIN", "incident:12:CR-01", ctx)
    assert results[-1]["status"] == "SKIPPED"


@pytest.mark.parametrize("field,step", [("user_id", "invalidate_sessions"),
                                      ("user_email", "notify_owner_email")])
def test_missing_context_skips_only_that_step(field, step, fake, ctx):
    ctx[field] = None
    results = playbooks.run("SUSPICIOUS_SUCCESS_LOGIN", "incident:12:CR-03", ctx)
    assert next(r for r in results if r["step"] == step)["status"] == "SKIPPED"
    assert results[-1]["status"] == "OK"


def test_wrong_permanent_playbook_is_failed(monkeypatch, fake, ctx):
    monkeypatch.setitem(playbooks.PLAYBOOKS, "NET_FLOOD", ["block_l4", "notify_slack"])
    results = playbooks.run("NET_FLOOD", "incident:12:CR-02", ctx)
    assert results[0]["status"] == "FAILED"
    assert [c[0] for c in fake.calls] == [playbooks.ACTIONS["notify_slack"]]


@pytest.mark.parametrize("value,status", [("SENT", "OK"), ("FAILED", "FAILED"),
                                         ("REFUSED", "SKIPPED"), ("SKIPPED", "SKIPPED")])
def test_mail_return_status(value, status, fake, ctx):
    fake.values[playbooks.ACTIONS["notify_owner_email"]] = value
    results = playbooks.run("SUSPICIOUS_SUCCESS_LOGIN", "incident:12:CR-03", ctx)
    assert results[1]["status"] == status
    assert fake.calls[0][1] == (7,)
    assert fake.calls[1][1][:2] == (ctx["user_email"], ctx["ip"])
    assert datetime.fromisoformat(fake.calls[1][1][2]).tzinfo is not None


def test_net01_integration(monkeypatch, fake, ctx):
    monkeypatch.setattr(db, "get_recent_distinct_event_types", lambda *a: ["NET_SYN_FLOOD"])
    monkeypatch.setattr(db, "get_open_incident", lambda *a: None)
    monkeypatch.setattr(db, "list_recent_security_events_for_correlation", lambda *a: [], raising=False)
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: dict(id=12, matched_rules=[k["rule_id"]]))
    correlate.check_and_correlate(ctx["ip"], "NET_SYN_FLOOD", "HIGH", source="NET")
    assert [r[2] for r in fake.records] == ["block_l4_ttl", "notify_slack"]
    assert all(r[1] == "incident:12:NET-01" for r in fake.records)


def test_db_insert_and_export(monkeypatch):
    captured = []
    class Query:
        def table(self, name):
            assert name == "playbook_runs"
            return self
        def insert(self, row):
            captured.append(row)
            return self
        def execute(self):
            return SimpleNamespace(data=[])
    monkeypatch.setattr(db, "get_client", lambda: Query())
    playbook_runs.insert_playbook_run("NET_FLOOD", "incident:12:CR-02", "block_l4_ttl", "OK")
    assert captured == [dict(playbook="NET_FLOOD", trigger_ref="incident:12:CR-02",
                             step="block_l4_ttl", status="OK", error=None)]
    assert db.insert_playbook_run is playbook_runs.insert_playbook_run
    assert "insert_playbook_run" in playbook_runs.__all__
