# ============================================================================
# tests/track_d/test_c_fw_agent.py — fw-agent 단위 테스트 [작업 C1-3]
# ============================================================================

import importlib.util
from pathlib import Path
import pytest


def _load_fw_agent_module():
    file_path = Path(__file__).resolve().parents[2] / "netwatch" / "fw_agent" / "fw_agent.py"
    spec = importlib.util.spec_from_file_location("fw_agent", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fw_agent = _load_fw_agent_module()


class MockClient:
    def __init__(self):
        self.acks = []

    def ack(self, ip, status, error=None):
        self.acks.append((ip, status, error))
        return {"status": "ok"}


def test_sign_headers_matches_contract():
    secret = "test-key"
    timestamp = "1760930000"
    body = b'{"a":1}'
    headers = fw_agent.sign_headers(secret, body, timestamp=timestamp)

    assert headers["X-LW-Sender"] == "fw-agent"
    assert headers["X-LW-Timestamp"] == "1760930000"
    assert headers["X-LW-Signature"] == "2f744cec328f65506df5ad72df7fdd688c7a3cf3c6f90b1e0085849106179de2"


def test_sign_headers_matches_fixture(signed_headers):
    secret = "my-secret"
    body = b'{"hello":"world"}'
    ts = "100000"

    agent_h = fw_agent.sign_headers(secret, body, timestamp=ts)
    fixture_h = signed_headers("fw-agent", secret, body, timestamp=ts)

    assert agent_h == fixture_h


def test_process_blocks_pending_apply():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [
        {"ip_address": "1.2.3.4", "status": "PENDING_APPLY", "expires_at": None}
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[])

    assert desired == {"1.2.3.4": None}
    assert ("1.2.3.4", "APPLIED", None) in client.acks
    assert ["ipset", "add", "lw_block", "1.2.3.4", "timeout", "0", "-exist"] in runner.calls


def test_process_blocks_allowlisted_ip():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [
        {"ip_address": "127.0.0.1", "status": "PENDING_APPLY", "expires_at": None}
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=["127.0.0.1"])

    assert "127.0.0.1" not in desired
    assert ("127.0.0.1", "FAILED", "allowlisted") in client.acks
    assert len(runner.calls) == 0


def test_process_blocks_pending_remove():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [
        {"ip_address": "5.6.7.8", "status": "PENDING_REMOVE"}
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[])

    assert "5.6.7.8" not in desired
    assert ("5.6.7.8", "REMOVED", None) in client.acks
    assert ["ipset", "del", "lw_block", "5.6.7.8", "-exist"] in runner.calls


def test_reconcile_adds_missing_and_removes_extra():
    responses = {
        ("ipset", "list", "lw_block", "-output", "save"): (
            0,
            "add lw_block 1.1.1.1\nadd lw_block 9.9.9.9\n"
        )
    }
    runner = fw_agent.FakeRunner(responses)
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")

    desired = {"1.1.1.1": None, "2.2.2.2": 3600}
    fw_agent.reconcile(desired, backend, allowlist=["9.9.9.9"])

    # 9.9.9.9은 허용목록/desired에 없어 del
    assert ["ipset", "del", "lw_block", "9.9.9.9", "-exist"] in runner.calls
    # 2.2.2.2는 빠져있어 add
    assert ["ipset", "add", "lw_block", "2.2.2.2", "timeout", "3600", "-exist"] in runner.calls