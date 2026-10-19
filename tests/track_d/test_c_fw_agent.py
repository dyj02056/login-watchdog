# ============================================================================
# tests/track_d/test_c_fw_agent.py — fw-agent 단위 테스트 [작업 C1-3]
#
# netwatch/fw_agent는 다른 컨테이너용 프로그램이라 패키지가 아니므로 파일 경로로 불러온다.
# 실제 ipset·iptables·앱 API는 부르지 않는다 — FakeRunner(명령 기록)와 가짜 client/session을 쓴다.
# 목록 항목의 모양은 계약서 K9 ①({"ip", "status", "ttl_seconds"})을 따른다.
# ============================================================================

import importlib.util
import json
from pathlib import Path


def _load_fw_agent_module():
    file_path = Path(__file__).resolve().parents[2] / "netwatch" / "fw_agent" / "fw_agent.py"
    spec = importlib.util.spec_from_file_location("fw_agent", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fw_agent = _load_fw_agent_module()


class MockClient:
    """process_blocks가 보낸 ack를 기록만 하는 가짜. fail_statuses에 든 상태는 전송 실패를 흉내 낸다."""

    def __init__(self, fail_statuses=()):
        self.acks = []
        self.fail_statuses = set(fail_statuses)

    def ack(self, ip, status, error=None):
        self.acks.append((ip, status, error))
        if status in self.fail_statuses:
            raise ConnectionError("app down")
        return {"changed": True}


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeSession:
    """requests.Session 대신 쓰는 가짜. 보낸 주소·본문·헤더를 기록한다."""

    def __init__(self, payload=None):
        self.calls = []
        self.payload = payload if payload is not None else {"ok": True}

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url, b"", headers, timeout))
        return _FakeResponse(self.payload)

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(("POST", url, data, headers, timeout))
        return _FakeResponse(self.payload)


# ---------------------------------------------------------------------------
# 서명 (K3)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# AgentClient — 계약서 K9 주소·본문 모양
# ---------------------------------------------------------------------------

def test_client_get_blocks_signs_empty_body():
    session = FakeSession({"generated_at": "2026-10-20T03:12:46Z", "blocks": [{"ip": "1.2.3.4", "status": "APPLIED", "ttl_seconds": None}]})
    client = fw_agent.AgentClient("http://app:5000/", "test-agent-secret", session=session)

    blocks = client.get_blocks()

    method, url, _, headers, timeout = session.calls[0]
    assert method == "GET"
    assert url == "http://app:5000/api/internal/blocks"
    assert timeout == 3
    expected = fw_agent.sign_headers("test-agent-secret", b"", timestamp=headers["X-LW-Timestamp"])
    assert headers["X-LW-Signature"] == expected["X-LW-Signature"]
    assert blocks == [{"ip": "1.2.3.4", "status": "APPLIED", "ttl_seconds": None}]


def test_client_ack_posts_contract_body():
    session = FakeSession({"changed": True})
    client = fw_agent.AgentClient("http://app:5000", "test-agent-secret", session=session)

    client.ack("1.2.3.4", "APPLIED")

    method, url, data, headers, _ = session.calls[0]
    assert method == "POST"
    assert url == "http://app:5000/api/internal/blocks/ack"
    assert json.loads(data) == {"ip": "1.2.3.4", "status": "APPLIED", "error": None}
    # 보낸 바이트 그대로 서명했는지(K3)
    expected = fw_agent.sign_headers("test-agent-secret", data, timestamp=headers["X-LW-Timestamp"])
    assert headers["X-LW-Signature"] == expected["X-LW-Signature"]


def test_client_ack_truncates_long_error():
    session = FakeSession({"changed": True})
    client = fw_agent.AgentClient("http://app:5000", "test-agent-secret", session=session)

    client.ack("1.2.3.4", "FAILED", "x" * 900)

    body = json.loads(session.calls[0][2])
    assert len(body["error"]) == 500


def test_client_heartbeat_wraps_detail_with_agent():
    session = FakeSession({"ok": True})
    client = fw_agent.AgentClient("http://app:5000", "test-agent-secret", session=session)

    client.heartbeat({"poll_failures": 0, "ipset_size": 2})

    _, url, data, headers, _ = session.calls[0]
    assert url == "http://app:5000/api/internal/heartbeat"
    assert json.loads(data) == {"agent": "fw-agent", "detail": {"poll_failures": 0, "ipset_size": 2}}
    assert headers["X-LW-Sender"] == "fw-agent"


# ---------------------------------------------------------------------------
# process_blocks
# ---------------------------------------------------------------------------

def test_process_blocks_pending_apply():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [
        {"ip": "1.2.3.4", "status": "PENDING_APPLY", "ttl_seconds": None}
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[])

    assert desired == {"1.2.3.4": None}
    assert ("1.2.3.4", "APPLIED", None) in client.acks
    # 영구(ttl None)는 timeout 0
    assert ["ipset", "add", "lw_block", "1.2.3.4", "timeout", "0", "-exist"] in runner.calls


def test_process_blocks_pending_apply_uses_remaining_ttl():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [{"ip": "1.2.3.5", "status": "PENDING_APPLY", "ttl_seconds": 3600}]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[])

    assert desired == {"1.2.3.5": 3600}
    assert ["ipset", "add", "lw_block", "1.2.3.5", "timeout", "3600", "-exist"] in runner.calls


def test_process_blocks_rejects_zero_ttl_instead_of_permanent():
    """ttl_seconds=0이 그대로 ipset timeout 0(영구)이 되면 안 된다."""
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [{"ip": "1.2.3.6", "status": "PENDING_APPLY", "ttl_seconds": 0}]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[])

    assert desired == {}
    assert runner.calls == []
    assert client.acks[0][1] == "FAILED"


def test_process_blocks_allowlisted_ip():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [
        {"ip": "127.0.0.1", "status": "PENDING_APPLY", "ttl_seconds": None}
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=["127.0.0.1"])

    assert "127.0.0.1" not in desired
    assert ("127.0.0.1", "FAILED", "allowlisted") in client.acks
    assert len(runner.calls) == 0


def test_process_blocks_allowlist_accepts_cidr_entry():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [{"ip": "172.28.0.1", "status": "PENDING_APPLY", "ttl_seconds": None}]
    fw_agent.process_blocks(blocks, backend, client, allowlist=["172.28.0.0/30", "bad-entry"])

    assert runner.calls == []
    assert ("172.28.0.1", "FAILED", "allowlisted") in client.acks


def test_process_blocks_pending_remove():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [
        {"ip": "5.6.7.8", "status": "PENDING_REMOVE", "ttl_seconds": None}
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[])

    assert "5.6.7.8" not in desired
    assert ("5.6.7.8", "REMOVED", None) in client.acks
    assert ["ipset", "del", "lw_block", "5.6.7.8", "-exist"] in runner.calls


def test_process_blocks_add_failure_acks_failed():
    responses = {("ipset", "add", "lw_block", "1.2.3.7", "timeout", "0", "-exist"): (1, "no such set")}
    runner = fw_agent.FakeRunner(responses)
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    desired = fw_agent.process_blocks(
        [{"ip": "1.2.3.7", "status": "PENDING_APPLY", "ttl_seconds": None}], backend, client, allowlist=[]
    )

    assert desired == {}
    assert client.acks[0][0:2] == ("1.2.3.7", "FAILED")
    assert "no such set" in client.acks[0][2]


def test_process_blocks_ack_failure_keeps_block_and_does_not_report_failed():
    """ipset add는 성공했는데 ack 전송만 실패하면 FAILED를 보내지 않고 desired에 남긴다."""
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient(fail_statuses={"APPLIED"})

    desired = fw_agent.process_blocks(
        [{"ip": "1.2.3.8", "status": "PENDING_APPLY", "ttl_seconds": 600}], backend, client, allowlist=[]
    )

    assert desired == {"1.2.3.8": 600}
    assert [a[1] for a in client.acks] == ["APPLIED"]


def test_process_blocks_skips_invalid_ip_and_continues():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()

    blocks = [
        {"ip": "1.2.3.4; rm -rf /", "status": "PENDING_APPLY", "ttl_seconds": None},
        {"ip": "2001:db8::1", "status": "PENDING_APPLY", "ttl_seconds": None},
        {"ip": "9.9.9.9", "status": "APPLIED", "ttl_seconds": 120},
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[])

    assert desired == {"9.9.9.9": 120}
    assert runner.calls == []
    assert client.acks == []


# ---------------------------------------------------------------------------
# reconcile
# ---------------------------------------------------------------------------

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


def test_reconcile_skips_before_first_successful_poll():
    """시작 직후 앱이 응답하지 않아 목록을 못 받았으면(None) 기존 차단을 지우지 않는다."""
    responses = {("ipset", "list", "lw_block", "-output", "save"): (0, "add lw_block 1.1.1.1\n")}
    runner = fw_agent.FakeRunner(responses)
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")

    fw_agent.reconcile(None, backend, allowlist=[])

    assert runner.calls == []


# ---------------------------------------------------------------------------
# IptablesBackend.ensure_ready
# ---------------------------------------------------------------------------

def test_ensure_ready_inserts_rule_only_when_missing():
    check = ("iptables", "-C", "INPUT", "-m", "set", "--match-set", "lw_block", "src", "-j", "DROP")
    runner = fw_agent.FakeRunner({check: (1, "rule missing")})
    fw_agent.IptablesBackend(runner, set_name="lw_block").ensure_ready()
    assert runner.calls[0] == ["ipset", "create", "lw_block", "hash:ip", "timeout", "0", "-exist"]
    assert runner.calls[-1][:4] == ["iptables", "-I", "INPUT", "1"]

    runner2 = fw_agent.FakeRunner()  # -C 성공 = 이미 있음
    fw_agent.IptablesBackend(runner2, set_name="lw_block").ensure_ready()
    assert not any(call[:2] == ["iptables", "-I"] for call in runner2.calls)
