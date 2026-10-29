"""guide57 fw-agent 보완 — 대역 밖·인프라 주소 거부, ICMP 속도 제한 체인(LW_L3), 규칙 점검.

실제 iptables 없이 FakeRunner로 부른 명령과 돌려준 결과만 확인한다.
"""

import importlib.util
import ipaddress
from pathlib import Path


_PATH = Path(__file__).resolve().parents[2] / "netwatch" / "fw_agent" / "fw_agent.py"
_spec = importlib.util.spec_from_file_location("fw_agent_guide57_under_test", _PATH)
fw_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fw_agent)

EDGE = ipaddress.ip_network("172.28.13.0/24")
MATCH = ["-m", "set", "--match-set", "lw_block", "src", "-j", "DROP"]


class MockClient:
    def __init__(self):
        self.acks = []

    def ack(self, ip, status, error=None, version=None):
        self.acks.append((ip, status, error))


# ---------------------------------------------------------------------------
# 대역 밖·인프라 주소 거부
# ---------------------------------------------------------------------------

def test_refusal_reasons():
    assert fw_agent._refusal_reason("172.30.0.4", None) == "infrastructure"
    assert fw_agent._refusal_reason("172.30.0.4", EDGE) == "infrastructure"
    assert fw_agent._refusal_reason("172.28.13.10", EDGE) == "infrastructure"
    assert fw_agent._refusal_reason("172.28.12.101", EDGE) == "out_of_subnet"
    assert fw_agent._refusal_reason("172.28.13.101", EDGE) is None
    # 대역을 모르면 core만 거부한다.
    assert fw_agent._refusal_reason("172.28.12.101", None) is None


def test_process_blocks_refuses_core_and_out_of_subnet():
    runner = fw_agent.FakeRunner()
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    client = MockClient()
    blocks = [
        {"ip": "172.30.0.4", "status": "PENDING_APPLY", "ttl_seconds": 60},
        {"ip": "172.28.12.101", "status": "PENDING_APPLY", "ttl_seconds": 60},
        {"ip": "172.28.13.10", "status": "APPLIED", "ttl_seconds": None},
        {"ip": "172.28.13.101", "status": "PENDING_APPLY", "ttl_seconds": 60},
    ]
    desired = fw_agent.process_blocks(blocks, backend, client, allowlist=[], edge_network=EDGE)

    assert desired == {"172.28.13.101": 60}
    assert ("172.30.0.4", "FAILED", "infrastructure") in client.acks
    assert ("172.28.12.101", "FAILED", "out_of_subnet") in client.acks
    assert ("172.28.13.101", "APPLIED", None) in client.acks
    added = [call[3] for call in runner.calls if call[:2] == ["ipset", "add"]]
    assert added == ["172.28.13.101"]


def test_reconcile_removes_refused_ips_already_in_set():
    responses = {("ipset", "list", "lw_block", "-output", "save"): (0, "add lw_block 172.30.0.4\nadd lw_block 172.28.13.101\n")}
    runner = fw_agent.FakeRunner(responses)
    backend = fw_agent.IptablesBackend(runner, set_name="lw_block")
    fw_agent.reconcile({"172.30.0.4": None, "172.28.13.101": None}, backend, allowlist=[], edge_network=EDGE)

    assert ["ipset", "del", "lw_block", "172.30.0.4", "-exist"] in runner.calls
    assert ["ipset", "del", "lw_block", "172.28.13.101", "-exist"] not in runner.calls


def test_edge_network_from_env():
    assert fw_agent._edge_network_from_env("172.28.13.0/24") == EDGE
    assert fw_agent._edge_network_from_env("") is None
    assert fw_agent._edge_network_from_env("not-a-net") is None


# ---------------------------------------------------------------------------
# LW_L3 체인
# ---------------------------------------------------------------------------

def _l3_check(rule):
    return ("iptables", "-t", "raw", "-C", "LW_L3", *rule)


def test_ensure_l3_builds_chain_in_order_when_missing():
    responses = {("iptables", "-t", "raw", "-L", "LW_L3", "-n"): (1, "No chain")}
    for rule in fw_agent._L3_RULES:
        responses[_l3_check(rule)] = (1, "missing")
    responses[("iptables", "-t", "raw", "-C", *fw_agent._L3_JUMP)] = (1, "missing")
    runner = fw_agent.FakeRunner(responses)

    assert fw_agent.IptablesBackend(runner, set_name="lw_block").ensure_l3() is True

    calls = [tuple(call) for call in runner.calls]
    assert ("iptables", "-t", "raw", "-N", "LW_L3") in calls
    appended = [call[5:] for call in calls if call[:5] == ("iptables", "-t", "raw", "-A", "LW_L3")]
    assert appended == [tuple(rule) for rule in fw_agent._L3_RULES]
    assert ("iptables", "-t", "raw", "-A", *fw_agent._L3_JUMP) in calls
    # 출발지별 제한 → 전체 제한 → 나머지 DROP 순서
    assert "hashlimit" in fw_agent._L3_RULES[0] and fw_agent._L3_RULES[1][-1] == "RETURN"


def test_ensure_l3_leaves_existing_chain_untouched():
    runner = fw_agent.FakeRunner()  # 모든 -L·-C 성공 = 이미 있음
    assert fw_agent.IptablesBackend(runner, set_name="lw_block").ensure_l3() is True
    assert not any(call[3] in ("-N", "-F", "-A") for call in runner.calls if call[:3] == ["iptables", "-t", "raw"])


def test_ensure_l3_failure_returns_false_without_raising(capsys):
    responses = {
        ("iptables", "-t", "raw", "-L", "LW_L3", "-n"): (1, "No chain"),
        ("iptables", "-t", "raw", "-N", "LW_L3"): (1, "can't initialize iptables table `raw'"),
    }
    runner = fw_agent.FakeRunner(responses)
    assert fw_agent.IptablesBackend(runner, set_name="lw_block").ensure_l3() is False
    assert "ICMP" in capsys.readouterr().out


def test_jump_skips_core_network():
    assert fw_agent._L3_JUMP[:5] == ["PREROUTING", "-p", "icmp", "!", "-s"]
    assert fw_agent._L3_JUMP[5] == "172.30.0.0/24"


# ---------------------------------------------------------------------------
# 규칙 점검과 ICMP 카운터
# ---------------------------------------------------------------------------

def test_check_rules_reports_missing_input_rule():
    runner = fw_agent.FakeRunner({("iptables", "-C", "INPUT", *MATCH): (1, "missing")})
    rules = fw_agent.IptablesBackend(runner, set_name="lw_block").check_rules()
    assert rules == {"input": False, "raw": True, "l3": True}


def test_check_rules_reports_missing_l3_rule():
    runner = fw_agent.FakeRunner({_l3_check(fw_agent._L3_RULES[2]): (1, "missing")})
    rules = fw_agent.IptablesBackend(runner, set_name="lw_block").check_rules()
    assert rules == {"input": True, "raw": True, "l3": False}


def test_icmp_dropped_total_sums_drop_counters():
    listing = (
        "Chain LW_L3 (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "     120     10080 DROP       icmp --  *      *       0.0.0.0/0            0.0.0.0/0  limit: above 50/sec\n"
        "    4000    336000 RETURN     icmp --  *      *       0.0.0.0/0            0.0.0.0/0  limit: avg 2000/sec\n"
        "      30      2520 DROP       icmp --  *      *       0.0.0.0/0            0.0.0.0/0\n"
    )
    runner = fw_agent.FakeRunner({("iptables", "-t", "raw", "-L", "LW_L3", "-v", "-x", "-n"): (0, listing)})
    assert fw_agent.IptablesBackend(runner, set_name="lw_block").icmp_dropped_total() == 150


def test_icmp_dropped_total_zero_when_chain_missing():
    runner = fw_agent.FakeRunner({("iptables", "-t", "raw", "-L", "LW_L3", "-v", "-x", "-n"): (1, "No chain")})
    assert fw_agent.IptablesBackend(runner, set_name="lw_block").icmp_dropped_total() == 0
