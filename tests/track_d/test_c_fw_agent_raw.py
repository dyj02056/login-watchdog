"""fw-agent가 연결 추적 전(raw PREROUTING)에도 DROP 규칙을 거는지 검증한다.

raw 규칙은 연결 추적보다 앞에서 버려 차단된 IP의 패킷마다 하던 연결 추적 처리를 건너뛰고,
INPUT 규칙은 예비로 남는다. 실제 iptables 없이 FakeRunner로 부른 명령 순서만 확인한다.
"""

import importlib.util
from pathlib import Path


_PATH = Path(__file__).resolve().parents[2] / "netwatch" / "fw_agent" / "fw_agent.py"
_spec = importlib.util.spec_from_file_location("fw_agent_raw_under_test", _PATH)
fw_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fw_agent)

RAW_CHECK = ("iptables", "-t", "raw", "-C", "PREROUTING", "-m", "set", "--match-set", "lw_block", "src", "-j", "DROP")
RAW_INSERT = ("iptables", "-t", "raw", "-I", "PREROUTING", "1", "-m", "set", "--match-set", "lw_block", "src", "-j", "DROP")
INPUT_CHECK = ("iptables", "-C", "INPUT", "-m", "set", "--match-set", "lw_block", "src", "-j", "DROP")


def test_raw_rule_inserted_before_input_rule_when_missing():
    runner = fw_agent.FakeRunner({RAW_CHECK: (1, "missing"), INPUT_CHECK: (1, "missing")})
    fw_agent.IptablesBackend(runner, set_name="lw_block").ensure_ready()

    calls = [tuple(call) for call in runner.calls]
    assert RAW_INSERT in calls
    input_insert = next(i for i, c in enumerate(calls) if c[:4] == ("iptables", "-I", "INPUT", "1"))
    assert calls.index(RAW_INSERT) < input_insert


def test_raw_rule_not_duplicated_when_present():
    runner = fw_agent.FakeRunner()  # -C 성공 = 이미 있음
    fw_agent.IptablesBackend(runner, set_name="lw_block").ensure_ready()

    assert RAW_CHECK in [tuple(call) for call in runner.calls]
    assert RAW_INSERT not in [tuple(call) for call in runner.calls]


def test_raw_rule_failure_does_not_stop_startup(capsys):
    runner = fw_agent.FakeRunner({
        RAW_CHECK: (1, "missing"),
        RAW_INSERT: (1, "can't initialize iptables table `raw'"),
        INPUT_CHECK: (1, "missing"),
    })
    fw_agent.IptablesBackend(runner, set_name="lw_block").ensure_ready()  # 예외 없이 끝나야 한다

    assert runner.calls[-1][:4] == ["iptables", "-I", "INPUT", "1"]
    assert "raw PREROUTING" in capsys.readouterr().out
