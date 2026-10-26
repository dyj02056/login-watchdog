"""fw-agent가 앱이 멈춘 동안에도 TTL 차단을 "정해진 시각"에 풀고, 형식이 틀린 목록을 빈 목록으로
받지 않는지 검사한다(10/26 강사 피드백 2, 추가 상황 "차단 목록 응답 형식").
"""

from __future__ import annotations

import pytest

from tests.track_d.test_c_fw_agent import FakeSession, fw_agent

LIST_CMD = ("ipset", "list", "lw_block", "-output", "save")


def _backend(present: str = ""):
    runner = fw_agent.FakeRunner({LIST_CMD: (0, present)})
    return runner, fw_agent.IptablesBackend(runner, set_name="lw_block")


def _adds(runner):
    return [call for call in runner.calls if call[:2] == ["ipset", "add"]]


def test_expired_ttl_is_not_re_added_while_app_is_down():
    # 10초 차단을 받은 뒤 앱이 멈췄고, 70초 뒤 커널이 이미 지운 상태에서 reconcile이 돈다.
    runner, backend = _backend()
    desired = {"1.2.3.4": 10}

    fw_agent.reconcile(desired, backend, allowlist=[], received_at=100.0, now=170.0)

    assert _adds(runner) == []
    assert desired == {}  # 다음 reconcile에서도 되살리지 않는다


def test_partially_elapsed_ttl_is_re_added_with_remaining_seconds():
    # 누가 손으로 지운 경우(drift)는 다시 넣되, 받은 남은 초가 아니라 "지금부터 남은 초"로 넣는다.
    runner, backend = _backend()
    desired = {"1.2.3.4": 600}

    fw_agent.reconcile(desired, backend, allowlist=[], received_at=100.0, now=130.5)

    assert _adds(runner) == [["ipset", "add", "lw_block", "1.2.3.4", "timeout", "570", "-exist"]]


def test_permanent_block_is_always_re_added():
    runner, backend = _backend()

    fw_agent.reconcile({"1.2.3.4": None}, backend, allowlist=[], received_at=100.0, now=10_000.0)

    assert _adds(runner) == [["ipset", "add", "lw_block", "1.2.3.4", "timeout", "0", "-exist"]]


@pytest.mark.parametrize("payload", [{}, {"generated_at": "2026-10-26T00:00:00Z"}, [], {"blocks": None}])
def test_malformed_blocks_response_raises(payload):
    client = fw_agent.AgentClient("http://app:5000", "test-agent-secret", session=FakeSession(payload))
    with pytest.raises(ValueError):
        client.get_blocks()


def test_real_empty_list_is_accepted():
    client = fw_agent.AgentClient("http://app:5000", "test-agent-secret",
                                  session=FakeSession({"generated_at": "x", "blocks": []}))
    assert client.get_blocks() == []
