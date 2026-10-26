"""S4 판정이 "차단 요청"이 아니라 "실제 적용"까지 확인하는지 검사한다(10/26 강사 피드백 6).

예전 판정은 status=FAILED·applied_at 없음도 PASS로 냈다. 공격 컨테이너·DB 없이 check_common의
조회·실행 함수를 가짜로 바꿔 판정 규칙만 본다.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.net import check_common as cc
from scripts.net import check_s4

IP = "172.28.0.120"
OTHER = "172.28.0.121"
APPLIED_ROW = {
    "ip_address": IP, "evidence": "CONNECTED", "expires_at": None,
    "status": "APPLIED", "applied_at": "2026-10-26T06:40:40+00:00",
}


@pytest.fixture
def fake_cc(monkeypatch):
    """S4가 쓰는 check_common 함수를 가짜로 바꾸고, 바꿀 값을 담은 상태를 돌려준다."""
    state = SimpleNamespace(
        block=dict(APPLIED_ROW), fresh=[IP, OTHER],
        probes={IP: False, OTHER: True}, oneshots=[],
    )
    monkeypatch.setattr(cc, "choose_fresh_ip", lambda client, prefix: state.fresh.pop(0) if state.fresh else None)
    monkeypatch.setattr(cc, "run_oneshot", lambda template, ip, prefix, **k: state.oneshots.append(template[-1]))
    monkeypatch.setattr(cc, "network_block", lambda client, ip: state.block)
    monkeypatch.setattr(cc, "latest_incident_rules", lambda client, ip: ["CR-01"])
    monkeypatch.setattr(cc, "lockout", lambda client, ip: {"lock_type": "PERMANENT", "recoverable": "ADMIN_ONLY"})
    monkeypatch.setattr(cc, "probe_reachable", lambda ip, prefix: state.probes.get(ip))
    # 시간 초과 상황을 흉내 내려고 기다리지 않고 조건을 한 번만 본다.
    monkeypatch.setattr(cc, "wait_until", lambda condition, **k: condition() or None)
    return state


def _run():
    return check_s4.run(SimpleNamespace(client=None, prefix="172.28.0"))


def test_applied_block_and_probe_pass(fake_cc):
    result = _run()
    assert result.status == "PASS"
    assert OTHER in result.reason


def test_failed_block_without_applied_at_is_fail(fake_cc):
    # 피드백에서 짚은 상황: 요청은 있었지만 fw-agent가 적용하지 못함
    fake_cc.block.update(status="FAILED", applied_at=None, last_error="ipset add failed")
    result = _run()
    assert result.status == "FAIL"
    assert "APPLIED 아님(현재 FAILED, last_error=ipset add failed)" in result.reason
    assert "applied_at 없음" in result.reason


def test_pending_apply_after_timeout_is_fail(fake_cc):
    fake_cc.block.update(status="PENDING_APPLY", applied_at=None)
    assert _run().status == "FAIL"


def test_target_still_reachable_is_fail(fake_cc):
    # 장부는 APPLIED인데 ipset·iptables가 실제로 막지 못하는 경우
    fake_cc.probes[IP] = True
    result = _run()
    assert result.status == "FAIL"
    assert "막히지 않음" in result.reason


def test_other_ip_blocked_is_fail(fake_cc):
    fake_cc.probes[OTHER] = False
    result = _run()
    assert result.status == "FAIL"
    assert OTHER in result.reason


def test_with_release_checks_reconnect(fake_cc, monkeypatch):
    calls = []

    def fake_release(cmd, **kwargs):
        calls.append(cmd)
        fake_cc.block.update(status="REMOVED")
        fake_cc.probes[IP] = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(check_s4.subprocess, "run", fake_release)
    result = check_s4.run(SimpleNamespace(client=None, prefix="172.28.0", with_release=True))
    assert result.status == "PASS"
    assert "해제 후 재접속" in result.reason
    assert IP in calls[0] and "--permanent" in calls[0]


def test_with_release_still_blocked_is_fail(fake_cc, monkeypatch):
    def fake_release(cmd, **kwargs):
        fake_cc.block.update(status="REMOVED")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(check_s4.subprocess, "run", fake_release)
    result = check_s4.run(SimpleNamespace(client=None, prefix="172.28.0", with_release=True))
    assert result.status == "FAIL"
    assert "해제 후에도" in result.reason


def _load_lw():
    path = Path(__file__).resolve().parents[2] / "netwatch" / "attacker" / "lw.py"
    spec = importlib.util.spec_from_file_location("test_i_check_s4_lw", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_lw_probe_reports_reachable_and_blocked():
    lw = _load_lw()

    class Conn:
        closed = False

        def close(self):
            Conn.closed = True

    ok, code = lw.command_probe("172.28.0.10", 8080, "http://172.28.0.10:8080", 3, connect=lambda *a, **k: Conn())
    assert (ok["reachable"], code, Conn.closed) == (True, 0, True)

    def timeout(*a, **k):
        raise TimeoutError("timed out")

    blocked, code = lw.command_probe("172.28.0.10", 8080, "http://172.28.0.10:8080", 3, connect=timeout)
    assert (blocked["reachable"], blocked["error_kind"], code) == (False, "TimeoutError", 0)
