# ============================================================================
# tests/track_d/test_c_release_unblock.py — lockdown.release()가 L4 차단 해제도 요청하는지(C2-2)
#
# tests/test_unlock_permanent.py·test_permanent_lock.py처럼 db 함수와 alert를 "호출 기록용
# 가짜"로 바꾸고, netblock.request_unblock도 가짜로 바꿔 실제 DB에 접속하지 않게 한다.
# 실제 release() 본문을 시험해야 하므로 영구 잠금 기본 stub(autouse)을 끄는 real_lockdown 마커를 단다.
# ============================================================================

import pytest

import db
from notify import alert
from security import lockdown, netblock

pytestmark = pytest.mark.real_lockdown

IP = "203.0.113.40"
ACTOR = "admin:boss"


@pytest.fixture
def log(monkeypatch):
    """release()가 부르는 db/alert/netblock 함수를 가짜로 바꾸고 호출을 순서대로 기록한다."""
    calls = []
    monkeypatch.setattr(db, "release_permanent_lockout", lambda ip: True)
    monkeypatch.setattr(db, "release_permanent_account_lockout", lambda username: True)
    monkeypatch.setattr(db, "resolve_security_events_for_ip", lambda ip: calls.append(("resolve", ip)))
    monkeypatch.setattr(db, "resolve_security_events_for_username", lambda u: calls.append(("resolve", u)))
    monkeypatch.setattr(db, "mark_lock_released", lambda *a, **k: calls.append(("history", a)))
    monkeypatch.setattr(alert, "send_permanent_release_alert", lambda *a: calls.append(("alert", a)))
    monkeypatch.setattr(netblock, "request_unblock", lambda ip, actor: calls.append(("unblock", (ip, actor))) or True)
    return calls


def _unblocks(calls):
    return [args for name, args in calls if name == "unblock"]


def test_ip_release_requests_l4_unblock_once_before_alert(log):
    # (a) IP 해제 성공 → (IP, actor)로 한 번, Slack 알림보다 먼저
    assert lockdown.release("ip", IP, ACTOR, "오탐 확인") is True

    assert _unblocks(log) == [(IP, ACTOR)]
    names = [name for name, _ in log]
    assert names.index("unblock") < names.index("alert")


def test_account_release_does_not_request_l4_unblock(log):
    # (b) 계정 해제는 IP가 아니므로 L4 해제 요청 없음
    assert lockdown.release("account", "alice", ACTOR, "x") is True

    assert _unblocks(log) == []
    assert ("alert", ("account", "alice", ACTOR, "x")) in log


def test_unblock_exception_does_not_break_release(log, monkeypatch, capsys):
    # (c) request_unblock이 예외를 내도 release()는 True, 이력·Slack 알림도 그대로
    def boom(ip, actor):
        raise RuntimeError("network_blocks 접속 실패")

    monkeypatch.setattr(netblock, "request_unblock", boom)

    assert lockdown.release("ip", IP, ACTOR, "n") is True

    assert ("history", ("ip", IP, ACTOR, "n")) in log
    assert ("alert", ("ip", IP, ACTOR, "n")) in log
    assert "L4 차단 해제 요청 실패" in capsys.readouterr().out


def test_unblock_false_is_not_an_error(log, monkeypatch):
    # L4 차단이 원래 없던 IP(False)도 해제 흐름은 그대로 끝난다
    monkeypatch.setattr(netblock, "request_unblock", lambda ip, actor: False)

    assert lockdown.release("ip", IP, ACTOR, "n") is True
    assert ("alert", ("ip", IP, ACTOR, "n")) in log


def test_failed_release_does_not_request_l4_unblock(log, monkeypatch):
    # (d) 영구 잠금이 아니어서 해제 실패(False) → L4 해제 요청 없음
    monkeypatch.setattr(db, "release_permanent_lockout", lambda ip: False)

    assert lockdown.release("ip", IP, ACTOR, "x") is False

    assert _unblocks(log) == []
    assert not any(name == "alert" for name, _ in log)
