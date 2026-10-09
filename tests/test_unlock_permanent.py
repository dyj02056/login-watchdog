# ============================================================================
# test_unlock_permanent.py — scripts/unlock_ip.py / unlock_account.py의 --permanent 옵션 (guide33)
#
# 영구 잠금은 --permanent가 있을 때만 lockdown.release()(대시보드 "영구 해제"와 같은 경로)로
# 풀리고, 없으면 건너뛰어야 한다. 옵션을 받고도 main()에서 안 넘기던 버그가 실제 E2E에서
# 발견돼서 main()의 인자 전달까지 검증한다.
# ============================================================================

import os
import sys

import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)

import db
from security import lockdown
import unlock_account  # noqa: E402
import unlock_ip  # noqa: E402

pytestmark = pytest.mark.real_lockdown


@pytest.fixture
def released(monkeypatch):
    log = []
    monkeypatch.setattr(lockdown, "release", lambda kind, value, actor, note: log.append((kind, value, actor, note)) or True)
    monkeypatch.setattr(db, "release_lockout", lambda ip: log.append(("temp-release", ip)))
    monkeypatch.setattr(db, "release_account_lockout", lambda u: log.append(("temp-release", u)))
    monkeypatch.setattr(db, "resolve_security_events_for_ip", lambda ip: None)
    monkeypatch.setattr(db, "resolve_security_events_for_username", lambda u: None)
    return log


def test_unlock_ip_skips_permanent_lock_without_the_option(monkeypatch, released, capsys):
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: {"lock_type": "PERMANENT", "failure_count": 6, "locked_at": "t"})

    assert unlock_ip.unlock_one("1.1.1.1") is False

    assert released == [] and "--permanent" in capsys.readouterr().out


def test_unlock_ip_releases_permanent_lock_through_lockdown_with_the_option(monkeypatch, released):
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: {"lock_type": "PERMANENT", "failure_count": 6, "locked_at": "t"})

    assert unlock_ip.unlock_one("1.1.1.1", permanent=True, note="긴급") is True

    assert released == [("ip", "1.1.1.1", "script:unlock_ip", "긴급")]


def test_unlock_ip_still_releases_temporary_lock_without_the_option(monkeypatch, released):
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: {"lock_type": "TEMPORARY", "failure_count": 6, "locked_at": "t"})

    assert unlock_ip.unlock_one("1.1.1.1") is True

    assert released == [("temp-release", "1.1.1.1")]


def test_unlock_account_skips_and_releases_permanent_lock_like_unlock_ip(monkeypatch, released):
    monkeypatch.setattr(db, "get_active_account_lockout", lambda u: {"lock_type": "PERMANENT", "failure_count": 9, "locked_at": "t"})

    assert unlock_account.unlock_one("alice") is False
    assert unlock_account.unlock_one("alice", permanent=True, note="n") is True

    assert released == [("account", "alice", "script:unlock_account", "n")]


def test_unlock_all_skips_permanent_rows_unless_option_given(released):
    rows = [{"ip_address": "1.1.1.1", "lock_type": "PERMANENT"}, {"ip_address": "2.2.2.2", "lock_type": "TEMPORARY"}]

    unlock_ip.unlock_all(rows)
    assert released == [("temp-release", "2.2.2.2")]

    released.clear()
    unlock_ip.unlock_all(rows, permanent=True, note="n")
    assert ("ip", "1.1.1.1", "script:unlock_ip", "n") in released


@pytest.mark.parametrize("module, flag, value, lister, locks", [
    (unlock_ip, "--ip", "1.1.1.1", "list_active_lockouts", [{"ip_address": "1.1.1.1", "lock_type": "PERMANENT", "locked_at": "t"}]),
    (unlock_account, "--username", "alice", "list_active_account_lockouts", [{"username": "alice", "lock_type": "PERMANENT", "locked_at": "t"}]),
])
def test_main_passes_permanent_option_through_to_the_release(monkeypatch, released, module, flag, value, lister, locks):
    getter = "get_active_lockout" if module is unlock_ip else "get_active_account_lockout"
    monkeypatch.setattr(db, getter, lambda key: {"lock_type": "PERMANENT", "failure_count": 1, "locked_at": "t"})
    monkeypatch.setattr(db, lister, lambda: locks)

    monkeypatch.setattr(sys, "argv", ["x", flag, value])
    module.main()
    assert released == []  # 옵션 없이는 영구 잠금을 풀지 않는다

    monkeypatch.setattr(sys, "argv", ["x", flag, value, "--permanent", "--note", "사유"])
    module.main()
    assert [entry[0] for entry in released] == ["ip" if module is unlock_ip else "account"]
    assert released[0][3] == "사유"

    released.clear()
    monkeypatch.setattr(sys, "argv", ["x", "--all", "--permanent"])
    module.main()
    assert len(released) == 1
