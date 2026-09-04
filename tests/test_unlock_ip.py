# ============================================================================
# test_unlock_ip.py — scripts/unlock_ip.py가 db.py를 올바른 조건으로 호출하는지
# 확인하는 단위 테스트
#
# test_soar.py와 같은 방식이다: 진짜 Supabase에 접속하는 대신, db.py의 함수를
# "호출된 사실만 기록하는 가짜 함수"로 바꿔치기(monkeypatch)해서 확인한다.
#
# unlock_ip.py는 scripts/ 폴더 안에 있어서 tests/ 쪽에서 그냥 "import unlock_ip"만
# 하면 파이썬이 파일을 못 찾는다(scripts/에 __init__.py가 없어서 패키지가 아님).
# 그래서 daily_report.py/unlock_ip.py가 프로젝트 루트를 sys.path에 추가하던 것과
# 똑같은 방식으로, 이번엔 scripts/ 폴더를 sys.path에 추가해서 import가 되게 한다.
# ============================================================================

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)

import db
import unlock_ip  # noqa: E402  (위 sys.path 추가 이후에 import 해야 함)


def test_show_active_lockouts_returns_empty_list_when_none_locked(monkeypatch, capsys):
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [])

    result = unlock_ip.show_active_lockouts()

    assert result == []
    assert "활성 잠금이 없습니다" in capsys.readouterr().out


def test_show_active_lockouts_returns_and_prints_each_ip(monkeypatch, capsys):
    lockouts = [
        {"ip_address": "1.1.1.1", "failure_count": 6, "locked_at": "t1", "unlock_at": "t2"},
        {"ip_address": "2.2.2.2", "failure_count": 7, "locked_at": "t3", "unlock_at": "t4"},
    ]
    monkeypatch.setattr(db, "list_active_lockouts", lambda: lockouts)

    result = unlock_ip.show_active_lockouts()

    assert result == lockouts
    out = capsys.readouterr().out
    assert "1.1.1.1" in out
    assert "2.2.2.2" in out


def test_unlock_one_returns_false_and_skips_release_when_not_locked(monkeypatch):
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: None)
    monkeypatch.setattr(db, "release_lockout", lambda ip: (_ for _ in ()).throw(
        AssertionError("잠긴 적 없는 IP인데 release_lockout이 호출되면 안 된다")
    ))

    result = unlock_ip.unlock_one("9.9.9.9")

    assert result is False


def test_unlock_one_releases_and_returns_true_when_locked(monkeypatch):
    monkeypatch.setattr(
        db, "get_active_lockout",
        lambda ip: {"ip_address": ip, "failure_count": 6, "locked_at": "t1"},
    )
    released = []
    monkeypatch.setattr(db, "release_lockout", lambda ip: released.append(ip))

    result = unlock_ip.unlock_one("127.0.0.1")

    assert result is True
    assert released == ["127.0.0.1"]


def test_unlock_all_releases_every_ip_in_order(monkeypatch):
    lockouts = [{"ip_address": "1.1.1.1"}, {"ip_address": "2.2.2.2"}]
    released = []
    monkeypatch.setattr(db, "release_lockout", lambda ip: released.append(ip))

    unlock_ip.unlock_all(lockouts)

    assert released == ["1.1.1.1", "2.2.2.2"]


def test_main_rejects_ip_and_all_together(monkeypatch):
    # --ip와 --all을 동시에 주면 db를 아예 건드리기 전에 argparse가 즉시
    # 종료(exit code 2)해야 한다 — 실수로 둘 다 넘겨서 예상 밖의 동작을 하는
    # 사고를 막기 위한 안전장치를 확인한다.
    monkeypatch.setattr(sys, "argv", ["unlock_ip.py", "--ip", "127.0.0.1", "--all"])
    monkeypatch.setattr(db, "list_active_lockouts", lambda: (_ for _ in ()).throw(
        AssertionError("인자 검증에서 걸러져야 하는데 db까지 호출됐다")
    ))

    try:
        unlock_ip.main()
        assert False, "SystemExit이 발생했어야 한다"
    except SystemExit as exc:
        assert exc.code == 2
