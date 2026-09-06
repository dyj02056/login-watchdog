# ============================================================================
# test_soar.py — soar.py(집행관 역할)가 db.py / alert.py를 올바른 순서와
# 조건으로 호출하는지 확인하는 단위 테스트
#
# 여기서 확인하고 싶은 건 "정말로 Slack에 메시지가 갔는가"가 아니라
# "soar.py가 db.create_lockout과 alert.send_lockout_alert를 올바르게,
# 올바른 값으로, 올바른 순서로 호출하는가"이다. 그래서 진짜 함수 대신
# "호출된 사실을 기록만 해두는 가짜 함수"로 바꿔치기해서 확인한다.
# ============================================================================

import alert
import db
import soar


def test_enforce_lockout_creates_lockout_then_sends_alert(monkeypatch):
    calls = []  # 호출된 순서를 기록해둘 리스트

    def fake_create_lockout(ip, failure_count):
        calls.append(("create_lockout", ip, failure_count))

    def fake_send_lockout_alert(ip, failure_count, locked_at, distinct_usernames):
        calls.append(("send_lockout_alert", ip, failure_count, distinct_usernames))

    monkeypatch.setattr(db, "create_lockout", fake_create_lockout)
    monkeypatch.setattr(alert, "send_lockout_alert", fake_send_lockout_alert)

    soar.enforce_lockout("9.9.9.9", 6, 2)

    # 두 함수가 다 호출됐는지, 그리고 "잠그기 → 알리기" 순서가 지켜졌는지,
    # distinct_usernames가 그대로 alert.py까지 전달됐는지 확인.
    assert calls == [
        ("create_lockout", "9.9.9.9", 6),
        ("send_lockout_alert", "9.9.9.9", 6, 2),
    ]


def test_try_release_expired_lockouts_releases_each_expired_ip(monkeypatch):
    expired = [{"ip_address": "1.1.1.1"}, {"ip_address": "2.2.2.2"}]
    released = []

    monkeypatch.setattr(db, "list_expired_active_lockouts", lambda: expired)
    monkeypatch.setattr(db, "release_lockout", lambda ip: released.append(ip))

    soar.try_release_expired_lockouts()

    # 만료된 IP 두 개가 각각 한 번씩, 빠짐없이 풀렸는지 확인.
    assert released == ["1.1.1.1", "2.2.2.2"]


def test_try_release_expired_lockouts_does_nothing_when_none_expired(monkeypatch):
    monkeypatch.setattr(db, "list_expired_active_lockouts", lambda: [])
    monkeypatch.setattr(db, "release_lockout", lambda ip: (_ for _ in ()).throw(
        AssertionError("풀어줄 게 없는데 release_lockout이 호출되면 안 된다")
    ))

    soar.try_release_expired_lockouts()  # 예외가 안 나면 통과


def test_manual_release_returns_true_when_ip_is_locked(monkeypatch):
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [{"ip_address": "5.5.5.5"}])
    released_ip = {}
    monkeypatch.setattr(db, "release_lockout", lambda ip: released_ip.setdefault("ip", ip))

    result = soar.manual_release("5.5.5.5")

    assert result is True
    assert released_ip["ip"] == "5.5.5.5"


def test_manual_release_returns_false_when_ip_not_locked(monkeypatch):
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [{"ip_address": "5.5.5.5"}])
    monkeypatch.setattr(db, "release_lockout", lambda ip: (_ for _ in ()).throw(
        AssertionError("잠긴 적 없는 IP인데 release_lockout이 호출되면 안 된다")
    ))

    result = soar.manual_release("6.6.6.6")  # 잠긴 목록(5.5.5.5)에 없는 IP

    assert result is False
