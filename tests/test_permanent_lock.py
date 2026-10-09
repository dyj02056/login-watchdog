# ============================================================================
# test_permanent_lock.py — 영구 잠금(guide33)의 승격·해제·DB 보호 로직 단위 테스트
#
# security/lockdown.py(승격/해제 본체), security/soar/·security/correlate.py의 연결 지점, db/lockouts.py·
# db/account_lockouts.py의 "영구 잠금 보호"를 확인한다. 다른 테스트들과 같은 방식으로
# 진짜 Supabase 대신 db/alert 함수를 "호출 기록용 가짜"로 바꿔치기한다.
#
# 이 파일은 conftest.py의 영구 잠금 기본 stub(autouse)을 꺼야 실제 함수를 테스트할 수
# 있어서 real_lockdown 마커를 단다.
# ============================================================================

import types

import pytest

import config
import db
from notify import alert
from security import correlate, detector, lockdown, soar

pytestmark = pytest.mark.real_lockdown


# ---------------------------------------------------------------------------
# 공용 준비물: 호출을 기록하는 가짜 db/alert
# ---------------------------------------------------------------------------

@pytest.fixture
def calls(monkeypatch):
    """lockdown이 부르는 db/alert/correlate 함수를 전부 가짜로 바꾸고, 호출을 순서대로 기록한다."""
    log = []

    def record(name, result=None):
        def fake(*args, **kwargs):
            log.append((name, args, kwargs))
            return result

        return fake

    monkeypatch.setattr(db, "insert_lock_history", record("insert_lock_history"))
    monkeypatch.setattr(db, "insert_security_event", record("insert_security_event"))
    monkeypatch.setattr(db, "promote_lockout_permanent", record("promote_lockout_permanent", True))
    monkeypatch.setattr(db, "promote_account_lockout_permanent", record("promote_account_lockout_permanent", True))
    monkeypatch.setattr(db, "get_user_by_username", lambda username: {"id": 7, "username": username})
    monkeypatch.setattr(db, "get_account_lockout_row", lambda username: {})
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 0)
    monkeypatch.setattr(alert, "send_permanent_lock_alert", record("send_permanent_lock_alert"))
    monkeypatch.setattr(correlate, "check_and_correlate", record("check_and_correlate"))
    return log


def names(log):
    return [entry[0] for entry in log]


# ---------------------------------------------------------------------------
# after_temporary_lock — T1 / T2 / T5
# ---------------------------------------------------------------------------

def test_ip_below_strike_count_only_records_history(calls, monkeypatch):
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: config.PERMANENT_LOCK_STRIKE_COUNT - 1)

    lockdown.after_temporary_lock("ip", "9.9.9.9", "BRUTE_FORCE", 6)

    assert names(calls) == ["insert_lock_history"]
    assert calls[0][1] == ("ip", "9.9.9.9", "TEMPORARY", "THRESHOLD", "BRUTE_FORCE")


def test_ip_at_strike_count_promotes_to_permanent_with_exemption_recovery(calls, monkeypatch):
    seen = {}

    def fake_count(kind, value, days, event_types=None):
        seen["args"] = (kind, value, days, event_types)
        return config.PERMANENT_LOCK_STRIKE_COUNT

    monkeypatch.setattr(db, "count_lock_history", fake_count)

    lockdown.after_temporary_lock("ip", "9.9.9.9", "BRUTE_FORCE", 6)

    # 일반 로그인 잠금끼리만 센다(관리자 로그인 잠금은 따로 센다)
    assert seen["args"] == ("ip", "9.9.9.9", config.PERMANENT_LOCK_STRIKE_WINDOW_DAYS, ["BRUTE_FORCE", "PASSWORD_SPRAYING"])
    assert names(calls) == [
        "insert_lock_history",            # 임시 잠금 이력
        "promote_lockout_permanent",      # 조건부 승격
        "insert_lock_history",            # 영구 승격 이력
        "insert_security_event",          # PERMANENT_LOCK(CRITICAL) 이벤트
        "check_and_correlate",            # 상관분석으로 전달
        "send_permanent_lock_alert",
    ]
    assert calls[1][1][:3] == ("9.9.9.9", "REPEAT_OFFENDER", "EXEMPTION")
    assert calls[3][1][:2] == ("PERMANENT_LOCK", "CRITICAL")
    assert calls[4][1] == ("9.9.9.9", "PERMANENT_LOCK", "CRITICAL")


def test_admin_login_lockout_promotes_with_admin_only_recovery(calls, monkeypatch):
    seen = {}

    def fake_count(kind, value, days, event_types=None):
        seen["event_types"] = event_types
        return config.PERMANENT_LOCK_STRIKE_COUNT

    monkeypatch.setattr(db, "count_lock_history", fake_count)

    lockdown.after_temporary_lock("ip", "9.9.9.9", "ADMIN_BRUTE_FORCE", 6)

    assert seen["event_types"] == ["ADMIN_BRUTE_FORCE"]
    promote = next(c for c in calls if c[0] == "promote_lockout_permanent")
    assert promote[1][:3] == ("9.9.9.9", "REPEAT_OFFENDER", "ADMIN_ONLY")


def test_allowlisted_ip_is_never_promoted(calls, monkeypatch):
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 99)

    lockdown.after_temporary_lock("ip", "127.0.0.1", "BRUTE_FORCE", 6)

    assert "promote_lockout_permanent" not in names(calls)
    assert "send_permanent_lock_alert" not in names(calls)


def test_promotion_that_changes_nothing_sends_no_event_or_alert(calls, monkeypatch):
    # 이미 영구 잠금이라 DB가 0행을 돌려주면(False) 이력/이벤트/알림이 다시 나가면 안 된다.
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 5)
    monkeypatch.setattr(db, "promote_lockout_permanent", lambda *a, **k: False)

    lockdown.after_temporary_lock("ip", "9.9.9.9", "BRUTE_FORCE", 6)

    assert names(calls) == ["insert_lock_history"]


def test_account_at_strike_count_promotes_with_self_recovery(calls, monkeypatch):
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: config.PERMANENT_LOCK_ACCOUNT_STRIKE_COUNT)

    lockdown.after_temporary_lock("account", "alice", "DISTRIBUTED_BRUTE_FORCE", 9, triggering_ip="8.8.8.8")

    promote = next(c for c in calls if c[0] == "promote_account_lockout_permanent")
    assert promote[1][:3] == ("alice", "REPEAT_OFFENDER", "SELF")
    # 계정 이벤트는 상관분석에 보내지 않는다(무관한 IP가 사건에 섞이는 것을 막는다)
    assert "check_and_correlate" not in names(calls)
    event = next(c for c in calls if c[0] == "insert_security_event")
    assert event[2] == {"username": "alice"}


def test_account_that_does_not_exist_is_not_promoted(calls, monkeypatch):
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 99)
    monkeypatch.setattr(db, "get_user_by_username", lambda username: None)

    lockdown.after_temporary_lock("account", "ghost", "DISTRIBUTED_BRUTE_FORCE", 9)

    assert "promote_account_lockout_permanent" not in names(calls)


def test_account_with_undeliverable_email_is_promoted_as_admin_only(calls, monkeypatch):
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 99)
    monkeypatch.setattr(
        db, "get_user_by_username", lambda username: {"id": 7, "username": username, "email_status": "UNDELIVERABLE"}
    )

    lockdown.after_temporary_lock("account", "alice", "DISTRIBUTED_BRUTE_FORCE", 9)

    promote = next(c for c in calls if c[0] == "promote_account_lockout_permanent")
    assert promote[1][:3] == ("alice", "REPEAT_OFFENDER", "ADMIN_ONLY")


def test_account_relocked_during_probation_is_promoted_as_admin_only_even_below_strike_count(calls, monkeypatch):
    from datetime import datetime, timedelta, timezone

    future = (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()
    monkeypatch.setattr(db, "get_account_lockout_row", lambda username: {"probation_until": future})
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 1)

    lockdown.after_temporary_lock("account", "alice", "DISTRIBUTED_BRUTE_FORCE", 9)

    promote = next(c for c in calls if c[0] == "promote_account_lockout_permanent")
    assert promote[1][:3] == ("alice", "REPEAT_OFFENDER", "ADMIN_ONLY")


def test_account_relocked_after_probation_ended_is_not_promoted_below_strike_count(calls, monkeypatch):
    from datetime import datetime, timedelta, timezone

    past = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    monkeypatch.setattr(db, "get_account_lockout_row", lambda username: {"probation_until": past})
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 1)

    lockdown.after_temporary_lock("account", "alice", "DISTRIBUTED_BRUTE_FORCE", 9)

    assert "promote_account_lockout_permanent" not in names(calls)


# ---------------------------------------------------------------------------
# security/soar/ 연결 — 임시 잠금 직후 lockdown 호출, manual_release의 영구 잠금 보호
# ---------------------------------------------------------------------------

def test_enforce_lockout_hands_over_to_lockdown_after_event_is_recorded(monkeypatch):
    order = []
    monkeypatch.setattr(db, "create_lockout", lambda ip, count: order.append("create_lockout"))
    monkeypatch.setattr(alert, "send_lockout_alert", lambda *a, **k: order.append("alert"))
    monkeypatch.setattr(db, "insert_security_event", lambda *a, **k: order.append("event"))
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: order.append("correlate"))
    monkeypatch.setattr(
        lockdown, "after_temporary_lock", lambda *a, **k: order.append(("after", a))
    )

    soar.enforce_lockout("9.9.9.9", 6, 1, is_admin=True)

    assert order[-1] == ("after", ("ip", "9.9.9.9", "ADMIN_BRUTE_FORCE", 6))
    assert order[:4] == ["create_lockout", "alert", "event", "correlate"]


def test_enforce_account_lockout_hands_over_to_lockdown(monkeypatch):
    seen = []
    monkeypatch.setattr(db, "create_account_lockout", lambda *a, **k: None)
    monkeypatch.setattr(alert, "send_account_lockout_alert", lambda *a, **k: None)
    monkeypatch.setattr(db, "insert_security_event", lambda *a, **k: None)
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: None)
    monkeypatch.setattr(lockdown, "after_temporary_lock", lambda *a, **k: seen.append((a, k)))

    soar.enforce_account_lockout("alice", 9, 3, "8.8.8.8")

    assert seen == [(("account", "alice", "DISTRIBUTED_BRUTE_FORCE", 9), {"triggering_ip": "8.8.8.8"})]


def test_manual_release_does_not_release_permanent_ip_lock(monkeypatch):
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [{"ip_address": "1.1.1.1", "lock_type": "PERMANENT"}])
    monkeypatch.setattr(db, "release_lockout", lambda ip: (_ for _ in ()).throw(AssertionError("영구 잠금을 풀면 안 된다")))

    assert soar.manual_release("1.1.1.1") is False


def test_manual_release_account_does_not_release_permanent_account_lock(monkeypatch):
    monkeypatch.setattr(db, "get_active_account_lockout", lambda username: {"lock_type": "PERMANENT"})
    monkeypatch.setattr(
        db, "release_account_lockout", lambda u: (_ for _ in ()).throw(AssertionError("영구 잠금을 풀면 안 된다"))
    )

    assert soar.manual_release_account("alice") is False


def test_manual_release_still_releases_temporary_lock(monkeypatch):
    released = []
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [{"ip_address": "1.1.1.1", "lock_type": "TEMPORARY"}])
    monkeypatch.setattr(db, "release_lockout", lambda ip: released.append(ip))
    monkeypatch.setattr(db, "resolve_security_events_for_ip", lambda ip: None)

    assert soar.manual_release("1.1.1.1") is True
    assert released == ["1.1.1.1"]


# ---------------------------------------------------------------------------
# 사건 기반 승격 — T3 (CRITICAL) / T4 (HIGH)
# ---------------------------------------------------------------------------

@pytest.fixture
def incident_env(monkeypatch):
    log = []
    monkeypatch.setattr(
        lockdown, "promote_ip", lambda ip, reason, recoverable, **kw: log.append(("promote_ip", ip, reason, recoverable, kw)) or True
    )
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: None)
    monkeypatch.setattr(db, "get_pending_request", lambda *a: None)
    monkeypatch.setattr(db, "insert_pending_request", lambda *a, **k: log.append(("insert_pending_request", a)))
    monkeypatch.setattr(alert, "send_pending_approval_alert", lambda *a, **k: log.append(("pending_alert", a)))
    return log


def test_critical_incident_promotes_immediately(incident_env):
    lockdown.consider_incident_promotion(
        "9.9.9.9", {"id": 3, "event_types": ["BRUTE_FORCE", "WEB_SCANNING"], "severity_max": "CRITICAL"}
    )

    assert incident_env == [("promote_ip", "9.9.9.9", "SIEM_CRITICAL", "EXEMPTION", {"incident_id": 3})]


def test_high_incident_goes_to_approval_queue_by_default(incident_env, monkeypatch):
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_ON_HIGH", False)

    lockdown.consider_incident_promotion(
        "9.9.9.9", {"id": 3, "event_types": ["SIGNUP_RATE_LIMIT", "WEB_SCANNING"], "severity_max": "HIGH"}
    )

    kinds = [entry[0] for entry in incident_env]
    assert kinds == ["insert_pending_request", "pending_alert"]
    assert incident_env[0][1][:4] == ("SIEM_HIGH_INCIDENT", "PERMANENT_LOCK_IP", "ip", "9.9.9.9")


def test_high_incident_promotes_when_auto_on_high_enabled(incident_env, monkeypatch):
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_ON_HIGH", True)

    lockdown.consider_incident_promotion(
        "9.9.9.9", {"id": 3, "event_types": ["SIGNUP_RATE_LIMIT", "WEB_SCANNING"], "severity_max": "HIGH"}
    )

    assert incident_env == [("promote_ip", "9.9.9.9", "SIEM_HIGH", "EXEMPTION", {"incident_id": 3})]


def test_high_incident_is_not_queued_again_when_already_permanently_locked(incident_env, monkeypatch):
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_ON_HIGH", False)
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: {"lock_type": "PERMANENT"})

    lockdown.consider_incident_promotion("9.9.9.9", {"id": 3, "event_types": ["A", "B"], "severity_max": "HIGH"})

    assert incident_env == []


def test_medium_incident_and_allowlisted_ip_do_nothing(incident_env):
    lockdown.consider_incident_promotion("9.9.9.9", {"id": 3, "event_types": ["A", "B"], "severity_max": "MEDIUM"})
    lockdown.consider_incident_promotion("127.0.0.1", {"id": 4, "event_types": ["A", "B"], "severity_max": "CRITICAL"})

    assert incident_env == []


def test_approved_siem_high_request_promotes_the_ip(monkeypatch):
    promoted = []
    monkeypatch.setattr(
        lockdown, "promote_ip", lambda ip, reason, recoverable, **kw: promoted.append((ip, reason, recoverable))
    )

    soar._run_pending_action(
        {"pending_action": "PERMANENT_LOCK_IP", "event_type": "SIEM_HIGH_INCIDENT", "target_value": "9.9.9.9"}
    )

    assert promoted == [("9.9.9.9", "SIEM_HIGH", "EXEMPTION")]


# ---------------------------------------------------------------------------
# security/correlate.py 연결 — PERMANENT_LOCK 이벤트는 재승격하지 않는다
# ---------------------------------------------------------------------------

def _stub_correlate_db(monkeypatch, incident):
    monkeypatch.setattr(db, "get_recent_distinct_event_types", lambda ip, w: ["BRUTE_FORCE", "PERMANENT_LOCK"])
    monkeypatch.setattr(db, "record_incident", lambda *a: incident)


def test_permanent_lock_event_does_not_trigger_promotion_again(monkeypatch):
    incident = {"id": 1, "event_types": ["BRUTE_FORCE", "PERMANENT_LOCK"], "severity_max": "CRITICAL", "escalated": True}
    _stub_correlate_db(monkeypatch, incident)
    monkeypatch.setattr(
        lockdown, "consider_incident_promotion", lambda *a: (_ for _ in ()).throw(AssertionError("재귀 승격 금지"))
    )
    closed = []
    monkeypatch.setattr(lockdown, "close_incident_if_configured", lambda inc: closed.append(inc["id"]))

    correlate.check_and_correlate("9.9.9.9", "PERMANENT_LOCK", "CRITICAL")

    assert closed == [1]


def test_other_events_trigger_promotion_consideration(monkeypatch):
    incident = {"id": 1, "event_types": ["BRUTE_FORCE", "WEB_SCANNING"], "severity_max": "CRITICAL", "escalated": True}
    _stub_correlate_db(monkeypatch, incident)
    considered = []
    monkeypatch.setattr(lockdown, "consider_incident_promotion", lambda ip, inc: considered.append((ip, inc["id"])))

    correlate.check_and_correlate("9.9.9.9", "BRUTE_FORCE", "CRITICAL")

    assert considered == [("9.9.9.9", 1)]


def test_auto_close_switch_off_does_not_close_incident(monkeypatch):
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_CLOSE_INCIDENT", False)
    monkeypatch.setattr(db, "close_incident_system", lambda *a: (_ for _ in ()).throw(AssertionError("닫으면 안 된다")))

    lockdown.close_incident_if_configured({"id": 5})


def test_auto_close_switch_on_closes_incident_as_system(monkeypatch):
    monkeypatch.setattr(config, "PERMANENT_LOCK_AUTO_CLOSE_INCIDENT", True)
    closed = []
    monkeypatch.setattr(db, "close_incident_system", lambda incident_id, actor: closed.append((incident_id, actor)))

    lockdown.close_incident_if_configured({"id": 5})

    assert closed == [(5, "system:permanent_lock")]


# ---------------------------------------------------------------------------
# release — 관리자/스크립트 해제
# ---------------------------------------------------------------------------

def test_release_ip_records_history_and_alerts(monkeypatch):
    log = []
    monkeypatch.setattr(db, "release_permanent_lockout", lambda ip: True)
    monkeypatch.setattr(db, "resolve_security_events_for_ip", lambda ip: log.append(("resolve", ip)))
    monkeypatch.setattr(db, "mark_lock_released", lambda *a, **k: log.append(("history", a)))
    monkeypatch.setattr(alert, "send_permanent_release_alert", lambda *a: log.append(("alert", a)))

    assert lockdown.release("ip", "1.1.1.1", "admin:boss", "오탐 확인") is True

    assert ("history", ("ip", "1.1.1.1", "admin:boss", "오탐 확인")) in log
    assert ("alert", ("ip", "1.1.1.1", "admin:boss", "오탐 확인")) in log


def test_release_returns_false_and_stays_silent_when_not_permanent(monkeypatch):
    monkeypatch.setattr(db, "release_permanent_account_lockout", lambda username: False)
    monkeypatch.setattr(
        db, "mark_lock_released", lambda *a, **k: (_ for _ in ()).throw(AssertionError("기록하면 안 된다"))
    )
    monkeypatch.setattr(
        alert, "send_permanent_release_alert", lambda *a: (_ for _ in ()).throw(AssertionError("알리면 안 된다"))
    )

    assert lockdown.release("account", "alice", "admin:boss", "x") is False


# ---------------------------------------------------------------------------
# db 계층 — 영구 잠금 보호 (가짜 Supabase 클라이언트)
# ---------------------------------------------------------------------------

class _Chain:
    """supabase의 .table().select().eq()... 체이닝을 흉내내고, 호출을 전부 기록한다."""

    def __init__(self, rows_by_table, log):
        self._rows_by_table = rows_by_table
        self._log = log
        self._table = None
        self._op = None

    def table(self, name):
        self._table = name
        self._op = "select"
        self._log.append(("table", name))
        return self

    def __getattr__(self, method):
        def call(*args, **kwargs):
            if method in ("select", "update", "upsert", "insert", "delete"):
                self._op = method
            self._log.append((method, args, kwargs))
            return self

        return call

    def execute(self):
        rows = self._rows_by_table.get((self._table, self._op), [])
        return types.SimpleNamespace(data=rows, count=len(rows))


@pytest.fixture
def fake_client(monkeypatch):
    log = []
    rows = {}
    monkeypatch.setattr(db, "get_client", lambda: _Chain(rows, log))
    return rows, log


def _upserts(log):
    return [entry[1][0] for entry in log if entry[0] == "upsert"]


def test_create_lockout_does_not_downgrade_active_permanent_lock(fake_client):
    rows, log = fake_client
    rows[("lockouts", "select")] = [{"ip_address": "1.1.1.1", "active": True, "lock_type": "PERMANENT"}]

    db.create_lockout("1.1.1.1", 6)

    assert _upserts(log) == []  # 영구 잠금을 5분 잠금으로 덮어쓰면 안 된다


def test_create_lockout_overwrites_released_permanent_row_with_explicit_temporary_fields(fake_client):
    rows, log = fake_client
    rows[("lockouts", "select")] = [{"ip_address": "1.1.1.1", "active": False, "lock_type": "PERMANENT"}]

    db.create_lockout("1.1.1.1", 6)

    payload = _upserts(log)[0]
    # payload에 lock_type을 안 적으면 PERMANENT가 남은 채 unlock_at만 채워져 CHECK 제약에 걸린다.
    assert payload["lock_type"] == "TEMPORARY"
    assert payload["unlock_at"] is not None
    assert payload["permanent_reason"] is None and payload["promoted_at"] is None


def test_create_account_lockout_does_not_downgrade_and_keeps_probation(fake_client):
    rows, log = fake_client
    rows[("account_lockouts", "select")] = [{"username": "alice", "active": True, "lock_type": "PERMANENT"}]
    db.create_account_lockout("alice", 9)
    assert _upserts(log) == []

    rows[("account_lockouts", "select")] = [{"username": "alice", "active": False, "lock_type": "PERMANENT"}]
    db.create_account_lockout("alice", 9)
    payload = _upserts(log)[0]
    assert payload["lock_type"] == "TEMPORARY"
    assert "probation_until" not in payload  # 보호관찰 종료 시각은 임시 잠금이 지우면 안 된다


def test_promote_lockout_permanent_updates_active_temporary_row(fake_client):
    rows, log = fake_client
    rows[("lockouts", "update")] = [{"ip_address": "1.1.1.1"}]

    assert db.promote_lockout_permanent("1.1.1.1", "REPEAT_OFFENDER", "EXEMPTION") is True
    assert ("eq", ("lock_type", "TEMPORARY"), {}) in log  # 조건부 UPDATE
    assert _upserts(log) == []


def test_promote_lockout_permanent_returns_false_when_already_permanent(fake_client):
    rows, log = fake_client
    rows[("lockouts", "update")] = []
    rows[("lockouts", "select")] = [{"ip_address": "1.1.1.1", "active": True, "lock_type": "PERMANENT"}]

    assert db.promote_lockout_permanent("1.1.1.1", "REPEAT_OFFENDER", "EXEMPTION") is False
    assert _upserts(log) == []


def test_promote_lockout_permanent_creates_row_when_ip_had_no_lockout(fake_client):
    rows, log = fake_client  # update 0행, 기존 행 없음 → 사건 기반 승격(T3/T4)
    assert db.promote_lockout_permanent("1.1.1.1", "SIEM_CRITICAL", "EXEMPTION") is True
    payload = _upserts(log)[0]
    assert payload["lock_type"] == "PERMANENT" and payload["unlock_at"] is None


def test_get_active_lockout_counts_permanent_rows_as_locked(fake_client):
    rows, log = fake_client
    db.get_active_lockout("1.1.1.1")

    or_calls = [entry for entry in log if entry[0] == "or_"]
    assert or_calls and "lock_type.eq.PERMANENT" in or_calls[0][1][0]  # unlock_at이 NULL이어도 잠김으로 판정


def test_list_expired_lockouts_only_targets_temporary_rows(fake_client):
    rows, log = fake_client
    db.list_expired_active_lockouts()
    db.list_expired_active_account_lockouts()

    assert log.count(("eq", ("lock_type", "TEMPORARY"), {})) == 2


# ---------------------------------------------------------------------------
# detector — 잠금 상태 판정
# ---------------------------------------------------------------------------

def test_detector_lock_state_distinguishes_none_temporary_and_permanent(monkeypatch):
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: None)
    assert detector.get_ip_lock_state("1.1.1.1") == "NONE"
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: {"lock_type": "TEMPORARY"})
    assert detector.get_ip_lock_state("1.1.1.1") == "TEMPORARY"
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: {"lock_type": "PERMANENT"})
    assert detector.get_ip_lock_state("1.1.1.1") == "PERMANENT"

    monkeypatch.setattr(db, "get_active_account_lockout", lambda u: {"lock_type": "PERMANENT"})
    assert detector.get_account_lock_state("alice") == "PERMANENT"


# ---------------------------------------------------------------------------
# 회귀 테스트 — 콘솔 인코딩(cp949)이 못 찍는 글자 때문에 알림 하나가 요청을 500으로 만들면 안 된다
# (Slack 웹훅이 없는 한국어 Windows 환경에서 영구 잠금 승격 요청이 실제로 500이 났었다)
# ---------------------------------------------------------------------------

def test_console_fallback_survives_characters_the_terminal_cannot_encode(monkeypatch, capsys):
    import io

    class _Cp949Stdout(io.TextIOWrapper):
        pass

    raw = io.BytesIO()
    fake_stdout = _Cp949Stdout(raw, encoding="cp949", errors="strict")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.setattr("sys.stdout", fake_stdout)

    alert.send_permanent_lock_alert("ip", "1.1.1.1", "REPEAT_OFFENDER", "EXEMPTION", 2)  # 예외가 나면 실패
    alert._safe_print("특수문자 — 포함")  # cp949로 못 찍는 글자

    fake_stdout.flush()
    assert "1.1.1.1" in raw.getvalue().decode("cp949")


def test_mark_lock_released_only_stamps_the_permanent_history_rows(fake_client):
    rows, log = fake_client

    db.mark_lock_released("ip", "1.1.1.1", "admin:boss", "사유")

    # 같은 IP의 지난 임시 잠금 이력까지 "관리자가 풀었다"고 찍으면 안 된다
    assert ("eq", ("lock_type", "PERMANENT"), {}) in log
