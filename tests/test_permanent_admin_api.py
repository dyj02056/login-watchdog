# ============================================================================
# test_permanent_admin_api.py — 영구 잠금 관리자 API(guide33)와 RBAC 권한 분리 검증
#
# 확인하는 것
#   - 쓰기 API 4개가 각각 서로 다른 권한 하나(1:1)로 보호되는가
#   - 영구 해제(release_permanent_lock)는 권한이 없으면 403이고, 사유(note)가 없으면 400인가
#   - 영구 행에 기존 "즉시 해제" API를 쓰면 409로 안내하는가
#   - /api/status가 permanent_locks / recovery_requests / ip_exemptions / permissions를 내려주는가
# test_app.py와 같은 방식(Flask 테스트 클라이언트 + monkeypatch)을 쓰며, 영구 잠금 기본
# stub(autouse)을 꺼야 해서 real_lockdown 마커를 단다.
# ============================================================================

import pytest

import db
import lockdown
import soar

from tests.test_app import get_csrf_token  # noqa: E402
from tests.admin_session import login_admin_session, stub_admin_role  # noqa: E402

pytestmark = pytest.mark.real_lockdown


def _login_as(client, monkeypatch, granted_actions):
    """주어진 action들만 허용하는 관리자로 로그인하고, 요청에 쓸 CSRF 토큰을 돌려준다."""
    asked = []

    def fake_has_permission(role, action):
        asked.append(action)
        return action in granted_actions

    stub_admin_role(monkeypatch, "test-role")
    monkeypatch.setattr(db, "has_permission", fake_has_permission)
    with client.session_transaction() as sess:
        login_admin_session(sess, "boss")
    return get_csrf_token(client, "/admin/dashboard"), asked


def _post(client, token, path, body):
    return client.post(path, json=body, headers={"X-CSRFToken": token})


# ---------------------------------------------------------------------------
# release (super_admin 전용)
# ---------------------------------------------------------------------------

def test_release_requires_release_permanent_lock_permission(client, monkeypatch):
    token, asked = _login_as(client, monkeypatch, granted_actions=set())
    monkeypatch.setattr(
        lockdown, "release", lambda *a: (_ for _ in ()).throw(AssertionError("권한 없는데 해제되면 안 된다"))
    )

    response = _post(client, token, "/api/permanent-locks/release",
                     {"target_kind": "ip", "target_value": "1.1.1.1", "note": "사유"})

    assert response.status_code == 403
    assert asked == ["release_permanent_lock"]


def test_release_succeeds_for_permitted_admin_and_records_actor_and_note(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"release_permanent_lock"})
    seen = []
    monkeypatch.setattr(lockdown, "release", lambda kind, value, actor, note: seen.append((kind, value, actor, note)) or True)

    response = _post(client, token, "/api/permanent-locks/release",
                     {"target_kind": "ip", "target_value": "1.1.1.1", "note": "  오탐 확인  "})

    assert response.status_code == 200 and response.get_json() == {"success": True}
    # 해제한 관리자는 요청 본문이 아니라 로그인 세션에서 가져온다
    assert seen == [("ip", "1.1.1.1", "admin:boss", "오탐 확인")]


@pytest.mark.parametrize("note", ["", "   ", None])
def test_release_without_note_is_rejected_with_400(client, monkeypatch, note):
    token, _ = _login_as(client, monkeypatch, {"release_permanent_lock"})
    monkeypatch.setattr(
        lockdown, "release", lambda *a: (_ for _ in ()).throw(AssertionError("사유 없이 해제되면 안 된다"))
    )

    response = _post(client, token, "/api/permanent-locks/release",
                     {"target_kind": "account", "target_value": "alice", "note": note})

    assert response.status_code == 400
    assert "사유" in response.get_json()["error"]


def test_release_with_invalid_kind_or_missing_target_is_400(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"release_permanent_lock"})
    assert _post(client, token, "/api/permanent-locks/release",
                 {"target_kind": "other", "target_value": "x", "note": "n"}).status_code == 400
    assert _post(client, token, "/api/permanent-locks/release",
                 {"target_kind": "ip", "note": "n"}).status_code == 400


def test_release_of_target_that_is_not_permanent_returns_404(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"release_permanent_lock"})
    monkeypatch.setattr(lockdown, "release", lambda *a: False)

    response = _post(client, token, "/api/permanent-locks/release",
                     {"target_kind": "ip", "target_value": "1.1.1.1", "note": "n"})

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# promote
# ---------------------------------------------------------------------------

def test_promote_requires_promote_permanent_lock_permission(client, monkeypatch):
    token, asked = _login_as(client, monkeypatch, granted_actions=set())

    response = _post(client, token, "/api/permanent-locks/promote",
                     {"target_kind": "ip", "target_value": "1.1.1.1", "reason": "r"})

    assert response.status_code == 403
    assert asked == ["promote_permanent_lock"]


def test_promote_ip_locks_as_admin_only_with_reason_and_admin_name(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"promote_permanent_lock"})
    seen = []
    monkeypatch.setattr(
        lockdown, "promote_ip", lambda ip, reason, recoverable, **kw: seen.append((ip, reason, recoverable, kw)) or True
    )

    response = _post(client, token, "/api/permanent-locks/promote",
                     {"target_kind": "ip", "target_value": "8.8.8.8", "reason": "스캐닝 반복"})

    assert response.status_code == 200
    assert seen == [("8.8.8.8", "ADMIN_MANUAL", "ADMIN_ONLY", {"note": "boss: 스캐닝 반복"})]


def test_promote_rejects_invalid_ip_allowlisted_ip_and_missing_reason(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"promote_permanent_lock"})

    assert _post(client, token, "/api/permanent-locks/promote",
                 {"target_kind": "ip", "target_value": "not-an-ip", "reason": "r"}).status_code == 400
    allowlisted = _post(client, token, "/api/permanent-locks/promote",
                        {"target_kind": "ip", "target_value": "127.0.0.1", "reason": "r"})
    assert allowlisted.status_code == 400 and "허용 목록" in allowlisted.get_json()["error"]
    assert _post(client, token, "/api/permanent-locks/promote",
                 {"target_kind": "ip", "target_value": "8.8.8.8", "reason": ""}).status_code == 400


def test_promote_account_requires_existing_user_and_reports_conflict(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"promote_permanent_lock"})
    monkeypatch.setattr(db, "get_user_by_username", lambda username: None)
    assert _post(client, token, "/api/permanent-locks/promote",
                 {"target_kind": "account", "target_value": "ghost", "reason": "r"}).status_code == 404

    monkeypatch.setattr(db, "get_user_by_username", lambda username: {"id": 1})
    monkeypatch.setattr(lockdown, "promote_account", lambda *a, **k: False)  # 이미 영구 잠금
    assert _post(client, token, "/api/permanent-locks/promote",
                 {"target_kind": "account", "target_value": "alice", "reason": "r"}).status_code == 409


# ---------------------------------------------------------------------------
# 예외 회수 / 복구 요청 취소 — 서로 다른 권한 하나씩
# ---------------------------------------------------------------------------

def test_revoke_exemption_uses_its_own_permission(client, monkeypatch):
    token, asked = _login_as(client, monkeypatch, granted_actions=set())
    response = _post(client, token, "/api/ip-exemptions/revoke", {"id": 3})
    assert response.status_code == 403 and asked == ["revoke_ip_exemption"]

    token, _ = _login_as(client, monkeypatch, {"revoke_ip_exemption"})
    revoked = []
    monkeypatch.setattr(db, "revoke_ip_exemption", lambda i, reason: revoked.append((i, reason)) or True)
    assert _post(client, token, "/api/ip-exemptions/revoke", {"id": 3}).status_code == 200
    assert revoked[0][0] == 3 and "boss" in revoked[0][1]


def test_revoke_recovery_request_uses_its_own_permission_not_the_exemption_one(client, monkeypatch):
    # 복구 요청 취소는 revoke_ip_exemption이 아니라 revoke_recovery_request 권한이어야 한다(1:1 관례).
    token, asked = _login_as(client, monkeypatch, granted_actions={"revoke_ip_exemption"})

    response = _post(client, token, "/api/recovery-requests/revoke", {"id": 5})

    assert response.status_code == 403 and asked == ["revoke_recovery_request"]


def test_revoke_endpoints_validate_id_and_report_not_found(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"revoke_ip_exemption", "revoke_recovery_request"})
    for path in ("/api/ip-exemptions/revoke", "/api/recovery-requests/revoke"):
        assert _post(client, token, path, {}).status_code == 400
        assert _post(client, token, path, {"id": True}).status_code == 400  # bool은 int가 아니다
        assert _post(client, token, path, {"id": "3"}).status_code == 400

    monkeypatch.setattr(db, "revoke_ip_exemption", lambda i, reason: False)
    monkeypatch.setattr(db, "revoke_recovery_request", lambda i: False)
    assert _post(client, token, "/api/ip-exemptions/revoke", {"id": 3}).status_code == 404
    assert _post(client, token, "/api/recovery-requests/revoke", {"id": 3}).status_code == 404

    monkeypatch.setattr(db, "revoke_recovery_request", lambda i: True)
    assert _post(client, token, "/api/recovery-requests/revoke", {"id": 3}).status_code == 200


def test_super_admin_only_matrix_matches_migration_sql():
    # 마이그레이션 SQL의 역할-권한 매핑이 계획과 같은지(security_admin은 release 불가) 확인한다.
    import pathlib

    sql = (pathlib.Path(__file__).parent.parent / "docs" / "migrations" / "guide33_permanent_lock.sql").read_text(
        encoding="utf-8"
    )
    assert "('super_admin',    'release_permanent_lock')" in sql
    assert "('security_admin', 'release_permanent_lock')" not in sql
    for action in ("promote_permanent_lock", "revoke_ip_exemption", "revoke_recovery_request"):
        assert f"('security_admin', '{action}')" in sql
        assert f"('super_admin',    '{action}')" in sql


# ---------------------------------------------------------------------------
# 기존 "즉시 해제" API — 영구 행은 409
# ---------------------------------------------------------------------------

def test_existing_unlock_apis_answer_409_for_permanent_targets(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"unlock_ip"})
    monkeypatch.setattr(soar, "manual_release", lambda ip: False)
    monkeypatch.setattr(soar, "manual_release_account", lambda username: False)
    monkeypatch.setattr(lockdown, "is_permanent_ip", lambda ip: True)
    monkeypatch.setattr(lockdown, "is_permanent_account", lambda username: True)

    ip_response = _post(client, token, "/api/unlock", {"ip": "1.1.1.1"})
    account_response = _post(client, token, "/api/unlock-account", {"username": "alice"})

    assert ip_response.status_code == 409 and "영구 해제" in ip_response.get_json()["error"]
    assert account_response.status_code == 409


def test_existing_unlock_api_for_plain_missing_target_is_still_200_false(client, monkeypatch):
    token, _ = _login_as(client, monkeypatch, {"unlock_ip"})
    monkeypatch.setattr(soar, "manual_release", lambda ip: False)
    monkeypatch.setattr(lockdown, "is_permanent_ip", lambda ip: False)

    response = _post(client, token, "/api/unlock", {"ip": "1.1.1.1"})

    assert response.status_code == 200 and response.get_json() == {"success": False}


# ---------------------------------------------------------------------------
# /api/status
# ---------------------------------------------------------------------------

def _mock_status_db(monkeypatch):
    monkeypatch.setattr(db, "list_recent_attempts", lambda page, size: ([], 0))
    monkeypatch.setattr(db, "list_admin_login_log", lambda page, size: ([], 0))
    monkeypatch.setattr(db, "list_users", lambda page, size: ([], 0))
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(db, "list_posts", lambda page, size: ([], 0))
    monkeypatch.setattr(db, "list_comments_admin", lambda page, size: ([], 0))
    monkeypatch.setattr(db, "list_security_events", lambda page, size: ([], 0))
    monkeypatch.setattr(db, "list_security_incidents", lambda page, size: ([], 0))
    monkeypatch.setattr(db, "list_pending_requests", lambda page, size: ([], 0))
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(soar, "try_release_expired_account_lockouts", lambda: None)


def test_api_status_exposes_permanent_locks_requests_exemptions_and_permissions(client, monkeypatch):
    _mock_status_db(monkeypatch)
    stub_admin_role(monkeypatch, "super_admin")
    monkeypatch.setattr(db, "has_permission", lambda role, action: True)
    monkeypatch.setattr(db, "list_role_permissions", lambda role: ["release_permanent_lock", "unlock_ip"])
    monkeypatch.setattr(
        db,
        "list_active_lockouts",
        lambda: [
            {"ip_address": "1.1.1.1", "lock_type": "PERMANENT", "permanent_reason": "REPEAT_OFFENDER",
             "recoverable": "EXEMPTION", "failure_count": 6, "locked_at": "t", "promoted_at": "t2"},
            {"ip_address": "2.2.2.2", "lock_type": "TEMPORARY", "failure_count": 6, "locked_at": "t", "unlock_at": "u"},
        ],
    )
    monkeypatch.setattr(
        db,
        "list_active_account_lockouts",
        lambda: [{"username": "alice", "lock_type": "PERMANENT", "permanent_reason": "REPEAT_OFFENDER",
                  "recoverable": "ADMIN_ONLY", "failure_count": 9, "locked_at": "t", "promoted_at": "t2"}],
    )
    monkeypatch.setattr(db, "get_email_statuses", lambda usernames: {"alice": "UNDELIVERABLE"})
    monkeypatch.setattr(db, "list_recent_recovery_requests", lambda limit=20: [{"id": 1, "status": "PENDING"}])
    monkeypatch.setattr(db, "list_active_ip_exemptions", lambda limit=20: [{"id": 2, "ip_address": "1.1.1.1"}])
    monkeypatch.setattr(db, "list_admin_users", lambda: [])

    with client.session_transaction() as sess:
        login_admin_session(sess, "boss")
    data = client.get("/api/status").get_json()

    # 임시 잠금(2.2.2.2)은 영구 잠금 목록에 섞이지 않는다
    assert [(lock["kind"], lock["target"]) for lock in data["permanent_locks"]] == [("ip", "1.1.1.1"), ("account", "alice")]
    assert data["permanent_locks"][1]["email_status"] == "UNDELIVERABLE"
    assert data["recovery_requests"] == [{"id": 1, "status": "PENDING"}]
    assert data["ip_exemptions"] == [{"id": 2, "ip_address": "1.1.1.1"}]
    assert data["permissions"] == ["release_permanent_lock", "unlock_ip"]


def test_api_status_does_not_query_email_status_without_permanent_accounts(client, monkeypatch):
    _mock_status_db(monkeypatch)
    stub_admin_role(monkeypatch, "security_admin")
    monkeypatch.setattr(db, "has_permission", lambda role, action: False)
    monkeypatch.setattr(db, "list_role_permissions", lambda role: [])
    monkeypatch.setattr(db, "list_active_lockouts", lambda: [])
    monkeypatch.setattr(db, "list_active_account_lockouts", lambda: [])
    monkeypatch.setattr(db, "list_recent_recovery_requests", lambda limit=20: [])
    monkeypatch.setattr(db, "list_active_ip_exemptions", lambda limit=20: [])
    monkeypatch.setattr(
        db, "get_email_statuses", lambda usernames: (_ for _ in ()).throw(AssertionError("불필요한 조회"))
    )

    with client.session_transaction() as sess:
        login_admin_session(sess, "boss")
    data = client.get("/api/status").get_json()

    assert data["permanent_locks"] == []
    assert data["permissions"] == []
