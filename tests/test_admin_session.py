# ============================================================================
# test_admin_session.py — 관리자 세션 검증(guide37)
#
# 세션 쿠키는 서명만 되어 있고 서버가 따로 보관하지 않으므로, 문지기가 요청마다 DB의 계정과
# 대조해야 "삭제된 관리자의 쿠키"나 "수명이 지난 쿠키"를 걸러낼 수 있다. 이 파일은
#   - 삭제/재생성된 계정, 수명 초과, 옛 형식 세션이 대시보드·API에서 모두 거절되는지
#   - 그런 "무효 세션"은 미인증 접근 공격으로 기록되지 않는지(세션이 아예 없을 때만 기록)
#   - require_permission이 문지기가 조회한 계정(g.admin)의 role·id를 쓰는지
#   - 로그아웃이 같은 브라우저의 회원 세션은 남겨두는지
# 를 확인한다.
# ============================================================================

import time

import pytest

import config
import db
from security import soar

from tests.admin_session import login_admin_session, stub_admin_role
from tests.test_app import get_csrf_token  # noqa: E402


@pytest.fixture
def unauthorized_log(monkeypatch):
    logged = []
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: logged.append(path))
    monkeypatch.setattr(
        "security.detector.is_unauthorized_access_suspicious", lambda ip: (False, 1, False)
    )
    return logged


def _assert_admin_session_cleared(client):
    with client.session_transaction() as sess:
        assert "admin_username" not in sess
        assert "admin_id" not in sess
        assert "admin_login_at" not in sess


def test_valid_admin_session_opens_the_dashboard(client):
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")

    assert client.get("/admin/dashboard").status_code == 200


def test_deleted_admin_cannot_poll_api_status(client, monkeypatch, unauthorized_log):
    monkeypatch.setattr(db, "get_admin_by_id", lambda admin_id: None)
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")

    response = client.get("/api/status")

    assert response.status_code == 401
    assert unauthorized_log == []  # 다시 로그인해야 하는 관리자이지 공격이 아니다
    _assert_admin_session_cleared(client)


def test_deleted_admin_is_sent_back_to_login_from_the_dashboard(client, monkeypatch):
    monkeypatch.setattr(db, "get_admin_by_id", lambda admin_id: None)
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")

    response = client.get("/admin/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"] == "/admin/login"
    _assert_admin_session_cleared(client)


def test_recreated_admin_with_same_username_does_not_revive_old_session(client, monkeypatch, unauthorized_log):
    # 옛 계정(id=1)을 지우고 같은 아이디로 다시 만들면 id가 달라진다 — 옛 쿠키는 id=1을 들고 있다.
    accounts = {2: {"id": 2, "username": "test-admin", "role": "super_admin"}}
    monkeypatch.setattr(db, "get_admin_by_id", lambda admin_id: accounts.get(admin_id))
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin", admin_id=1)

    assert client.get("/api/status").status_code == 401
    assert unauthorized_log == []


def test_session_pointing_to_a_different_username_is_rejected(client, monkeypatch):
    monkeypatch.setattr(
        db, "get_admin_by_id", lambda admin_id: {"id": admin_id, "username": "someone-else", "role": "super_admin"}
    )
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")

    assert client.get("/admin/dashboard").status_code == 302


def test_session_older_than_max_lifetime_is_rejected(client, unauthorized_log):
    expired = int(time.time()) - config.ADMIN_SESSION_MAX_HOURS * 3600 - 1
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin", login_at=expired)

    assert client.get("/api/status").status_code == 401
    assert unauthorized_log == []
    _assert_admin_session_cleared(client)


def test_session_within_max_lifetime_is_accepted(client):
    almost = int(time.time()) - config.ADMIN_SESSION_MAX_HOURS * 3600 + 60
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin", login_at=almost)

    assert client.get("/admin/dashboard").status_code == 200


def test_session_from_before_this_change_requires_login_again(client, unauthorized_log):
    # 배포 전에 만들어진 세션에는 admin_username만 있다 — 한 번 다시 로그인하게 한다.
    with client.session_transaction() as sess:
        sess["admin_username"] = "test-admin"

    assert client.get("/api/status").status_code == 401
    assert unauthorized_log == []
    _assert_admin_session_cleared(client)


def test_request_without_any_session_is_still_recorded_as_unauthorized(client, unauthorized_log):
    assert client.get("/api/status").status_code == 401
    assert unauthorized_log == ["/api/status"]


def test_deleted_admin_cannot_call_write_api(client, monkeypatch, unauthorized_log):
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")
    token = get_csrf_token(client, "/admin/dashboard")
    monkeypatch.setattr(db, "get_admin_by_id", lambda admin_id: None)
    monkeypatch.setattr(soar, "manual_release", lambda ip: pytest.fail("삭제된 관리자의 요청이 실행됐다"))

    response = client.post("/api/unlock", json={"ip": "1.2.3.4"}, headers={"X-CSRFToken": token})

    assert response.status_code == 401
    assert unauthorized_log == []


def test_require_permission_uses_role_from_the_session_lookup(client, monkeypatch):
    stub_admin_role(monkeypatch, "security_viewer")
    checked = []
    monkeypatch.setattr(db, "has_permission", lambda role, action: checked.append((role, action)) or False)
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-viewer")
    token = get_csrf_token(client, "/admin/dashboard")

    response = client.post("/api/unlock", json={"ip": "1.2.3.4"}, headers={"X-CSRFToken": token})

    assert response.status_code == 403
    assert checked == [("security_viewer", "unlock_ip")]


def test_approve_records_the_admin_id_from_the_session_lookup(client, monkeypatch):
    stub_admin_role(monkeypatch, "security_admin")
    monkeypatch.setattr(db, "has_permission", lambda role, action: True)
    executed = []
    monkeypatch.setattr(
        soar, "execute_approved_request", lambda request_id, admin_id: executed.append((request_id, admin_id)) or True
    )
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin", admin_id=42)
    token = get_csrf_token(client, "/admin/dashboard")

    response = client.post("/api/access-requests/approve", json={"request_id": 5}, headers={"X-CSRFToken": token})

    assert response.get_json() == {"success": True}
    assert executed == [(5, 42)]


def test_admin_logout_keeps_the_member_session(client):
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")
        sess["username"] = "alice"
        sess["user_id"] = 7
    token = get_csrf_token(client, "/admin/dashboard")

    response = client.post("/admin/logout", data={"csrf_token": token})

    assert response.status_code == 302
    _assert_admin_session_cleared(client)
    with client.session_transaction() as sess:
        assert sess["username"] == "alice"
        assert sess["user_id"] == 7
