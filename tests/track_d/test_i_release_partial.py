"""관리자 영구 해제에서 앱 잠금(L7)과 정문 차단(L4)의 결과를 따로 알려 주고, 일부만 실패했을 때
같은 해제로 나머지를 이어서 처리하는지 검사한다(10/26 강사 피드백 5).
"""

from __future__ import annotations

import pytest

import db
from security import lockdown, netblock
from tests.admin_session import login_admin_session, stub_admin_role
from tests.test_app import get_csrf_token

pytestmark = pytest.mark.real_lockdown

IP = "172.28.0.120"
URL = "/api/permanent-locks/release"


# ---------------------------------------------------------------------------
# lockdown.ensure_l4_released — 상태별 결과
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("row,expected", [
    (None, "NONE"),
    ({"status": "FAILED"}, "NONE"),
    ({"status": "REMOVED"}, "REMOVED"),
    ({"status": "PENDING_REMOVE"}, "REQUESTED"),
])
def test_ensure_does_not_request_again_when_nothing_left(monkeypatch, row, expected):
    monkeypatch.setattr(db, "get_network_block", lambda ip: row, raising=False)
    monkeypatch.setattr(netblock, "request_unblock", lambda ip, actor: pytest.fail("다시 요청하면 안 됨"))
    assert lockdown.ensure_l4_released(IP, "admin:boss") == expected


@pytest.mark.parametrize("status", ["APPLIED", "PENDING_APPLY"])
def test_ensure_requests_unblock_for_active_block(monkeypatch, status):
    calls = []
    monkeypatch.setattr(db, "get_network_block", lambda ip: {"status": status}, raising=False)
    monkeypatch.setattr(netblock, "request_unblock", lambda ip, actor: calls.append((ip, actor)) or True)
    assert lockdown.ensure_l4_released(IP, "admin:boss") == "REQUESTED"
    assert calls == [(IP, "admin:boss")]


def test_ensure_reports_failed_on_db_error(monkeypatch):
    def boom(ip):
        raise RuntimeError("db down")

    monkeypatch.setattr(db, "get_network_block", boom, raising=False)
    assert lockdown.ensure_l4_released(IP, "admin:boss") == "FAILED"


def test_ensure_reports_failed_when_unblock_raises(monkeypatch):
    monkeypatch.setattr(db, "get_network_block", lambda ip: {"status": "APPLIED"}, raising=False)
    monkeypatch.setattr(netblock, "request_unblock", lambda ip, actor: (_ for _ in ()).throw(RuntimeError("x")))
    assert lockdown.ensure_l4_released(IP, "admin:boss") == "FAILED"


# ---------------------------------------------------------------------------
# POST /api/permanent-locks/release — 응답으로 단계별 결과를 알림
# ---------------------------------------------------------------------------

@pytest.fixture
def admin(client, monkeypatch):
    stub_admin_role(monkeypatch, "test-role")
    monkeypatch.setattr(db, "has_permission", lambda role, action: action == "release_permanent_lock")
    with client.session_transaction() as sess:
        login_admin_session(sess, "boss")
    token = get_csrf_token(client, "/admin/dashboard")
    return lambda: client.post(URL, json={"target_kind": "ip", "target_value": IP, "note": "오탐"},
                               headers={"X-CSRFToken": token})


def test_l4_failure_is_reported_even_though_l7_was_released(admin, monkeypatch):
    monkeypatch.setattr(lockdown, "release", lambda *a: True)
    monkeypatch.setattr(lockdown, "ensure_l4_released", lambda ip, actor: "FAILED")

    response = admin()

    assert response.status_code == 502
    body = response.get_json()
    assert body["success"] is False and body["l7"] == "RELEASED" and body["l4"] == "FAILED"
    assert "다시" in body["error"]


def test_retry_after_partial_failure_finishes_l4(admin, monkeypatch):
    # 두 번째 해제: L7은 이미 풀려 release()가 False지만, 남은 L4 해제를 이어서 한다.
    monkeypatch.setattr(lockdown, "release", lambda *a: False)
    monkeypatch.setattr(lockdown, "ensure_l4_released", lambda ip, actor: "REQUESTED")

    response = admin()

    assert response.status_code == 200
    assert response.get_json() == {"success": True, "l7": "NOT_LOCKED", "l4": "REQUESTED"}


def test_full_release_reports_l4_request(admin, monkeypatch):
    monkeypatch.setattr(lockdown, "release", lambda *a: True)
    monkeypatch.setattr(lockdown, "ensure_l4_released", lambda ip, actor: "REQUESTED")

    assert admin().get_json() == {"success": True, "l4": "REQUESTED"}


def test_nothing_to_release_is_still_404(admin, monkeypatch):
    monkeypatch.setattr(lockdown, "release", lambda *a: False)
    monkeypatch.setattr(lockdown, "ensure_l4_released", lambda ip, actor: "NONE")

    assert admin().status_code == 404
