# ============================================================================
# test_spa.py — Next.js 정적 화면 어댑터(helpers/spa.py)
#
# 껍데기(HTML)는 DB를 거치지 않고 내려가고, 어댑터 헤더가 붙은 요청만 기존 라우트를 실행해
# JSON(템플릿 값·flash·리다이렉트)으로 돌려받는지, 그리고 비밀 칸이 새어 나가지 않는지 확인한다.
# ============================================================================

import json

import pytest

import db
from helpers import spa

SHELL = (
    "<!doctype html><html><body><div id=root></div>"
    "<script>self.__next_f=[]</script><script src=\"/_next/static/a.js\"></script></body></html>"
)
HEADERS = {spa.SPA_HEADER: spa.SPA_HEADER_VALUE}


@pytest.fixture
def spa_dir(tmp_path, monkeypatch):
    for name in ("login.html", "signup.html", "dashboard.html"):
        (tmp_path / name).write_text(SHELL, encoding="utf-8")
    monkeypatch.setattr(spa, "SPA_DIR", tmp_path)
    monkeypatch.setenv("SPA_ENABLED", "true")
    spa._csp_cache.clear()
    return tmp_path


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


def test_shell_is_served_for_browser_navigation_with_script_hash(client, spa_dir):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"__next_f" in response.data
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self' 'sha256-" in csp
    assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert "X-Spa-Script-Hashes" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"


def test_only_inline_scripts_are_hashed_not_external_ones(spa_dir):
    hashes = spa.inline_script_hashes(spa_dir / "login.html")
    assert len(hashes) == 1


def test_adapter_header_returns_template_context_as_json(client, spa_dir):
    response = client.get("/login", headers=HEADERS)
    body = response.get_json()
    assert response.status_code == 200
    assert body["page"] == "login_form.html"
    assert body["data"]["form_action"] == "/login"
    assert body["csrf"]


def test_redirect_becomes_json_with_flash_messages(client, spa_dir):
    response = client.get("/dashboard", headers=HEADERS)
    body = response.get_json()
    assert response.status_code == 200
    assert body["redirect"] == "/login"
    assert "Location" not in response.headers


def test_flash_survives_a_redirect_so_the_next_screen_can_show_it(client, spa_dir):
    # /dashboard(로그인 필요) → /login 리다이렉트. 그 flash는 리다이렉트 응답에서 꺼내지 않고, 다음 화면 조회에서 나온다.
    client.get("/dashboard", headers=HEADERS)
    with client.session_transaction() as sess:
        sess["_flashes"] = [("message", "비밀번호가 변경되었습니다.")]
    redirect = client.get("/dashboard", headers=HEADERS).get_json()
    assert redirect["redirect"] == "/login"
    page = client.get("/login", headers=HEADERS).get_json()
    assert "비밀번호가 변경되었습니다." in page["messages"]
    assert client.get("/login", headers=HEADERS).get_json()["messages"] == []  # 한 번 보여주면 사라진다


def test_form_post_error_is_json_with_flash_text(client, spa_dir, monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: False)
    token = client.get("/api/spa/session").get_json()["csrf"]
    response = client.post("/signup", data={"username": "x"}, headers={**HEADERS, "X-CSRFToken": token})
    body = response.get_json()
    assert body["page"] == "signup.html"
    assert body["data"]["signup_enabled"] is False
    assert any("회원가입" in m for m in body["messages"])
    assert len(body["messages"]) == len(set(body["messages"]))  # 템플릿이 꺼낸 flash를 두 번 세지 않는다


def test_missing_csrf_token_is_reported_as_error_not_redirect_loop(client, spa_dir, monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    response = client.post("/signup", data={"username": "x"}, headers=HEADERS)
    body = response.get_json()
    assert body["status"] == 400
    assert body["messages"]


def test_json_api_responses_pass_through_untouched(client, spa_dir):
    response = client.get("/api/spa/session", headers=HEADERS)
    assert response.get_json().keys() == {"csrf", "member", "admin", "username", "admin_username"}


def test_secret_columns_are_scrubbed_from_template_context():
    user = {"id": 1, "username": "kim", "password_hash": "x", "session_version": 3, "nested": [{"token_hash": "y", "ok": 1}]}
    assert spa._scrub(user) == {"id": 1, "username": "kim", "nested": [{"ok": 1}]}


def test_without_a_build_the_old_jinja_page_is_served(client, tmp_path, monkeypatch):
    monkeypatch.setenv("SPA_ENABLED", "true")
    monkeypatch.setattr(spa, "SPA_DIR", tmp_path)  # 빈 폴더 = 빌드 없음
    response = client.get("/login")
    assert response.status_code == 200
    assert b"__next_f" not in response.data
    assert b"<form" in response.data


def test_kill_switch_serves_jinja_even_with_a_build(client, spa_dir, monkeypatch):
    monkeypatch.setenv("SPA_ENABLED", "false")
    assert b"__next_f" not in client.get("/login").data


def test_stats_endpoint_requires_admin_login(client, spa_dir, monkeypatch):
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    from security import detector, soar

    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 1, False), raising=False)
    monkeypatch.setattr(soar, "notify_unauthorized_access", lambda *a, **k: None, raising=False)
    response = client.get("/api/stats", headers=HEADERS)
    assert response.get_json().get("redirect") == "/admin/login" or response.status_code == 401


def test_stats_endpoint_returns_aggregates_for_logged_in_admin(client, monkeypatch):
    from db import stats as db_stats
    from tests.admin_session import login_admin_session

    monkeypatch.setattr(db, "list_active_lockouts", lambda: [{"ip_address": "1.1.1.1"}])
    monkeypatch.setattr(db, "list_active_account_lockouts", lambda: [{"username": "a"}, {"username": "b"}])
    monkeypatch.setattr(db, "list_pending_requests", lambda page, size: ([{}], 4))
    seen = {}

    def fake(active_locks, pending_ai):
        seen.update(active_locks=active_locks, pending_ai=pending_ai)
        return {"kpi": {}}

    monkeypatch.setattr(db_stats, "get_threat_stats", fake)
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")
    response = client.get("/api/stats")
    assert response.status_code == 200
    assert seen == {"active_locks": 3, "pending_ai": 4}


def test_admin_json_post_works_with_the_csrf_token_from_the_session_endpoint(client, monkeypatch):
    # 화면이 쓰는 방식 그대로: /api/spa/session에서 받은 토큰을 X-CSRFToken으로 실어 JSON을 POST한다.
    from security import soar
    from tests.admin_session import login_admin_session

    released = []
    monkeypatch.setattr(soar, "manual_release", lambda ip: released.append(ip) or True)
    monkeypatch.setattr(db, "has_permission", lambda role, action: True)
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")

    token = client.get("/api/spa/session", headers=HEADERS).get_json()["csrf"]
    ok = client.post("/api/unlock", json={"ip": "203.0.113.5"}, headers={**HEADERS, "X-CSRFToken": token})
    assert ok.get_json() == {"success": True}
    assert released == ["203.0.113.5"]

    # 토큰 없이는 같은 요청이 거부된다(오류 문장이 JSON으로 온다).
    denied = client.post("/api/unlock", json={"ip": "203.0.113.5"}, headers=HEADERS)
    assert denied.get_json()["status"] == 400
    assert released == ["203.0.113.5"]
