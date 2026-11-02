# ============================================================================
# test_pip_check.py — 관리자 미니 창(크롬 확장 extension/)의 새 공격 확인 API(/api/pip/check)
#
# 미니 창은 하루 종일 10초마다 이 API를 부른다. 그래서 지켜야 할 것은
# 1) 로그인한 관리자만 볼 수 있고, 2) 평소엔 조회 1번만 하며, 3) 반복 접근 관찰·요청 한도에
# 걸리지 않는 것이다. 실제 Supabase에 접속하지 않도록 db 조회는 전부 가짜로 바꾼다.
# ============================================================================

from db import security_events
from helpers.hooks import PAGE_ACCESS_EXCLUDED_ENDPOINTS
from tests.admin_session import login_admin_session


def _event(event_id: int, severity: str = "HIGH") -> dict:
    return {
        "id": event_id, "severity": severity, "event_type": "BRUTE_FORCE", "ip_address": "192.0.2.10",
        "path": "/login", "count": 5, "action": "LOCKED", "detected_at": "2026-11-02T00:28:27+00:00",
    }


def _login(client):
    with client.session_transaction() as sess:
        login_admin_session(sess, "test-admin")


def test_requires_admin_login(client, monkeypatch):
    import db
    from security import detector

    # 세션 없는 /api/ 요청은 unauthorized_attempts에 기록된다 — 그 기록·판정도 가짜로 바꾼다.
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 1, False))
    calls = []
    monkeypatch.setattr(security_events, "list_security_events_after", lambda *a: calls.append(a) or [])
    response = client.get("/api/pip/check?after=1")
    assert response.status_code == 401
    assert calls == []  # 로그인 전에는 보안 이벤트를 조회조차 하지 않는다


def test_without_after_returns_only_the_starting_point(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(security_events, "get_latest_security_event_id", lambda: 812)
    monkeypatch.setattr(
        security_events, "list_security_events_after", lambda *a: (_ for _ in ()).throw(AssertionError("조회하면 안 됨"))
    )
    body = client.get("/api/pip/check").get_json()
    assert body == {"latest_id": 812, "new": [], "more": False}


def test_empty_table_gives_null_starting_point(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(security_events, "get_latest_security_event_id", lambda: None)
    assert client.get("/api/pip/check").get_json()["latest_id"] is None


def test_no_new_events_keeps_the_same_id(client, monkeypatch):
    _login(client)
    calls = []
    monkeypatch.setattr(security_events, "list_security_events_after", lambda after, limit: calls.append((after, limit)) or [])
    body = client.get("/api/pip/check?after=812").get_json()
    assert body == {"latest_id": 812, "new": [], "more": False}
    assert calls == [(812, 21)]  # 평소엔 이 조회 한 번뿐(남은 게 있는지 보려고 하나 더 요청)


def test_new_events_move_the_id_forward(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(security_events, "list_security_events_after", lambda after, limit: [_event(813), _event(814, "CRITICAL")])
    body = client.get("/api/pip/check?after=812").get_json()
    assert body["latest_id"] == 814
    assert [e["severity"] for e in body["new"]] == ["HIGH", "CRITICAL"]
    assert body["more"] is False


def test_flood_is_split_and_continued(client, monkeypatch):
    # 21건이 왔으면 20건만 주고 more=True — 다음 확인은 20번째 id부터 이어서 받는다.
    _login(client)
    monkeypatch.setattr(security_events, "list_security_events_after", lambda after, limit: [_event(i) for i in range(1, limit + 1)])
    body = client.get("/api/pip/check?after=0").get_json()
    assert len(body["new"]) == 20
    assert body["latest_id"] == 20
    assert body["more"] is True


def test_bad_after_is_treated_as_first_open(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(security_events, "get_latest_security_event_id", lambda: 5)
    assert client.get("/api/pip/check?after=abc").get_json()["latest_id"] == 5
    assert client.get("/api/pip/check?after=-3").get_json()["latest_id"] == 5


def test_polling_endpoint_is_excluded_from_repeat_access_tracking(client, monkeypatch):
    # 반복 접근 관찰 훅이 이 API를 기록하면 미니 창을 켜 둔 관리자 PC가 "반복 접근"으로 잡힌다.
    import db

    assert "admin.api_pip_check" in PAGE_ACCESS_EXCLUDED_ENDPOINTS
    logged = []
    monkeypatch.setattr(db, "log_page_access_attempt", lambda ip, path: logged.append(path))
    monkeypatch.setattr(db, "log_api_access", lambda ip, path, method: logged.append(path))
    monkeypatch.setattr(security_events, "list_security_events_after", lambda after, limit: [])
    _login(client)
    for _ in range(3):
        assert client.get("/api/pip/check?after=1").status_code == 200
    assert logged == []
