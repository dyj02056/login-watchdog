# ============================================================================
# test_dashboard_speed.py — 대시보드 반응 속도 개선 (guide46)
#
#   B. /api/status?only=<표> — 그 표 하나만 조회하고 돌려준다(전체 조회 약 21번 → 1~2번)
#   C. 만료된 잠금 정리는 정해진 간격마다만, 화면 데이터 조회는 한 번에(동시 처리 한도 = 조회 개수)
#   A. 화면 쪽(누른 즉시 반응, 처리 중 표시)은 실제 대시보드 템플릿 + 실제 JS + 가짜 서버로 브라우저에서
#      검증했다 — 여기서는 연결이 끊기지 않았는지만 정적으로 지킨다.
# ============================================================================

import re
from pathlib import Path

import pytest

import config
import db
import soar
from tests.admin_session import login_admin_session

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / "public" / "js" / "dashboard"

FULL_STATUS_QUERIES = {
    "list_recent_attempts": ([], 0), "list_active_lockouts": [], "list_active_account_lockouts": [],
    "list_active_admin_account_lockouts": [], "list_admin_login_log": ([], 0), "list_users": ([], 0),
    "get_signup_enabled": True, "list_posts": ([], 0), "list_comments_admin": ([], 0),
    "list_security_events": ([], 0), "list_security_incidents": ([], 0), "list_pending_requests": ([], 0),
    "list_recent_recovery_requests": [], "list_active_ip_exemptions": [], "list_role_permissions": [],
}


@pytest.fixture
def admin_client(client):
    with client.session_transaction() as sess:
        login_admin_session(sess, "root")
    return client


@pytest.fixture
def calls(monkeypatch):
    """전체 조회에 쓰이는 db 함수와 만료 정리 3종을 가짜로 바꾸고, 불린 이름을 기록한다."""
    called = []
    for name, value in FULL_STATUS_QUERIES.items():
        monkeypatch.setattr(db, name, lambda *a, _n=name, _v=value, **k: called.append(_n) or _v)
    monkeypatch.setattr(db, "has_permission", lambda role, action: False)
    for name in ("try_release_expired_lockouts", "try_release_expired_account_lockouts",
                 "try_release_expired_admin_account_lockouts"):
        monkeypatch.setattr(soar, name, lambda _n=name: called.append(_n))
    return called


# ---------------------------------------------------------------------------
# B. 표 하나만
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name, query, rows_key, total_key", [
    ("users", "list_users", "users", "users_total_pages"),
    ("posts", "list_posts", "recent_posts", "posts_total_pages"),
    ("comments", "list_comments_admin", "recent_comments", "comments_total_pages"),
    ("admin_log", "list_admin_login_log", "admin_login_log", "admin_log_total_pages"),
    ("security_events", "list_security_events", "security_events", "security_events_total_pages"),
    ("security_incidents", "list_security_incidents", "security_incidents", "security_incidents_total_pages"),
    ("access_requests", "list_pending_requests", "access_requests", "access_requests_total_pages"),
])
def test_only_returns_that_table_with_a_single_query(admin_client, calls, monkeypatch, name, query, rows_key, total_key):
    page_param = f"{name}_page"
    seen = []
    monkeypatch.setattr(db, query, lambda page, size: seen.append(page) or ([{"id": 7}], 35))

    response = admin_client.get(f"/api/status?only={name}&{page_param}=3")

    assert response.status_code == 200
    assert response.get_json() == {rows_key: [{"id": 7}], total_key: 4}   # 35건 / 10 = 4페이지
    assert seen == [3]
    assert calls == []   # 다른 표·카드 조회도, 만료된 잠금 정리도 하지 않는다


def test_only_attempts_also_attaches_locations(admin_client, calls, monkeypatch):
    monkeypatch.setattr(db, "list_recent_attempts", lambda page, size: ([{"ip_address": "1.1.1.1"}], 1))
    import routes.admin
    monkeypatch.setattr(routes.admin, "_attach_locations", lambda rows: [dict(r, location="KR") for r in rows])

    data = admin_client.get("/api/status?only=attempts").get_json()

    assert data == {"recent_attempts": [{"ip_address": "1.1.1.1", "location": "KR"}], "attempts_total_pages": 1}
    assert calls == []


def test_unknown_table_is_rejected(admin_client, calls):
    assert admin_client.get("/api/status?only=admin_users").status_code == 400
    assert calls == []


def test_only_still_requires_login(client, calls, monkeypatch):
    import detector
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 1, False))

    assert client.get("/api/status?only=users").status_code == 401
    assert calls == []


# ---------------------------------------------------------------------------
# C. 만료된 잠금 정리 간격 + 한 번에 조회
# ---------------------------------------------------------------------------

RELEASES = {"try_release_expired_lockouts", "try_release_expired_account_lockouts",
            "try_release_expired_admin_account_lockouts"}


def _release_count(calls):
    return sum(1 for name in calls if name in RELEASES)


def test_expired_lock_cleanup_runs_at_most_once_per_interval(admin_client, calls, monkeypatch):
    import routes.admin
    clock = [1000.0]
    monkeypatch.setattr(routes.admin.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(config, "ADMIN_STATUS_RELEASE_INTERVAL_SECONDS", 15)

    admin_client.get("/api/status")
    assert _release_count(calls) == 3          # 첫 갱신은 정리한다(3종)

    clock[0] += 14
    admin_client.get("/api/status")
    assert _release_count(calls) == 3          # 15초 안에는 건너뛴다

    clock[0] += 2
    admin_client.get("/api/status")
    assert _release_count(calls) == 6          # 간격이 지나면 다시 정리한다


def test_interval_zero_cleans_up_on_every_refresh(admin_client, calls, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_STATUS_RELEASE_INTERVAL_SECONDS", 0)
    admin_client.get("/api/status")
    admin_client.get("/api/status")
    assert _release_count(calls) == 6


def test_all_dashboard_queries_go_out_in_one_wave():
    # 동시 처리 한도가 조회 개수보다 작으면 일부가 앞 조회를 기다렸다가 두 번째로 나간다.
    source = (ROOT / "routes" / "admin.py").read_text(encoding="utf-8")
    body = source[source.index("def api_status():"):source.index("response_data = {")]
    pool = body[body.index("with ThreadPoolExecutor(max_workers=17) as executor:"):]
    assert pool.count("executor.submit(") == 17


def test_admin_users_list_is_dropped_without_permission(admin_client, calls, monkeypatch):
    monkeypatch.setattr(db, "list_admin_users", lambda: [{"id": 1, "username": "boss"}])
    monkeypatch.setattr(db, "has_permission", lambda role, action: False)
    assert "admin_users" not in admin_client.get("/api/status").get_json()

    monkeypatch.setattr(db, "has_permission", lambda role, action: action == "manage_admin_users")
    assert admin_client.get("/api/status").get_json()["admin_users"] == [{"id": 1, "username": "boss"}]


# ---------------------------------------------------------------------------
# A. 화면 연결(정적 검사)
# ---------------------------------------------------------------------------

def test_page_buttons_go_through_go_to_page():
    events = (JS / "events.js").read_text(encoding="utf-8")
    assert len(re.findall(r'bindPagination\("[\w-]+-pagination", "\w+", ', events)) == 8
    assert "goToPage(sectionName, getPage() - 1)" in events
    api = (JS / "api.js").read_text(encoding="utf-8")
    assert "pages[section.pageKey] = Math.min(Math.max(1, page), total);" in api   # 1 ~ 마지막 페이지


def test_every_action_request_marks_its_button_busy():
    api = (JS / "api.js").read_text(encoding="utf-8")
    assert 'await fetch("/api/' not in api                     # 처리 요청은 모두 sendAction을 거친다
    assert api.count('await sendAction(button, "/api/') == 17
    events = (JS / "events.js").read_text(encoding="utf-8")
    assert events.count("runAction(") == 17


def test_stale_responses_never_overwrite_newer_screens():
    api = (JS / "api.js").read_text(encoding="utf-8")
    assert api.count("if (requestId !== latestStatusRequest)") == 2
    assert api.count("if (requestId !== latestSectionRequest[name])") == 2
    assert "sectionEpoch[name] === epochAtSend[name]" in api   # 전체 갱신이 넘긴 표를 되돌리지 않는다
