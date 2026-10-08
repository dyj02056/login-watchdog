# ============================================================================
# test_polling.py — 대시보드·게시글 화면 폴링 줄이기 (guide45)
#
# 폴링 부품(public/js/polling.js)의 동작 자체(숨기면 멈춤, 돌아오면 즉시 갱신, 요청 겹침
# 없음, 실패해도 계속)는 가짜 브라우저 환경의 Node 스크립트로 검증했다 — 이 프로젝트에는
# 자바스크립트 테스트 환경이 없다. 여기서는 그 부품이 제대로 연결돼 있는지와 서버 쪽 변경을 지킨다.
# ============================================================================

import threading
from pathlib import Path

import db
import soar
from tests.admin_session import login_admin_session

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / "public" / "js"


def test_no_screen_polls_with_set_interval_anymore():
    # setInterval은 탭이 숨겨져도, 이전 요청이 안 끝나도 계속 보낸다 — 폴링은 polling.js로만 한다.
    offenders = [p.relative_to(ROOT).as_posix() for p in JS.rglob("*.js") if "setInterval(" in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_dashboard_and_board_use_the_shared_polling_module():
    main = (JS / "dashboard" / "main.js").read_text(encoding="utf-8")
    board = (JS / "board.js").read_text(encoding="utf-8")
    polling = (JS / "polling.js").read_text(encoding="utf-8")

    assert 'from "../polling.js"' in main and "startPolling(fetchStatus, pollIntervalMs)" in main
    assert 'from "./polling.js"' in board and "{ immediate: false }" in board
    assert "visibilitychange" in polling and "document.hidden" in polling


def test_board_script_is_loaded_as_a_module():
    # board.js가 import를 쓰므로 type="module"이어야 한다(아니면 문법 오류로 배너·삭제 확인창이 모두 멈춘다).
    template = (ROOT / "templates" / "board_detail.html").read_text(encoding="utf-8")
    assert """<script type="module" src="{{ url_for('static', filename='js/board.js') }}"></script>""" in template


def test_dashboard_refetch_is_awaited_so_requests_never_overlap():
    api = (JS / "dashboard" / "api.js").read_text(encoding="utf-8")
    assert "await fetchStatus();" in api


def _stub_status_queries(monkeypatch):
    for name, value in {
        "list_recent_attempts": ([], 0), "list_active_lockouts": [], "list_active_account_lockouts": [],
        "list_admin_login_log": ([], 0), "list_users": ([], 0), "get_signup_enabled": True,
        "list_posts": ([], 0), "list_comments_admin": ([], 0), "list_security_events": ([], 0),
        "list_security_incidents": ([], 0), "list_pending_requests": ([], 0),
    }.items():
        monkeypatch.setattr(db, name, lambda *a, _v=value, **k: _v)
    monkeypatch.setattr(db, "has_permission", lambda role, action: False)


def test_expired_lock_cleanup_runs_concurrently_and_before_the_listing(client, monkeypatch):
    # 정리 3종은 서로 기다리지 않고 동시에 돈다 — 세 작업이 모두 시작돼야 풀리는 장벽으로 확인한다.
    # 하나씩 차례로 돌았다면 첫 작업이 장벽에서 시간 초과(BrokenBarrierError)로 실패한다.
    _stub_status_queries(monkeypatch)
    barrier = threading.Barrier(3, timeout=2)
    order = []

    def release(kind):
        def run():
            barrier.wait()
            order.append(kind)
        return run

    monkeypatch.setattr(soar, "try_release_expired_lockouts", release("ip"))
    monkeypatch.setattr(soar, "try_release_expired_account_lockouts", release("account"))
    monkeypatch.setattr(soar, "try_release_expired_admin_account_lockouts", release("admin"))
    monkeypatch.setattr(db, "list_active_lockouts", lambda: order.append("listing") or [])
    with client.session_transaction() as sess:
        login_admin_session(sess, "root")

    response = client.get("/api/status")

    assert response.status_code == 200
    assert sorted(order[:3]) == ["account", "admin", "ip"]
    assert order[3] == "listing"  # 목록은 정리가 끝난 뒤에 조회한다(방금 풀린 잠금이 "잠김"으로 안 보이게)
