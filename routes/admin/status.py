# ============================================================================
# routes/admin/status.py — 관리자 대시보드 화면(/admin/dashboard)과 대시보드 폴링 API(/api/status)
#
# 예전 routes/admin.py(798줄)를 기능 묶음별로 나눈 조각 중 하나다. Blueprint(admin_bp)는
# routes/admin/__init__.py에서 하나만 만들고, 이 파일은 거기에 라우트를 붙이기만 한다
# — 그래서 엔드포인트 이름(url_for("admin.xxx"))은 나누기 전과 똑같다.
# 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from flask import g, jsonify, render_template, request

import config
import db
from helpers import _attach_locations, login_required
from routes.admin import admin_bp
from security import soar


# ============================================================================
# 관리자 대시보드 화면 및 API — 조회는 login_required, 상태를 바꾸는 API는
# require_permission(역할별 권한 확인, guide26)으로 보호됨
#
# 주소가 /dashboard가 아니라 /admin/login·/admin/logout과 같은 묶음인
# /admin/dashboard인 이유: 12단계에서 회원(일반 사용자) 전용 대시보드를
# /dashboard 주소에 새로 만들면서, 기존 관리자 대시보드를 이 주소로 옮겼다.
# ============================================================================

@admin_bp.route("/admin/dashboard", methods=["GET"])
@login_required
def admin_dashboard():
    """관리자 대시보드 화면의 뼈대(HTML)만 보여준다. 실제 데이터는 화면의
    자바스크립트가 아래 /api/status를 주기적으로 호출해서 채워넣는다(6단계에서 구현).

    poll_interval_ms : dashboard/main.js가 몇 밀리초마다 /api/status를 다시 부를지.
    숫자를 JS 파일에 직접 박아두지 않고 config.py 한 곳에서 관리한다(다른
    상수들과 동일한 원칙 — 값을 바꾸려고 여러 파일을 찾아다닐 필요가 없게 함).
    """
    return render_template("admin_dashboard.html", poll_interval_ms=config.ADMIN_DASHBOARD_POLL_MS)


def _page_param(name: str) -> int:
    """쿼리 파라미터로 받은 페이지 번호를 정수로 변환한다. board_list()의 page
    처리와 동일한 원칙 — 값이 없거나 이상해도(?users_page=abc) 에러 없이
    1페이지로 취급한다.
    """
    page = request.args.get(name, 1, type=int)
    return page if page and page > 0 else 1


# 페이지가 있는 표 8개 — 대시보드가 한 표의 페이지만 넘길 때 ?only=<이름>으로 그 표만 받는다(guide46).
# 이름: (페이지 파라미터, db 조회 함수 이름, 응답의 목록 키, 응답의 전체 페이지 수 키)
_PAGED_SECTIONS = {
    "attempts": ("attempts_page", "list_recent_attempts", "recent_attempts", "attempts_total_pages"),
    "users": ("users_page", "list_users", "users", "users_total_pages"),
    "posts": ("posts_page", "list_posts", "recent_posts", "posts_total_pages"),
    "comments": ("comments_page", "list_comments_admin", "recent_comments", "comments_total_pages"),
    "admin_log": ("admin_log_page", "list_admin_login_log", "admin_login_log", "admin_log_total_pages"),
    "security_events": (
        "security_events_page", "list_security_events", "security_events", "security_events_total_pages",
    ),
    "security_incidents": (
        "security_incidents_page", "list_security_incidents", "security_incidents", "security_incidents_total_pages",
    ),
    "access_requests": (
        "access_requests_page", "list_pending_requests", "access_requests", "access_requests_total_pages",
    ),
}


def _api_status_section(name: str):
    """표 하나의 이번 페이지만 돌려준다(?only=<이름>). 세션 확인 + 조회 1번(로그인 시도 표는 위치
    캐시 1번 더)으로 끝난다 — 전체 조회는 약 21번이다. 만료된 잠금 정리는 전체 갱신이 맡는다."""
    if name not in _PAGED_SECTIONS:
        return jsonify({"error": "알 수 없는 표입니다."}), 400
    page_param, query_name, rows_key, total_key = _PAGED_SECTIONS[name]
    rows, count = getattr(db, query_name)(_page_param(page_param), config.ADMIN_PAGE_SIZE)
    if name == "attempts":
        rows = _attach_locations(rows)
    return jsonify({rows_key: rows, total_key: max(1, math.ceil(count / config.ADMIN_PAGE_SIZE))})


# 이 서버 인스턴스가 마지막으로 만료된 잠금을 정리한 시각(time.monotonic). 대시보드 갱신마다 정리하지
# 않고 ADMIN_STATUS_RELEASE_INTERVAL_SECONDS에 한 번만 한다(guide46). 동시에 들어온 갱신 둘이 함께
# 정리하지 않게 잠금으로 보호한다.
_expiry_release_state = {"at": None}
_expiry_release_lock = threading.Lock()


def _release_expired_locks_if_due() -> None:
    """만료된 잠금 정리 3종(IP·회원 계정·관리자 계정)을 정해진 간격마다 동시에 돌린다.

    서로 무관하므로 동시에 돌리고(guide45), 호출한 쪽의 목록 조회보다는 먼저 끝난다 — 같이 돌리면
    방금 풀린 잠금이 한 주기 동안 "잠김"으로 보일 수 있다. 예외는 .result()가 그대로 다시 일으킨다.
    """
    interval = config.ADMIN_STATUS_RELEASE_INTERVAL_SECONDS
    now = time.monotonic()
    with _expiry_release_lock:
        last = _expiry_release_state["at"]
        if interval > 0 and last is not None and now - last < interval:
            return
        _expiry_release_state["at"] = now

    with ThreadPoolExecutor(max_workers=3) as executor:
        release_futures = [
            executor.submit(soar.try_release_expired_lockouts),
            executor.submit(soar.try_release_expired_account_lockouts),
            executor.submit(soar.try_release_expired_admin_account_lockouts),
        ]
        for future in release_futures:
            future.result()


def _build_permanent_locks(ip_lockouts: list[dict], account_lockouts: list[dict]) -> list[dict]:
    """active인 잠금 중 영구(PERMANENT)인 것만 골라 대시보드 "영구 잠금" 카드용 한 목록으로 만든다.

    이미 위에서 조회한 active_lockouts/active_account_lockouts를 걸러내기만 하므로 추가 조회가
    없다(계정의 "이메일 확인 불가" 배지용 email_status만 영구 계정이 있을 때 한 번 조회한다).
    """
    locks = [
        {
            "kind": "ip",
            "target": row["ip_address"],
            "locked_at": row.get("locked_at"),
            "promoted_at": row.get("promoted_at"),
            "permanent_reason": row.get("permanent_reason"),
            "recoverable": row.get("recoverable"),
            "failure_count": row.get("failure_count"),
            "email_status": None,
        }
        for row in ip_lockouts
        if row.get("lock_type") == "PERMANENT"
    ]
    accounts = [row for row in account_lockouts if row.get("lock_type") == "PERMANENT"]
    statuses = db.get_email_statuses([row["username"] for row in accounts]) if accounts else {}
    locks += [
        {
            "kind": "account",
            "target": row["username"],
            "locked_at": row.get("locked_at"),
            "promoted_at": row.get("promoted_at"),
            "permanent_reason": row.get("permanent_reason"),
            "recoverable": row.get("recoverable"),
            "failure_count": row.get("failure_count"),
            "email_status": statuses.get(row["username"]),
        }
        for row in accounts
    ]
    return locks


@admin_bp.route("/api/status", methods=["GET"])
@login_required
def api_status():
    """대시보드가 5초마다 호출하는 API(탭이 보일 때만, guide45). 최신 상태를 JSON으로 돌려준다.

    JSON이란? 파이썬의 딕셔너리(dict)와 거의 똑같이 생긴, 서버와 브라우저가
    데이터를 주고받을 때 가장 널리 쓰이는 표준 형식이다. jsonify()는 파이썬
    딕셔너리를 이 JSON 형식으로 자동 변환해서 브라우저에 보내주는 Flask 도구다.

    관리자 대시보드의 페이지가 있는 표 8개(최근 로그인 시도/회원/게시글/댓글/관리자
    로그인 기록/보안 이벤트/연관 사건/AI 조기 경보 — _PAGED_SECTIONS)는 각자
    ?attempts_page=, ?users_page=, ?posts_page=, ?comments_page=, ?admin_log_page=,
    ?security_events_page=, ?security_incidents_page=, ?access_requests_page=로
    현재 보고 있는 페이지 번호를 받는다 —
    dashboard/api.js가 board_list()와 동일한 페이지 번호 방식으로 표를 그릴 수 있도록,
    각 표의 이번 페이지 데이터와 전체 페이지 수(*_total_pages)를 함께 내려준다
    (예전에는 최근 N개만 고정으로 가져와서, 그 이상 쌓이면 오래된 항목이 화면에서
    아예 사라졌었다).

    db.list_*() 함수들은 (이번 페이지 데이터, 전체 개수) 튜플을 돌려준다 — 목록
    조회와 개수 조회를 별도 쿼리 두 번으로 나누지 않고 한 번의 왕복으로 끝내기
    위해서다(db.list_recent_attempts() 설명 참고).

    그래도 여전히 서로 무관한 쿼리들(처음엔 9개, 지금은 표·카드·권한 조회까지 17개)을
    하나씩 순서대로 기다리면, Supabase까지의 왕복 시간(쿼리 하나당 대략 150~500ms)이
    그대로 다 더해진다 — 쿼리가 9개였던 시절에도 요청 하나가 2~3초까지 걸렸고, 특히
    Vercel 서버리스 환경은 매 요청마다 커넥션을 새로 맺어야 해서 체감이 더 심했다.
    ThreadPoolExecutor로 이 쿼리들을 동시에 보내면
    전체 소요 시간이 "가장 느린 쿼리 하나" 수준으로 줄어든다(실측 약 5배 개선).
    IP 위치 조회(_attach_locations)는 attempts 결과가 있어야 시작할 수 있는
    후속 작업이라 별도로 남겨뒀지만, 나머지 futures가 백그라운드에서 계속
    돌고 있는 동안 같이 실행되므로 추가 대기 시간은 거의 없다.

    응답 속도(guide46):
    - ?only=<표 이름>이면 그 표 하나만 돌려준다(_api_status_section) — 페이지 넘기기용.
    - 만료된 잠금 정리는 정해진 간격마다만 한다(_release_expired_locks_if_due).
    - 아래 조회는 전부 한 번에(동시 처리 한도 = 조회 개수) 보낸다. "관리자 계정 관리" 카드의
      권한 확인과 목록도 같은 배치에 넣고, 권한이 없으면 목록은 버린다(응답에 싣지 않는다).
    """
    only = request.args.get("only")
    if only is not None:
        return _api_status_section(only)

    _release_expired_locks_if_due()

    attempts_page = _page_param("attempts_page")
    users_page = _page_param("users_page")
    posts_page = _page_param("posts_page")
    comments_page = _page_param("comments_page")
    admin_log_page = _page_param("admin_log_page")
    security_events_page = _page_param("security_events_page")
    security_incidents_page = _page_param("security_incidents_page")
    access_requests_page = _page_param("access_requests_page")
    # login_required가 세션을 확인하면서 계정(role 포함)을 이미 조회해 g.admin에 담아뒀다(guide37).
    # 아래 스레드에서는 g를 쓸 수 없으므로 여기서 먼저 꺼내둔다.
    role = g.admin["role"]

    with ThreadPoolExecutor(max_workers=17) as executor:
        attempts_future = executor.submit(db.list_recent_attempts, attempts_page, config.ADMIN_PAGE_SIZE)
        lockouts_future = executor.submit(db.list_active_lockouts)
        # "현재 잠긴 IP / 계정" 카드의 계정 잠금 목록 — IP 잠금 목록과 같은 배치로 병렬 조회.
        account_lockouts_future = executor.submit(db.list_active_account_lockouts)
        admin_account_lockouts_future = executor.submit(db.list_active_admin_account_lockouts)
        admin_log_future = executor.submit(db.list_admin_login_log, admin_log_page, config.ADMIN_PAGE_SIZE)
        users_future = executor.submit(db.list_users, users_page, config.ADMIN_PAGE_SIZE)
        signup_future = executor.submit(db.get_signup_enabled)
        posts_future = executor.submit(db.list_posts, posts_page, config.ADMIN_PAGE_SIZE)
        comments_future = executor.submit(db.list_comments_admin, comments_page, config.ADMIN_PAGE_SIZE)
        security_events_future = executor.submit(
            db.list_security_events, security_events_page, config.ADMIN_PAGE_SIZE
        )
        # 연관 사건(SIEM 상관분석, Track C guide27) 표 — 위 보안 이벤트와 같은
        # 페이지네이션 방식이다.
        security_incidents_future = executor.submit(
            db.list_security_incidents, security_incidents_page, config.ADMIN_PAGE_SIZE
        )
        # "AI 조기 경보" 표(Track A, guide31) — 위 표들과 같은 페이지네이션 방식이다.
        access_requests_future = executor.submit(
            db.list_pending_requests, access_requests_page, config.ADMIN_PAGE_SIZE
        )
        # 영구 잠금 + 이메일 복구(guide33/34-a) 카드용 데이터와, 화면이 어떤 버튼을 보여줄지
        # 정하는 데 쓰는 "현재 관리자의 권한 목록" — 위 쿼리들과 같은 배치로 병렬 조회한다.
        recovery_future = executor.submit(db.list_recent_recovery_requests, 20)
        exemptions_future = executor.submit(db.list_active_ip_exemptions, 20)
        permissions_future = executor.submit(db.list_role_permissions, role)
        # "관리자 계정 관리" 카드 — 권한 확인과 목록을 같은 배치로 미리 보낸다(권한이 없으면 목록은 버림).
        can_manage_admins_future = executor.submit(db.has_permission, role, "manage_admin_users")
        admin_users_future = executor.submit(db.list_admin_users)

        attempts, attempts_count = attempts_future.result()
        recent_attempts = _attach_locations(attempts)  # 다른 future들이 도는 동안 함께 실행됨
        active_lockouts = lockouts_future.result()
        active_account_lockouts = account_lockouts_future.result()
        active_admin_account_lockouts = admin_account_lockouts_future.result()
        admin_log, admin_log_count = admin_log_future.result()
        users, users_count = users_future.result()
        signup_enabled = signup_future.result()
        posts, posts_count = posts_future.result()
        comments, comments_count = comments_future.result()
        security_events, security_events_count = security_events_future.result()
        security_incidents, security_incidents_count = security_incidents_future.result()
        access_requests, access_requests_count = access_requests_future.result()
        recovery_requests = recovery_future.result()
        ip_exemptions = exemptions_future.result()
        permissions = permissions_future.result()
        can_manage_admins = can_manage_admins_future.result()
        # 권한이 없으면 결과를 꺼내지 않는다 — 실패했더라도 그 관리자의 화면과는 무관하다.
        admin_users = admin_users_future.result() if can_manage_admins else None

    response_data = {
            "recent_attempts": recent_attempts,
            "attempts_total_pages": max(1, math.ceil(attempts_count / config.ADMIN_PAGE_SIZE)),
            "active_lockouts": active_lockouts,
            "active_account_lockouts": active_account_lockouts,
            # 관리자 계정 단위 잠금(guide38) — 회원 계정 잠금과 같은 카드에 "관리자" 배지로 표시한다.
            "active_admin_account_lockouts": active_admin_account_lockouts,
            "admin_login_log": admin_log,
            "admin_log_total_pages": max(1, math.ceil(admin_log_count / config.ADMIN_PAGE_SIZE)),
            "users": users,
            "users_total_pages": max(1, math.ceil(users_count / config.ADMIN_PAGE_SIZE)),
            "signup_enabled": signup_enabled,
            # 게시판 관리 섹션(관리자 대시보드)용 — recent_attempts 등과 같은 폴링
            # 주기(dashboard/main.js, 5초)로 함께 갱신된다.
            "recent_posts": posts,
            "posts_total_pages": max(1, math.ceil(posts_count / config.ADMIN_PAGE_SIZE)),
            "recent_comments": comments,
            "comments_total_pages": max(1, math.ceil(comments_count / config.ADMIN_PAGE_SIZE)),
            # 보안 이벤트(위험등급 통합) 섹션 — security-risk-response-summary.md 5절.
            "security_events": security_events,
            "security_events_total_pages": max(1, math.ceil(security_events_count / config.ADMIN_PAGE_SIZE)),
            # 연관 사건(SIEM 상관분석) 섹션 — Track C guide27.
            "security_incidents": security_incidents,
            "security_incidents_total_pages": max(1, math.ceil(security_incidents_count / config.ADMIN_PAGE_SIZE)),
            # AI 조기 경보(Track A guide31) 섹션 — 임계값을 아직 안 넘긴 코앞
            # 구간에서 LLM이 위험하다고 판단해 등록한 PENDING 요청과, SIEM HIGH 사건의
            # 영구 잠금 후보(guide33, security/lockdown.py)를 보여준다.
            "access_requests": access_requests,
            "access_requests_total_pages": max(1, math.ceil(access_requests_count / config.ADMIN_PAGE_SIZE)),
            # 영구 잠금 + 이메일 복구(guide33/34-a): 영구 잠금 카드·복구 요청 카드·IP 예외
            # 카드와, 현재 관리자가 가진 권한(버튼 노출용 — 실제 검사는 서버가 따로 한다).
            "permanent_locks": _build_permanent_locks(active_lockouts, active_account_lockouts),
            "recovery_requests": recovery_requests,
            "ip_exemptions": ip_exemptions,
            "permissions": permissions,
        }

    # "관리자 계정 관리" 카드는 super_admin(manage_admin_users 권한 보유자)에게만
    # 응답에 실어 보낸다 — viewer/security_admin의 화면에는 이 키 자체가 없어서
    # dashboard/render/tables.js가 카드를 숨긴다(다른 관리자 계정 목록이 노출되지 않음).
    if can_manage_admins:
        response_data["admin_users"] = admin_users

    return jsonify(response_data)
