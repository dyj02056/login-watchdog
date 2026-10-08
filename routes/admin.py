# ============================================================================
# routes/admin.py — 관리자 로그인/로그아웃(/admin/*) + 관리자 대시보드 화면 및 API
#
# 원래 app.py의 "관리자 로그인/로그아웃" / "관리자 대시보드 화면 및 API"
# 두 섹션을 그대로 옮겨왔다. 배경은 docs/refactor/2026-09-15-file-split.md 참고.
# ============================================================================

import ipaddress
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, session, url_for

import config
import db
import detector
import lockdown
import soar
from helpers import (
    _attach_locations,
    clear_admin_session,
    get_request_ip,
    is_bot_submission,
    login_required,
    require_permission,
    start_admin_session,
)

admin_bp = Blueprint("admin", __name__)


# ============================================================================
# 관리자 로그인/로그아웃 (/admin/login, /admin/logout)
# — 감시 대상(/login)과 완전히 분리된 별도 경로이므로 위의 IP 잠금 로직과 무관하다.
# ============================================================================

@admin_bp.route("/admin/login", methods=["GET"])
def admin_login():
    """관리자 로그인 화면을 보여준다. 이미 로그인된 상태라면 대시보드로 바로 보낸다.

    화면은 /login과 똑같은 login_form.html을 공유하되, form_action만 이 라우트로
    지정해서 실제 제출은 admin_login_submit()이 처리한다 — 겉보기로는 두 로그인
    화면을 구분할 수 없지만, 뒤에서 어떤 표(users vs admin_users)와 비교하고 IP
    잠금이 적용되는지는 여전히 완전히 분리되어 있다.
    """
    if "admin_username" in session:
        return redirect(url_for("admin.admin_dashboard"))
    return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))


@admin_bp.route("/admin/login", methods=["POST"])
def admin_login_submit():
    """관리자 로그인 폼 제출을 처리한다.

    /login(감시 대상 로그인)과 마찬가지로 IP 잠금을 적용한다 — 이전에는 이 라우트가
    시도 기록만 남길 뿐 잠금 판정을 전혀 하지 않아서, 관리자 계정만 브루트포스에
    무방비로 노출돼 있었다(18단계 보안 점검에서 발견 및 보완). 관리자 계정이 뚫리면
    회원 삭제·잠금 해제·회원가입 On/Off까지 전부 장악되므로 우선순위가 가장 높았다.

    IP 잠금만으로는 IP를 나눠 쓰는 분산 브루트포스를 못 막아서, 회원 로그인처럼 관리자
    계정 단위 잠금도 건다(guide38). 아이디가 실제로 있든 없든 같은 기준으로 잠그고 같은
    문구로 거절해서 관리자 아이디 존재 여부가 드러나지 않게 한다. 계정 잠금은 공격자가
    관리자를 못 들어오게 만드는 수단도 될 수 있으므로, 허용 목록(PERMANENT_LOCK_IP_ALLOWLIST,
    관리자 PC) IP에서의 로그인은 계정 잠금을 건너뛴다(IP 잠금은 그대로 적용).
    """
    # 1) 시간이 지나 자동으로 풀려야 할 잠금들을 정리 (login_submit()과 동일)
    soar.try_release_expired_lockouts()
    soar.try_release_expired_admin_account_lockouts()

    ip = get_request_ip()

    # 허니팟 필드가 채워져 있으면 사람이 아니라 자동화 스크립트라고 보고,
    # 자격 증명 확인/시도 기록 없이 즉시 거부한다 (L7 공격 보강 계획 Tier 3).
    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))

    # 2) 이미 잠긴 IP라면 자격 증명 확인 자체를 건너뛰고 즉시 거부
    #    영구 잠금(T5)된 관리자 IP에는 이메일 복구·예외가 없다 — 관리자 로그인은 위험도가
    #    가장 높아서 오직 관리자 해제(대시보드/scripts/unlock_ip.py --permanent)로만 풀린다.
    if detector.is_locked(ip):
        if detector.get_ip_lock_state(ip) == detector.LOCK_STATE_PERMANENT:
            flash("이 네트워크는 차단되어 있습니다. 관리자에게 문의해주세요.")
        else:
            flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # 3) 이 관리자 아이디가 계정 단위로 잠겨 있으면 비밀번호를 확인하지 않고 거절한다(guide38).
    #    허용 목록 IP는 건너뛴다 — 공격자가 일부러 틀려서 관리자를 잠가도 관리자 PC에서는
    #    로그인해서 대시보드에서 풀 수 있게 하기 위해서다.
    account_locked = detector.is_admin_account_locked(username)
    if account_locked and not lockdown.is_ip_allowlisted(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))

    success = db.verify_admin_credentials(username, password)
    # 성공/실패와 무관하게 "누가 언제 관리자 로그인을 시도했는지"는 항상 기록해서
    # 나중에 대시보드에서 감사(audit) 이력을 확인할 수 있게 한다.
    db.log_admin_attempt(username, success, ip)

    if success:
        # 세션(session)은 "이 브라우저는 로그인된 상태다"를 서버가 기억하게 해주는
        # 저장 공간이다. 여기 값을 넣어두면, 같은 브라우저로 다시 요청이 올 때마다
        # Flask가 자동으로 이 값을 복원해줘서 "로그인 유지"가 가능해진다.
        # 아이디뿐 아니라 기본키와 로그인 시각까지 넣는다 — 요청마다 DB의 계정과 대조해서,
        # 삭제된 계정의 쿠키나 수명(ADMIN_SESSION_MAX_HOURS)이 지난 쿠키를 걸러낸다(guide37).
        admin_id = db.get_admin_id_by_username(username)
        if admin_id is not None:
            start_admin_session(admin_id, username)
            return redirect(url_for("admin.admin_dashboard"))

    # 4) 이 실패로 인해 방금 임계값을 넘었는지 확인하고, 넘었다면 잠근다
    #    (login_submit()과 동일한 detector/soar 조합 — 잠금 상태 자체는 lockouts
    #    표를 공유하므로, 이 IP는 /login 쪽에서도 함께 잠긴다). IP 기준을 먼저 보고,
    #    아니면 IP와 무관하게 이 관리자 아이디의 총 실패 횟수를 본다(guide38).
    suspicious, failure_count = detector.is_admin_suspicious(ip)
    if suspicious:
        distinct_usernames = detector.count_distinct_admin_usernames(ip)
        soar.enforce_lockout(ip, failure_count, distinct_usernames, is_admin=True)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))

    # 이미 잠긴 계정(허용 목록 IP라서 여기까지 온 경우)은 다시 잠그지 않는다 — 실패할
    # 때마다 Slack 알림과 이벤트가 반복되는 것을 막는다.
    if not account_locked:
        account_suspicious, account_failure_count = detector.is_admin_account_suspicious(username)
        if account_suspicious:
            distinct_ips = db.count_recent_distinct_admin_ips_by_username(username)
            soar.enforce_admin_account_lockout(username, account_failure_count, distinct_ips, ip)
            flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
            return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))

    flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))


@admin_bp.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    """로그아웃 처리. 관리자 세션 값만 지운다 — 같은 브라우저에서 회원으로도 로그인해 있었다면
    그 세션은 그대로 둔다(guide37 이전에는 session.clear()로 회원 세션까지 끊겼다)."""
    clear_admin_session()
    return redirect(url_for("admin.admin_login"))


# ============================================================================
# 관리자 대시보드 화면 및 API — 전부 login_required로 보호됨
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

    poll_interval_ms : dashboard.js가 몇 밀리초마다 /api/status를 다시 부를지.
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

    관리자 대시보드의 표 7개(최근 로그인 시도/회원/게시글/댓글/관리자 로그인 기록/
    보안 이벤트/연관 사건)는 각자 ?attempts_page=, ?users_page=, ?posts_page=,
    ?comments_page=, ?admin_log_page=, ?security_events_page=,
    ?security_incidents_page=로 현재 보고 있는 페이지 번호를 받는다 —
    dashboard.js가 board_list()와 동일한 페이지 번호 방식으로 표를 그릴 수 있도록,
    각 표의 이번 페이지 데이터와 전체 페이지 수(*_total_pages)를 함께 내려준다
    (예전에는 최근 N개만 고정으로 가져와서, 그 이상 쌓이면 오래된 항목이 화면에서
    아예 사라졌었다).

    db.list_*() 함수들은 (이번 페이지 데이터, 전체 개수) 튜플을 돌려준다 — 목록
    조회와 개수 조회를 별도 쿼리 두 번으로 나누지 않고 한 번의 왕복으로 끝내기
    위해서다(db.list_recent_attempts() 설명 참고).

    그래도 여전히 서로 무관한 쿼리 9개(로그인 시도/잠긴 IP/관리자 로그인 기록/
    회원/회원가입 설정/게시글/댓글/보안 이벤트/연관 사건)를 하나씩 순서대로
    기다리면, Supabase까지의 왕복 시간(쿼리 하나당 대략 150~500ms)이 그대로 다
    더해져서 요청 하나가 2~3초까지 걸렸다 — 특히 Vercel 서버리스 환경은 매
    요청마다 커넥션을 새로 맺어야 해서 체감이 더 심했다. ThreadPoolExecutor로 이 9개를 동시에 보내면
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
        # "관리자 계정 관리" 카드가 이 응답에 포함될지 결정하려면 지금 요청한
        # 관리자의 role을 알아야 한다 — 다른 8개 쿼리와 같은 배치에 묶어서
        # 병렬로 조회하면(순서상 9번째지만 동시에 실행됨) 이 role 조회 때문에
        # 폴링 응답이 느려지지 않는다.
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
            # 주기(dashboard.js, 5초)로 함께 갱신된다.
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
            # 구간에서 LLM이 위험하다고 판단해 등록한 PENDING 요청만 보여준다.
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
    # dashboard.js가 카드를 숨긴다(다른 관리자 계정 목록이 노출되지 않음).
    if can_manage_admins:
        response_data["admin_users"] = admin_users

    return jsonify(response_data)


@admin_bp.route("/api/unlock", methods=["POST"])
@require_permission("unlock_ip")
def api_unlock():
    """대시보드의 "즉시 해제" 버튼을 눌렀을 때 브라우저가 호출하는 API.

    이 라우트가 login_required로 보호되어 있으므로, 이 함수가 실행되는 시점엔
    이미 "로그인된 관리자의 요청"이라는 게 보장된 상태다 — 그래서 soar.manual_release는
    권한 확인을 다시 하지 않고 바로 실행에만 집중할 수 있다(4단계 soar.py 설명 참고).
    """
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "ip 값이 필요합니다."}), 400

    released = soar.manual_release(ip)
    if not released and lockdown.is_permanent_ip(ip):
        return jsonify({"success": False, "error": "영구 잠금은 '영구 해제'로만 풀 수 있습니다."}), 409
    return jsonify({"success": released})


@admin_bp.route("/api/unlock-account", methods=["POST"])
@require_permission("unlock_ip")
def api_unlock_account():
    """대시보드 "현재 잠긴 IP / 계정" 카드에서 계정 잠금의 "즉시 해제" 버튼을
    눌렀을 때 호출되는 API. /api/unlock의 계정 버전이며, 별도 권한을 새로 만들지
    않고 같은 "잠금 해제" 권한(unlock_ip)을 그대로 쓴다.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    if not username:
        return jsonify({"success": False, "error": "username 값이 필요합니다."}), 400

    released = soar.manual_release_account(username)
    if not released and lockdown.is_permanent_account(username):
        return jsonify({"success": False, "error": "영구 잠금은 '영구 해제'로만 풀 수 있습니다."}), 409
    return jsonify({"success": released})


@admin_bp.route("/api/unlock-admin-account", methods=["POST"])
@require_permission("unlock_admin_account")
def api_unlock_admin_account():
    """잠긴 관리자 계정의 "즉시 해제" 버튼이 호출하는 API(guide38). super_admin만 가진
    unlock_admin_account 권한이 필요하다 — 관리자 계정의 잠금을 푸는 것은 회원 계정보다
    위험도가 높아서 /api/unlock-account(unlock_ip 권한)와 권한을 나눴다.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    if not username:
        return jsonify({"success": False, "error": "username 값이 필요합니다."}), 400

    return jsonify({"success": soar.manual_release_admin_account(username)})


@admin_bp.route("/api/access-requests/approve", methods=["POST"])
@require_permission("approve_pending_action")
def api_access_requests_approve():
    """대시보드 "AI 조기 경보" 표의 "승인" 버튼을 눌렀을 때 브라우저가 호출하는
    API (Track A, guide31).

    security_admin/super_admin 둘 다 가진다 — unlock_ip/resolve_security_event와
    같은 급의 "IP·계정 관련 보안 조치" 권한이라, 그 두 액션과 동일한 두 역할에게
    부여한다(login_watchdog_expansion_plan.md 논의 참고). session의
    문지기(require_permission)가 확인해 둔 g.admin의 id로 "누가 승인했는지"를
    access_requests에 함께 남긴다.
    """
    data = request.get_json(silent=True) or {}
    request_id = data.get("request_id")
    if not request_id:
        return jsonify({"success": False, "error": "request_id 값이 필요합니다."}), 400

    admin_id = g.admin["id"]
    executed = soar.execute_approved_request(request_id, admin_id)
    return jsonify({"success": executed})


@admin_bp.route("/api/access-requests/reject", methods=["POST"])
@require_permission("approve_pending_action")
def api_access_requests_reject():
    """"AI 조기 경보" 표의 "반려" 버튼을 눌렀을 때 호출되는 API. 승인과 동일한
    권한을 쓴다 — 승인/반려는 "같은 결정을 내릴 수 있는 권한"의 앞뒤 면일 뿐이다.
    """
    data = request.get_json(silent=True) or {}
    request_id = data.get("request_id")
    if not request_id:
        return jsonify({"success": False, "error": "request_id 값이 필요합니다."}), 400

    admin_id = g.admin["id"]
    rejected = soar.reject_pending_request(request_id, admin_id)
    return jsonify({"success": rejected})


@admin_bp.route("/api/security-events/resolve", methods=["POST"])
@require_permission("resolve_security_event")
def api_security_events_resolve():
    """대시보드의 "처리 완료" 버튼을 눌렀을 때 브라우저가 호출하는 API.

    /api/board/posts/delete와 동일한 패턴 — login_required가 이미 "로그인된 관리자의
    요청"임을 보장해주므로, db.resolve_security_event는 권한 확인 없이 바로 실행한다.
    CRITICAL(IP 잠금) 이벤트는 잠금이 풀릴 때 자동으로 처리되므로(soar.py의
    resolve_security_events_for_ip 참고), 이 버튼은 HIGH/MEDIUM 이벤트에서만 쓰인다.
    """
    data = request.get_json(silent=True) or {}
    event_id = data.get("event_id")
    if not event_id:
        return jsonify({"success": False, "error": "event_id 값이 필요합니다."}), 400

    resolved = db.resolve_security_event(event_id)
    return jsonify({"success": resolved})


@admin_bp.route("/api/security-incidents/resolve", methods=["POST"])
@require_permission("resolve_incident")
def api_security_incidents_resolve():
    """대시보드 "연관 사건" 표의 "해결" 버튼을 눌렀을 때 브라우저가 호출하는 API.

    IP 잠금 해제(/api/unlock)와는 별개다 — 잠금을 푸는 것은 접속 차단을 거두는
    조치이고, 사건 해결은 "관리자가 내용을 확인하고 조사가 끝났다"는 판단이라
    오직 이 API로만 사건이 CLOSED가 된다. 누가 해결했는지는 요청 본문이 아니라
    로그인 세션(admin_username)에서 가져온다 — 본문 값은 위조할 수 있기 때문이다.
    """
    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    if isinstance(incident_id, bool) or not isinstance(incident_id, int):
        return jsonify({"success": False, "error": "incident_id 값이 필요합니다."}), 400

    resolved = db.resolve_incident(incident_id, session["admin_username"])
    return jsonify({"success": resolved})


# ============================================================================
# 영구 잠금 + 이메일 복구 관리 API (guide33) — 쓰기 API 하나당 권한 하나(1:1)
#
#   promote_permanent_lock   : security_admin, super_admin  (수동 영구 승격)
#   release_permanent_lock   : super_admin만               (영구 잠금 완전 해제 — 가장 신중해야 하는 조치)
#   revoke_ip_exemption      : security_admin, super_admin  (IP 예외 회수)
#   revoke_recovery_request  : security_admin, super_admin  (진행 중인 복구 요청 취소)
# ============================================================================

_PERMANENT_LOCK_KINDS = ("ip", "account")


def _int_field(data: dict, key: str) -> int | None:
    """JSON 본문에서 정수 id 하나를 꺼낸다. bool(True/False)은 파이썬에서 int의 하위 타입이라
    따로 걸러야 한다(api_security_incidents_resolve와 같은 이유)."""
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


@admin_bp.route("/api/permanent-locks/promote", methods=["POST"])
@require_permission("promote_permanent_lock")
def api_permanent_locks_promote():
    """대시보드 "영구 잠금 수동 승격" 폼이 호출하는 API — IP나 계정을 관리자가 직접 영구 잠금한다.

    수동 승격은 이메일 복구 대상이 아니라 관리자만 풀 수 있게(ADMIN_ONLY) 건다.
    허용 목록 IP(관리자 PC 등)와 가입되지 않은 아이디는 거부한다.
    """
    data = request.get_json(silent=True) or {}
    kind = data.get("target_kind")
    value = (data.get("target_value") or "").strip()
    reason = (data.get("reason") or "").strip()
    if kind not in _PERMANENT_LOCK_KINDS or not value or not reason:
        return jsonify({"success": False, "error": "target_kind(ip/account), target_value, reason이 필요합니다."}), 400

    note = f"{session['admin_username']}: {reason}"
    if kind == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return jsonify({"success": False, "error": "올바른 IP 주소가 아닙니다."}), 400
        if lockdown.is_ip_allowlisted(value):
            return jsonify({"success": False, "error": "허용 목록의 IP는 영구 잠금할 수 없습니다."}), 400
        promoted = lockdown.promote_ip(value, "ADMIN_MANUAL", "ADMIN_ONLY", note=note)
    else:
        if db.get_user_by_username(value) is None:
            return jsonify({"success": False, "error": "가입되지 않은 아이디입니다."}), 404
        promoted = lockdown.promote_account(value, "ADMIN_MANUAL", "ADMIN_ONLY", note=note)

    if not promoted:
        return jsonify({"success": False, "error": "이미 영구 잠금 상태입니다."}), 409
    return jsonify({"success": True})


@admin_bp.route("/api/permanent-locks/release", methods=["POST"])
@require_permission("release_permanent_lock")
def api_permanent_locks_release():
    """대시보드 영구 잠금 카드의 "영구 해제" 버튼이 호출하는 API(super_admin 전용).

    사유(note)가 비어 있으면 거부한다 — "누가 언제 왜 풀었는지"가 lock_history에 남아야 하기
    때문이다. 해제한 관리자는 요청 본문이 아니라 로그인 세션에서 가져온다(본문은 위조 가능).
    """
    data = request.get_json(silent=True) or {}
    kind = data.get("target_kind")
    value = (data.get("target_value") or "").strip()
    note = (data.get("note") or "").strip()
    if kind not in _PERMANENT_LOCK_KINDS or not value:
        return jsonify({"success": False, "error": "target_kind(ip/account)와 target_value가 필요합니다."}), 400
    if not note:
        return jsonify({"success": False, "error": "해제 사유(note)를 입력해야 합니다."}), 400

    released = lockdown.release(kind, value, f"admin:{session['admin_username']}", note)
    if not released:
        return jsonify({"success": False, "error": "영구 잠금 상태가 아닌 대상입니다."}), 404
    return jsonify({"success": True})


@admin_bp.route("/api/ip-exemptions/revoke", methods=["POST"])
@require_permission("revoke_ip_exemption")
def api_ip_exemptions_revoke():
    """IP 영구 잠금 예외(본인+본인 기기 출입증)를 관리자가 회수하는 API."""
    data = request.get_json(silent=True) or {}
    exemption_id = _int_field(data, "id")
    if exemption_id is None:
        return jsonify({"success": False, "error": "id 값이 필요합니다."}), 400
    reason = (data.get("reason") or "").strip() or f"관리자 회수 ({session['admin_username']})"

    if not db.revoke_ip_exemption(exemption_id, reason):
        return jsonify({"success": False, "error": "유효한 예외가 아닙니다."}), 404
    return jsonify({"success": True})


@admin_bp.route("/api/recovery-requests/revoke", methods=["POST"])
@require_permission("revoke_recovery_request")
def api_recovery_requests_revoke():
    """진행 중(PENDING)인 이메일 복구 요청을 관리자가 취소하는 API."""
    data = request.get_json(silent=True) or {}
    request_id = _int_field(data, "id")
    if request_id is None:
        return jsonify({"success": False, "error": "id 값이 필요합니다."}), 400

    if not db.revoke_recovery_request(request_id):
        return jsonify({"success": False, "error": "진행 중인 복구 요청이 아닙니다."}), 404
    return jsonify({"success": True})


@admin_bp.route("/api/users/delete", methods=["POST"])
@require_permission("delete_user")
def api_users_delete():
    """대시보드의 회원 목록에서 "삭제" 버튼을 눌렀을 때 호출되는 API.

    /api/unlock과 똑같은 패턴이다 — login_required가 이미 "로그인된 관리자의
    요청"임을 보장해주므로, 이 함수는 삭제 실행에만 집중한다.
    """
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "user_id 값이 필요합니다."}), 400

    deleted = db.delete_user(user_id)
    return jsonify({"success": deleted})


@admin_bp.route("/api/settings/signup", methods=["POST"])
@require_permission("toggle_signup")
def api_settings_signup():
    """대시보드의 "회원가입 켜기/끄기" 토글을 눌렀을 때 호출되는 API.

    {"enabled": true} 또는 {"enabled": false}를 받아 db.set_signup_enabled()로
    Supabase에 반영한다. 이 값을 서버 메모리가 아니라 Supabase에 저장해두는
    이유는 db.get_signup_enabled() 설명(db.py) 참고 — 로컬/Vercel 등 여러 곳에서
    서버가 동시에 돌아도 항상 같은 값을 보게 하기 위함이다.
    """
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"success": False, "error": "enabled(true/false) 값이 필요합니다."}), 400

    db.set_signup_enabled(enabled)
    return jsonify({"success": True, "signup_enabled": enabled})


@admin_bp.route("/api/board/posts/delete", methods=["POST"])
@require_permission("delete_post")
def api_board_posts_delete():
    """관리자 대시보드의 "게시글 관리" 섹션에서 임의 게시글을 삭제할 때 호출되는 API.

    /api/users/delete와 동일한 패턴 — login_required가 이미 "로그인된 관리자의
    요청"임을 보장해주므로, 회원 본인 글인지 여부와 무관하게 바로 삭제한다
    (docs/board-comment/02-design-decisions.md 결정 #2 — 삭제 권한: 본인 + 관리자).
    """
    data = request.get_json(silent=True) or {}
    post_id = data.get("post_id")
    if not post_id:
        return jsonify({"success": False, "error": "post_id 값이 필요합니다."}), 400

    deleted = db.delete_post(post_id)
    return jsonify({"success": deleted})


@admin_bp.route("/api/board/comments/delete", methods=["POST"])
@require_permission("delete_comment")
def api_board_comments_delete():
    """관리자 대시보드에서 임의 댓글을 삭제할 때 호출되는 API. 위 함수와 동일한 패턴."""
    data = request.get_json(silent=True) or {}
    comment_id = data.get("comment_id")
    if not comment_id:
        return jsonify({"success": False, "error": "comment_id 값이 필요합니다."}), 400

    deleted = db.delete_comment(comment_id)
    return jsonify({"success": deleted})


# super_admin만 만들 수 있는 역할. 여기 super_admin을 넣지 않은 게 핵심 안전장치다 —
# 이 화면(그리고 아래 삭제 API)으로는 super_admin 계정을 만들거나 지울 수 없게
# 만들어서, "super_admin은 1명만 둔다"는 운영 정책(login_watchdog_expansion_plan.md
# 논의)을 코드 수준에서도 지키게 한다.
_CREATABLE_ADMIN_ROLES = ("security_viewer", "security_admin")


@admin_bp.route("/api/admin-users/create", methods=["POST"])
@require_permission("manage_admin_users")
def api_admin_users_create():
    """대시보드 "관리자 계정 관리" 카드의 생성 폼이 호출하는 API.

    scripts/create_admin.py와 동일한 검증 규칙(아이디 형식, 비밀번호 길이)을
    쓰고, db.create_admin_user()도 그대로 재사용한다 — 다만 역할은
    _CREATABLE_ADMIN_ROLES 두 가지로만 제한한다. 화면(select 옵션)에서도
    super_admin을 아예 안 보여주지만, fetch()를 직접 조작해 super_admin을
    보내는 요청도 여기서 한 번 더 막아야 실질적인 방어가 된다.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    role = data.get("role", "")

    if not config.USERNAME_PATTERN.match(username):
        return jsonify({"success": False, "error": "아이디는 영문/숫자/밑줄 3~20자여야 합니다."}), 400
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return jsonify({"success": False, "error": f"비밀번호는 최소 {config.MIN_PASSWORD_LENGTH}자 이상이어야 합니다."}), 400
    if role not in _CREATABLE_ADMIN_ROLES:
        return jsonify({"success": False, "error": "role은 security_viewer 또는 security_admin만 가능합니다."}), 400

    created = db.create_admin_user(username, password, role)
    if not created:
        return jsonify({"success": False, "error": "이미 존재하는 아이디입니다."}), 400
    return jsonify({"success": True})


@admin_bp.route("/api/admin-users/delete", methods=["POST"])
@require_permission("manage_admin_users")
def api_admin_users_delete():
    """대시보드 "관리자 계정 관리" 카드의 "삭제" 버튼이 호출하는 API.

    삭제 전에 대상의 role을 먼저 조회해서 super_admin이면 거부한다 —
    db.delete_admin_user() 자체는 그 구분을 하지 않으므로(db/admin.py 설명 참고),
    여기서 막지 않으면 마지막 super_admin 계정까지 지워질 수 있다.
    """
    data = request.get_json(silent=True) or {}
    admin_id = data.get("admin_id")
    if not admin_id:
        return jsonify({"success": False, "error": "admin_id 값이 필요합니다."}), 400

    target_role = db.get_admin_role_by_id(admin_id)
    if target_role == "super_admin":
        return jsonify({"success": False, "error": "super_admin 계정은 이 화면에서 삭제할 수 없습니다."}), 400

    deleted = db.delete_admin_user(admin_id)
    return jsonify({"success": deleted})
