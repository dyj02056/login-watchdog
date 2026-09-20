# ============================================================================
# routes/admin.py — 관리자 로그인/로그아웃(/admin/*) + 관리자 대시보드 화면 및 API
#
# 원래 app.py의 "관리자 로그인/로그아웃" / "관리자 대시보드 화면 및 API"
# 두 섹션을 그대로 옮겨왔다. 배경은 docs/refactor/2026-09-15-file-split.md 참고.
# ============================================================================

import math
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

import config
import db
import detector
import soar
from helpers import _attach_locations, get_request_ip, is_bot_submission, login_required

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
    """
    # 1) 시간이 지나 자동으로 풀려야 할 잠금들을 정리 (login_submit()과 동일)
    soar.try_release_expired_lockouts()

    ip = get_request_ip()

    # 허니팟 필드가 채워져 있으면 사람이 아니라 자동화 스크립트라고 보고,
    # 자격 증명 확인/시도 기록 없이 즉시 거부한다 (L7 공격 보강 계획 Tier 3).
    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))

    # 2) 이미 잠긴 IP라면 자격 증명 확인 자체를 건너뛰고 즉시 거부
    if detector.is_locked(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    success = db.verify_admin_credentials(username, password)
    # 성공/실패와 무관하게 "누가 언제 관리자 로그인을 시도했는지"는 항상 기록해서
    # 나중에 대시보드에서 감사(audit) 이력을 확인할 수 있게 한다.
    db.log_admin_attempt(username, success, ip)

    if success:
        # 세션(session)은 "이 브라우저는 로그인된 상태다"를 서버가 기억하게 해주는
        # 저장 공간이다. 여기 값을 넣어두면, 같은 브라우저로 다시 요청이 올 때마다
        # Flask가 자동으로 이 값을 복원해줘서 "로그인 유지"가 가능해진다.
        session["admin_username"] = username
        return redirect(url_for("admin.admin_dashboard"))

    # 3) 이 실패로 인해 방금 임계값을 넘었는지 확인하고, 넘었다면 잠근다
    #    (login_submit()과 동일한 detector/soar 조합 — 잠금 상태 자체는 lockouts
    #    표를 공유하므로, 이 IP는 /login 쪽에서도 함께 잠긴다).
    suspicious, failure_count = detector.is_admin_suspicious(ip)
    if suspicious:
        distinct_usernames = detector.count_distinct_admin_usernames(ip)
        soar.enforce_lockout(ip, failure_count, distinct_usernames, is_admin=True)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
    else:
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template("login_form.html", form_action=url_for("admin.admin_login_submit"))


@admin_bp.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    """로그아웃 처리. 세션에 저장된 로그인 정보를 전부 지운다."""
    session.clear()
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


@admin_bp.route("/api/status", methods=["GET"])
@login_required
def api_status():
    """대시보드가 2~3초마다 호출하는 API. 최신 상태를 JSON으로 돌려준다.

    JSON이란? 파이썬의 딕셔너리(dict)와 거의 똑같이 생긴, 서버와 브라우저가
    데이터를 주고받을 때 가장 널리 쓰이는 표준 형식이다. jsonify()는 파이썬
    딕셔너리를 이 JSON 형식으로 자동 변환해서 브라우저에 보내주는 Flask 도구다.

    관리자 대시보드의 표 6개(최근 로그인 시도/회원/게시글/댓글/관리자 로그인 기록/
    보안 이벤트)는 각자 ?attempts_page=, ?users_page=, ?posts_page=, ?comments_page=,
    ?admin_log_page=, ?security_events_page=로 현재 보고 있는 페이지 번호를 받는다 —
    dashboard.js가 board_list()와 동일한 페이지 번호 방식으로 표를 그릴 수 있도록,
    각 표의 이번 페이지 데이터와 전체 페이지 수(*_total_pages)를 함께 내려준다
    (예전에는 최근 N개만 고정으로 가져와서, 그 이상 쌓이면 오래된 항목이 화면에서
    아예 사라졌었다).

    db.list_*() 함수들은 (이번 페이지 데이터, 전체 개수) 튜플을 돌려준다 — 목록
    조회와 개수 조회를 별도 쿼리 두 번으로 나누지 않고 한 번의 왕복으로 끝내기
    위해서다(db.list_recent_attempts() 설명 참고).

    그래도 여전히 서로 무관한 쿼리 8개(로그인 시도/잠긴 IP/관리자 로그인 기록/
    회원/회원가입 설정/게시글/댓글/보안 이벤트)를 하나씩 순서대로 기다리면, Supabase까지의
    왕복 시간(쿼리 하나당 대략 150~500ms)이 그대로 다 더해져서 요청 하나가
    2~3초까지 걸렸다 — 특히 Vercel 서버리스 환경은 매 요청마다 커넥션을 새로
    맺어야 해서 체감이 더 심했다. ThreadPoolExecutor로 이 8개를 동시에 보내면
    전체 소요 시간이 "가장 느린 쿼리 하나" 수준으로 줄어든다(실측 약 5배 개선).
    IP 위치 조회(_attach_locations)는 attempts 결과가 있어야 시작할 수 있는
    후속 작업이라 별도로 남겨뒀지만, 나머지 futures가 백그라운드에서 계속
    돌고 있는 동안 같이 실행되므로 추가 대기 시간은 거의 없다.
    """
    soar.try_release_expired_lockouts()

    attempts_page = _page_param("attempts_page")
    users_page = _page_param("users_page")
    posts_page = _page_param("posts_page")
    comments_page = _page_param("comments_page")
    admin_log_page = _page_param("admin_log_page")
    security_events_page = _page_param("security_events_page")

    with ThreadPoolExecutor(max_workers=8) as executor:
        attempts_future = executor.submit(db.list_recent_attempts, attempts_page, config.ADMIN_PAGE_SIZE)
        lockouts_future = executor.submit(db.list_active_lockouts)
        admin_log_future = executor.submit(db.list_admin_login_log, admin_log_page, config.ADMIN_PAGE_SIZE)
        users_future = executor.submit(db.list_users, users_page, config.ADMIN_PAGE_SIZE)
        signup_future = executor.submit(db.get_signup_enabled)
        posts_future = executor.submit(db.list_posts, posts_page, config.ADMIN_PAGE_SIZE)
        comments_future = executor.submit(db.list_comments_admin, comments_page, config.ADMIN_PAGE_SIZE)
        security_events_future = executor.submit(
            db.list_security_events, security_events_page, config.ADMIN_PAGE_SIZE
        )

        attempts, attempts_count = attempts_future.result()
        recent_attempts = _attach_locations(attempts)  # 다른 future들이 도는 동안 함께 실행됨
        active_lockouts = lockouts_future.result()
        admin_log, admin_log_count = admin_log_future.result()
        users, users_count = users_future.result()
        signup_enabled = signup_future.result()
        posts, posts_count = posts_future.result()
        comments, comments_count = comments_future.result()
        security_events, security_events_count = security_events_future.result()

    return jsonify(
        {
            "recent_attempts": recent_attempts,
            "attempts_total_pages": max(1, math.ceil(attempts_count / config.ADMIN_PAGE_SIZE)),
            "active_lockouts": active_lockouts,
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
        }
    )


@admin_bp.route("/api/unlock", methods=["POST"])
@login_required
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
    return jsonify({"success": released})


@admin_bp.route("/api/security-events/resolve", methods=["POST"])
@login_required
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


@admin_bp.route("/api/users/delete", methods=["POST"])
@login_required
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
@login_required
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
@login_required
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
@login_required
def api_board_comments_delete():
    """관리자 대시보드에서 임의 댓글을 삭제할 때 호출되는 API. 위 함수와 동일한 패턴."""
    data = request.get_json(silent=True) or {}
    comment_id = data.get("comment_id")
    if not comment_id:
        return jsonify({"success": False, "error": "comment_id 값이 필요합니다."}), 400

    deleted = db.delete_comment(comment_id)
    return jsonify({"success": deleted})
