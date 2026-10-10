# ============================================================================
# routes/admin/login.py — 관리자 로그인/로그아웃 (/admin/login, /admin/logout)
#
# 예전 routes/admin.py(798줄)를 기능 묶음별로 나눈 조각 중 하나다. Blueprint(admin_bp)는
# routes/admin/__init__.py에서 하나만 만들고, 이 파일은 거기에 라우트를 붙이기만 한다
# — 그래서 엔드포인트 이름(url_for("admin.xxx"))은 나누기 전과 똑같다.
# 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

from flask import flash, redirect, render_template, request, session, url_for

import db
from helpers import (
    clear_admin_session,
    get_request_ip,
    is_bot_submission,
    login_required,
    start_admin_session,
)
from routes.admin import admin_bp
from security import detector, lockdown, soar


# ============================================================================
# 관리자 로그인/로그아웃 (/admin/login, /admin/logout)
# — 감시 대상(/login)과 별도 경로·별도 계정 표(admin_users)를 쓰지만, IP 잠금 표(lockouts)는
#   공유한다(아래 admin_login_submit 설명 참고).
# ============================================================================

@admin_bp.route("/admin/login", methods=["GET"])
def admin_login():
    """관리자 로그인 화면을 보여준다. 이미 로그인된 상태라면 대시보드로 바로 보낸다.

    화면은 /login과 똑같은 login_form.html을 공유하되, form_action만 이 라우트로
    지정해서 실제 제출은 admin_login_submit()이 처리한다 — 겉보기로는 두 로그인
    화면을 구분할 수 없지만, 뒤에서 어떤 표(users vs admin_users)와 비교하는지는
    완전히 분리되어 있다(IP 잠금 표만 공유한다 — admin_login_submit 설명 참고).
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
    #    가장 높아서 오직 관리자 해제(대시보드/scripts/management/unlock_ip.py --permanent)로만 풀린다.
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
