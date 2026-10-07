# ============================================================================
# routes/member.py — 회원 대시보드 (/dashboard) — 전부 member_login_required로 보호됨
#
# 이름이 "/admin/dashboard"와 비슷해 보이지만 완전히 다른 화면이다. 회원은
# 본인 계정에 관한 정보만 볼 수 있고, 다른 회원 정보나 관리자 기능(잠긴 IP,
# 전체 회원 목록 등)에는 접근할 수 없다 — member_login_required와
# login_required가 서로 다른 세션 키를 확인하기 때문에 이 구분이 코드 수준에서
# 강제된다.
#
# 원래 app.py의 "회원 대시보드" 섹션을 그대로 옮겨왔다. 배경은
# docs/refactor/2026-09-15-file-split.md 참고.
# ============================================================================

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

import config
import db
import detector
import mailer
import soar
from helpers import (
    _attach_locations,
    clear_member_session,
    get_request_ip,
    is_bot_submission,
    member_login_required,
)

member_bp = Blueprint("member", __name__)


def _logout_missing_member():
    """세션은 남아있는데 실제 계정이 사라진 경우(예: 관리자가 회원 삭제 버튼을
    눌렀는데 그 회원이 다른 탭에서 아직 로그인 상태였던 경우) 세션을 정리하고
    로그인 화면으로 돌려보낸다.

    member_login_required는 "세션에 값이 있는지"만 확인하지, 그 값이 가리키는
    회원이 지금도 실제로 존재하는지는 확인하지 않는다 — 그래서 회원용 화면들이
    db.get_user_by_id()로 다시 한번 확인하고, 없으면 이 함수를 부른다.
    """
    clear_member_session()
    flash("계정 정보를 찾을 수 없습니다. 다시 로그인해주세요.")
    return redirect(url_for("auth.login"))


@member_bp.route("/dashboard", methods=["GET"])
@member_login_required
def member_dashboard():
    """로그인한 회원 본인을 위한 첫 화면. 인사말과 이동 버튼 2개만 보여준다.

    인사말에는 "표시 이름"(user.name)이 설정돼 있으면 그걸 쓰고, 아직 프로필을
    한 번도 안 고쳐서 비어있으면(기본값 '') 로그인 아이디로 대신 보여준다.
    (예전 버전은 항상 아이디만 보여줬는데, 프로필에서 이름을 바꿔도 인사말에
    반영되지 않는 것처럼 보이는 문제가 있었다 — 이번에 고쳤다.)
    """
    user = db.get_user_by_id(session["user_id"])
    if user is None:
        return _logout_missing_member()
    display_name = user["name"] if user["name"] else session["username"]
    return render_template("member_dashboard.html", display_name=display_name)


@member_bp.route("/dashboard/history", methods=["GET"])
@member_login_required
def member_history():
    """본인의 최근 로그인 시도 기록만 보여준다.

    db.list_attempts_by_username()에 session["username"]을 넘겨서, 다른 회원의
    시도 기록은 애초에 조회조차 되지 않게 한다 — "권한 확인 후 전체를 가져와서
    화면에서 걸러낸다"가 아니라 "애초에 본인 것만 데이터베이스에 물어본다"가
    더 안전한 설계다.
    """
    attempts = _attach_locations(db.list_attempts_by_username(session["username"], 20))
    return render_template("member_history.html", attempts=attempts)


@member_bp.route("/dashboard/profile", methods=["GET"])
@member_login_required
def member_profile():
    """프로필(표시 이름/이메일) 조회 및 수정 화면을 보여준다."""
    user = db.get_user_by_id(session["user_id"])
    if user is None:
        return _logout_missing_member()
    return render_template("member_profile.html", user=user)


@member_bp.route("/dashboard/profile", methods=["POST"])
@member_login_required
def member_profile_submit():
    """프로필 수정 폼 제출을 처리한다.

    처리가 끝나면 render_template으로 바로 화면을 그리지 않고 redirect()로
    /dashboard/profile을 "다시 방문"하게 만든다. 이렇게 하면 사용자가 수정 후
    브라우저를 새로고침해도 폼이 다시 제출되며 오류가 나는 대신, 그냥 최신
    프로필을 다시 보여준다("Post-Redirect-Get" 패턴이라고 부른다).
    """
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()

    if not email:
        flash("이메일을 입력해주세요.")
        return redirect(url_for("member.member_profile"))

    updated = db.update_user_profile(session["user_id"], name, email)
    if not updated:
        flash("이미 다른 회원이 사용 중인 이메일입니다.")
        return redirect(url_for("member.member_profile"))

    flash("프로필이 수정되었습니다.")
    return redirect(url_for("member.member_profile"))


@member_bp.route("/dashboard/password", methods=["POST"])
@member_login_required
def member_password_submit():
    """비밀번호 변경 폼 제출을 처리한다(guide35).

    1) 새 비밀번호 형식을 먼저 확인한다 — 여기서 걸리는 건 본인 확인과 무관한 입력 실수라서
       실패 횟수에 넣지 않는다.
    2) 현재 비밀번호를 확인한다 — 세션만 탈취한 사람이 비밀번호를 바꾸지 못하게 하는 장치다.
       틀리면 로그인 실패와 똑같이 기록하고 같은 임계값으로 잠근다. 그러지 않으면 이 화면이
       "로그인 잠금 없이 비밀번호를 무한히 맞춰보는" 우회로가 된다.
    3) 바꾸면 세션 세대 번호가 올라가 다른 기기의 로그인이 모두 끊긴다(이 기기는 유지).
       계정 이메일로 변경 알림을 보내서, 본인이 한 일이 아니면 바로 알 수 있게 한다.
    """
    ip = get_request_ip()
    username = session["username"]

    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        flash("일시적인 오류가 발생했습니다. 다시 시도해주세요.")
        return redirect(url_for("member.member_profile"))

    user = db.get_user_by_id(session["user_id"])
    if user is None:
        return _logout_missing_member()
    if detector.is_account_locked(username):
        clear_member_session()
        flash("잠긴 계정입니다. 잠시 후 다시 로그인해주세요.")
        return redirect(url_for("auth.login"))

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    new_password_confirm = request.form.get("new_password_confirm", "")

    if not current_password or not new_password:
        flash("현재 비밀번호와 새 비밀번호를 모두 입력해주세요.")
        return redirect(url_for("member.member_profile"))
    if len(new_password) < config.MIN_PASSWORD_LENGTH:
        flash(f"새 비밀번호는 최소 {config.MIN_PASSWORD_LENGTH}자 이상이어야 합니다.")
        return redirect(url_for("member.member_profile"))
    if new_password != new_password_confirm:
        flash("새 비밀번호와 확인이 일치하지 않습니다.")
        return redirect(url_for("member.member_profile"))
    if new_password == current_password:
        flash("새 비밀번호가 현재 비밀번호와 같습니다.")
        return redirect(url_for("member.member_profile"))

    if not db.verify_user_credentials(username, current_password):
        db.log_attempt(ip, username, False)
        if _lock_if_suspicious(ip, username):
            clear_member_session()
            flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
            return redirect(url_for("auth.login"))
        flash("현재 비밀번호가 올바르지 않습니다.")
        return redirect(url_for("member.member_profile"))

    session["session_version"] = db.update_user_password(user["id"], new_password)
    mailer.send_password_changed_notice(user["email"])
    flash("비밀번호가 변경되었습니다. 다른 기기의 로그인은 모두 해제되었습니다.")
    return redirect(url_for("member.member_profile"))


def _lock_if_suspicious(ip: str, username: str) -> bool:
    """비밀번호 변경 화면에서 현재 비밀번호를 틀렸을 때, 로그인 실패와 같은 기준으로 잠근다.
    이번 실패로 잠금이 걸렸으면 True. 이미 잠긴 IP(예: 영구 잠금 예외로 들어온 회원)는 다시
    잠그지 않는다 — 같은 IP에 5분 잠금 알림이 중복으로 나가지 않게 하기 위해서다."""
    locked = False
    if not detector.is_locked(ip):
        suspicious, failure_count = detector.is_suspicious(ip)
        if suspicious:
            soar.enforce_lockout(ip, failure_count, detector.count_distinct_usernames(ip))
            locked = True
    account_suspicious, account_failure_count = detector.is_account_suspicious(username)
    if account_suspicious:
        soar.enforce_account_lockout(
            username, account_failure_count, detector.count_distinct_ips_by_username(username), ip
        )
        locked = True
    return locked


@member_bp.route("/dashboard/logout", methods=["POST"])
@member_login_required
def member_logout():
    """회원 로그아웃 처리.

    admin_logout()과 달리 session.clear()를 쓰지 않고 회원 관련 키(username,
    user_id)만 콕 집어 지운다 — 만약 같은 브라우저에서 관리자로도 로그인되어
    있었다면, 회원만 로그아웃하고 관리자 세션은 그대로 유지하기 위해서다.
    """
    clear_member_session()
    return redirect(url_for("auth.login"))
