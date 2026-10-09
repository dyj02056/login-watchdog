# ============================================================================
# routes/password.py — 비밀번호 찾기(재설정) 화면 4개 (guide41)
#
#   GET  /password/forgot   아이디 입력 폼 (?username=으로 미리 채울 수 있다 — 프로필의 연결 링크)
#   POST /password/forgot   재설정 링크 메일 요청 — 결과와 무관하게 항상 같은 안내, 고정 응답 시간
#   GET  /password/reset    메일 링크가 여는 새 비밀번호 입력 화면 (토큰을 소비하지 않음)
#   POST /password/reset    새 비밀번호 검사 → 토큰 1회 소비 → 비밀번호 변경 → 모든 기기 로그아웃
#
# 판단·발송은 services/email_verification.py가 한다. 원칙은 영구 잠금 복구(routes/recovery.py)와 같다 —
# 계정 존재 여부·인증 여부를 응답 문구로도 응답 시간으로도 드러내지 않고, 링크는 PUBLIC_BASE_URL로만
# 만들며, GET은 화면만 보여준다. 두 POST에는 app.py가 IP당 분당 한도를 따로 건다.
# ============================================================================

import time

from flask import Blueprint, flash, redirect, render_template, request, url_for

import config
import db
from helpers import get_request_ip, is_bot_submission, mask_username, run_with_fixed_response_time
from security import soar
from services import email_verification

password_bp = Blueprint("password", __name__)

GENERIC_SENT_MESSAGE = (
    "인증된 이메일이 등록된 계정이라면 비밀번호 재설정 메일을 보냈습니다. 메일함을 확인해주세요."
)
RATE_LIMITED_MESSAGE = "요청이 너무 많습니다. 잠시 후 다시 시도해주세요."
INVALID_LINK_MESSAGE = "만료되었거나 이미 사용된 링크입니다. 비밀번호 찾기를 다시 요청해주세요."


@password_bp.route("/password/forgot", methods=["GET"])
def password_forgot_form():
    """아이디 입력 폼. 프로필의 "현재 비밀번호가 기억나지 않나요?" 링크는 아이디를 미리 채워 보낸다."""
    username = request.args.get("username", "")
    if not config.USERNAME_PATTERN.match(username):
        username = ""
    return render_template("password_forgot.html", message=None, username=username)


@password_bp.route("/password/forgot", methods=["POST"])
def password_forgot_submit():
    """재설정 메일을 요청한다. 아이디 없음·미인증·반송·회원별 한도 모두 같은 안내로 답한다.
    IP 빈도 제한에 걸렸을 때만 다른 문구를 보여준다 — IP 기준이라 계정 존재 여부와 무관하다."""
    started = time.monotonic()
    ip = get_request_ip()

    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        return render_template("password_forgot.html", message=GENERIC_SENT_MESSAGE, username="")

    username = request.form.get("username", "").strip()

    def work():
        purpose = db.email_tokens.PURPOSE_PASSWORD_RESET
        if db.count_email_tokens_by_ip(ip, purpose, 1) >= config.PASSWORD_RESET_MAX_PER_IP_PER_HOUR:
            return RATE_LIMITED_MESSAGE
        email_verification.request_password_reset(username, ip)
        return GENERIC_SENT_MESSAGE

    result = {}
    run_with_fixed_response_time(lambda: result.update(message=work()), started)
    message = result.get("message", GENERIC_SENT_MESSAGE)
    return render_template("password_forgot.html", message=message, username="")


def _reset_form(token: str, user: dict, message: str | None):
    return render_template(
        "password_reset.html", mode="form", token=token, message=message,
        masked_username=mask_username(user["username"]), min_length=config.MIN_PASSWORD_LENGTH,
    )


def _invalid():
    return render_template("password_reset.html", mode="invalid", message=INVALID_LINK_MESSAGE)


@password_bp.route("/password/reset", methods=["GET"])
def password_reset_form():
    """메일 링크(?t=토큰)가 여는 새 비밀번호 입력 화면. 토큰은 소비하지 않는다 — 메일 보안
    스캐너가 링크를 미리 열어도 사용자가 나중에 정상적으로 쓸 수 있어야 하기 때문이다."""
    token = request.args.get("t", "")
    target = email_verification.get_reset_target(token)
    if target is None:
        return _invalid()
    return _reset_form(token, target[1], None)


@password_bp.route("/password/reset", methods=["POST"])
def password_reset_submit():
    """새 비밀번호를 검사한 뒤에만 토큰을 소비한다 — 입력 실수 때문에 링크가 닳지 않게 하기 위해서다.
    바꾸면 session_version이 올라가 모든 기기의 로그인이 끊기고, 알림 메일이 간다."""
    token = request.form.get("t", "")
    target = email_verification.get_reset_target(token)
    if target is None:
        return _invalid()

    new_password = request.form.get("new_password", "")
    if len(new_password) < config.MIN_PASSWORD_LENGTH:
        return _reset_form(token, target[1], f"비밀번호는 최소 {config.MIN_PASSWORD_LENGTH}자 이상이어야 합니다.")
    if new_password != request.form.get("new_password_confirm", ""):
        return _reset_form(token, target[1], "새 비밀번호와 확인이 일치하지 않습니다.")

    result, _user = email_verification.reset_password(token, new_password)
    if result != email_verification.RESET_DONE:
        return _invalid()
    flash("비밀번호가 재설정되었습니다. 모든 기기의 로그인이 해제되었으니 새 비밀번호로 로그인해주세요.")
    return redirect(url_for("auth.login"))
