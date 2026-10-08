# ============================================================================
# routes/email.py — 메일 링크가 여는 이메일 확인 화면 2개 (guide40)
#
#   GET  /email/confirm?t=...   확인 화면만 보여준다(토큰을 소비하지 않음)
#   POST /email/confirm         토큰을 1회 소비하고 이메일 인증 / 이메일 변경을 반영한다
#
# 로그인을 요구하지 않는다 — 메일은 휴대폰에서 여는 경우가 많고, 링크에 담긴 추측할 수 없는
# 토큰을 가진 사람이 곧 그 메일함의 주인이기 때문이다. GET에서 소비하지 않는 이유는 메일 보안
# 스캐너가 링크를 미리 열어도 토큰이 닳지 않게 하기 위해서다(routes/recovery.py와 같은 원칙).
# POST에는 app.py가 IP당 분당 한도(EMAIL_CONFIRM_RATE_LIMIT_PER_MINUTE)를 따로 건다.
# ============================================================================

from flask import Blueprint, render_template, request

import db
import email_verification
from helpers import mask_username

email_bp = Blueprint("email", __name__)

INVALID_MESSAGE = "만료되었거나 이미 사용된 링크입니다. 필요하면 회원 화면에서 다시 요청해주세요."

_RESULT_MESSAGES = {
    email_verification.CONFIRMED_VERIFIED: ("이메일 인증 완료", "이메일이 인증되었습니다."),
    email_verification.CONFIRMED_CHANGED: (
        "이메일 변경 완료",
        "계정 이메일이 변경되었습니다. 기존 주소로 변경 알림을 보냈습니다.",
    ),
    email_verification.CONFIRM_STALE: (
        "이메일 확인",
        "인증 메일을 보낸 뒤 이메일이 바뀌어 이 링크로는 인증할 수 없습니다. 회원 화면에서 다시 요청해주세요.",
    ),
    email_verification.CONFIRM_TAKEN: (
        "이메일 변경 실패",
        "그사이 다른 계정이 이 주소를 등록해 변경할 수 없습니다. 기존 이메일은 그대로입니다.",
    ),
}


def _invalid():
    return render_template("email_confirm.html", mode="invalid", title="이메일 확인", message=INVALID_MESSAGE)


@email_bp.route("/email/confirm", methods=["GET"])
def email_confirm_form():
    """메일 링크(?t=토큰)가 여는 확인 화면. 토큰은 소비하지 않는다."""
    token = request.args.get("t", "")
    row = email_verification.get_pending_email_token(token)
    if row is None:
        return _invalid()
    user = db.get_user_by_id(row["user_id"])
    if user is None:
        return _invalid()
    return render_template(
        "email_confirm.html",
        mode="confirm",
        title=email_verification.PURPOSE_LABELS.get(row["purpose"], "이메일 확인"),
        message=None,
        token=token,
        purpose=row["purpose"],
        masked_username=mask_username(user["username"]),
        masked_email=email_verification.mask_email(row["email"]),
    )


@email_bp.route("/email/confirm", methods=["POST"])
def email_confirm_submit():
    """확인 버튼 — 토큰을 1회 소비하고 이메일 인증 또는 이메일 변경을 반영한다."""
    result, _user = email_verification.confirm(request.form.get("t", ""))
    if result == email_verification.CONFIRM_INVALID:
        return _invalid()
    title, message = _RESULT_MESSAGES[result]
    return render_template("email_confirm.html", mode="done", title=title, message=message)
