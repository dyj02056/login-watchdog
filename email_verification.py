# ============================================================================
# email_verification.py — "이메일 담당": 이메일 인증 / 이메일 변경 확인 링크를 만들고 처리한다 (guide40)
#
# 왜 필요한가: 비밀번호 재설정(guide41)은 "계정을 되찾는 메일"이라 확인된 주소로만 보내야 한다.
# 그런데 지금까지 가입 이메일은 형식만 검사했고(오타·남의 주소 그대로 저장), 이메일 변경은 세션만
# 있으면 비밀번호 확인도 없이 바로 됐다(세션 탈취 → 이메일 바꿔치기 → 계정 탈취). 이 모듈이
#   1) 가입 직후·대시보드에서 인증 링크를 보내고(EMAIL_VERIFY → users.email_status = VERIFIED)
#   2) 이메일 변경을 "새 주소로 보낸 링크를 눌러야 반영"되게 하고(EMAIL_CHANGE), 바뀌면 옛 주소로 알린다.
#
# 원칙은 영구 잠금 복구(routes/recovery.py)와 같다 — 토큰은 해시만 저장, 링크는 PUBLIC_BASE_URL로만,
# GET은 확인 화면만(메일 스캐너가 미리 열어도 안 닳게) 실제 처리는 POST에서 조건부 1회 소비.
# 메일 링크를 눌렀다는 것 자체가 그 메일함의 주인이라는 증거라서, 처리하면 VERIFIED가 된다.
#
# 라우트(routes/member.py, routes/email.py, routes/auth.py)는 "언제" 부를지만 정하고, 실제
# 판단·발송은 전부 이 파일이 한다 — alert.py/mailer.py처럼 결과를 예외 대신 값으로 돌려준다.
# ============================================================================

import secrets
from datetime import datetime, timedelta, timezone

import config
import db
import mailer
from helpers import hash_secret, public_base_url

# send_verification() / request_email_change()가 돌려주는 결과
SENT = "SENT"                    # 메일을 보냈다(또는 화면에는 보냈다고 안내할 상황)
ALREADY_VERIFIED = "ALREADY_VERIFIED"
RATE_LIMITED = "RATE_LIMITED"    # 쿨다운 또는 하루 한도
UNAVAILABLE = "UNAVAILABLE"      # 메일 설정 없음·발송 실패·반송 — 화면에서 "잠시 후 다시" 안내

# confirm()이 돌려주는 결과
CONFIRMED_VERIFIED = "VERIFIED"
CONFIRMED_CHANGED = "CHANGED"
CONFIRM_INVALID = "INVALID"      # 없는·만료·이미 쓴 토큰
CONFIRM_STALE = "STALE"          # 인증 메일을 보낸 뒤 이메일이 바뀌었음
CONFIRM_TAKEN = "TAKEN"          # 링크를 누르기 전에 다른 계정이 그 주소를 차지함

PURPOSE_LABELS = {
    db.email_tokens.PURPOSE_EMAIL_VERIFY: "이메일 인증",
    db.email_tokens.PURPOSE_EMAIL_CHANGE: "이메일 변경",
}


def mask_email(email: str) -> str:
    """메일·화면에 보여줄 주소를 가린다(예: alice@example.com → a***e@example.com)."""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = (local[:1] + "*") if local else ""
    else:
        masked = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked}@{domain}" if domain else masked


def _rate_limited(user_id: int, purpose: str) -> bool:
    """같은 회원·용도로 최근 쿨다운 안에 보냈거나, 하루 한도를 채웠으면 True."""
    count, latest = db.get_email_token_activity(user_id, purpose, 24)
    if count >= config.EMAIL_TOKEN_MAX_PER_DAY:
        return True
    if latest:
        latest_dt = datetime.fromisoformat(latest)
        if latest_dt.tzinfo is None:
            latest_dt = latest_dt.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - latest_dt < timedelta(seconds=config.EMAIL_TOKEN_COOLDOWN_SECONDS):
            return True
    return False


def _issue(user_id: int, purpose: str, email: str, ip: str) -> tuple[dict, str] | None:
    """토큰을 만들어 저장하고 (행, 메일에 넣을 링크)를 돌려준다. 링크를 만들 수 없거나(운영에서
    PUBLIC_BASE_URL 없음) 동시 요청에 밀렸으면 None."""
    base_url = public_base_url()
    if not base_url:
        mailer.report_failure(mailer.FAIL_CONFIG, "PUBLIC_BASE_URL이 설정되지 않아 이메일 인증 메일을 보내지 않았습니다.")
        return None
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.EMAIL_TOKEN_TTL_MINUTES)
    row = db.create_email_token(user_id, purpose, email, hash_secret(token), ip, expires_at.isoformat())
    if row is None:
        return None
    return row, f"{base_url}/email/confirm?t={token}"


def _after_send(user_id: int, row: dict, result: str) -> str:
    """메일 발송 결과를 반영한다 — 못 보냈으면 토큰을 취소하고, 수신자 영구 거부면 반송 표시."""
    if result == mailer.SENT:
        return SENT
    db.revoke_email_token(row["id"])
    if result == mailer.REFUSED and row["purpose"] == db.email_tokens.PURPOSE_EMAIL_VERIFY:
        db.set_user_email_status(user_id, "UNDELIVERABLE")
    return UNAVAILABLE


def send_verification(user: dict, ip: str) -> str:
    """이 회원의 현재 이메일로 인증 링크를 보낸다(가입 직후, 대시보드 "다시 보내기")."""
    if user.get("email_status") == "VERIFIED":
        return ALREADY_VERIFIED
    purpose = db.email_tokens.PURPOSE_EMAIL_VERIFY
    if _rate_limited(user["id"], purpose):
        return RATE_LIMITED
    issued = _issue(user["id"], purpose, user["email"], ip)
    if issued is None:
        return UNAVAILABLE
    row, link = issued
    return _after_send(user["id"], row, mailer.send_email_verification(user["email"], link))


def request_email_change(user: dict, new_email: str, ip: str) -> str:
    """새 주소로 변경 확인 링크를 보낸다. 이메일은 링크를 눌러야 바뀐다.

    그 주소를 다른 계정이 이미 쓰고 있으면 링크 대신 "이미 등록된 주소" 안내 메일을 보낸다.
    어느 쪽이든 토큰 행은 똑같이 만들고(하루 한도·쿨다운에 들어가게, 처리 시간도 비슷하게),
    호출부(화면)에는 똑같이 SENT를 돌려준다 — 화면으로는 남의 이메일 가입 여부를 알 수 없다.
    """
    purpose = db.email_tokens.PURPOSE_EMAIL_CHANGE
    if _rate_limited(user["id"], purpose):
        return RATE_LIMITED
    issued = _issue(user["id"], purpose, new_email, ip)
    if issued is None:
        return UNAVAILABLE
    row, link = issued

    if db.is_email_taken(new_email, exclude_user_id=user["id"]):
        db.revoke_email_token(row["id"])
        mailer.send_email_in_use_notice(new_email)
        return SENT
    return _after_send(user["id"], row, mailer.send_email_change_confirmation(new_email, link))


def get_pending_token(token: str) -> dict | None:
    """링크(GET)로 들어왔을 때 확인 화면에 보여줄 토큰 정보. 소비하지 않는다."""
    if not token:
        return None
    return db.get_pending_email_token(hash_secret(token))


def confirm(token: str) -> tuple[str, dict | None]:
    """확인 버튼(POST)으로 토큰을 소비하고 용도에 맞게 반영한다. (결과, 회원 행)을 돌려준다."""
    row = get_pending_token(token)
    if row is None:
        return CONFIRM_INVALID, None
    consumed = db.consume_email_token(row["id"])
    if consumed is None:
        return CONFIRM_INVALID, None
    user = db.get_user_by_id(consumed["user_id"])
    if user is None:
        return CONFIRM_INVALID, None

    if consumed["purpose"] == db.email_tokens.PURPOSE_EMAIL_VERIFY:
        # 메일을 보낸 뒤 이메일을 바꿨다면 옛 주소로 간 링크는 새 주소를 인증하지 못한다.
        if not db.mark_user_email_verified(user["id"], consumed["email"]):
            return CONFIRM_STALE, user
        return CONFIRMED_VERIFIED, user

    if consumed["purpose"] == db.email_tokens.PURPOSE_EMAIL_CHANGE:
        old_email = user["email"]
        if not db.change_user_email(user["id"], consumed["email"]):
            return CONFIRM_TAKEN, user
        # 바뀐 사실을 옛 주소로 알린다 — 세션을 탈취한 사람이 바꿨다면 원래 주인이 알아챈다.
        mailer.send_email_changed_notice(old_email, mask_email(consumed["email"]))
        return CONFIRMED_CHANGED, {**user, "email": consumed["email"], "email_status": "VERIFIED"}

    return CONFIRM_INVALID, None


def mark_verified_after_recovery(user: dict) -> None:
    """영구 잠금 복구 링크·코드로 복구에 성공했다 = 그 메일을 받았다는 증거이므로 VERIFIED로
    표시한다(guide40). 실패해도 복구 자체에는 영향을 주지 않는다."""
    if user.get("email_status") != "VERIFIED":
        db.mark_user_email_verified(user["id"], user["email"])
