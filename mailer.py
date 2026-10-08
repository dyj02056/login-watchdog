# ============================================================================
# mailer.py — "우체부" 역할: 복구 메일을 실제로 보낸다 (guide34-a)
#
# alert.py(Slack)와 같은 구조다 — 메시지를 조립하는 함수(send_recovery_email 등)와
# 실제로 내보내는 함수 하나(_send_mail)로 나뉜다. "언제 보낼지"는 이 파일이 아니라
# routes/recovery.py가 결정한다.
#
# 전송 결과는 예외가 아니라 세 가지 문자열 중 하나로 돌려준다:
#   SENT    — 메일 서버가 받아줬다
#   REFUSED — 메일 서버가 "그런 수신자는 없다"고 영구적으로 거부했다(5xx).
#             존재하지 않는 이메일 주소일 가능성이 높다 → 호출부가 계정의
#             email_status를 UNDELIVERABLE로 올린다
#   FAILED  — 설정이 없거나 네트워크/일시 장애라 못 보냈다(이메일 문제라고 단정할 수 없음)
# (Gmail처럼 일단 받고 나중에 반송하는 비동기 반송은 SMTP 응답만으로는 알 수 없다.)
#
# FAILED일 때는 원인을 네 가지로 나눠 기록하고(설정/인증/연결/기타) 관리자에게 Slack으로
# 알린다. 사용자 화면은 계정 존재 여부가 드러나지 않게 항상 같은 안내를 보여주기 때문에,
# 알림이 없으면 메일 설정이 틀려도 아무도 모른 채 "메일을 보냈습니다"만 계속 뜨게 된다.
# ============================================================================

import smtplib
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

import alert
import config
from alert import _safe_print

SENT = "SENT"
REFUSED = "REFUSED"
FAILED = "FAILED"

# 실패 원인 분류 — 관리자가 "무엇을 고쳐야 하는지" 바로 알 수 있게 나눈다.
FAIL_CONFIG = "CONFIG"    # MAIL_BACKEND/SMTP_HOST/PUBLIC_BASE_URL 등 설정 누락
FAIL_AUTH = "AUTH"        # SMTP 아이디/앱 비밀번호가 틀림
FAIL_CONNECT = "CONNECT"  # 서버에 접속하지 못함(포트 차단, 시간 초과, 서버 다운)
FAIL_OTHER = "OTHER"      # 발신자 거부, 일시적 수신 거부 등
FAIL_INTERNAL = "INTERNAL"  # 복구 요청 처리 중 DB 연결 오류 등 서버 내부 오류(메일 설정 문제 아님)

# 같은 원인의 Slack 알림을 반복해서 보내지 않기 위한 마지막 알림 시각(프로세스 메모리).
# 서버리스(Vercel)에서는 인스턴스마다 따로라서 "완벽한 1회"는 아니고 알림 폭주를 줄이는 용도다.
_last_alert_at: dict[str, float] = {}


def report_failure(category: str, detail: str) -> None:
    """메일 발송 실패를 콘솔에 남기고, 같은 원인은 일정 시간(MAIL_FAILURE_ALERT_COOLDOWN_SECONDS)에
    한 번만 Slack으로 알린다. detail에는 비밀번호·토큰이 들어가지 않는다(예외 종류와 서버 응답 요약뿐)."""
    _safe_print(f"[mailer] 메일 발송 실패 ({category}): {detail}")
    now = time.monotonic()
    last = _last_alert_at.get(category)
    if last is not None and now - last < config.MAIL_FAILURE_ALERT_COOLDOWN_SECONDS:
        return
    _last_alert_at[category] = now
    alert.send_mail_failure_alert(category, detail)


def configuration_warnings() -> list[str]:
    """운영(production)에서 메일 설정이 비어 있으면 그 목록을 돌려준다(서버 시작 시 경고용).
    개발 환경은 console 백엔드가 기본이라 경고하지 않는다."""
    if not config.IS_PRODUCTION:
        return []
    warnings = []
    if config.MAIL_BACKEND != "smtp":
        warnings.append("MAIL_BACKEND가 smtp가 아니라서 복구 메일이 발송되지 않습니다.")
    elif not config.SMTP_HOST:
        warnings.append("SMTP_HOST가 비어 있어 복구 메일이 발송되지 않습니다.")
    elif config.SMTP_USER and not config.SMTP_PASSWORD:
        warnings.append("SMTP_USER는 있는데 SMTP_PASSWORD가 비어 있습니다.")
    if not config.PUBLIC_BASE_URL:
        warnings.append("PUBLIC_BASE_URL이 비어 있어 복구 메일을 보내지 않습니다.")
    return warnings


def print_configuration_warnings() -> None:
    for warning in configuration_warnings():
        _safe_print(f"[mailer] 경고: {warning}")


def _from_domain() -> str:
    """Message-ID에 쓸 도메인(MAIL_FROM의 @ 뒤). 없으면 localhost."""
    address = parseaddr(config.MAIL_FROM)[1]
    return address.rsplit("@", 1)[-1] if "@" in address else "localhost"


def _build_message(to_address: str, subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = config.MAIL_FROM
    message["To"] = to_address
    message["Subject"] = subject
    # Date와 Message-ID가 없는 메일은 스팸으로 분류되거나 일부 서버에서 거부되기 쉽다.
    message["Date"] = formatdate(localtime=False, usegmt=True)
    message["Message-ID"] = make_msgid(domain=_from_domain())
    message.set_content(body)
    return message


def _deliver(to_address: str, subject: str, body: str) -> tuple[str, str | None, str]:
    """메일 한 통을 전송하고 (결과, 실패 원인 분류, 설명)을 돌려준다. 예외는 밖으로 던지지 않는다.
    결과가 SENT/REFUSED면 분류는 None이다."""
    backend = config.MAIL_BACKEND

    if backend == "console":
        # console 백엔드는 토큰·코드가 담긴 메일 본문을 터미널(=서버 로그)에 그대로 찍는다.
        # 운영(FLASK_ENV=production)에서는 그 로그가 토큰을 남기게 되므로 절대 허용하지 않는다.
        if config.IS_PRODUCTION:
            return FAILED, FAIL_CONFIG, "운영 환경에서는 MAIL_BACKEND=console을 쓸 수 없습니다(메일 미발송)."
        _safe_print(f"[mailer] (console 백엔드, 개발 전용) To: {to_address}\nSubject: {subject}\n{body}")
        return SENT, None, ""

    if backend != "smtp" or not config.SMTP_HOST:
        return FAILED, FAIL_CONFIG, "메일 설정(MAIL_BACKEND=smtp, SMTP_HOST)이 없어 발송하지 못했습니다."

    message = _build_message(to_address, subject, body)
    try:
        # 타임아웃을 반드시 둔다 — Vercel 서버리스에서 메일 서버가 응답하지 않으면
        # 요청 전체가 오래 붙잡히기 때문이다. 포트 465(암시적 TLS)는 SMTP_USE_SSL, 587은 STARTTLS.
        smtp_class = smtplib.SMTP_SSL if config.SMTP_USE_SSL else smtplib.SMTP
        with smtp_class(config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT_SECONDS) as smtp:
            if config.SMTP_STARTTLS and not config.SMTP_USE_SSL:
                smtp.starttls()
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(message)
        return SENT, None, ""
    except smtplib.SMTPRecipientsRefused as e:
        # 모든 수신자가 거부됐다. 5xx(영구 거부)일 때만 "존재하지 않는 이메일"로 본다 —
        # 4xx(일시 거부, 예: 잠시 후 재시도)는 이메일 자체의 문제가 아니다.
        codes = [code for code, _ in e.recipients.values()]
        if codes and all(500 <= code < 600 for code in codes):
            return REFUSED, None, ""
        return FAILED, FAIL_OTHER, f"수신자 일시 거부: {codes}"
    except smtplib.SMTPAuthenticationError as e:
        # 아이디/앱 비밀번호가 틀렸거나, Gmail에서 앱 비밀번호가 아닌 일반 비밀번호를 쓴 경우다.
        return FAILED, FAIL_AUTH, f"SMTP 인증 실패(SMTP_USER/앱 비밀번호 확인): {e.smtp_code}"
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, OSError) as e:
        return FAILED, FAIL_CONNECT, f"SMTP 서버 접속 실패(SMTP_HOST/SMTP_PORT/방화벽 확인): {type(e).__name__}: {str(e)[:150]}"
    except smtplib.SMTPException as e:
        return FAILED, FAIL_OTHER, f"{type(e).__name__}: {str(e)[:150]}"


def _send_mail(to_address: str, subject: str, body: str) -> str:
    """메일 한 통을 전송하고 SENT / REFUSED / FAILED 중 하나를 돌려준다. 실패 원인은 기록하고 알린다."""
    result, category, detail = _deliver(to_address, subject, body)
    if result == FAILED:
        report_failure(category or FAIL_OTHER, detail)
    return result


def send_test_mail(to_address: str) -> tuple[str, str | None, str]:
    """설정 점검용 테스트 메일(scripts/send_test_mail.py). 실패해도 Slack 알림은 보내지 않고
    (결과, 실패 원인 분류, 설명)을 그대로 돌려준다."""
    return _deliver(
        to_address,
        "[로그인 워치독] 메일 발송 테스트",
        "이 메일이 보인다면 로그인 워치독의 복구 메일 발송 설정(SMTP)이 정상입니다.\n"
        "스팸함으로 들어왔다면 '스팸 아님'으로 표시해 주세요.",
    )


def send_recovery_email(to_address: str, link: str, code: str, kind: str) -> str:
    """복구 링크와 6자리 코드가 담긴 메일을 보낸다. kind는 'account'(계정 잠금 해제) 또는
    'ip'(이 네트워크에서 본인·본인 기기만 접속 허용)다."""
    if kind == "account":
        purpose = "계정 영구 잠금을 해제"
    else:
        purpose = "이 네트워크에서 회원님과 요청하신 기기의 접속을 허용"
    body = (
        f"로그인 워치독에서 {purpose}하기 위한 본인 확인 요청이 접수되었습니다.\n\n"
        f"아래 링크를 열어 확인 화면에서 [해제] 버튼을 눌러주세요 "
        f"(유효시간 {config.RECOVERY_TOKEN_TTL_MINUTES}분, 1회용):\n{link}\n\n"
        f"링크를 열 수 없는 기기라면, 복구를 요청하신 기기의 /recovery/verify 화면에서 "
        f"아래 6자리 코드를 입력하세요:\n{code}\n\n"
        "본인이 요청하지 않았다면 이 메일을 무시하세요. 링크를 누르지 않으면 아무 일도 일어나지 않습니다."
    )
    return _send_mail(to_address, "[로그인 워치독] 본인 확인 및 잠금 해제 안내", body)


def send_recovery_done_notice(to_address: str, kind: str) -> str:
    """복구가 완료됐다는 사실을 계정 이메일로 알린다 — 본인이 한 일이 아니라면 바로 알 수 있게 한다."""
    if kind == "account":
        what = "계정 영구 잠금이 해제되었습니다. 이후 24시간은 보호관찰 기간이라 다시 잠기면 관리자만 해제할 수 있습니다."
    else:
        what = "이 네트워크에서 회원님과 복구를 요청하신 기기의 접속이 허용되었습니다."
    body = (
        f"{what}\n\n"
        "본인이 한 일이 아니라면 관리자에게 알려주세요.\n"
        "계정이 공격받아 잠겼던 것이므로, 로그인한 뒤 '내 프로필' 화면에서 비밀번호를 바꾸는 것을 권장합니다"
        f"{_profile_link_line()}\n"
        "비밀번호를 바꾸면 다른 기기의 로그인은 모두 해제됩니다."
    )
    return _send_mail(to_address, "[로그인 워치독] 잠금 해제가 완료되었습니다", body)


def _profile_link_line() -> str:
    """메일에 넣을 '내 프로필' 주소(PUBLIC_BASE_URL이 있을 때만). Host 헤더는 쓰지 않는다."""
    return f":\n{config.PUBLIC_BASE_URL}/dashboard/profile" if config.PUBLIC_BASE_URL else "."


def send_password_changed_notice(to_address: str) -> str:
    """비밀번호가 바뀌었다는 사실을 계정 이메일로 알린다(guide35) — 세션을 탈취한 사람이 바꿨다면
    본인이 바로 알아챌 수 있게 하는 장치다. 실패해도 비밀번호 변경 자체는 그대로 유지된다."""
    body = (
        "로그인 워치독 계정의 비밀번호가 변경되었습니다. 다른 기기의 로그인은 모두 해제되었습니다.\n\n"
        "본인이 변경한 것이 아니라면 즉시 관리자에게 알려주세요."
    )
    return _send_mail(to_address, "[로그인 워치독] 비밀번호가 변경되었습니다", body)


# ============================================================================
# 이메일 인증 / 이메일 변경 확인 (guide40)
# ============================================================================

def send_email_verification(to_address: str, link: str) -> str:
    """가입 직후 또는 대시보드 "인증 메일 다시 보내기"로 보내는 이메일 인증 메일."""
    body = (
        "로그인 워치독 가입 이메일을 확인하기 위한 메일입니다.\n\n"
        f"아래 링크를 열어 확인 화면에서 [인증] 버튼을 눌러주세요 "
        f"(유효시간 {config.EMAIL_TOKEN_TTL_MINUTES}분, 1회용):\n{link}\n\n"
        "인증된 이메일로만 비밀번호 재설정 메일을 보내드립니다.\n"
        "본인이 가입하지 않았다면 이 메일을 무시하세요. 링크를 누르지 않으면 아무 일도 일어나지 않습니다."
    )
    return _send_mail(to_address, "[로그인 워치독] 이메일 인증 안내", body)


def send_email_change_confirmation(to_address: str, link: str) -> str:
    """프로필에서 이메일 변경을 요청했을 때 "새 주소"로 보내는 확인 메일 — 링크를 눌러야 바뀐다."""
    body = (
        "로그인 워치독 계정의 이메일을 이 주소로 바꾸는 요청이 접수되었습니다.\n\n"
        f"아래 링크를 열어 확인 화면에서 [이메일 변경] 버튼을 눌러야 변경됩니다 "
        f"(유효시간 {config.EMAIL_TOKEN_TTL_MINUTES}분, 1회용):\n{link}\n\n"
        "본인이 요청하지 않았다면 이 메일을 무시하세요. 링크를 누르지 않으면 아무 일도 일어나지 않습니다."
    )
    return _send_mail(to_address, "[로그인 워치독] 이메일 변경 확인", body)


def send_email_in_use_notice(to_address: str) -> str:
    """이미 다른 계정이 쓰고 있는 주소로 이메일 변경을 요청했을 때 그 주소로 보내는 안내.

    화면 응답은 "확인 메일을 보냈습니다"로 항상 같게 두고(그 주소의 가입 여부를 화면으로 알
    수 없게), 실제 안내는 메일함 주인에게만 간다 — 이 메일을 받는 사람이 곧 그 주소의 주인이다.
    """
    body = (
        "로그인 워치독에서 이 주소로 이메일을 변경하려는 요청이 있었지만, "
        "이 주소는 이미 다른 계정에 등록되어 있어 변경할 수 없습니다.\n\n"
        "본인이 요청하지 않았다면 이 메일을 무시하세요. 아무것도 바뀌지 않았습니다."
    )
    return _send_mail(to_address, "[로그인 워치독] 이메일 변경 요청 안내", body)


def send_email_changed_notice(old_address: str, masked_new_address: str) -> str:
    """이메일 변경이 완료됐다는 사실을 "기존 주소"로 알린다 — 세션을 탈취한 사람이 이메일을
    바꿨다면 원래 주인이 바로 알아챌 수 있게 하는 장치다. 새 주소는 가려서 보낸다."""
    body = (
        f"로그인 워치독 계정의 이메일이 {masked_new_address}(으)로 변경되었습니다.\n"
        "앞으로 비밀번호 재설정 등 안내 메일은 새 주소로 갑니다.\n\n"
        "본인이 변경한 것이 아니라면 즉시 로그인해 비밀번호를 바꾸고 관리자에게 알려주세요"
        f"{_profile_link_line()}"
    )
    return _send_mail(old_address, "[로그인 워치독] 이메일이 변경되었습니다", body)
