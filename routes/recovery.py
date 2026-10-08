# ============================================================================
# routes/recovery.py — 이메일 인증으로 영구 잠금을 풀거나(계정) 본인 기기만 통과시키는(IP)
# 복구 화면 4개 (guide34-a)
#
#   GET  /recovery           아이디 입력 폼
#   POST /recovery/request   복구 메일 발송 (항상 같은 응답)
#   GET  /recovery/verify    메일 링크가 여는 확인 화면 (토큰을 소비하지 않음)
#   POST /recovery/verify    토큰/6자리 코드를 소비하고 실제로 해제·예외 발급
#
# 보안 원칙 (계획서 1.3-C)
#   - 계정 존재 여부를 숨긴다: 아이디가 없든, 잠기지 않았든, 복구 대상이 아니든 항상 같은
#     문구·비슷한 응답 시간으로 답한다.
#   - 메일 보안 스캐너가 링크를 먼저 GET으로 열어도 토큰이 닳지 않게, GET은 확인 화면만
#     보여주고 토큰은 POST에서만 소비한다.
#   - 링크는 request.host_url(공격자가 조작 가능한 Host 헤더)이 아니라 PUBLIC_BASE_URL로만 만든다.
#   - 토큰·코드는 SHA-256 해시만 저장하고, 비교는 hmac.compare_digest로 한다.
#   - IP 복구는 "복구를 요청한 그 기기"에서만 완료된다(피해자의 메일 링크를 공격자의 요청과
#     엮어서 공격자 기기에 예외를 발급받는 시나리오 차단).
# ============================================================================

import hmac
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
from flask import Blueprint, make_response, render_template, request

import config
import db
import email_verification
import lockdown
import mailer
import soar
from helpers import (
    get_device_hash,
    get_request_ip,
    hash_secret,
    is_bot_submission,
    mask_username,
    new_device_token,
    public_base_url,
    set_device_cookie,
)

recovery_bp = Blueprint("recovery", __name__)

# 아이디가 있든 없든 복구 대상이든 아니든 똑같이 보여주는 문구(계정 존재 여부 노출 방지).
GENERIC_SENT_MESSAGE = "등록된 이메일이 있다면 안내 메일을 보냈습니다. 메일함을 확인해주세요."
RATE_LIMITED_MESSAGE = "요청이 너무 많습니다. 잠시 후 다시 시도해주세요."
INVALID_LINK_MESSAGE = "만료되었거나 이미 사용된 링크입니다. 복구를 다시 요청해주세요."
CODE_EXHAUSTED_MESSAGE = "코드가 올바르지 않습니다. 복구를 다시 요청해주세요."
# 6자리 코드 경로의 공통 실패 문구(guide39) — 아이디 없음 / 진행 중인 요청 없음 / 요청한 기기가
# 아님을 구분하지 않는다. 구분하면 "이 아이디에 진행 중인 복구가 있다(= 가입된 아이디)"가 드러난다.
CODE_GENERIC_FAILURE_MESSAGE = "아이디 또는 코드가 올바르지 않거나 만료되었습니다."
WRONG_DEVICE_MESSAGE = (
    "이 링크는 복구를 요청한 기기에서만 사용할 수 있습니다. "
    "요청한 기기의 브라우저에서 아래에 아이디와 메일의 6자리 코드를 입력해주세요."
)


def _report_internal_error(error: Exception) -> None:
    """복구 요청 처리 중 예외를 로그에 남기고 관리자에게 알린다. 사용자 화면에는 영향이 없다
    (예외가 500으로 새면 계정 존재 여부가 드러나므로 응답은 항상 같다) — 그래서 이 알림이 없으면
    복구 메일이 안 나가고 있어도 아무도 모른다."""
    print(f"[recovery] 복구·재설정 요청 처리 중 오류: {type(error).__name__}: {error}", flush=True)
    mailer.report_failure(mailer.FAIL_INTERNAL, f"복구·재설정 요청 처리 중 오류: {type(error).__name__}")


def run_with_fixed_response_time(work, started: float) -> None:
    """`work()`를 실행하고, 처리가 빨리 끝났든 오래 걸렸든 응답 시점이 항상
    RECOVERY_MIN_RESPONSE_SECONDS로 같아지게 맞춘다(타이밍 사이드채널 방지).
    비밀번호 찾기 요청(routes/password.py, guide41)도 같은 이유로 이 함수를 쓴다.

    "아이디 없음"은 DB 조회 한두 번으로 끝나고 "실제 복구 메일"은 조회 여러 번 + SMTP까지
    거치므로, 그냥 두면 응답 시간 차이로 아이디 존재 여부가 드러난다.

    - 기본(RECOVERY_BACKGROUND_WORK=false): 요청 안에서 처리(메일 발송 포함)를 끝낸 뒤
      남은 시간만큼 기다리고 응답한다. Vercel 같은 서버리스는 응답을 보내는 순간 함수를
      멈추므로, 메일 발송을 응답 뒤로 미루면 끝나기 전에 끊길 수 있다.
    - RECOVERY_BACKGROUND_WORK=true(상시 실행 서버): 처리를 스레드로 돌리고 고정 시간까지만
      기다린 뒤 응답한다(처리가 더 걸리면 응답 뒤에도 스레드가 마무리한다).
    - 고정 시간이 0이면(테스트) 기다림 없이 그 자리에서 처리한다.

    어느 쪽이든 처리 중 예외는 로그만 남기고 삼킨다 — 예외가 500으로 새면 "이 아이디는
    처리 중 오류가 났다"는 신호가 되어 계정 존재 여부가 드러난다.
    """
    target = config.RECOVERY_MIN_RESPONSE_SECONDS

    def safe_work():
        # 서버리스에서 한동안 쉬던 DB 연결을 재사용하면 첫 요청이 "Server disconnected" 같은
        # 일시적 전송 오류로 실패한다(실제 배포 테스트에서 복구 요청이 이 오류로 조용히 사라졌다).
        # 이런 오류만 한 번 더 시도한다 — work()는 메일을 보내기 전까지의 DB 작업이 다시 해도
        # 안전하게 짜여 있고(기존 PENDING 요청을 취소하고 새로 만든다), 메일 발송 실패는
        # mailer가 예외 없이 처리하므로 재시도해도 메일이 두 번 나가지 않는다.
        for attempt in (1, 2):
            try:
                work()
                return
            except httpx.TransportError as e:
                if attempt == 1:
                    continue
                _report_internal_error(e)
            except Exception as e:  # noqa: BLE001
                _report_internal_error(e)
            return

    if target <= 0:
        safe_work()
        return

    if config.RECOVERY_BACKGROUND_WORK:
        thread = threading.Thread(target=safe_work, daemon=True)
        thread.start()
        thread.join(timeout=max(0.0, target - (time.monotonic() - started)))
    else:
        safe_work()

    remaining = target - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)


def _eligible_target(user: dict, account_lock: dict | None, ip_lock: dict | None, ip: str) -> tuple[str, str] | None:
    """이 요청으로 풀 수 있는 대상(kind, value)을 정한다. 없으면 None(메일을 보내지 않음).

    계정이 영구 잠금이고 복구 방식이 SELF면 'account' — 단 이메일을 신뢰할 수 없는
    계정(UNDELIVERABLE)은 제외한다. 아니면 요청 IP가 영구 잠금이고 복구 방식이
    EXEMPTION이면 'ip'(예외만 발급, 허용 목록 IP는 애초에 영구 잠금되지 않는다).
    account_lock/ip_lock은 호출부가 미리(병렬로) 조회해 넘긴 active 잠금 행이다.
    """
    if (
        account_lock
        and account_lock.get("lock_type") == "PERMANENT"
        and account_lock.get("recoverable") == "SELF"
        and user.get("email_status") != "UNDELIVERABLE"
    ):
        return "account", user["username"]

    if ip_lock and ip_lock.get("lock_type") == "PERMANENT" and ip_lock.get("recoverable") == "EXEMPTION":
        return "ip", ip
    return None


def _flag_undeliverable(user: dict, ip: str) -> None:
    """메일 서버가 수신자를 영구 거부(존재하지 않는 이메일)했을 때의 위험 상향 처리.

    users.email_status를 UNDELIVERABLE로 표시하고, 그 계정의 영구 잠금이 있으면 이메일로는
    풀 수 없게(ADMIN_ONLY) 올린다. 이벤트는 MEDIUM으로만 기록하고 상관분석에는 보내지 않는다
    — 요청한 IP가 HIGH 사건에 묶여 영구 잠금 후보가 되는 부작용을 피하기 위해서다.
    """
    db.set_user_email_status(user["id"], "UNDELIVERABLE")
    db.insert_security_event(
        "EMAIL_UNDELIVERABLE", "MEDIUM", ip, None, 1, "FLAGGED", username=user["username"]
    )
    db.set_account_lockout_recoverable(user["username"], "ADMIN_ONLY")


def _issue_recovery(ip: str, user: dict | None, device_token: str) -> None:
    """복구 요청 한 건을 처리한다 — 조건에 맞지 않으면 아무것도 하지 않고(메일 없음) 조용히 끝낸다.

    원격 DB 왕복이 느려서(쿼리 하나에 수백 ms) 서로 무관한 조회 3개(최근 요청 이력, 계정 잠금,
    IP 잠금)는 동시에 보낸다. 응답을 보내기 전에 메일 발송까지 끝내야 하는 서버리스 환경에서
    Vercel 함수 시간 제한 안에 들어오게 하려는 것이다.
    """
    if user is None:
        return

    with ThreadPoolExecutor(max_workers=3) as executor:
        activity_future = executor.submit(db.get_recovery_activity, user["id"], 24)
        account_lock_future = executor.submit(db.get_active_account_lockout, user["username"])
        ip_lock_future = executor.submit(db.get_active_lockout, ip)
        recent_count, latest = activity_future.result()
        account_lock = account_lock_future.result()
        ip_lock = ip_lock_future.result()

    if recent_count >= config.RECOVERY_MAX_PER_USER_PER_DAY:
        return
    if latest:
        latest_dt = datetime.fromisoformat(latest)
        if latest_dt.tzinfo is None:
            latest_dt = latest_dt.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - latest_dt < timedelta(seconds=config.RECOVERY_COOLDOWN_SECONDS):
            return

    target = _eligible_target(user, account_lock, ip_lock, ip)
    if target is None:
        return
    base_url = public_base_url()
    if not base_url:
        mailer.report_failure(mailer.FAIL_CONFIG, "PUBLIC_BASE_URL이 설정되지 않아 복구 메일을 보내지 않았습니다.")
        return

    kind, value = target
    token = secrets.token_urlsafe(32)
    code = f"{secrets.randbelow(10**6):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.RECOVERY_TOKEN_TTL_MINUTES)
    created = db.create_recovery_request(
        user["id"], kind, value, hash_secret(token), hash_secret(code),
        hash_secret(device_token), ip, expires_at.isoformat(),
    )
    if created is None:
        return

    link = f"{base_url}/recovery/verify?t={token}"
    result = mailer.send_recovery_email(user["email"], link, code, kind)
    if result == mailer.SENT:
        return
    # 메일이 못 나갔다면 쓸 수 없는 요청이므로 취소한다. 사용자에게는 항상 같은 안내만 보인다.
    db.revoke_recovery_request(created["id"])
    if result == mailer.REFUSED:
        _flag_undeliverable(user, ip)


@recovery_bp.route("/recovery", methods=["GET"])
def recovery_request_form():
    """복구 요청 폼(아이디 입력)을 보여준다."""
    return render_template("recovery_request.html", message=None)


@recovery_bp.route("/recovery/request", methods=["POST"])
def recovery_request_submit():
    """복구 메일을 요청한다. 결과와 무관하게 항상 같은 안내 문구로 응답한다."""
    started = time.monotonic()
    ip = get_request_ip()

    # 요청 기기를 구분하는 쿠키 — 이 기기에서만 IP 복구를 마칠 수 있다. 항상 (재)발급해서
    # 응답이 계정 존재 여부와 무관하게 똑같이 보이게 한다.
    device_token = request.cookies.get(config.DEVICE_COOKIE_NAME) or new_device_token()

    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        message = GENERIC_SENT_MESSAGE
    else:
        message = GENERIC_SENT_MESSAGE
        username = request.form.get("username", "").strip()

        def work():
            # 서로 무관한 조회(만료 정리, IP 빈도, 사용자)는 동시에 보낸다(_issue_recovery 설명 참고).
            valid_username = bool(config.USERNAME_PATTERN.match(username))
            with ThreadPoolExecutor(max_workers=3) as executor:
                executor.submit(db.expire_old_recovery_requests)
                ip_count_future = executor.submit(db.count_recovery_requests_by_ip, ip, 1)
                user_future = executor.submit(db.get_user_by_username, username) if valid_username else None
                ip_count = ip_count_future.result()
                user = user_future.result() if user_future else None
            if ip_count >= config.RECOVERY_MAX_PER_IP_PER_HOUR:
                return RATE_LIMITED_MESSAGE
            _issue_recovery(ip, user, device_token)
            return GENERIC_SENT_MESSAGE

        result = {}
        run_with_fixed_response_time(lambda: result.update(message=work()), started)
        # IP 빈도 제한에 걸렸을 때만 다른 문구를 보여준다(IP 기준이라 계정 존재 여부와 무관).
        # 처리가 고정 시간 안에 끝나지 않았다면 기본 안내 문구로 응답한다.
        message = result.get("message", GENERIC_SENT_MESSAGE)

    response = make_response(render_template("recovery_request.html", message=message))
    return set_device_cookie(response, device_token)


def _confirm_page(req: dict, token: str):
    """링크로 들어온 사용자에게 보여줄 확인 화면. IP 복구는 요청한 기기에서만 완료할 수 있다."""
    user = db.get_user_by_id(req["user_id"])
    if user is None:
        return render_template("recovery_verify.html", mode="invalid", message=INVALID_LINK_MESSAGE)

    wrong_device = req["target_kind"] == "ip" and not _device_matches(req)
    return render_template(
        "recovery_verify.html",
        mode="wrong_device" if wrong_device else "confirm",
        message=WRONG_DEVICE_MESSAGE if wrong_device else None,
        token=token,
        kind=req["target_kind"],
        masked_username=mask_username(user["username"]),
        requested_ip=req["requested_ip"],
        requested_at=req["created_at"],
    )


def _device_matches(req: dict) -> bool:
    """지금 이 기기의 쿠키가 복구를 요청했던 기기와 같은지(타이밍 안전 비교)."""
    current = get_device_hash()
    stored = req.get("device_hash")
    return bool(current and stored) and hmac.compare_digest(current, stored)


@recovery_bp.route("/recovery/verify", methods=["GET"])
def recovery_verify_form():
    """메일 링크(?t=토큰)가 여는 확인 화면. 토큰을 소비하지 않는다 — 메일 보안 스캐너가
    링크를 미리 열어도 사용자가 나중에 정상적으로 쓸 수 있어야 하기 때문이다.
    토큰 없이 들어오면 6자리 코드 입력 폼을 보여준다."""
    token = request.args.get("t", "")
    if not token:
        return render_template("recovery_verify.html", mode="code", message=None)

    req = db.get_pending_recovery_by_token_hash(hash_secret(token))
    if req is None:
        return render_template("recovery_verify.html", mode="invalid", message=INVALID_LINK_MESSAGE)
    return _confirm_page(req, token)


def _finish(req: dict):
    """검증을 통과한 요청을 원자적으로 소비하고 실제 조치(해제/예외 발급)를 반영한다."""
    consumed = db.consume_recovery_request(req["id"])
    if consumed is None:
        return render_template("recovery_verify.html", mode="invalid", message=INVALID_LINK_MESSAGE)

    user = db.get_user_by_id(consumed["user_id"])
    if user is None or not lockdown.apply_recovery(consumed, user["username"]):
        return render_template(
            "recovery_done.html",
            success=False,
            kind=consumed["target_kind"],
            message="이미 해제되었거나 이메일 인증으로 풀 수 없는 상태입니다. 관리자에게 문의해주세요.",
        )

    # 복구 메일의 링크·코드를 썼다 = 그 메일함의 주인이라는 증거이므로 이메일 인증으로도 친다(guide40).
    try:
        email_verification.mark_verified_after_recovery(user)
    except Exception as e:  # noqa: BLE001
        _report_internal_error(e)
    mailer.send_recovery_done_notice(user["email"], consumed["target_kind"])
    return render_template("recovery_done.html", success=True, kind=consumed["target_kind"], message=None)


@recovery_bp.route("/recovery/verify", methods=["POST"])
def recovery_verify_submit():
    """확인 버튼(토큰) 또는 6자리 코드 입력으로 복구를 완료한다."""
    token = request.form.get("t", "")
    if token:
        req = db.get_pending_recovery_by_token_hash(hash_secret(token))
        if req is None:
            return render_template("recovery_verify.html", mode="invalid", message=INVALID_LINK_MESSAGE)
        # IP 복구는 요청한 기기에서만 — 다른 기기에서 누른 확인은 소비하지 않고 거부한다.
        if req["target_kind"] == "ip" and not _device_matches(req):
            return _confirm_page(req, token)
        return _finish(req)

    username = request.form.get("username", "").strip()
    code = request.form.get("code", "").strip()
    req = (
        db.get_latest_pending_recovery_for_username(username)
        if code and config.USERNAME_PATTERN.match(username)
        else None
    )

    # 코드는 복구 종류와 무관하게 "복구를 요청한 기기"에서만 받는다(guide39, 이전에는 IP 복구만).
    # 아이디 없음 / 요청 없음 / 다른 기기를 같은 문구로 답하고 시도권도 쓰지 않는다 — 그래서
    # 다른 기기에서는 (1) 이 아이디에 복구가 진행 중인지 알 수 없고 (2) 틀린 코드를 넣어 남의
    # 복구 요청을 취소시킬 수도 없다. 메일 링크(토큰) 경로는 그대로 어느 기기에서나 동작한다.
    if req is None or not _device_matches(req):
        return render_template("recovery_verify.html", mode="code", message=CODE_GENERIC_FAILURE_MESSAGE)

    # 비교하기 "전에" 시도권부터 예약한다(guide37). 동시에 수백 개를 보내도 한도를 넘는
    # 요청은 코드를 비교조차 하지 못한다 — 예약 실패(None)면 맞는 코드여도 통과시키지 않는다.
    attempt = db.reserve_recovery_code_attempt(
        req["id"], req["code_attempts"], config.RECOVERY_MAX_CODE_ATTEMPTS
    )
    if attempt is None:
        return render_template("recovery_verify.html", mode="code", message=CODE_EXHAUSTED_MESSAGE)

    if not hmac.compare_digest(hash_secret(code), req["code_hash"]):
        remaining = config.RECOVERY_MAX_CODE_ATTEMPTS - attempt
        if remaining <= 0:
            db.revoke_recovery_request(req["id"])
            return render_template("recovery_verify.html", mode="code", message=CODE_EXHAUSTED_MESSAGE)
        return render_template(
            "recovery_verify.html", mode="code", message=f"코드가 올바르지 않습니다. (남은 시도 {remaining}회)"
        )

    return _finish(req)
