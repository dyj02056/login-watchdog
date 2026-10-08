# ============================================================================
# routes/auth.py — 회원가입(/signup) + 감시 대상 로그인(/login)
#
# 원래 app.py의 "회원가입 입력 검증 규칙" / "회원가입" / "감시 대상 로그인"
# 세 섹션을 그대로 옮겨왔다. 배경은 docs/refactor/2026-09-15-file-split.md 참고.
# ============================================================================

import re

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

import config
import db
import detector
import soar
from helpers import get_device_hash, get_request_ip, is_bot_submission

auth_bp = Blueprint("auth", __name__)


# ============================================================================
# 회원가입 입력 검증 규칙
#
# 이전에는 "아이디/이메일/비밀번호 칸이 비어있지 않은지"만 확인하고 그대로
# db.create_user()에 넘겼다. 그러면 두 가지 문제가 생긴다.
# 1) 아이디에 아무 문자나 허용되므로 `<img src=x onerror=...>` 같은 값도 그대로
#    저장된다 — 대시보드 쪽 escapeHtml()로 화면 출력은 막아뒀지만(6단계 XSS 수정
#    참고),애초에 이런 값이 데이터베이스에 들어가는 것 자체를 막는 편이 더 안전한
#    "심층 방어(defense in depth)"다.
# 2) 이메일 형식이 아닌 문자열이나 아주 짧은 비밀번호도 그대로 가입돼버린다.
#
# 정규식(re) 패턴으로 "허용하는 모양"을 미리 정해두고, 그 모양에 안 맞으면
# db.create_user()를 아예 호출하지 않고 바로 안내 메시지를 보여준다.
# ============================================================================

# 아이디/비밀번호 규칙은 config.USERNAME_PATTERN / config.MIN_PASSWORD_LENGTH로
# 옮겨졌다 — scripts/create_admin.py, 대시보드 "관리자 계정 관리"(Track B guide26)도
# 같은 규칙을 써야 해서 공용 상수가 됐다(config.py 상단 주석 참고).

# 이메일: "글자@글자.글자" 형태의 아주 기본적인 모양만 확인한다. 완벽한 RFC 5322
# 검증은 아니지만(그런 정규식은 매우 복잡하다), "이메일처럼 안 생긴 값"을 걸러내는
# 데는 충분하고, 실제 도달 가능 여부는 어차피 별도의 인증 메일 없이는 확인할 수 없다.
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# 계정 잠금 안내(guide39) — 임시든 영구든 같은 문구와 같은 복구 링크를 보여준다. 영구 승격은
# 가입된 아이디에만 일어나서(lockdown.promote_account), "영구 잠금"이라고 따로 알려주면 그
# 아이디가 실제로 가입돼 있다는 사실이 드러나기 때문이다. 링크도 영구 잠금에만 보여주면
# 링크 유무로 다시 구분되므로 모든 계정 잠금에 보여준다(복구 화면은 원래 항상 같은 응답).
ACCOUNT_LOCKED_MESSAGE = (
    "잠긴 계정입니다. 잠시 후 다시 시도해주세요. 계속 로그인할 수 없다면 아래 "
    "'본인 인증으로 잠금 해제'를 이용하거나 관리자에게 문의해주세요."
)


# ============================================================================
# 회원가입 (신규 확장 기능) — 감시 대상 /login에 실제로 로그인할 계정을 만드는 곳
# ============================================================================

@auth_bp.route("/signup", methods=["GET"])
def signup():
    """회원가입 폼 화면을 보여준다. (아직 아무것도 제출하지 않은 상태)

    관리자가 대시보드에서 회원가입을 꺼뒀다면(db.get_signup_enabled()가 False),
    폼 대신 "지금은 가입할 수 없습니다"라는 안내만 보여준다. 실제로 화면 안의
    무엇을 보여줄지는 signup.html이 signup_enabled 값을 보고 스스로 결정한다.
    """
    return render_template("signup.html", signup_enabled=db.get_signup_enabled())


@auth_bp.route("/signup", methods=["POST"])
def signup_submit():
    """회원가입 폼에서 "가입하기" 버튼을 눌렀을 때 실제로 처리하는 부분.

    GET(화면 보여주기)과 POST(데이터 제출 처리)를 같은 주소(/signup)에 대해
    따로 등록해두는 것이 Flask에서 아주 흔한 패턴이다 — "이 주소를 그냥 방문하면
    빈 폼을 보여주고, 이 주소로 폼 데이터를 제출하면 그때는 처리 로직을 실행해라"
    는 뜻이다.
    """
    # 화면에서 폼 자체를 숨겨뒀더라도, 누군가 개발자 도구 등으로 이 주소에 직접
    # 요청을 보낼 수 있으므로 서버 쪽에서도 다시 한번 막아준다(이중 안전장치).
    if not db.get_signup_enabled():
        flash("현재 회원가입이 잠시 중단되어 있습니다.")
        return render_template("signup.html", signup_enabled=False)

    ip = get_request_ip()

    # 허니팟 필드가 채워져 있으면 사람이 아니라 자동화 스크립트라고 보고,
    # 시도 기록조차 남기지 않고 즉시 거부한다 (L7 공격 보강 계획 Tier 3).
    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        flash("일시적인 오류가 발생했습니다. 다시 시도해주세요.")
        return render_template("signup.html", signup_enabled=True)

    # 영구 잠금된 IP는 가입도 막는다 — 공격자가 새 계정을 만들어 자기 IP의 예외를
    # 받아내는 경로를 차단한다(guide33). 일반 임시 잠금(5분)은 가입을 막지 않는다.
    if detector.get_ip_lock_state(ip) == detector.LOCK_STATE_PERMANENT:
        flash("현재 이 네트워크에서는 회원가입을 할 수 없습니다. 관리자에게 문의해주세요.")
        return render_template("signup.html", signup_enabled=True)

    # 같은 IP가 짧은 시간에 너무 많이 가입을 시도하면 거부한다 — 이전에는 이 주소에
    # 요청 빈도 제한이 전혀 없어서, 스크립트로 계정을 무제한 찍어낼 수 있었다
    # (18단계 보안 점검에서 발견 및 보완). 성공/실패와 무관하게 시도 자체를 세므로,
    # 검증에서 계속 걸러지는 값을 반복 제출하는 남용도 함께 막는다.
    rate_limited, signup_count = detector.is_signup_rate_limited(ip)
    if rate_limited:
        soar.record_rejection("SIGNUP_RATE_LIMIT", ip, request.path, config.SIGNUP_RATE_LIMIT)
        flash("너무 많은 가입 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return render_template("signup.html", signup_enabled=True)
    # 아직 기준치(SIGNUP_RATE_LIMIT)는 안 넘었지만 코앞이면, LLM에게 조기 경보
    # 여부를 물어본다 (Track A, guide31 — config.EARLY_WARNING_BAND 설명 참고).
    if signup_count >= config.SIGNUP_RATE_LIMIT - config.EARLY_WARNING_BAND:
        soar.consider_early_warning(
            "SIGNUP_RATE_LIMIT", "ALERT_ONLY", "ip", ip, signup_count, config.SIGNUP_RATE_LIMIT,
            path=request.path,
        )
    db.log_signup_attempt(ip)

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    if not username or not email or not password:
        flash("아이디, 이메일, 비밀번호를 모두 입력해주세요.")
        return render_template("signup.html", signup_enabled=True)

    if not config.USERNAME_PATTERN.match(username):
        flash("아이디는 영문자, 숫자, 밑줄(_)만 사용해 3~20자로 입력해주세요.")
        return render_template("signup.html", signup_enabled=True)

    if not EMAIL_PATTERN.match(email):
        flash("올바른 이메일 형식이 아닙니다.")
        return render_template("signup.html", signup_enabled=True)

    if len(password) < config.MIN_PASSWORD_LENGTH:
        flash(f"비밀번호는 최소 {config.MIN_PASSWORD_LENGTH}자 이상이어야 합니다.")
        return render_template("signup.html", signup_enabled=True)

    if password != password_confirm:
        flash("비밀번호와 비밀번호 확인이 일치하지 않습니다.")
        return render_template("signup.html", signup_enabled=True)

    created = db.create_user(username, email, password)
    if not created:
        flash("이미 사용 중인 아이디 또는 이메일입니다.")
        return render_template("signup.html", signup_enabled=True)

    flash("회원가입이 완료되었습니다. 로그인해주세요.")
    return redirect(url_for("auth.login"))


# ============================================================================
# 감시 대상 로그인 (/login) — 이 프로젝트가 실제로 감시하는 화면
# ============================================================================

def _login_form(recovery_link: bool = False):
    """로그인 폼을 다시 보여준다. recovery_link=True면 영구 잠금 안내 아래에 이메일
    복구(/recovery) 링크를 함께 보여준다(templates/login_form.html 참고)."""
    return render_template(
        "login_form.html",
        form_action=url_for("auth.login_submit"),
        recovery_link=recovery_link,
    )


def _find_ip_exemption(ip: str, username: str) -> dict | None:
    """이 IP에서 이 사용자가 "이 기기"로 유효한 영구 잠금 예외를 가졌는지 찾는다.
    사용자가 없거나 기기 쿠키가 없으면 항상 None이다(공격자는 둘 다 갖지 못한다)."""
    device_hash = get_device_hash()
    if not device_hash:
        return None
    user = db.get_user_by_username(username)
    if user is None:
        return None
    return db.get_active_ip_exemption(ip, user["id"], device_hash)


@auth_bp.route("/login", methods=["GET"])
def login():
    """감시 대상 로그인 화면을 보여준다. 이미 로그인된 상태라면 회원 대시보드로 바로 보낸다.

    화면 자체는 관리자 로그인과 똑같은 login_form.html을 공유하지만(겉보기로는
    구분이 안 됨), form_action만 이 라우트로("/login") 지정해서 실제 제출은
    login_submit()이 처리하게 한다.
    """
    if "username" in session:
        return redirect(url_for("member.member_dashboard"))
    return render_template("login_form.html", form_action=url_for("auth.login_submit"))


@auth_bp.route("/login", methods=["POST"])
def login_submit():
    """로그인 폼 제출을 처리한다. 이 함수 하나가 이 프로젝트의 핵심 흐름을 담당한다.

    처리 순서:
    1. 혹시 자동으로 풀어줘야 할 만료된 잠금(IP 단위 + 계정 단위)이 있으면 먼저 정리한다.
    2. 이번 요청을 보낸 IP와 입력된 아이디를 알아낸다.
    3. 이 IP가 지금 잠긴 상태이거나, 이 계정 자체가 (다른 IP들이 나눠서 공격해서)
       잠긴 상태라면 아이디/비밀번호를 확인하지도 않고 곧바로 거부한다.
    4. 잠긴 상태가 아니라면 실제로 아이디/비밀번호를 확인하고, 그 시도를 기록한다.
    5. 실패했다면 "혹시 이 IP가 수상한 수준(5회 초과)이 됐는지"를 먼저 보고,
       아니라면 "혹시 이 계정이 여러 IP에 걸쳐 총합으로 수상한 수준(8회 초과)이
       됐는지"도 본다 — 전자는 soar.enforce_lockout(IP 잠금), 후자는
       soar.enforce_account_lockout(계정 잠금)이 알림까지 같이 보낸다
       (L7 공격 보강 계획 Tier 1: 분산/저속 브루트포스 대응).
    6. 성공했다면 회원 세션을 만들어서 회원 대시보드로 이동시킨다(12단계에서 추가).
    """
    # 1) 시간이 지나 자동으로 풀려야 할 잠금들을 정리 (IP 단위 + 계정 단위)
    soar.try_release_expired_lockouts()
    soar.try_release_expired_account_lockouts()

    ip = get_request_ip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # 허니팟 필드가 채워져 있으면 사람이 아니라 자동화 스크립트라고 보고,
    # 자격 증명 확인/시도 기록 없이 즉시 거부한다 (L7 공격 보강 계획 Tier 3).
    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return render_template("login_form.html", form_action=url_for("auth.login_submit"))

    # 2) 이미 잠긴 IP이거나, 이미 잠긴 계정이라면 검증 자체를 건너뛰고 즉시 거부
    #    — 단, 영구 잠금된 IP는 "이메일 복구로 예외를 받은 본인+본인 기기"만 통과시킨다(guide33).
    exemption = None
    if detector.is_locked(ip):
        if detector.get_ip_lock_state(ip) != detector.LOCK_STATE_PERMANENT:
            flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
            return _login_form()
        exemption = _find_ip_exemption(ip, username)
        if exemption is None:
            flash("이 네트워크는 차단되어 있습니다. 본인이라면 아래 '본인 인증으로 접속 허용'을 이용해주세요.")
            return _login_form(recovery_link=True)
        # 예외가 있으면 IP 잠금 안내 없이 아래 계정 잠금 확인과 정상적인 비밀번호 확인으로 계속 진행한다.

    if detector.is_account_locked(username):
        flash(ACCOUNT_LOCKED_MESSAGE)
        return _login_form(recovery_link=True)

    success = db.verify_user_credentials(username, password)
    db.log_attempt(ip, username, success)

    if success:
        # 관리자 세션("admin_username")과는 완전히 다른 키("username")를 쓴다 —
        # 그래야 같은 브라우저에서 관리자 세션이 있더라도 서로 섞이지 않는다.
        # user_id도 같이 저장해두는 이유는 member_login_required 문지기 뒤에서
        # "아이디"가 아니라 변하지 않는 "번호"로 본인 행을 정확히 찾기 위해서다.
        user = db.get_user_by_username(username)
        session["username"] = username
        session["user_id"] = user["id"]
        # 세션 세대 번호 — 나중에 비밀번호가 바뀌면 이 세션을 끊는 데 쓴다(guide35).
        session["session_version"] = user.get("session_version") or 0
        return redirect(url_for("member.member_dashboard"))

    # 영구 잠금 예외로 통과한 사용자가 연달아 실패하면 그 예외를 회수한다 — 예외는 "본인이
    # 비밀번호를 아는 상황"을 전제로 한 출입증이라, 계속 틀리는 건 도용 신호로 본다.
    # (예외 통과자의 실패는 IP 임계값 판정으로 넘기지 않는다 — 이 IP는 이미 영구 잠금 중이라
    # enforce_lockout()이 5분 잠금 알림을 또 보내는 일이 없도록 하기 위해서다.)
    if exemption is not None:
        if db.count_recent_failures(ip) >= config.IP_EXEMPTION_MAX_FAILURES:
            db.revoke_ip_exemption(exemption["id"], "예외 통과 후 연속 로그인 실패")
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
        return _login_form()

    # 실패했다면, 먼저 이 IP가 방금 임계값을 넘었는지 확인한다.
    suspicious, failure_count = detector.is_suspicious(ip)
    if suspicious:
        # 최근 실패에 쓰인 아이디가 몇 개였는지도 함께 세서, Slack 알림이 Brute
        # Force(계정 1개 집중)와 Password Spraying(계정 여러 개 순회)을 구분해
        # 표시할 수 있게 한다 (attack_response_state.md 구현 대상 #5).
        distinct_usernames = detector.count_distinct_usernames(ip)
        soar.enforce_lockout(ip, failure_count, distinct_usernames)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
    else:
        # 아직 기준치(FAILURE_THRESHOLD)는 안 넘었지만 코앞이면, LLM에게 조기
        # 경보 여부를 물어본다 (Track A, guide31). 공격자가 임계값을 살짝
        # 피해 가려고 실패 횟수를 일부러 코앞에서 멈추는 패턴을 이 구간에서 잡는다.
        if failure_count >= config.FAILURE_THRESHOLD - config.EARLY_WARNING_BAND:
            distinct_usernames = detector.count_distinct_usernames(ip)
            soar.consider_early_warning(
                "BRUTE_FORCE", "LOCK_IP", "ip", ip, failure_count, config.FAILURE_THRESHOLD,
                context_count=distinct_usernames,
            )

        # IP 단위로는 아직 수상하지 않더라도, 이 계정이 여러 IP에 걸쳐 나뉘어서
        # 총합 기준으로 수상한 수준이 됐는지 확인한다 — 공격자가 IP를 돌려가며
        # (봇넷/프록시 로테이션) 한 계정만 노리는 분산 브루트포스를 잡아낸다.
        account_suspicious, account_failure_count = detector.is_account_suspicious(username)
        if account_suspicious:
            distinct_ips = detector.count_distinct_ips_by_username(username)
            soar.enforce_account_lockout(username, account_failure_count, distinct_ips, ip)
            flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        else:
            # 이 계정도 마찬가지로 임계값(ACCOUNT_FAILURE_THRESHOLD) 코앞이면
            # 조기 경보 대상이다 — 여러 IP에 나눠 시도하되 각 IP·계정 총합
            # 모두를 임계값 아래로 유지하려는 패턴을 잡아낸다.
            if account_failure_count >= config.ACCOUNT_FAILURE_THRESHOLD - config.EARLY_WARNING_BAND:
                distinct_ips = detector.count_distinct_ips_by_username(username)
                soar.consider_early_warning(
                    "DISTRIBUTED_BRUTE_FORCE", "LOCK_ACCOUNT", "account", username,
                    account_failure_count, config.ACCOUNT_FAILURE_THRESHOLD,
                    context_count=distinct_ips, context_ip=ip,
                )
            # 사용자 존재 여부(아이디가 없는지, 비밀번호만 틀렸는지)를 구분해서
            # 알려주면 공격자에게 힌트를 주게 되므로, 항상 똑같은 문구로만 실패를 알린다.
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login_form.html", form_action=url_for("auth.login_submit"))
