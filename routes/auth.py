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
from helpers import get_request_ip

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

# 아이디: 영문자/숫자/밑줄(_)만 허용, 3~20자. `<`, `"`, 공백 같은 HTML/스크립트에
# 쓰이는 특수문자는 애초에 통과하지 못한다.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")

# 이메일: "글자@글자.글자" 형태의 아주 기본적인 모양만 확인한다. 완벽한 RFC 5322
# 검증은 아니지만(그런 정규식은 매우 복잡하다), "이메일처럼 안 생긴 값"을 걸러내는
# 데는 충분하고, 실제 도달 가능 여부는 어차피 별도의 인증 메일 없이는 확인할 수 없다.
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# 비밀번호 최소 길이. 복잡도(대소문자/특수문자 조합 강제)까지는 요구하지 않는다 —
# 최근 보안 가이드라인(NIST 등)은 억지로 복잡한 조합을 강제하는 것보다 "충분히
# 긴 비밀번호"를 권장하는 추세다.
MIN_PASSWORD_LENGTH = 8


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

    # 같은 IP가 짧은 시간에 너무 많이 가입을 시도하면 거부한다 — 이전에는 이 주소에
    # 요청 빈도 제한이 전혀 없어서, 스크립트로 계정을 무제한 찍어낼 수 있었다
    # (18단계 보안 점검에서 발견 및 보완). 성공/실패와 무관하게 시도 자체를 세므로,
    # 검증에서 계속 걸러지는 값을 반복 제출하는 남용도 함께 막는다.
    ip = get_request_ip()
    if detector.is_signup_rate_limited(ip):
        soar.record_rejection("SIGNUP_RATE_LIMIT", ip, request.path, config.SIGNUP_RATE_LIMIT)
        flash("너무 많은 가입 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return render_template("signup.html", signup_enabled=True)
    db.log_signup_attempt(ip)

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    if not username or not email or not password:
        flash("아이디, 이메일, 비밀번호를 모두 입력해주세요.")
        return render_template("signup.html", signup_enabled=True)

    if not USERNAME_PATTERN.match(username):
        flash("아이디는 영문자, 숫자, 밑줄(_)만 사용해 3~20자로 입력해주세요.")
        return render_template("signup.html", signup_enabled=True)

    if not EMAIL_PATTERN.match(email):
        flash("올바른 이메일 형식이 아닙니다.")
        return render_template("signup.html", signup_enabled=True)

    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f"비밀번호는 최소 {MIN_PASSWORD_LENGTH}자 이상이어야 합니다.")
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
    1. 혹시 자동으로 풀어줘야 할 만료된 잠금이 있으면 먼저 정리한다.
    2. 이번 요청을 보낸 IP를 알아낸다.
    3. 이 IP가 지금 잠긴 상태라면, 아이디/비밀번호를 확인하지도 않고
       곧바로 "잠긴 계정입니다" 메시지를 보여준다.
    4. 잠긴 상태가 아니라면 실제로 아이디/비밀번호를 확인하고, 그 시도를 기록한다.
    5. 만약 이번 시도가 실패였다면 "혹시 이 IP가 수상한 수준(5회 초과)이 됐는지"
       판정하고, 그렇다면 즉시 잠근다(soar.enforce_lockout이 알림까지 같이 보냄).
    6. 성공했다면 회원 세션을 만들어서 회원 대시보드로 이동시킨다(12단계에서 추가).
    """
    # 1) 시간이 지나 자동으로 풀려야 할 잠금들을 정리
    soar.try_release_expired_lockouts()

    ip = get_request_ip()

    # 2) 이미 잠긴 IP라면 계정 검증 자체를 건너뛰고 즉시 거부
    if detector.is_locked(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("auth.login_submit"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")

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
        return redirect(url_for("member.member_dashboard"))

    # 실패했다면, 이 실패로 인해 방금 임계값을 넘었는지 확인한다.
    suspicious, failure_count = detector.is_suspicious(ip)
    if suspicious:
        # 최근 실패에 쓰인 아이디가 몇 개였는지도 함께 세서, Slack 알림이 Brute
        # Force(계정 1개 집중)와 Password Spraying(계정 여러 개 순회)을 구분해
        # 표시할 수 있게 한다 (attack_response_state.md 구현 대상 #5).
        distinct_usernames = detector.count_distinct_usernames(ip)
        soar.enforce_lockout(ip, failure_count, distinct_usernames)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
    else:
        # 사용자 존재 여부(아이디가 없는지, 비밀번호만 틀렸는지)를 구분해서 알려주면
        # 공격자에게 힌트를 주게 되므로, 항상 똑같은 문구로만 실패를 알린다.
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login_form.html", form_action=url_for("auth.login_submit"))
