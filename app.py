# ============================================================================
# app.py — 이 프로그램의 "정문" 역할을 하는 Flask 진입점
#
# 지금까지 만든 db.py(데이터 저장/조회), detector.py(판정), soar.py(조치),
# alert.py(알림)는 전부 "부품"이었다. 이 파일은 그 부품들을 실제 웹 화면의
# 버튼·주소(URL)와 연결해서, 사용자가 브라우저로 방문했을 때 실제로 동작하는
# "완성된 웹사이트"로 만들어주는 역할을 한다.
#
# Flask란? 파이썬으로 웹사이트(웹 서버)를 아주 적은 코드로 만들 수 있게
# 도와주는 도구(프레임워크)다. "이 주소로 누가 들어오면 이 함수를 실행해라"
# 는 규칙을 하나씩 등록해두면, 사용자가 그 주소로 접속했을 때 자동으로
# 해당 함수가 실행되어 화면을 만들어 보여준다.
# ============================================================================

import os
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

# .env 파일에 적어둔 값(SUPABASE_URL, SECRET_KEY 등)을 파이썬이 읽을 수 있는
# "환경변수"로 불러온다. 반드시 db 등 다른 모듈을 불러오기 "전에" 실행해야
# 그 모듈들이 필요한 값을 정상적으로 찾을 수 있다.
load_dotenv()

import config
import db
import detector
import soar

app = Flask(__name__)

# Flask가 로그인 상태를 기억하기 위해 사용하는 "세션 쿠키"에 서명(위조 방지)할 때
# 쓰는 비밀 값. 이 값이 없으면 세션(로그인 유지) 기능 자체가 동작하지 않는다.
app.secret_key = os.environ["SECRET_KEY"]

# 서버가 켜질 때 딱 한 번, 관리자 계정이 하나도 없으면 .env 값으로 자동 생성한다.
# (회원가입 화면 없이 처음부터 관리자 1명이 존재하게 만드는 장치, db.py 3단계 참고)
db.ensure_bootstrap_admin()


def get_request_ip() -> str:
    """이번 요청을 보낸 사람의 IP 주소를 알아낸다.

    보통은 request.remote_addr(브라우저가 서버에 직접 연결한 진짜 주소)를 쓴다.
    다만 config.TRUST_FORWARDED_FOR가 켜져 있을 때만(데모/시연 전용 설정) 예외적으로
    X-Forwarded-For 헤더 값을 대신 신뢰한다 — 로컬 데모 환경에서는 팀원 전원이
    같은 127.0.0.1(내 컴퓨터 자신을 가리키는 특수 주소)로 접속하게 되어 서로 다른
    공격자 IP를 흉내낼 수 없기 때문에, 시뮬레이션 스크립트가 "나는 1.2.3.4에서
    왔다"고 헤더로 주장하면 그걸 믿어주는 우회로를 마련해둔 것이다.
    실제 운영 서비스에서는 이 헤더를 함부로 신뢰하면 공격자가 IP를 속여
    잠금을 피해갈 수 있으므로 위험하다 — 그래서 기본값은 꺼짐(False)이다.
    """
    if config.TRUST_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # 이 헤더는 "1.2.3.4, 5.6.7.8"처럼 여러 IP가 콤마로 이어질 수 있어서
            # 맨 앞(가장 처음 요청을 보낸 곳) 값만 잘라서 쓴다.
            return forwarded.split(",")[0].strip()
    return request.remote_addr


def login_required(view):
    """"관리자 로그인이 되어 있어야만 들어올 수 있는 방"을 만들어주는 장치(데코레이터).

    데코레이터란? 함수(방) 앞에 "문지기"를 하나 세워두는 것과 같다.
    `@login_required`를 어떤 라우트 함수 위에 붙이면, 그 라우트가 실제로
    실행되기 전에 이 문지기 코드가 먼저 실행되어 "세션에 admin_username이
    있는지"부터 확인한다.

    - 없으면(로그인 안 된 상태):
        - 주소가 /api/로 시작하는 경우(JS가 fetch로 부르는 API) → 401(인증 필요) JSON 응답
        - 그 외(사람이 브라우저로 직접 들어온 화면) → 관리자 로그인 페이지로 강제 이동
    - 있으면(로그인 된 상태): 원래 요청했던 라우트 함수를 그대로 실행
    """
    @wraps(view)  # 문지기를 씌워도 원래 함수의 이름 등 정보가 유지되게 해주는 파이썬 관례
    def wrapped_view(*args, **kwargs):
        if "admin_username" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "로그인이 필요합니다."}), 401
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped_view


# ============================================================================
# 회원가입 (신규 확장 기능) — 감시 대상 /login에 실제로 로그인할 계정을 만드는 곳
# ============================================================================

@app.route("/signup", methods=["GET"])
def signup():
    """회원가입 폼 화면을 보여준다. (아직 아무것도 제출하지 않은 상태)"""
    return render_template("signup.html")


@app.route("/signup", methods=["POST"])
def signup_submit():
    """회원가입 폼에서 "가입하기" 버튼을 눌렀을 때 실제로 처리하는 부분.

    GET(화면 보여주기)과 POST(데이터 제출 처리)를 같은 주소(/signup)에 대해
    따로 등록해두는 것이 Flask에서 아주 흔한 패턴이다 — "이 주소를 그냥 방문하면
    빈 폼을 보여주고, 이 주소로 폼 데이터를 제출하면 그때는 처리 로직을 실행해라"
    는 뜻이다.
    """
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    if not username or not email or not password:
        flash("아이디, 이메일, 비밀번호를 모두 입력해주세요.")
        return render_template("signup.html")

    if password != password_confirm:
        flash("비밀번호와 비밀번호 확인이 일치하지 않습니다.")
        return render_template("signup.html")

    created = db.create_user(username, email, password)
    if not created:
        flash("이미 사용 중인 아이디 또는 이메일입니다.")
        return render_template("signup.html")

    flash("회원가입이 완료되었습니다. 로그인해주세요.")
    return redirect(url_for("login"))


# ============================================================================
# 감시 대상 로그인 (/login) — 이 프로젝트가 실제로 감시하는 화면
# ============================================================================

@app.route("/login", methods=["GET"])
def login():
    """감시 대상 로그인 화면을 보여준다."""
    return render_template("login.html")


@app.route("/login", methods=["POST"])
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
    """
    # 1) 시간이 지나 자동으로 풀려야 할 잠금들을 정리
    soar.try_release_expired_lockouts()

    ip = get_request_ip()

    # 2) 이미 잠긴 IP라면 계정 검증 자체를 건너뛰고 즉시 거부
    if detector.is_locked(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    success = db.verify_user_credentials(username, password)
    db.log_attempt(ip, username, success)

    if success:
        flash("로그인 성공")
        return render_template("login.html")

    # 실패했다면, 이 실패로 인해 방금 임계값을 넘었는지 확인한다.
    suspicious, failure_count = detector.is_suspicious(ip)
    if suspicious:
        soar.enforce_lockout(ip, failure_count)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
    else:
        # 사용자 존재 여부(아이디가 없는지, 비밀번호만 틀렸는지)를 구분해서 알려주면
        # 공격자에게 힌트를 주게 되므로, 항상 똑같은 문구로만 실패를 알린다.
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login.html")


# ============================================================================
# 관리자 로그인/로그아웃 (/admin/login, /admin/logout)
# — 감시 대상(/login)과 완전히 분리된 별도 경로이므로 위의 IP 잠금 로직과 무관하다.
# ============================================================================

@app.route("/admin/login", methods=["GET"])
def admin_login():
    """관리자 로그인 화면을 보여준다. 이미 로그인된 상태라면 대시보드로 바로 보낸다."""
    if "admin_username" in session:
        return redirect(url_for("dashboard"))
    return render_template("admin_login.html")


@app.route("/admin/login", methods=["POST"])
def admin_login_submit():
    """관리자 로그인 폼 제출을 처리한다."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip = get_request_ip()

    success = db.verify_admin_credentials(username, password)
    # 성공/실패와 무관하게 "누가 언제 관리자 로그인을 시도했는지"는 항상 기록해서
    # 나중에 대시보드에서 감사(audit) 이력을 확인할 수 있게 한다.
    db.log_admin_attempt(username, success, ip)

    if success:
        # 세션(session)은 "이 브라우저는 로그인된 상태다"를 서버가 기억하게 해주는
        # 저장 공간이다. 여기 값을 넣어두면, 같은 브라우저로 다시 요청이 올 때마다
        # Flask가 자동으로 이 값을 복원해줘서 "로그인 유지"가 가능해진다.
        session["admin_username"] = username
        return redirect(url_for("dashboard"))

    flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template("admin_login.html")


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    """로그아웃 처리. 세션에 저장된 로그인 정보를 전부 지운다."""
    session.clear()
    return redirect(url_for("admin_login"))


# ============================================================================
# 관리자 대시보드 화면 및 API — 전부 login_required로 보호됨
# ============================================================================

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """대시보드 화면의 뼈대(HTML)만 보여준다. 실제 데이터는 화면의 자바스크립트가
    아래 /api/status를 주기적으로 호출해서 채워넣는다(6단계에서 구현)."""
    return render_template("dashboard.html")


@app.route("/api/status", methods=["GET"])
@login_required
def api_status():
    """대시보드가 2~3초마다 호출하는 API. 최신 상태를 JSON으로 돌려준다.

    JSON이란? 파이썬의 딕셔너리(dict)와 거의 똑같이 생긴, 서버와 브라우저가
    데이터를 주고받을 때 가장 널리 쓰이는 표준 형식이다. jsonify()는 파이썬
    딕셔너리를 이 JSON 형식으로 자동 변환해서 브라우저에 보내주는 Flask 도구다.
    """
    soar.try_release_expired_lockouts()
    return jsonify(
        {
            "recent_attempts": db.list_recent_attempts(50),
            "active_lockouts": db.list_active_lockouts(),
            "admin_login_log": db.list_admin_login_log(20),
        }
    )


@app.route("/api/unlock", methods=["POST"])
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


if __name__ == "__main__":
    # 이 파일을 "python app.py"로 직접 실행했을 때만 개발용 서버를 켠다
    # (다른 파일이 이 파일을 import만 할 때는 서버가 자동으로 켜지지 않게 하는 관례).
    # PORT 환경변수가 있으면 그 포트를, 없으면 기본값 5000을 쓴다
    # (다른 프로그램이 이미 5000번을 쓰고 있을 때 충돌 없이 다른 포트로 띄우기 위함).
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)
