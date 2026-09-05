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


import math
import os
import re
from datetime import datetime
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

# .env 파일에 적어둔 값(SUPABASE_URL, SECRET_KEY 등)을 파이썬이 읽을 수 있는
# "환경변수"로 불러온다. 반드시 db 등 다른 모듈을 불러오기 "전에" 실행해야
# 그 모듈들이 필요한 값을 정상적으로 찾을 수 있다.
load_dotenv()

import config
import db
import detector
import geoip
import soar

# static_folder="public", static_url_path="": 기본값이면 Flask가 "static/" 폴더를
# "/static/파일명" 주소로 서빙하는데, Vercel은 CSS/JS 같은 정적 파일을 "public/" 폴더에서
# 찾아 "/파일명" 형태의 루트 경로로 서빙하는 게 규칙이다(Vercel 배포 시 설명 참고).
# 로컬 개발 서버와 Vercel 배포본이 똑같은 주소 구조를 쓰도록, Flask도 처음부터
# "public/" 폴더를 "/파일명" 경로로 서빙하게 맞춰뒀다 — 이러면 템플릿 코드는
# 하나도 안 고쳐도 된다(url_for('static', ...)가 알아서 "/css/auth.css" 형태로 바뀜).
app = Flask(__name__, static_folder="public", static_url_path="")

# Flask가 로그인 상태를 기억하기 위해 사용하는 "세션 쿠키"에 서명(위조 방지)할 때
# 쓰는 비밀 값. 이 값이 없으면 세션(로그인 유지) 기능 자체가 동작하지 않는다.
app.secret_key = os.environ["SECRET_KEY"]

# 세션 쿠키 보안 옵션 — 지금까지는 Flask 기본값에만 의존하고 있었다.
# - SESSION_COOKIE_HTTPONLY: 브라우저의 자바스크립트(document.cookie)가 세션 쿠키를
#   읽지 못하게 막는다. Flask 기본값도 True지만, "당연히 켜져 있겠지"에 기대지 않고
#   명시적으로 적어둔다 — 나중에 누군가 실수로 끄더라도 이 줄을 보고 바로 알아챌 수 있다.
# - SESSION_COOKIE_SAMESITE="Lax": 다른 사이트에 있는 폼/스크립트가 이 쿠키를 실어서
#   요청을 보내는 걸 브라우저 차원에서 1차로 막아준다. CSRFProtect(토큰 검증)가
#   메인 방어선이고, 이건 브라우저 레벨의 보조 방어선이다.
# - SESSION_COOKIE_SECURE: HTTPS 연결에서만 쿠키를 전송하게 강제한다. 로컬 개발
#   서버는 보통 HTTP(암호화 없음)로 뜨므로 로컬에서까지 켜두면 쿠키가 아예 전달되지
#   않아 로그인이 깨진다 — 그래서 FLASK_ENV=production일 때만(Vercel 배포 환경) 켠다.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

# CSRF(Cross-Site Request Forgery) 방어 — 이 프로젝트는 세션 쿠키로 로그인 상태를
# 유지하는데, 브라우저는 같은 사이트로 가는 요청이면 쿠키를 자동으로 실어 보낸다.
# 그래서 관리자가 로그인된 상태로 악성 페이지를 열면, 그 페이지가 눈에 안 보이는
# 폼이나 fetch()로 /api/users/delete 같은 주소를 몰래 호출해도 브라우저가 알아서
# 관리자의 세션 쿠키를 함께 보내버려 "관리자 본인이 요청한 것"처럼 서버가 착각한다.
#
# CSRFProtect(app)를 등록해두면, 폼(POST) 제출과 fetch() 요청 모두에 대해 이 서버가
# 직접 발급한 csrf_token이 함께 왔는지 매번 검사한다. 악성 페이지는 이 토큰 값을
# 알아낼 방법이 없으므로(다른 사이트가 이 사이트의 토큰을 읽을 수 없다), 위조된
# 요청은 토큰이 없거나 틀려서 자동으로 거부된다.
csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """CSRF 토큰이 없거나 틀렸을 때 Flask-WTF가 던지는 예외를 붙잡아 처리한다.

    기본 동작(그냥 400 에러 페이지)도 안전하긴 하지만, 이 프로젝트의 다른 화면들과
    똑같이 flash 메시지 + 로그인 화면으로 안내하는 편이 사용자 경험상 자연스럽다.
    (세션이 너무 오래돼 토큰이 만료된 경우가 실제 사용자에게 가장 흔한 원인이다.)
    """
    flash("보안 토큰이 만료되었거나 올바르지 않습니다. 다시 시도해주세요.")
    return redirect(request.referrer or url_for("login")), 400


# 서버가 켜질 때 딱 한 번, 관리자 계정이 하나도 없으면 .env 값으로 자동 생성한다.
# (회원가입 화면 없이 처음부터 관리자 1명이 존재하게 만드는 장치, db.py 3단계 참고)
db.ensure_bootstrap_admin()


def format_kr_time(iso_string: str) -> str:
    """Supabase가 돌려주는 "2026-09-02T15:10:24.091+00:00" 같은 시각 문자열을
    "2026-09-02 15:10:24"처럼 사람이 읽기 편한 형태로 바꾼다.

    관리자 대시보드는 이 변환을 자바스크립트(dashboard.js의 formatTime())가
    브라우저에서 처리하지만, 회원 화면(member_history.html)은 폴링 없이 서버가
    한 번에 화면을 그려서 보내주는 방식이라, 변환도 자바스크립트 대신 여기
    파이썬 쪽에서 미리 해둔다.
    """
    return datetime.fromisoformat(iso_string).strftime("%Y-%m-%d %H:%M:%S")


# Jinja2 필터란: 템플릿 안에서 "|" 기호로 값을 걸러/변형해서 쓸 수 있게 등록해두는
# 함수다. 이렇게 등록해두면 템플릿에서 {{ attempt.attempted_at | kr_time }}처럼
# 간단히 쓸 수 있다 — 변환 로직을 템플릿 여기저기에 반복해서 적을 필요가 없다.
app.jinja_env.filters["kr_time"] = format_kr_time


def _attach_locations(attempts: list[dict]) -> list[dict]:
    """로그인 시도 목록 각 줄에 "location"이라는 새 칸을 추가해서 돌려준다.

    geoip.get_locations()는 IP 목록을 한 번에 넘기면 IP 하나당 몇 번씩
    조회하는 게 아니라 필요한 만큼만(캐시에 없는 것만) 조회해준다. 여기서는
    그 결과를 각 시도 기록에 사람이 읽을 문자열(geoip.format_location())로
    바꿔 붙여주기만 한다.
    """
    ips = [attempt["ip_address"] for attempt in attempts]
    locations = geoip.get_locations(ips)
    for attempt in attempts:
        attempt["location"] = geoip.format_location(locations[attempt["ip_address"]])
    return attempts


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


@app.errorhandler(404)
def handle_not_found(error):
    """존재하지 않는 경로 요청(404)을 기록하고, 반복되면 Web Scanning 의심 알림을 보낸다.

    화면에 보여주는 내용은 Flask/Werkzeug 기본 404 응답 그대로 둔다(error.get_response())
    — 이 라우트의 목적은 사용자 경험을 바꾸는 게 아니라, 그동안 아무 기록도 남기지
    않던 404 요청을 관찰 가능하게 만드는 것뿐이다 (21단계, attack_response_state.md
    구현 대상 #1).

    알림은 "임계값을 막 넘긴 바로 그 요청"에서 딱 한 번만 보낸다(count가 정확히
    threshold+1일 때). enforce_lockout처럼 "잠긴 상태"라는 별도 표시가 없는 대신,
    이 방식으로 매 요청마다 알림이 반복되는 걸(알림 피로) 막는다.
    """
    ip = get_request_ip()
    db.log_not_found_attempt(ip, request.path)

    suspicious, count = detector.is_web_scanning(ip)
    if suspicious and count == config.WEB_SCANNING_ALERT_THRESHOLD + 1:
        soar.notify_web_scanning(ip, count, request.path)

    return error.get_response()


# board.js/dashboard.js가 스스로 만들어내는 자동 폴링 API. 브라우저 탭 하나만
# 열려 있어도 정상적으로 초당 여러 번씩 호출되므로, track_page_access()가 이걸
# "반복 접근 의심"으로 잘못 판단하지 않도록 관찰 대상에서 제외한다
# ("static"은 Flask가 public/의 CSS·JS·이미지를 서빙할 때 쓰는 내장 엔드포인트).
_PAGE_ACCESS_EXCLUDED_ENDPOINTS = {"static", "api_status", "api_board_comments_latest"}


@app.before_request
def track_page_access():
    """같은 IP가 같은 GET 페이지를 반복 요청하는지 관찰하고, 반복되면 알린다.

    이 함수는 handle_not_found()와 달리 특정 경로가 아니라 "매 요청"마다 실행된다
    (Flask가 라우팅을 마친 뒤, 실제 뷰 함수를 부르기 직전에 호출해준다). 그래서
    대상을 신중하게 좁혀야 한다:
    - request.url_rule이 None이면 애초에 존재하지 않는 경로(404)라는 뜻이므로
      제외한다 — 그 경우는 not_found_attempts가 이미 별도로 기록한다.
    - GET이 아닌 요청(폼 제출 등)은 "페이지 접근"이 아니므로 제외한다.
    - _PAGE_ACCESS_EXCLUDED_ENDPOINTS에 있는 엔드포인트(정적 파일, 자동 폴링 API)도
      제외한다 — 이것들을 빼두지 않으면 정상 사용자가 항상 "수상함"으로
      잘못 판정된다.

    알림은 handle_not_found()와 동일하게 "임계값을 막 넘긴 바로 그 요청"에서
    딱 한 번만 보낸다 (attack_response_state.md 구현 대상 #4).
    """
    if request.method != "GET" or request.url_rule is None:
        return
    if request.endpoint in _PAGE_ACCESS_EXCLUDED_ENDPOINTS:
        return

    ip = get_request_ip()
    db.log_page_access_attempt(ip, request.path)

    suspicious, count = detector.is_page_access_suspicious(ip, request.path)
    if suspicious and count == config.PAGE_ACCESS_ALERT_THRESHOLD + 1:
        soar.notify_page_access(ip, count, request.path)


def login_required(view):
    """"관리자 로그인이 되어 있어야만 들어올 수 있는 방"을 만들어주는 장치(데코레이터).

    데코레이터란? 함수(방) 앞에 "문지기"를 하나 세워두는 것과 같다.
    `@login_required`를 어떤 라우트 함수 위에 붙이면, 그 라우트가 실제로
    실행되기 전에 이 문지기 코드가 먼저 실행되어 "세션에 admin_username이
    있는지"부터 확인한다.

    - 없으면(로그인 안 된 상태):
        - 주소가 /api/로 시작하는 경우(JS가 fetch로 부르는 API) → 401(인증 필요) JSON 응답
          (이때 unauthorized_attempts에 기록하고, 반복되면 Unauthorized Access 의심
          알림을 보낸다 — 21단계, attack_response_state.md 구현 대상 #2)
        - 그 외(사람이 브라우저로 직접 들어온 화면) → 관리자 로그인 페이지로 강제 이동
    - 있으면(로그인 된 상태): 원래 요청했던 라우트 함수를 그대로 실행
    """
    @wraps(view)  # 문지기를 씌워도 원래 함수의 이름 등 정보가 유지되게 해주는 파이썬 관례
    def wrapped_view(*args, **kwargs):
        if "admin_username" not in session:
            if request.path.startswith("/api/"):
                ip = get_request_ip()
                db.log_unauthorized_attempt(ip, request.path)
                suspicious, count = detector.is_unauthorized_access_suspicious(ip)
                if suspicious and count == config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD + 1:
                    soar.notify_unauthorized_access(ip, count, request.path)
                return jsonify({"error": "로그인이 필요합니다."}), 401
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped_view


def member_login_required(view):
    """"회원 로그인이 되어 있어야만 들어올 수 있는 방" 문지기 — login_required와
    구조는 완전히 똑같지만, 확인하는 세션 값이 다르다("admin_username"이 아니라
    "username"). 관리자 세션과 회원 세션은 서로 다른 키를 쓰기 때문에, 같은
    브라우저에서 관리자로도 회원으로도 동시에 로그인된 상태가 될 수 있다 —
    이 프로젝트에서는 문제가 되지 않는다(두 화면이 서로 다른 데이터를 다룸).
    """
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


# ============================================================================
# 루트 주소 (/) — 도메인만 입력해서 들어온 방문자를 위한 안내
# ============================================================================

@app.route("/", methods=["GET"])
def index():
    """"/"(도메인만 입력한 경우)로 들어오면 감시 대상 로그인 화면으로 안내한다.

    "/"에는 원래 화면을 따로 만들지 않았기 때문에(로그인 워치독은 /login이 첫
    화면), 아무 라우트도 없으면 방문자가 404 페이지를 보게 된다. redirect()로
    "여기 말고 /login으로 가라"고 안내만 해주면, 브라우저가 자동으로 다시
    /login에 요청을 보내 정상적인 화면이 뜬다.
    """
    return redirect(url_for("login"))


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

# 게시판 입력 길이 제한 (docs/board-comment/plan_board.md 참고). 아이디/이메일과
# 달리 제목·본문은 임의의 문자를 허용해야 하므로(한글, 문장부호 등) 정규식
# 화이트리스트 대신 "길이만" 제한한다 — 내용 자체의 안전성은 Jinja2 auto-escape가
# 출력 시점에 보장한다(결정 #5).
POST_TITLE_MAX_LENGTH = 100
POST_BODY_MAX_LENGTH = 5000
COMMENT_BODY_MAX_LENGTH = 1000


# ============================================================================
# 회원가입 (신규 확장 기능) — 감시 대상 /login에 실제로 로그인할 계정을 만드는 곳
# ============================================================================

@app.route("/signup", methods=["GET"])
def signup():
    """회원가입 폼 화면을 보여준다. (아직 아무것도 제출하지 않은 상태)

    관리자가 대시보드에서 회원가입을 꺼뒀다면(db.get_signup_enabled()가 False),
    폼 대신 "지금은 가입할 수 없습니다"라는 안내만 보여준다. 실제로 화면 안의
    무엇을 보여줄지는 signup.html이 signup_enabled 값을 보고 스스로 결정한다.
    """
    return render_template("signup.html", signup_enabled=db.get_signup_enabled())


@app.route("/signup", methods=["POST"])
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
    return redirect(url_for("login"))


# ============================================================================
# 감시 대상 로그인 (/login) — 이 프로젝트가 실제로 감시하는 화면
# ============================================================================

@app.route("/login", methods=["GET"])
def login():
    """감시 대상 로그인 화면을 보여준다. 이미 로그인된 상태라면 회원 대시보드로 바로 보낸다.

    화면 자체는 관리자 로그인과 똑같은 login_form.html을 공유하지만(겉보기로는
    구분이 안 됨), form_action만 이 라우트로("/login") 지정해서 실제 제출은
    login_submit()이 처리하게 한다.
    """
    if "username" in session:
        return redirect(url_for("member_dashboard"))
    return render_template("login_form.html", form_action=url_for("login_submit"))


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
    6. 성공했다면 회원 세션을 만들어서 회원 대시보드로 이동시킨다(12단계에서 추가).
    """
    # 1) 시간이 지나 자동으로 풀려야 할 잠금들을 정리
    soar.try_release_expired_lockouts()

    ip = get_request_ip()

    # 2) 이미 잠긴 IP라면 계정 검증 자체를 건너뛰고 즉시 거부
    if detector.is_locked(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("login_submit"))

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
        return redirect(url_for("member_dashboard"))

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

    return render_template("login_form.html", form_action=url_for("login_submit"))


# ============================================================================
# 관리자 로그인/로그아웃 (/admin/login, /admin/logout)
# — 감시 대상(/login)과 완전히 분리된 별도 경로이므로 위의 IP 잠금 로직과 무관하다.
# ============================================================================

@app.route("/admin/login", methods=["GET"])
def admin_login():
    """관리자 로그인 화면을 보여준다. 이미 로그인된 상태라면 대시보드로 바로 보낸다.

    화면은 /login과 똑같은 login_form.html을 공유하되, form_action만 이 라우트로
    지정해서 실제 제출은 admin_login_submit()이 처리한다 — 겉보기로는 두 로그인
    화면을 구분할 수 없지만, 뒤에서 어떤 표(users vs admin_users)와 비교하고 IP
    잠금이 적용되는지는 여전히 완전히 분리되어 있다.
    """
    if "admin_username" in session:
        return redirect(url_for("admin_dashboard"))
    return render_template("login_form.html", form_action=url_for("admin_login_submit"))


@app.route("/admin/login", methods=["POST"])
def admin_login_submit():
    """관리자 로그인 폼 제출을 처리한다.

    /login(감시 대상 로그인)과 마찬가지로 IP 잠금을 적용한다 — 이전에는 이 라우트가
    시도 기록만 남길 뿐 잠금 판정을 전혀 하지 않아서, 관리자 계정만 브루트포스에
    무방비로 노출돼 있었다(18단계 보안 점검에서 발견 및 보완). 관리자 계정이 뚫리면
    회원 삭제·잠금 해제·회원가입 On/Off까지 전부 장악되므로 우선순위가 가장 높았다.
    """
    # 1) 시간이 지나 자동으로 풀려야 할 잠금들을 정리 (login_submit()과 동일)
    soar.try_release_expired_lockouts()

    ip = get_request_ip()

    # 2) 이미 잠긴 IP라면 자격 증명 확인 자체를 건너뛰고 즉시 거부
    if detector.is_locked(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("admin_login_submit"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    success = db.verify_admin_credentials(username, password)
    # 성공/실패와 무관하게 "누가 언제 관리자 로그인을 시도했는지"는 항상 기록해서
    # 나중에 대시보드에서 감사(audit) 이력을 확인할 수 있게 한다.
    db.log_admin_attempt(username, success, ip)

    if success:
        # 세션(session)은 "이 브라우저는 로그인된 상태다"를 서버가 기억하게 해주는
        # 저장 공간이다. 여기 값을 넣어두면, 같은 브라우저로 다시 요청이 올 때마다
        # Flask가 자동으로 이 값을 복원해줘서 "로그인 유지"가 가능해진다.
        session["admin_username"] = username
        return redirect(url_for("admin_dashboard"))

    # 3) 이 실패로 인해 방금 임계값을 넘었는지 확인하고, 넘었다면 잠근다
    #    (login_submit()과 동일한 detector/soar 조합 — 잠금 상태 자체는 lockouts
    #    표를 공유하므로, 이 IP는 /login 쪽에서도 함께 잠긴다).
    suspicious, failure_count = detector.is_admin_suspicious(ip)
    if suspicious:
        distinct_usernames = detector.count_distinct_admin_usernames(ip)
        soar.enforce_lockout(ip, failure_count, distinct_usernames)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
    else:
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template("login_form.html", form_action=url_for("admin_login_submit"))


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    """로그아웃 처리. 세션에 저장된 로그인 정보를 전부 지운다."""
    session.clear()
    return redirect(url_for("admin_login"))


# ============================================================================
# 관리자 대시보드 화면 및 API — 전부 login_required로 보호됨
#
# 주소가 /dashboard가 아니라 /admin/login·/admin/logout과 같은 묶음인
# /admin/dashboard인 이유: 12단계에서 회원(일반 사용자) 전용 대시보드를
# /dashboard 주소에 새로 만들면서, 기존 관리자 대시보드를 이 주소로 옮겼다.
# ============================================================================

@app.route("/admin/dashboard", methods=["GET"])
@login_required
def admin_dashboard():
    """관리자 대시보드 화면의 뼈대(HTML)만 보여준다. 실제 데이터는 화면의
    자바스크립트가 아래 /api/status를 주기적으로 호출해서 채워넣는다(6단계에서 구현).

    poll_interval_ms : dashboard.js가 몇 밀리초마다 /api/status를 다시 부를지.
    숫자를 JS 파일에 직접 박아두지 않고 config.py 한 곳에서 관리한다(다른
    상수들과 동일한 원칙 — 값을 바꾸려고 여러 파일을 찾아다닐 필요가 없게 함).
    """
    return render_template("admin_dashboard.html", poll_interval_ms=config.ADMIN_DASHBOARD_POLL_MS)


def _page_param(name: str) -> int:
    """쿼리 파라미터로 받은 페이지 번호를 정수로 변환한다. board_list()의 page
    처리와 동일한 원칙 — 값이 없거나 이상해도(?users_page=abc) 에러 없이
    1페이지로 취급한다.
    """
    page = request.args.get(name, 1, type=int)
    return page if page and page > 0 else 1


@app.route("/api/status", methods=["GET"])
@login_required
def api_status():
    """대시보드가 2~3초마다 호출하는 API. 최신 상태를 JSON으로 돌려준다.

    JSON이란? 파이썬의 딕셔너리(dict)와 거의 똑같이 생긴, 서버와 브라우저가
    데이터를 주고받을 때 가장 널리 쓰이는 표준 형식이다. jsonify()는 파이썬
    딕셔너리를 이 JSON 형식으로 자동 변환해서 브라우저에 보내주는 Flask 도구다.

    관리자 대시보드의 표 5개(최근 로그인 시도/회원/게시글/댓글/관리자 로그인 기록)는
    각자 ?attempts_page=, ?users_page=, ?posts_page=, ?comments_page=,
    ?admin_log_page=로 현재 보고 있는 페이지 번호를 받는다 — dashboard.js가
    board_list()와 동일한 페이지 번호 방식으로 표를 그릴 수 있도록, 각 표의
    이번 페이지 데이터와 전체 페이지 수(*_total_pages)를 함께 내려준다 (예전에는
    최근 N개만 고정으로 가져와서, 그 이상 쌓이면 오래된 항목이 화면에서 아예
    사라졌었다).

    db.list_*() 함수들은 (이번 페이지 데이터, 전체 개수) 튜플을 돌려준다 — 목록
    조회와 개수 조회를 별도 쿼리 두 번으로 나누지 않고 한 번의 왕복으로 끝내기
    위해서다(db.list_recent_attempts() 설명 참고). 표가 5개로 늘면서 이 둘을
    따로 뒀을 때 요청 한 번에 왕복이 10번까지 늘어나 응답이 눈에 띄게 느려졌었다.
    """
    soar.try_release_expired_lockouts()

    attempts_page = _page_param("attempts_page")
    users_page = _page_param("users_page")
    posts_page = _page_param("posts_page")
    comments_page = _page_param("comments_page")
    admin_log_page = _page_param("admin_log_page")

    attempts, attempts_count = db.list_recent_attempts(attempts_page, config.ADMIN_PAGE_SIZE)
    admin_log, admin_log_count = db.list_admin_login_log(admin_log_page, config.ADMIN_PAGE_SIZE)
    users, users_count = db.list_users(users_page, config.ADMIN_PAGE_SIZE)
    posts, posts_count = db.list_posts(posts_page, config.ADMIN_PAGE_SIZE)
    comments, comments_count = db.list_comments_admin(comments_page, config.ADMIN_PAGE_SIZE)

    return jsonify(
        {
            "recent_attempts": _attach_locations(attempts),
            "attempts_total_pages": max(1, math.ceil(attempts_count / config.ADMIN_PAGE_SIZE)),
            "active_lockouts": db.list_active_lockouts(),
            "admin_login_log": admin_log,
            "admin_log_total_pages": max(1, math.ceil(admin_log_count / config.ADMIN_PAGE_SIZE)),
            "users": users,
            "users_total_pages": max(1, math.ceil(users_count / config.ADMIN_PAGE_SIZE)),
            "signup_enabled": db.get_signup_enabled(),
            # 게시판 관리 섹션(관리자 대시보드)용 — recent_attempts 등과 같은 폴링
            # 주기(dashboard.js, 10초)로 함께 갱신된다.
            "recent_posts": posts,
            "posts_total_pages": max(1, math.ceil(posts_count / config.ADMIN_PAGE_SIZE)),
            "recent_comments": comments,
            "comments_total_pages": max(1, math.ceil(comments_count / config.ADMIN_PAGE_SIZE)),
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


@app.route("/api/users/delete", methods=["POST"])
@login_required
def api_users_delete():
    """대시보드의 회원 목록에서 "삭제" 버튼을 눌렀을 때 호출되는 API.

    /api/unlock과 똑같은 패턴이다 — login_required가 이미 "로그인된 관리자의
    요청"임을 보장해주므로, 이 함수는 삭제 실행에만 집중한다.
    """
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "user_id 값이 필요합니다."}), 400

    deleted = db.delete_user(user_id)
    return jsonify({"success": deleted})


@app.route("/api/settings/signup", methods=["POST"])
@login_required
def api_settings_signup():
    """대시보드의 "회원가입 켜기/끄기" 토글을 눌렀을 때 호출되는 API.

    {"enabled": true} 또는 {"enabled": false}를 받아 db.set_signup_enabled()로
    Supabase에 반영한다. 이 값을 서버 메모리가 아니라 Supabase에 저장해두는
    이유는 db.get_signup_enabled() 설명(db.py) 참고 — 로컬/Vercel 등 여러 곳에서
    서버가 동시에 돌아도 항상 같은 값을 보게 하기 위함이다.
    """
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"success": False, "error": "enabled(true/false) 값이 필요합니다."}), 400

    db.set_signup_enabled(enabled)
    return jsonify({"success": True, "signup_enabled": enabled})


@app.route("/api/board/posts/delete", methods=["POST"])
@login_required
def api_board_posts_delete():
    """관리자 대시보드의 "게시글 관리" 섹션에서 임의 게시글을 삭제할 때 호출되는 API.

    /api/users/delete와 동일한 패턴 — login_required가 이미 "로그인된 관리자의
    요청"임을 보장해주므로, 회원 본인 글인지 여부와 무관하게 바로 삭제한다
    (docs/board-comment/02-design-decisions.md 결정 #2 — 삭제 권한: 본인 + 관리자).
    """
    data = request.get_json(silent=True) or {}
    post_id = data.get("post_id")
    if not post_id:
        return jsonify({"success": False, "error": "post_id 값이 필요합니다."}), 400

    deleted = db.delete_post(post_id)
    return jsonify({"success": deleted})


@app.route("/api/board/comments/delete", methods=["POST"])
@login_required
def api_board_comments_delete():
    """관리자 대시보드에서 임의 댓글을 삭제할 때 호출되는 API. 위 함수와 동일한 패턴."""
    data = request.get_json(silent=True) or {}
    comment_id = data.get("comment_id")
    if not comment_id:
        return jsonify({"success": False, "error": "comment_id 값이 필요합니다."}), 400

    deleted = db.delete_comment(comment_id)
    return jsonify({"success": deleted})


# ============================================================================
# 게시판 (/board) — 전부 member_login_required로 보호됨 (회원 전용, 결정 #1)
#
# login_required/member_login_required는 "로그인 여부"만 확인하고 "이 글/댓글이
# 내 것인지"는 확인하지 않으므로, 수정/삭제 라우트마다 _is_post_owner() 등으로
# 직접 소유권을 검사한다 — 관리자는 위 /api/board/*/delete를 통해 별도로 전체
# 글/댓글을 삭제할 수 있다(docs/board-comment/plan_board.md 5-3절 참고).
# ============================================================================

def _is_post_owner(post: dict) -> bool:
    """지금 로그인한 회원이 이 글의 작성자인지 확인한다."""
    return post["author_username"] == session.get("username")


@app.route("/board", methods=["GET"])
@member_login_required
def board_list():
    """게시글 목록. 페이지 번호는 쿼리 파라미터 ?page=로 받는다 (결정 #9 — 페이지 번호 방식).

    page의 type=int 변환이 실패하면(예: ?page=abc) Flask가 자동으로 기본값 1을
    쓰므로, 잘못된 값이 와도 에러 없이 1페이지를 보여준다.
    """
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    posts, total_count = db.list_posts(page, config.BOARD_PAGE_SIZE)
    total_pages = max(1, math.ceil(total_count / config.BOARD_PAGE_SIZE))
    return render_template("board_list.html", posts=posts, page=page, total_pages=total_pages)


@app.route("/board/new", methods=["GET"])
@member_login_required
def board_new():
    """글쓰기 폼 화면. board_form.html은 board_edit()과 화면을 공유한다
    (login_form.html이 /login과 /admin/login을 공유하는 것과 동일한 패턴) —
    post=None이면 "새 글쓰기", post가 있으면 "수정"으로 폼이 스스로 판단한다.
    """
    return render_template("board_form.html", form_action=url_for("board_new_submit"), post=None)


@app.route("/board/new", methods=["POST"])
@member_login_required
def board_new_submit():
    """글쓰기 폼 제출을 처리한다."""
    ip = get_request_ip()

    # 같은 IP가 짧은 시간에 너무 많이 글을 올리면 거부한다 (signup_submit()과 동일한
    # "먼저 판정 → 성공/실패 무관하게 시도 자체를 기록" 순서, 결정 #7).
    if detector.is_post_rate_limited(ip):
        flash("너무 많은 게시글 작성 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return render_template("board_form.html", form_action=url_for("board_new_submit"), post=None)
    db.log_post_attempt(ip)

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()

    if not title or not body:
        flash("제목과 내용을 모두 입력해주세요.")
        return render_template("board_form.html", form_action=url_for("board_new_submit"), post=None)

    if len(title) > POST_TITLE_MAX_LENGTH or len(body) > POST_BODY_MAX_LENGTH:
        flash(
            f"제목은 최대 {POST_TITLE_MAX_LENGTH}자, 내용은 최대 {POST_BODY_MAX_LENGTH}자까지 "
            "입력할 수 있습니다."
        )
        return render_template("board_form.html", form_action=url_for("board_new_submit"), post=None)

    post = db.create_post(session["username"], title, body)
    flash("게시글이 등록되었습니다.")
    return redirect(url_for("board_detail", post_id=post["id"]))


@app.route("/board/<int:post_id>", methods=["GET"])
@member_login_required
def board_detail(post_id):
    """게시글 상세 + 댓글 목록 + 댓글 작성 폼 + "새 댓글" 알림 배너 자리."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board_list"))

    comments = db.list_comments_by_post(post_id)
    return render_template(
        "board_detail.html",
        post=post,
        comments=comments,
        is_owner=_is_post_owner(post),
        # board.js가 "새 댓글" 배너를 몇 밀리초마다 확인할지. admin_dashboard()와
        # 동일한 이유로 config.py에서 값을 받아 템플릿에 내려준다.
        poll_interval_ms=config.BOARD_COMMENT_POLL_MS,
    )


@app.route("/board/<int:post_id>/edit", methods=["GET"])
@member_login_required
def board_edit(post_id):
    """게시글 수정 폼. 본인 글이 아니면 폼을 아예 보여주지 않고 상세 화면으로 돌려보낸다."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board_list"))
    if not _is_post_owner(post):
        flash("본인이 작성한 글만 수정할 수 있습니다.")
        return redirect(url_for("board_detail", post_id=post_id))

    return render_template(
        "board_form.html", form_action=url_for("board_edit_submit", post_id=post_id), post=post
    )


@app.route("/board/<int:post_id>/edit", methods=["POST"])
@member_login_required
def board_edit_submit(post_id):
    """게시글 수정 폼 제출을 처리한다.

    화면에서 수정 버튼을 감췄더라도, 여기서도 다시 한번 소유권을 확인한다
    (signup_submit()의 이중 검증 원칙과 동일 — 개발자 도구로 우회한 요청까지 방어).
    """
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board_list"))
    if not _is_post_owner(post):
        flash("본인이 작성한 글만 수정할 수 있습니다.")
        return redirect(url_for("board_detail", post_id=post_id))

    form_action = url_for("board_edit_submit", post_id=post_id)

    # board_new_submit()과 동일한 빈도 제한 — 글 수정도 도배 대상이 될 수 있으므로
    # 새 글 작성과 같은 post_attempts 카운트를 공유한다 (원래 이 검사가 빠져있던
    # 공백을 보완, attack_response_state.md 구현 대상 #3).
    ip = get_request_ip()
    if detector.is_post_rate_limited(ip):
        flash("너무 많은 게시글 작성 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return render_template("board_form.html", form_action=form_action, post=post)
    db.log_post_attempt(ip)

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()

    if not title or not body:
        flash("제목과 내용을 모두 입력해주세요.")
        return render_template("board_form.html", form_action=form_action, post=post)

    if len(title) > POST_TITLE_MAX_LENGTH or len(body) > POST_BODY_MAX_LENGTH:
        flash(
            f"제목은 최대 {POST_TITLE_MAX_LENGTH}자, 내용은 최대 {POST_BODY_MAX_LENGTH}자까지 "
            "입력할 수 있습니다."
        )
        return render_template("board_form.html", form_action=form_action, post=post)

    db.update_post(post_id, title, body)
    flash("게시글이 수정되었습니다.")
    return redirect(url_for("board_detail", post_id=post_id))


@app.route("/board/<int:post_id>/delete", methods=["POST"])
@member_login_required
def board_delete(post_id):
    """본인 글 삭제 (결정 #2 — 삭제 권한: 본인 + 관리자. 관리자는 /api/board/posts/delete 사용)."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board_list"))
    if not _is_post_owner(post):
        flash("본인이 작성한 글만 삭제할 수 있습니다.")
        return redirect(url_for("board_detail", post_id=post_id))

    db.delete_post(post_id)
    flash("게시글이 삭제되었습니다.")
    return redirect(url_for("board_list"))


@app.route("/board/<int:post_id>/comments", methods=["POST"])
@member_login_required
def board_comment_submit(post_id):
    """댓글 작성. Post-Redirect-Get 패턴으로 처리 후 항상 상세 화면으로 돌아간다."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board_list"))

    ip = get_request_ip()
    if detector.is_comment_rate_limited(ip):
        flash("너무 많은 댓글 작성 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return redirect(url_for("board_detail", post_id=post_id))
    db.log_comment_attempt(ip)

    body = request.form.get("body", "").strip()
    if not body:
        flash("댓글 내용을 입력해주세요.")
        return redirect(url_for("board_detail", post_id=post_id))
    if len(body) > COMMENT_BODY_MAX_LENGTH:
        flash(f"댓글은 최대 {COMMENT_BODY_MAX_LENGTH}자까지 입력할 수 있습니다.")
        return redirect(url_for("board_detail", post_id=post_id))

    db.create_comment(post_id, session["username"], body)
    return redirect(url_for("board_detail", post_id=post_id))


@app.route("/board/<int:post_id>/comments/<int:comment_id>/delete", methods=["POST"])
@member_login_required
def board_comment_delete(post_id, comment_id):
    """본인 댓글 삭제."""
    comment = db.get_comment(comment_id)
    if comment is None:
        flash("존재하지 않는 댓글입니다.")
        return redirect(url_for("board_detail", post_id=post_id))
    if comment["author_username"] != session.get("username"):
        flash("본인이 작성한 댓글만 삭제할 수 있습니다.")
        return redirect(url_for("board_detail", post_id=post_id))

    db.delete_comment(comment_id)
    return redirect(url_for("board_detail", post_id=post_id))


@app.route("/api/board/<int:post_id>/comments/latest", methods=["GET"])
@member_login_required
def api_board_comments_latest(post_id):
    """board.js가 짧은 주기(15초)로 폴링하는 API. 댓글 개수/최신 시각만 가볍게
    돌려준다 — 표 전체를 다시 그리는 관리자 대시보드(/api/status)와 달리,
    "값이 바뀌었으니 배너를 띄워라"는 신호로만 쓰인다(결정 #6).
    """
    return jsonify(db.get_latest_comment_info(post_id))


# ============================================================================
# 회원 대시보드 (/dashboard) — 전부 member_login_required로 보호됨
#
# 이름이 "/admin/dashboard"와 비슷해 보이지만 완전히 다른 화면이다. 회원은
# 본인 계정에 관한 정보만 볼 수 있고, 다른 회원 정보나 관리자 기능(잠긴 IP,
# 전체 회원 목록 등)에는 접근할 수 없다 — member_login_required와
# login_required가 서로 다른 세션 키를 확인하기 때문에 이 구분이 코드 수준에서
# 강제된다.
# ============================================================================

def _logout_missing_member():
    """세션은 남아있는데 실제 계정이 사라진 경우(예: 관리자가 회원 삭제 버튼을
    눌렀는데 그 회원이 다른 탭에서 아직 로그인 상태였던 경우) 세션을 정리하고
    로그인 화면으로 돌려보낸다.

    member_login_required는 "세션에 값이 있는지"만 확인하지, 그 값이 가리키는
    회원이 지금도 실제로 존재하는지는 확인하지 않는다 — 그래서 회원용 화면들이
    db.get_user_by_id()로 다시 한번 확인하고, 없으면 이 함수를 부른다.
    """
    session.pop("username", None)
    session.pop("user_id", None)
    flash("계정 정보를 찾을 수 없습니다. 다시 로그인해주세요.")
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
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


@app.route("/dashboard/history", methods=["GET"])
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


@app.route("/dashboard/profile", methods=["GET"])
@member_login_required
def member_profile():
    """프로필(표시 이름/이메일) 조회 및 수정 화면을 보여준다."""
    user = db.get_user_by_id(session["user_id"])
    if user is None:
        return _logout_missing_member()
    return render_template("member_profile.html", user=user)


@app.route("/dashboard/profile", methods=["POST"])
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
        return redirect(url_for("member_profile"))

    updated = db.update_user_profile(session["user_id"], name, email)
    if not updated:
        flash("이미 다른 회원이 사용 중인 이메일입니다.")
        return redirect(url_for("member_profile"))

    flash("프로필이 수정되었습니다.")
    return redirect(url_for("member_profile"))


@app.route("/dashboard/logout", methods=["POST"])
@member_login_required
def member_logout():
    """회원 로그아웃 처리.

    admin_logout()과 달리 session.clear()를 쓰지 않고 회원 관련 키(username,
    user_id)만 콕 집어 지운다 — 만약 같은 브라우저에서 관리자로도 로그인되어
    있었다면, 회원만 로그아웃하고 관리자 세션은 그대로 유지하기 위해서다.
    """
    session.pop("username", None)
    session.pop("user_id", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    # 이 파일을 "python app.py"로 직접 실행했을 때만 개발용 서버를 켠다
    # (다른 파일이 이 파일을 import만 할 때는 서버가 자동으로 켜지지 않게 하는 관례).
    # PORT 환경변수가 있으면 그 포트를, 없으면 기본값 5000을 쓴다
    # (다른 프로그램이 이미 5000번을 쓰고 있을 때 충돌 없이 다른 포트로 띄우기 위함).
    #
    # debug=True를 항상 켜두면 위험하다: Flask 공식 문서가 명시하듯, 디버그 모드의
    # 대화형 디버거는 브라우저에서 임의의 파이썬 코드를 실행할 수 있는 콘솔을
    # 열어준다 — 개발 중에는 편리하지만, 이 상태로 운영 서버를 인터넷에 노출하면
    # 방문자 누구나 서버에서 코드를 실행할 수 있는 심각한 취약점이 된다. 그래서
    # FLASK_DEBUG 환경변수를 명시적으로 "true"로 켜둔 로컬 개발 환경에서만 켜지고,
    # 기본값은 항상 꺼진(False) 상태로 시작한다.
    #
    # 또한 "python app.py"로 직접 띄우는 이 개발 서버는 로컬 실습/디버깅용이지
    # 운영 배포용이 아니다(Flask 공식 문서가 프로덕션 사용을 금지함). 이 프로젝트가
    # 실제로 배포되는 Vercel(10단계 참고)은 이 if 블록을 아예 거치지 않고 `app`
    # 객체를 직접 서버리스 런타임으로 실행하므로 영향이 없지만, Vercel이 아닌
    # 곳(자체 서버 등)에 운영 배포한다면 이 개발 서버 대신 gunicorn 같은 프로덕션
    # WSGI 서버로 띄워야 한다 — 예: `gunicorn app:app --bind 0.0.0.0:5000`.
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=debug, port=port)
