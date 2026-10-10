# ============================================================================
# app.py — 이 프로그램의 "정문" 역할을 하는 Flask 진입점
#
# 지금까지 만든 db/(데이터 저장/조회), security/detector.py(판정), security/soar/(조치),
# notify/alert.py(알림)는 전부 "부품"이었다. 이 파일은 그 부품들을 실제 웹 화면의
# 버튼·주소(URL)와 연결해서, 사용자가 브라우저로 방문했을 때 실제로 동작하는
# "완성된 웹사이트"로 만들어주는 역할을 한다.
#
# Flask란? 파이썬으로 웹사이트(웹 서버)를 아주 적은 코드로 만들 수 있게
# 도와주는 도구(프레임워크)다. "이 주소로 누가 들어오면 이 함수를 실행해라"
# 는 규칙을 하나씩 등록해두면, 사용자가 그 주소로 접속했을 때 자동으로
# 해당 함수가 실행되어 화면을 만들어 보여준다.
#
# 실제 화면 라우트(회원가입/로그인/관리자/게시판/회원 대시보드 등)는 이제 이
# 파일이 아니라 routes/ 아래 Blueprint들에 나뉘어 있다 — 이 파일에는 앱을
# 만들고(Flask()), 공용 설정(세션/CSRF/요청 한도)을 하고, 그 Blueprint들을 등록하는
# "조립" 코드와, 요청 한도·CSRF 에러 핸들러만 남아있다. 모든 요청에 걸리는 관찰 훅
# (보안 헤더, 404 기록, 반복 접근·매크로 탐지)은 helpers/hooks.py에 있다.
# 분리 배경과 각 파일이 어디로 갔는지는 docs/refactor/2026-09-15-file-split.md,
# docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================


import os
from datetime import datetime
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, flash, redirect, request, url_for
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

# .env 파일에 적어둔 값(SUPABASE_URL, SECRET_KEY 등)을 파이썬이 읽을 수 있는
# "환경변수"로 불러온다. 반드시 db 등 다른 모듈을 불러오기 "전에" 실행해야
# 그 모듈들이 필요한 값을 정상적으로 찾을 수 있다.
load_dotenv()

import config
import db
from helpers import get_request_ip
from helpers import spa
from helpers.hooks import PAGE_ACCESS_EXCLUDED_ENDPOINTS, register_request_hooks
from notify import mailer
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.board import board_bp
from routes.email import email_bp
from routes.member import member_bp
from routes.password import password_bp
from routes.recovery import recovery_bp
from security import soar

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

# 라우트는 7개의 Blueprint(routes/auth.py, admin/, board.py, member.py, recovery.py,
# email.py, password.py)에 나뉘어 있다. url_prefix를 따로 주지 않으므로 실제 URL
# 경로(/login, /admin/dashboard 등)는
# 분리 이전과 완전히 동일하다 — 바뀐 건 Blueprint 등록에 따라 url_for()에 넘기는
# 이름이 "login"에서 "auth.login"처럼 <블루프린트 이름>.<함수 이름> 형태가 된 것뿐이다
# (이 파일과 templates/*.html의 url_for() 호출도 전부 그 형태로 맞춰뒀다).
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(board_bp)
app.register_blueprint(member_bp)
app.register_blueprint(recovery_bp)
app.register_blueprint(email_bp)
app.register_blueprint(password_bp)

# 운영(production)에서 복구 메일 설정이 비어 있으면 서버 시작 로그에 경고를 남긴다(guide34-a).
mailer.print_configuration_warnings()


# ============================================================================
# 전역 HTTP 플러딩(대량 요청 도배) 방어 (L7 공격 보강 계획 Tier 2)
#
# 지금까지의 *_RATE_LIMIT(로그인/가입/글쓰기/댓글)은 "특정 폼 제출"에만 걸려
# 있었고, 일반 GET 페이지(/board, /dashboard 등)는 아무리 요청이 쏟아져도 다
# 받아줬다 — Flask-Limiter로 "같은 IP가 1분에 이 횟수 이상 요청하면 429로
# 거절"하는 전역 기본 한도를 하나 더 건다. key_func으로 helpers.get_request_ip를
# 그대로 재사용해서, TRUST_FORWARDED_FOR 설정에 따라 실제 IP/신뢰하는 헤더 값
# 중 이미 검증된 같은 기준으로 카운트한다.
#
# board.js/dashboard.js가 스스로 만들어내는 자동 폴링 API(PAGE_ACCESS_EXCLUDED_
# ENDPOINTS, helpers/hooks.py의 track_page_access() 참고)는 정상적으로도 이 한도를 넘길 만큼 자주
# 호출되므로, default_limits_exempt_when으로 그 엔드포인트들만 제외한다.
# ============================================================================
limiter = Limiter(
    key_func=get_request_ip,
    app=app,
    default_limits=[f"{config.GLOBAL_RATE_LIMIT_PER_MINUTE} per minute"],
    default_limits_exempt_when=lambda: request.endpoint in PAGE_ACCESS_EXCLUDED_ENDPOINTS,
)

# 복구 코드 제출(POST /recovery/verify)에는 전역 한도보다 훨씬 좁은 한도를 따로 건다
# (guide37). 6자리 코드는 시도 횟수 제한이 핵심 방어선이고, 이건 그 앞단의 2차 방어선이다.
# limiter가 이 파일에서 만들어지므로 routes/recovery.py에서 데코레이터로 달면 순환
# import가 된다 — 그래서 등록된 뷰 함수를 여기서 감싼다. GET(확인 화면)은 다른
# 엔드포인트(recovery.recovery_verify_form)라 이 한도에 걸리지 않는다.
app.view_functions["recovery.recovery_verify_submit"] = limiter.limit(
    f"{config.RECOVERY_VERIFY_RATE_LIMIT_PER_MINUTE} per minute"
)(app.view_functions["recovery.recovery_verify_submit"])
# 복구 요청(POST /recovery/request, guide43)은 응답마다 고정 시간만큼 함수를 붙잡으므로 좁은 한도를
# 따로 건다. 한도를 넘긴 요청은 고정 대기 없이 바로 429로 끝난다.
app.view_functions["recovery.recovery_request_submit"] = limiter.limit(
    f"{config.RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE} per minute"
)(app.view_functions["recovery.recovery_request_submit"])
# 이메일 확인 링크 제출(POST /email/confirm, guide40)도 같은 이유로 좁은 한도를 따로 건다.
app.view_functions["email.email_confirm_submit"] = limiter.limit(
    f"{config.EMAIL_CONFIRM_RATE_LIMIT_PER_MINUTE} per minute"
)(app.view_functions["email.email_confirm_submit"])
# 비밀번호 찾기 요청·재설정 제출(guide41)도 같은 이유로 좁은 한도를 따로 건다.
for _endpoint in ("password.password_forgot_submit", "password.password_reset_submit"):
    app.view_functions[_endpoint] = limiter.limit(
        f"{config.PASSWORD_RESET_RATE_LIMIT_PER_MINUTE} per minute"
    )(app.view_functions[_endpoint])


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(error):
    """요청 한도를 넘긴 요청을 429로 거절하고 기록한다. 전역 한도(GLOBAL_RATE_LIMIT_PER_MINUTE)
    뿐 아니라 위에서 따로 건 라우트별 좁은 한도(복구·이메일 확인·비밀번호 찾기)도 같은 예외로
    여기에 온다 — 어느 쪽이든 HTTP_FLOOD 이벤트로 기록하고, count 칸에는 전역 한도 값을 넣는다.

    soar.record_rejection()은 signup/post/comment 요청 거부와 동일한 HIGH 등급
    "상태 기반 중복 방지" 패턴을 쓴다 — 같은 IP가 계속 도배해도 미해결 이벤트
    하나의 count만 올리고, security_events가 HIGH로 도배되지 않게 한다.
    """
    ip = get_request_ip()
    soar.record_rejection("HTTP_FLOOD", ip, request.path, config.GLOBAL_RATE_LIMIT_PER_MINUTE)
    return error.get_response()


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """CSRF 토큰이 없거나 틀렸을 때 Flask-WTF가 던지는 예외를 붙잡아 처리한다.

    기본 동작(그냥 400 에러 페이지)도 안전하긴 하지만, 이 프로젝트의 다른 화면들과
    똑같이 flash 메시지 + 로그인 화면으로 안내하는 편이 사용자 경험상 자연스럽다.
    (세션이 너무 오래돼 토큰이 만료된 경우가 실제 사용자에게 가장 흔한 원인이다.)

    오픈 리다이렉트 방지 (L7 공격 보강 계획 Tier 4): request.referrer는 브라우저가
    보내는 값이지만, 결국 요청을 보낸 클라이언트가 자유롭게 설정할 수 있는 헤더다.
    예전에는 이 값을 검증 없이 그대로 redirect()에 넘겨서, 공격자 사이트에서 이
    CSRF 에러 핸들러로 링크를 걸면 이론상 그 값을 우리 사이트가 신뢰하는 이동
    경로처럼 돌려주는 경로가 있었다. urlparse로 "이 사이트(request.host)로
    돌아가는 주소인지"부터 확인하고, 아니거나 아예 없으면 로그인 화면으로 고정
    폴백한다.
    """
    flash("보안 토큰이 만료되었거나 올바르지 않습니다. 다시 시도해주세요.")
    referrer = request.referrer
    if referrer and urlparse(referrer).netloc == request.host:
        return redirect(referrer), 400
    return redirect(url_for("auth.login")), 400


# 서버가 켜질 때 딱 한 번, 관리자 계정이 하나도 없으면 .env 값으로 자동 생성한다.
# (회원가입 화면 없이 처음부터 관리자 1명이 존재하게 만드는 장치, db/admin.py의 ensure_bootstrap_admin() 참고)
db.ensure_bootstrap_admin()


def format_kr_time(iso_string: str) -> str:
    """Supabase가 돌려주는 "2026-09-02T15:10:24.091+00:00" 같은 시각 문자열을
    "2026-09-02 15:10:24"처럼 사람이 읽기 편한 형태로 바꾼다.

    관리자 대시보드는 이 변환을 자바스크립트(dashboard/utils.js의 formatTime())가
    브라우저에서 처리하지만, 회원 화면(member_history.html)은 폴링 없이 서버가
    한 번에 화면을 그려서 보내주는 방식이라, 변환도 자바스크립트 대신 여기
    파이썬 쪽에서 미리 해둔다.
    """
    return datetime.fromisoformat(iso_string).strftime("%Y-%m-%d %H:%M:%S")


# Jinja2 필터란: 템플릿 안에서 "|" 기호로 값을 걸러/변형해서 쓸 수 있게 등록해두는
# 함수다. 이렇게 등록해두면 템플릿에서 {{ attempt.attempted_at | kr_time }}처럼
# 간단히 쓸 수 있다 — 변환 로직을 템플릿 여기저기에 반복해서 적을 필요가 없다.
app.jinja_env.filters["kr_time"] = format_kr_time

# 보안 헤더·404 기록·반복 접근/매크로 관찰 훅(helpers/hooks.py). 위의 Limiter보다 뒤에 등록해야
# 전역 요청 한도가 관찰 훅보다 먼저 돈다(register_request_hooks 설명 참고).
# Next.js 정적 화면 연결(helpers/spa.py) — Limiter 뒤, 관찰 훅 앞에 등록한다. web/ 빌드(spa/)가
# 없으면 아무 일도 하지 않아 예전 Jinja 화면이 그대로 나온다.
spa.register(app)
register_request_hooks(app)


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
    return redirect(url_for("auth.login"))


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
    # threaded=True: 요청마다 스레드를 써서 탭 여러 개가 서로를 막지 않게 한다(Flask 기본값이지만 명시).
    # use_reloader=False: 디버그 모드여도 파일 감시로 서버가 저절로 다시 시작되지 않게 한다.
    app.run(debug=debug, port=port, threaded=True, use_reloader=False)
