# ============================================================================
# helpers/spa.py — Next.js 정적 화면(web/)과 기존 Flask 라우트를 이어주는 어댑터
#
# 배경: 화면을 Jinja 템플릿에서 Next.js로 옮기면서, 로그인·잠금·요청 한도·타이밍 방어 같은
# 보안 로직이 들어 있는 기존 라우트(routes/*)를 다시 쓰지 않으려고 만든 얇은 층이다.
#
# 두 가지 일을 한다.
#
# 1) 화면(HTML) 요청 — 브라우저가 주소를 직접 열면(GET, 어댑터 헤더 없음) Next가 만든 정적
#    HTML을 그대로 내려준다. 이 요청은 "껍데기"일 뿐이라 DB 조회·잠금 판정을 하지 않고,
#    반복 접근 관찰 훅(helpers/hooks.py)에도 잡히지 않는다. 껍데기가 뜬 뒤 화면이
#    같은 주소를 어댑터 헤더와 함께 다시 요청하고, 그때 기존 라우트가 평소처럼(로그인 확인,
#    권한 확인, 요청 기록 포함) 실행된다.
#
# 2) 데이터 요청 — 어댑터 헤더(X-Requested-With: login-watchdog-spa)가 붙은 요청은 기존 라우트가
#    만든 응답을 JSON으로 바꿔서 돌려준다.
#      - render_template(...)  → {"page": 템플릿 이름, "data": 템플릿에 넘긴 값, "messages": [...]}
#      - redirect(...)         → {"redirect": "/경로", "messages": [...]}
#      - flash(...)            → "messages"에 담긴다
#      - 그 외 오류 응답(429 등) → {"messages": [...], "status": 코드}
#      - JSON 응답(/api/*)은 손대지 않는다
#    모든 어댑터 응답에는 CSRF 토큰("csrf")이 들어 있어서 화면이 다음 POST에 쓴다.
#    이 헤더는 다른 사이트가 보낼 수 없다(브라우저가 사전 검사 없이는 교차 출처 요청에
#    임의 헤더를 붙이지 못한다) — CSRF 토큰 검사와는 별개의 보조 방어선이다.
#
# 3) 404 화면 — 존재하지 않는 주소를 브라우저가 열면 not_found_page()가 spa/404.html을 404 상태로 내려준다
#    (helpers/hooks.py의 handle_not_found가 기록·탐지를 끝낸 뒤 부른다).
#
# web/out(Next 정적 빌드)이 없으면 아무것도 바꾸지 않는다 → 예전 Jinja 화면 그대로 동작한다.
# ============================================================================

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from flask import Response, g, get_flashed_messages, jsonify, request, send_file, session
from flask.signals import template_rendered
from flask_wtf.csrf import generate_csrf

SPA_HEADER = "X-Requested-With"
SPA_HEADER_VALUE = "login-watchdog-spa"

# 정적 빌드 결과물 위치. web/ 에서 `npm run build`를 하면 scripts가 여기로 옮겨 놓는다.
SPA_DIR = Path(__file__).resolve().parent.parent / "spa"

# 엔드포인트 → 정적 HTML 파일(SPA_DIR 기준). 화면이 있는 GET 라우트만 적는다.
SPA_PAGES = {
    "auth.login": "login.html",
    "auth.signup": "signup.html",
    "member.member_dashboard": "dashboard.html",
    "member.member_history": "dashboard/history.html",
    "member.member_profile": "dashboard/profile.html",
    "board.board_list": "board.html",
    "board.board_new": "board/new.html",
    "board.board_detail": "board/view.html",
    "board.board_edit": "board/edit.html",
    "recovery.recovery_request_form": "recovery.html",
    "recovery.recovery_verify_form": "recovery/verify.html",
    "password.password_forgot_form": "password/forgot.html",
    "password.password_reset_form": "password/reset.html",
    "email.email_confirm_form": "email/confirm.html",
    "admin.admin_login": "admin/login.html",
    "admin.admin_dashboard": "admin/dashboard.html",
    "admin.admin_attack": "admin/attack.html",
    "admin.admin_ops": "admin/ops.html",
}

# 어댑터가 JSON으로 바꾸지 않을 값(템플릿 기본 컨텍스트)
_CONTEXT_SKIP = {"g", "request", "session", "config"}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

_STATUS_MESSAGES = {
    400: "요청을 처리할 수 없습니다.",
    401: "로그인이 필요합니다.",
    403: "이 작업을 수행할 권한이 없습니다.",
    404: "찾을 수 없는 주소입니다.",
    429: "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.",
}

_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)
_csp_cache: dict[str, list[str]] = {}


def is_enabled() -> bool:
    """정적 빌드가 있고 꺼져 있지 않으면 켠다. SPA_ENABLED=false로 강제로 끌 수 있다."""
    if os.environ.get("SPA_ENABLED", "true").lower() == "false":
        return False
    return SPA_DIR.is_dir() and any(SPA_DIR.rglob("*.html"))


def is_spa_request() -> bool:
    return request.headers.get(SPA_HEADER) == SPA_HEADER_VALUE


def inline_script_hashes(html_path: Path) -> list[str]:
    """정적 HTML 안의 인라인 <script>마다 CSP 해시('sha256-...')를 계산한다.

    Next 정적 빌드는 화면 데이터를 인라인 스크립트로 심어 두는데, 이 사이트의 CSP는
    script-src 'self'라서 그대로는 막힌다. 'unsafe-inline'으로 풀면 XSS 방어가 사라지므로,
    우리가 빌드한 그 스크립트 내용만 해시로 허용한다(내용이 바뀌면 해시도 바뀌어 막힌다).
    """
    key = f"{html_path}:{html_path.stat().st_mtime_ns}"  # 다시 빌드하면 해시도 새로 계산한다
    if key not in _csp_cache:
        text = html_path.read_text(encoding="utf-8")
        _csp_cache[key] = [
            "'sha256-" + base64.b64encode(hashlib.sha256(m.encode("utf-8")).digest()).decode() + "'"
            for m in _INLINE_SCRIPT.findall(text)
            if m.strip()
        ]
    return _csp_cache[key]


# 화면으로 내려보내면 안 되는 칸 이름(해시·토큰·세션 세대 번호). 템플릿은 서버에서만 그려져서
# user 딕셔너리 통째로 넘겨도 문제가 없었지만, JSON은 그대로 브라우저로 나가므로 걸러낸다.
_SECRET_KEY_PARTS = ("password", "hash", "token", "secret", "session_version")


def _scrub(value):
    """JSON으로 바꿀 수 있는 값만 남기고, 비밀 칸은 지운다(함수·객체는 버린다)."""
    if isinstance(value, dict):
        return {
            k: _scrub(v)
            for k, v in value.items()
            if not any(part in str(k).lower() for part in _SECRET_KEY_PARTS)
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    return value


def _json_safe(value):
    try:
        json.dumps(value)
        return True
    except (TypeError, ValueError):
        return False


def _path_with_query(location: str) -> str:
    parts = urlsplit(location)
    return parts.path + (f"?{parts.query}" if parts.query else "")


def _capture_context(sender, template, context, **extra):
    if not is_spa_request():
        return
    data = {
        k: _scrub(v)
        for k, v in context.items()
        if k not in _CONTEXT_SKIP and not callable(v) and _json_safe(v)
    }
    g._spa_page = (template.name, data)


def serve_shell():
    """before_request: 화면이 있는 GET 주소를 브라우저가 직접 열면 정적 HTML을 내려준다."""
    if request.method != "GET" or is_spa_request() or not is_enabled():
        return None
    filename = SPA_PAGES.get(request.endpoint or "")
    if filename is None:
        return None
    html_path = SPA_DIR / filename
    if not html_path.is_file():
        return None
    response = send_file(html_path, mimetype="text/html", max_age=0)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Spa-Shell"] = filename
    response.headers["X-Spa-Script-Hashes"] = " ".join(inline_script_hashes(html_path))
    return response


def not_found_page() -> Response | None:
    """handle_not_found(helpers/hooks.py)가 부른다 — 브라우저가 존재하지 않는 주소를 직접 열면
    기본 영어 404 대신 스타일 있는 화면(spa/404.html)을 404 상태로 내려준다.

    어댑터 요청(JSON 응답), /api/ 경로, HTML을 받지 않는 요청, GET·HEAD가 아닌 요청은 건드리지 않는다
    (None을 돌려주면 호출부가 기존 404 응답을 그대로 쓴다). 404 기록·탐지는 호출부가 이미 끝낸 뒤다.
    """
    if request.method not in ("GET", "HEAD") or is_spa_request() or not is_enabled():
        return None
    if request.path.startswith("/api/") or not request.accept_mimetypes.accept_html:
        return None
    html_path = SPA_DIR / "404.html"
    if not html_path.is_file():
        return None
    response = Response(html_path.read_bytes(), status=404, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Spa-Script-Hashes"] = " ".join(inline_script_hashes(html_path))
    return response


def convert_response(response: Response) -> Response:
    """after_request: 어댑터 헤더가 붙은 요청의 응답을 JSON으로 바꾼다."""
    if not is_spa_request():
        return response

    response.headers["Cache-Control"] = "no-store"

    if response.mimetype == "application/json":
        return response

    # flash는 두 곳에 있을 수 있다. 템플릿이 렌더링하며 꺼냈다면 Flask가 요청 안에 기억해 두므로
    # get_flashed_messages()가 같은 목록을 다시 돌려주고, 아직 안 꺼냈다면 지금 꺼낸다.
    messages: list[str] = []
    is_redirect = response.status_code in _REDIRECT_STATUSES and bool(response.headers.get("Location"))
    if is_redirect:
        # 리다이렉트로 가는 화면이 그 문장을 보여주도록 세션에 남겨 둔다(꺼내면 사라진다).
        messages += [message for _category, message in session.get("_flashes", [])]
    else:
        messages += get_flashed_messages()

    payload: dict = {"messages": messages, "csrf": generate_csrf()}
    status = 200

    if is_redirect:
        # 리다이렉트는 HTTP 상태 대신 본문으로 알린다(fetch가 따라가 버리지 않게).
        payload["redirect"] = _path_with_query(response.headers["Location"])
        if response.status_code == 400:
            payload["status"] = 400  # CSRF 오류 핸들러처럼 400과 함께 돌려보내는 리다이렉트
        response.headers.pop("Location", None)
    elif getattr(g, "_spa_page", None) is not None:
        payload["page"], payload["data"] = g._spa_page
        payload["status"] = response.status_code
        status = response.status_code
    else:
        payload["status"] = response.status_code
        status = response.status_code
        if status >= 400 and not messages:
            payload["messages"] = [_STATUS_MESSAGES.get(status, "요청을 처리하지 못했습니다.")]

    response.set_data(json.dumps(payload, ensure_ascii=False))
    response.status_code = status
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Length"] = str(len(response.get_data()))
    return response


def apply_script_hashes(response: Response) -> Response:
    """껍데기 응답에만, 그 페이지의 인라인 스크립트 해시를 CSP script-src에 더한다."""
    hashes = response.headers.pop("X-Spa-Script-Hashes", None)
    response.headers.pop("X-Spa-Shell", None)
    if hashes is None:
        return response
    csp = response.headers.get("Content-Security-Policy", "")
    if hashes and "script-src 'self'" in csp:
        csp = csp.replace("script-src 'self'", f"script-src 'self' {hashes}", 1)
        response.headers["Content-Security-Policy"] = csp
    return response


def register(app) -> None:
    """app.py에서 한 번 호출한다. Limiter 뒤, register_request_hooks 앞에 등록해야 한다
    (껍데기 응답은 전역 요청 한도는 받되, 반복 접근 관찰에는 잡히지 않는다)."""
    template_rendered.connect(_capture_context, app)
    app.before_request(serve_shell)
    # after_request는 등록의 역순으로 돈다 — 보안 헤더(hooks)가 먼저 붙은 뒤 해시를 더하려면 이 둘이 뒤에 와야 한다.
    app.after_request(convert_response)
    app.after_request(apply_script_hashes)

    @app.route("/api/spa/session", methods=["GET"])
    def spa_session():
        """화면이 처음 열릴 때 CSRF 토큰과 로그인 상태를 알아가는 곳(조회만, DB 접근 없음)."""
        return jsonify(
            {
                "csrf": generate_csrf(),
                "member": "user_id" in session,
                "admin": "admin_id" in session,
                # 화면 머리줄에 "누구로 로그인했는지" 보여주는 데만 쓴다(본인 아이디, 세션에서 바로 읽음)
                "username": session.get("username"),
                "admin_username": session.get("admin_username"),
            }
        )
