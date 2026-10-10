# ============================================================================
# helpers/hooks.py — 모든 요청에 걸리는 공용 훅: 보안 헤더, 404 기록(Web Scanning),
# 반복 페이지 접근·매크로 API 패턴 관찰
#
# 원래 app.py에 @app.after_request / @app.errorhandler(404) / @app.before_request
# 데코레이터로 직접 달려 있었다. app.py가 앱 "조립"(설정·Blueprint 등록·요청 한도)에만
# 집중하도록 이 파일로 옮겼고, app.py는 register_request_hooks(app) 한 줄로 등록한다.
# 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

from flask import request

import config
import db
from helpers.request_utils import get_request_ip
from security import detector, soar


# board.js/dashboard.js가 스스로 만들어내는 자동 폴링 API. 브라우저 탭 하나만
# 열려 있어도 정상적으로 초당 여러 번씩 호출되므로, track_page_access()가 이걸
# "반복 접근 의심"으로 잘못 판단하지 않도록 관찰 대상에서 제외한다
# ("static"은 Flask가 public/의 CSS·JS·이미지를 서빙할 때 쓰는 내장 엔드포인트).
#
# Blueprint로 분리하면서 각 라우트의 엔드포인트 이름이 "api_status"에서
# "admin.api_status"처럼 "<블루프린트 이름>.<함수 이름>"으로 바뀌었다 — 이 집합도
# 그 이름을 그대로 맞춰줘야 폴링 API가 계속 관찰 대상에서 제외된다.
PAGE_ACCESS_EXCLUDED_ENDPOINTS = {
    "static",
    "admin.api_status",
    "admin.api_stats",
    "spa_session",
    "board.api_board_comments_latest",
}


def set_security_headers(response):
    """모든 응답에 클릭재킹/콘텐츠 스니핑 방어용 보안 헤더를 추가한다 (L7 공격 보강 계획 Tier 2).

    - X-Frame-Options / Content-Security-Policy(frame-ancestors): 이 사이트를
      다른 사이트가 <iframe>에 몰래 끼워넣고 투명하게 겹친 뒤 클릭을 유도하는
      클릭재킹을 막는다. "즉시 해제"/"회원 삭제" 같은 파괴적 버튼이 있는 관리자
      대시보드일수록 이 방어가 중요하다. 두 헤더를 함께 쓰는 이유는
      X-Frame-Options가 예전 브라우저 호환용이고, CSP의 frame-ancestors가 최신
      표준이기 때문이다.
    - Content-Security-Policy(그 외 지시문): 이 사이트가 직접 서빙하지 않는
      스크립트/스타일/이미지가 끼어드는 것을 막는다. style-src/font-src에
      Google Fonts 도메인만 예외로 열어둔 이유는 public/css/tokens.css가
      @import로 그 폰트를 불러오기 때문이다 — 그 외 템플릿/정적 파일은
      전부 이 사이트("'self'")에서만 가져온다.
    - X-Content-Type-Options: 브라우저가 응답의 Content-Type을 무시하고
      내용만 보고 실행 방식을 "추측"하는 MIME 스니핑을 막는다.
    - Referrer-Policy: 다른 사이트로 이동할 때 이 사이트의 전체 URL(쿼리스트링
      포함)이 Referer 헤더로 그대로 넘어가는 것을 줄인다.
    """
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


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

    suspicious, count, is_first_over_threshold = detector.is_web_scanning(ip)
    if suspicious and is_first_over_threshold:
        soar.notify_web_scanning(ip, count, request.path)
    elif not suspicious and count >= config.WEB_SCANNING_ALERT_THRESHOLD - config.EARLY_WARNING_BAND:
        # 아직 기준치는 안 넘었지만 코앞이면 LLM에게 조기 경보 여부를 물어본다
        # (Track A, guide31).
        soar.consider_early_warning(
            "WEB_SCANNING", "ALERT_ONLY", "ip", ip, count, config.WEB_SCANNING_ALERT_THRESHOLD,
            path=request.path,
        )

    return error.get_response()


def track_page_access():
    """같은 IP가 같은 GET 페이지를 반복 요청하는지 관찰하고, 반복되면 알린다.

    이 함수는 handle_not_found()와 달리 특정 경로가 아니라 "매 요청"마다 실행된다
    (Flask가 라우팅을 마친 뒤, 실제 뷰 함수를 부르기 직전에 호출해준다). 그래서
    대상을 신중하게 좁혀야 한다:
    - request.url_rule이 None이면 애초에 존재하지 않는 경로(404)라는 뜻이므로
      제외한다 — 그 경우는 not_found_attempts가 이미 별도로 기록한다.
    - GET이 아닌 요청(폼 제출 등)은 "페이지 접근"이 아니므로 제외한다.
    - PAGE_ACCESS_EXCLUDED_ENDPOINTS에 있는 엔드포인트(정적 파일, 자동 폴링 API)도
      제외한다 — 이것들을 빼두지 않으면 정상 사용자가 항상 "수상함"으로
      잘못 판정된다.

    알림은 handle_not_found()와 동일하게 "임계값을 막 넘긴 바로 그 요청"에서
    딱 한 번만 보낸다 (attack_response_state.md 구현 대상 #4).
    """
    if request.method != "GET" or request.url_rule is None:
        return
    if request.endpoint in PAGE_ACCESS_EXCLUDED_ENDPOINTS:
        return

    ip = get_request_ip()
    db.log_page_access_attempt(ip, request.path)

    suspicious, count, is_first_over_threshold = detector.is_page_access_suspicious(ip, request.path)
    if suspicious and is_first_over_threshold:
        soar.notify_page_access(ip, count, request.path)
    elif not suspicious and count >= config.PAGE_ACCESS_ALERT_THRESHOLD - config.EARLY_WARNING_BAND:
        soar.consider_early_warning(
            "PAGE_ACCESS", "ALERT_ONLY", "ip", ip, count, config.PAGE_ACCESS_ALERT_THRESHOLD,
            path=request.path,
        )


def track_api_access():
    """같은 IP가 짧은 시간 안에 서로 다른 /api/* 경로를 여러 개 호출하는지
    관찰하고, 매크로/봇 패턴으로 의심되면 알린다 (Track C guide29, 매크로/봇 탐지).

    track_page_access()와 별도 훅으로 둔 이유: track_page_access()는 GET만,
    "같은 경로 하나"의 반복만 본다 — 이 훅은 메서드를 가리지 않고(POST 포함),
    "서로 다른 여러 경로"에 걸친 패턴을 본다. 서로 다른 종류의 수상함이라
    하나로 합치지 않는다.

    PAGE_ACCESS_EXCLUDED_ENDPOINTS를 그대로 재사용해서 dashboard/api.js·board.js의
    자동 폴링 API는 여기서도 제외한다 — 어차피 경로 하나만 반복 호출하므로
    이 탐지(서로 다른 경로 개수)에는 원래 걸리지 않지만, 표를 불필요하게
    불리지 않기 위해 애초에 기록하지 않는다.
    """
    if request.url_rule is None or not request.path.startswith("/api/"):
        return
    if request.endpoint in PAGE_ACCESS_EXCLUDED_ENDPOINTS:
        return

    ip = get_request_ip()
    db.log_api_access(ip, request.path, request.method)

    suspicious, count, is_first_over_threshold = detector.is_macro_pattern_suspicious(ip)
    if suspicious and is_first_over_threshold:
        soar.notify_macro_pattern(ip, count)
    elif not suspicious and count >= config.MACRO_DISTINCT_API_THRESHOLD - config.EARLY_WARNING_BAND:
        soar.consider_early_warning(
            "API_MACRO_PATTERN", "ALERT_ONLY", "ip", ip, count, config.MACRO_DISTINCT_API_THRESHOLD,
        )


def register_request_hooks(app) -> None:
    """위 함수들을 Flask 앱에 훅으로 등록한다. app.py가 Limiter를 만든 "뒤"에 불러야 한다 —
    before_request는 등록한 순서대로 실행되므로, CSRF 검사·전역 요청 한도가 먼저 돌고
    그다음에 관찰 훅이 돈다(app.py에 데코레이터로 직접 달려 있던 때와 같은 순서)."""
    app.after_request(set_security_headers)
    app.register_error_handler(404, handle_not_found)
    app.before_request(track_page_access)
    app.before_request(track_api_access)
