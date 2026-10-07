# ============================================================================
# helpers.py — routes/*.py(블루프린트) 전체가 공유하는 문지기·공용 함수
#
# 원래 app.py 안에 있던 함수들 중, admin/board/member 블루프린트 라우트가
# 공통으로 가져다 쓰는 것들만 이 파일로 옮겼다. app.py 자체(에러 핸들러,
# before_request, index 라우트)도 그대로 이 파일을 가져다 쓴다.
#
# docs/refactor/2026-09-15-file-split.md — 이 분리 작업의 배경과 계획 문서.
# ============================================================================

import hashlib
import ipaddress
import secrets
from functools import wraps

from flask import flash, jsonify, redirect, request, session, url_for

import config
import db
import detector
import geoip
import soar


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


# 허니팟(봇 탐지)용 숨김 필드 이름 (L7 공격 보강 계획 Tier 3). 로그인/가입/
# 글쓰기/댓글 폼(templates/login_form.html 등)에 CSS(.hp-field, tokens.css
# 참고)로 화면에서 안 보이게 심어둔 입력칸이다. 사람은 화면에 보이는 칸만
# 채우므로 이 칸은 항상 비어있어야 정상이고, 폼의 모든 입력칸을 기계적으로
# 채우는 자동화 스크립트만 이 칸까지 채우게 된다. reCAPTCHA 같은 외부
# 서비스는 API 키 발급이 필요해 데모 프로젝트 성격과 안 맞아서, 이 무료·
# 의존성 없는 방식을 대신 택했다.
HONEYPOT_FIELD_NAME = "website"


def is_bot_submission() -> bool:
    """이번 폼 제출에 허니팟 필드가 채워져 있으면 True(봇 의심)를 돌려준다."""
    return bool(request.form.get(HONEYPOT_FIELD_NAME, "").strip())


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

    SSRF 방지 (L7 공격 보강 계획 Tier 3): 이 값은 이후 geoip.py가 외부
    위치 조회 API 주소에 그대로 끼워 넣는 데 쓰인다. X-Forwarded-For는
    클라이언트가 보내는 값이라 형식 검증 없이 그대로 신뢰하면, TRUST_FORWARDED_FOR
    를 켠 환경에서 그 문자열이 외부 요청 주소에 섞여 들어갈 수 있다.
    ipaddress.ip_address()로 "진짜 IP 형식인가"부터 확인하고, 아니면 헤더값을
    버리고 원래 접속 IP(request.remote_addr)로 되돌아간다.
    """
    if config.TRUST_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # 이 헤더는 "1.2.3.4, 5.6.7.8"처럼 여러 IP가 콤마로 이어질 수 있어서
            # 맨 앞(가장 처음 요청을 보낸 곳) 값만 잘라서 쓴다.
            candidate = forwarded.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return request.remote_addr
            return candidate
    return request.remote_addr


# ============================================================================
# 기기 쿠키(lw_dev) — IP 영구 잠금 "예외"를 요청한 그 기기에만 묶기 위한 표식 (guide34-a)
#
# 학교·회사처럼 여러 명이 같은 공인 IP(NAT)를 쓰는 곳에서, 피해자 A가 예외를 받았다고
# 하자. 예외를 아이디만으로 묶으면 같은 IP의 공격자가 A의 아이디로 무차별 대입을 계속할
# 수 있다. 예외를 "복구를 요청한 기기의 무작위 쿠키 해시"에까지 묶으면, 공격자에게는 그
# 쿠키가 없으므로 계속 막힌다. 쿠키 원문은 브라우저에만 있고 DB에는 해시만 저장한다.
# ============================================================================

def hash_secret(value: str) -> str:
    """토큰·코드·기기 쿠키를 DB에 저장하기 전에 SHA-256 지문(해시)으로 바꾼다.
    지문에서 원래 값을 되돌릴 수 없으므로 DB가 유출돼도 진짜 값은 새지 않는다."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_device_hash() -> str | None:
    """이번 요청의 기기 쿠키(lw_dev)를 해시로 바꿔 돌려준다. 쿠키가 없으면 None."""
    token = request.cookies.get(config.DEVICE_COOKIE_NAME)
    return hash_secret(token) if token else None


def new_device_token() -> str:
    """추측 불가능한 새 기기 쿠키 값을 만든다(secrets는 보안용 난수 — random은 예측 가능해 쓰면 안 된다)."""
    return secrets.token_urlsafe(32)


def set_device_cookie(response, token: str):
    """응답에 기기 쿠키를 심는다. HttpOnly(자바스크립트가 못 읽음) + SameSite=Lax이고,
    운영(HTTPS)에서는 Secure도 붙인다."""
    response.set_cookie(
        config.DEVICE_COOKIE_NAME,
        token,
        max_age=config.DEVICE_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=config.IS_PRODUCTION,
    )
    return response


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
                suspicious, count, is_first_over_threshold = detector.is_unauthorized_access_suspicious(ip)
                if suspicious and is_first_over_threshold:
                    soar.notify_unauthorized_access(ip, count, request.path)
                elif not suspicious and count >= config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD - config.EARLY_WARNING_BAND:
                    # 아직 기준치는 안 넘었지만 코앞이면 LLM에게 조기 경보 여부를
                    # 물어본다 (Track A, guide31).
                    soar.consider_early_warning(
                        "UNAUTHORIZED_ACCESS", "ALERT_ONLY", "ip", ip, count,
                        config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD, path=request.path,
                    )
                return jsonify({"error": "로그인이 필요합니다."}), 401
            return redirect(url_for("admin.admin_login"))
        return view(*args, **kwargs)
    return wrapped_view


def require_permission(action: str):
    """login_required보다 한 단계 더 세밀한 문지기 — "로그인됐는가"뿐 아니라
    "이 관리자의 역할이 정말 이 action을 해도 되는가"까지 확인한다
    (Track B guide26, RBAC 기본 구조).

    login_required와 다르게 데코레이터 팩토리(괄호로 action을 받아 진짜
    데코레이터를 만들어 돌려주는 함수) 형태다 — `@require_permission("delete_user")`
    처럼 라우트마다 어떤 액션을 확인할지 지정해야 하기 때문이다.

    순서: 1) 로그인 여부는 login_required와 완전히 동일하게 확인(미로그인 시
    /api/*는 401 JSON + 미인증 API 접근 기록, 그 외는 로그인 화면으로 리다이렉트).
    2) 로그인은 됐지만 role이 이 action을 못 하면 403(권한 없음) JSON을 돌려준다
    — 이미 로그인된 상태에서 걸리는 경우이므로 화면 리다이렉트가 아니라 항상
    JSON으로 응답한다(이 데코레이터가 보호하는 라우트는 전부 /api/* 뿐이라서).
    """
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if "admin_username" not in session:
                if request.path.startswith("/api/"):
                    ip = get_request_ip()
                    db.log_unauthorized_attempt(ip, request.path)
                    suspicious, count, is_first_over_threshold = detector.is_unauthorized_access_suspicious(ip)
                    if suspicious and is_first_over_threshold:
                        soar.notify_unauthorized_access(ip, count, request.path)
                    elif not suspicious and count >= config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD - config.EARLY_WARNING_BAND:
                        soar.consider_early_warning(
                            "UNAUTHORIZED_ACCESS", "ALERT_ONLY", "ip", ip, count,
                            config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD, path=request.path,
                        )
                    return jsonify({"error": "로그인이 필요합니다."}), 401
                return redirect(url_for("admin.admin_login"))

            role = db.get_admin_role(session["admin_username"])
            if role is None or not db.has_permission(role, action):
                return jsonify({"error": "이 작업을 수행할 권한이 없습니다."}), 403

            return view(*args, **kwargs)
        return wrapped_view
    return decorator


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
            return redirect(url_for("auth.login"))
        # 세션 세대 번호 확인(guide35) — 다른 기기에서 비밀번호를 바꿨다면 DB의 번호가 올라가
        # 있어서 이 세션은 더 이상 유효하지 않다. 회원이 삭제됐어도(None) 같은 방식으로 끊는다.
        # 이 기능 이전에 만들어진 세션은 번호가 없으므로 0(기본값)으로 본다.
        current = db.get_user_session_version(session.get("user_id"))
        if current is None or current != session.get("session_version", 0):
            clear_member_session()
            flash("비밀번호가 변경되었거나 계정 정보가 바뀌어 로그아웃되었습니다. 다시 로그인해주세요.")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped_view


def clear_member_session() -> None:
    """회원 로그인 관련 세션 값만 지운다(같은 브라우저의 관리자 세션은 그대로 둔다)."""
    for key in ("username", "user_id", "session_version"):
        session.pop(key, None)
