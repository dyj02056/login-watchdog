# ============================================================================
# helpers/auth.py — 관리자/회원 세션과 로그인·권한 문지기(데코레이터)
#
# 예전 helpers.py(314줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from helpers import ...`로 가져다 쓴다(helpers/__init__.py가
# 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import time
from functools import wraps

from flask import flash, g, jsonify, redirect, request, session, url_for

import config
import db
from helpers.request_utils import get_request_ip
from security import detector, soar


# ============================================================================
# 관리자 세션 (guide37)
#
# 세션 쿠키는 서명만 되어 있을 뿐 서버가 따로 보관하지 않으므로, 예전처럼 "admin_username이
# 들어 있는가"만 보면 계정이 삭제된 뒤에도 그 쿠키로 대시보드를 계속 볼 수 있었고, 같은 아이디로
# 계정을 다시 만들면 옛 쿠키가 되살아났다. 그래서 로그인할 때 기본키(admin_id)와 로그인 시각을
# 함께 넣어두고, 요청마다 DB의 계정과 대조한다(id가 같고 username도 같아야 통과).
# ============================================================================

ADMIN_SESSION_KEYS = ("admin_username", "admin_id", "admin_login_at")


def start_admin_session(admin_id: int, username: str) -> None:
    """관리자 로그인 성공 시 세션에 아이디·기본키·로그인 시각을 넣는다."""
    session["admin_username"] = username
    session["admin_id"] = admin_id
    session["admin_login_at"] = int(time.time())


def clear_admin_session() -> None:
    """관리자 세션 값만 지운다(같은 브라우저의 회원 세션은 그대로 둔다)."""
    for key in ADMIN_SESSION_KEYS:
        session.pop(key, None)


def _load_current_admin() -> dict | None:
    """세션이 아직 유효한 관리자 계정을 가리키면 그 계정({"id", "username", "role"})을
    g.admin에 담아 돌려주고, 아니면 None을 돌려준다.

    무효로 보는 경우: 세션 값 일부가 없음(이 기능 이전에 만들어진 세션 포함) /
    로그인한 지 ADMIN_SESSION_MAX_HOURS가 지남 / DB에 그 id가 없음(삭제됨) /
    id는 있는데 username이 다름. 수명은 "마지막 활동"이 아니라 "로그인 시각" 기준이다 —
    대시보드가 5초마다 폴링하므로 활동이 없는 상태가 생기지 않기 때문이다.
    """
    admin_id = session.get("admin_id")
    username = session.get("admin_username")
    login_at = session.get("admin_login_at")
    if admin_id is None or username is None or login_at is None:
        return None
    if time.time() - login_at > config.ADMIN_SESSION_MAX_HOURS * 3600:
        return None

    admin = db.get_admin_by_id(admin_id)
    if admin is None or admin["username"] != username:
        return None
    g.admin = admin
    return admin


def _reject_admin_request():
    """관리자 확인에 실패한 요청에 응답한다. 두 경우를 구분한다.

    - 세션이 아예 없음: 지금까지처럼 미인증 접근으로 기록하고(21단계), 반복되면 알리거나
      LLM 조기 경보를 판단한다(Track A, guide31).
    - 세션은 있는데 무효(삭제·만료·옛 형식): 공격이 아니라 "다시 로그인해야 하는 관리자"다.
      기록하지 않는다 — 기록하면 삭제된 관리자의 대시보드가 5초마다 폴링하면서 그 관리자의
      IP가 미인증 접근 공격으로 잡혀 알림이 울린다. 관리자 세션 값만 지우고 돌려보낸다.
    """
    is_api = request.path.startswith("/api/")
    if "admin_username" in session:
        clear_admin_session()
        if is_api:
            return jsonify({"error": "세션이 만료되었습니다. 다시 로그인해주세요."}), 401
        flash("세션이 만료되었거나 계정 정보가 바뀌었습니다. 다시 로그인해주세요.")
        return redirect(url_for("admin.admin_login"))

    if is_api:
        ip = get_request_ip()
        db.log_unauthorized_attempt(ip, request.path)
        suspicious, count, is_first_over_threshold = detector.is_unauthorized_access_suspicious(ip)
        if suspicious and is_first_over_threshold:
            soar.notify_unauthorized_access(ip, count, request.path)
        elif not suspicious and count >= config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD - config.EARLY_WARNING_BAND:
            # 아직 기준치는 안 넘었지만 코앞이면 LLM에게 조기 경보 여부를 물어본다
            # (Track A, guide31).
            soar.consider_early_warning(
                "UNAUTHORIZED_ACCESS", "ALERT_ONLY", "ip", ip, count,
                config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD, path=request.path,
            )
        return jsonify({"error": "로그인이 필요합니다."}), 401
    return redirect(url_for("admin.admin_login"))


def login_required(view):
    """"관리자 로그인이 되어 있어야만 들어올 수 있는 방"을 만들어주는 장치(데코레이터).

    데코레이터란? 함수(방) 앞에 "문지기"를 하나 세워두는 것과 같다.
    `@login_required`를 어떤 라우트 함수 위에 붙이면, 그 라우트가 실제로
    실행되기 전에 이 문지기 코드가 먼저 실행되어 "세션이 지금도 유효한 관리자
    계정을 가리키는지"부터 확인한다(_load_current_admin, guide37).

    - 유효하지 않으면 _reject_admin_request()가 응답한다:
        - 주소가 /api/로 시작하는 경우(JS가 fetch로 부르는 API) → 401(인증 필요) JSON 응답
          (세션이 아예 없을 때만 unauthorized_attempts에 기록하고, 반복되면 Unauthorized
          Access 의심 알림을 보낸다 — 21단계, attack_response_state.md 구현 대상 #2)
        - 그 외(사람이 브라우저로 직접 들어온 화면) → 관리자 로그인 페이지로 강제 이동
    - 유효하면: g.admin에 계정 정보를 담고 원래 요청했던 라우트 함수를 그대로 실행
    """
    @wraps(view)  # 문지기를 씌워도 원래 함수의 이름 등 정보가 유지되게 해주는 파이썬 관례
    def wrapped_view(*args, **kwargs):
        if _load_current_admin() is None:
            return _reject_admin_request()
        return view(*args, **kwargs)
    return wrapped_view


def require_permission(action: str):
    """login_required보다 한 단계 더 세밀한 문지기 — "로그인됐는가"뿐 아니라
    "이 관리자의 역할이 정말 이 action을 해도 되는가"까지 확인한다
    (Track B guide26, RBAC 기본 구조).

    login_required와 다르게 데코레이터 팩토리(괄호로 action을 받아 진짜
    데코레이터를 만들어 돌려주는 함수) 형태다 — `@require_permission("delete_user")`
    처럼 라우트마다 어떤 액션을 확인할지 지정해야 하기 때문이다.

    순서: 1) 세션 확인은 login_required와 완전히 동일하다(_load_current_admin /
    _reject_admin_request). 2) 로그인은 됐지만 role이 이 action을 못 하면 403(권한 없음)
    JSON을 돌려준다 — 이미 로그인된 상태에서 걸리는 경우이므로 화면 리다이렉트가 아니라
    항상 JSON으로 응답한다(이 데코레이터가 보호하는 라우트는 전부 /api/* 뿐이라서).
    role은 1)에서 계정을 조회할 때 함께 가져온 값을 쓴다 — 캐싱하지 않고 요청마다 DB에서
    읽은 값이므로 role이 바뀌면 바로 다음 요청부터 적용된다.
    """
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            admin = _load_current_admin()
            if admin is None:
                return _reject_admin_request()
            if not db.has_permission(admin["role"], action):
                return jsonify({"error": "이 작업을 수행할 권한이 없습니다."}), 403

            return view(*args, **kwargs)
        return wrapped_view
    return decorator


def member_login_required(view):
    """"회원 로그인이 되어 있어야만 들어올 수 있는 방" 문지기 — login_required와
    같은 역할이지만, 확인하는 세션 값이 다르다("admin_username"이 아니라
    "username"). 세션에 아이디가 있는지에 더해, 세션 세대 번호(session_version)가
    DB 값과 같은지도 요청마다 확인한다(guide35 — 아래 본문 주석 참고).
    관리자 세션과 회원 세션은 서로 다른 키를 쓰기 때문에, 같은
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
