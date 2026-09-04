# ============================================================================
# detector.py — "판사" 역할: 지금 이 IP가 수상한지, 지금 잠겨있는지만 판단한다
#
# 이 파일은 데이터베이스의 상태를 절대 바꾸지 않는다(아무것도 저장/수정/삭제하지 않음).
# 오직 db.py에게 "지금 상태가 어때?"라고 물어보고, 그 답을 바탕으로
# True/False 같은 "판정 결과"만 돌려준다.
#
# 실제로 잠그거나 알림을 보내는 "실행"은 이 파일이 아니라 soar.py가 담당한다
# (판단과 실행을 분리해두면, "판단 기준만 바꾸고 싶다" 같은 수정이 훨씬 쉬워진다).
# ============================================================================

import db
from config import (
    COMMENT_RATE_LIMIT,
    FAILURE_THRESHOLD,
    PAGE_ACCESS_ALERT_THRESHOLD,
    POST_RATE_LIMIT,
    SIGNUP_RATE_LIMIT,
    UNAUTHORIZED_ACCESS_ALERT_THRESHOLD,
    WEB_SCANNING_ALERT_THRESHOLD,
)


def is_suspicious(ip: str) -> tuple[bool, int]:
    """이 IP가 "수상한 상태"인지 판단한다.

    판단 기준: 최근 60초(config.DETECTION_WINDOW_SECONDS) 안에 실패한 횟수가
    기준치(FAILURE_THRESHOLD, 기본 5회)를 "초과"했는가?

    반환값은 (수상한가?, 실제 실패 횟수) 형태의 튜플(값 2개를 한 번에 묶어서 돌려주는 것).
    예: (True, 6)  → "수상함, 지금까지 6번 실패했음"
        (False, 3) → "아직 수상하지 않음, 3번 실패했음"
    """
    failure_count = db.count_recent_failures(ip)
    return failure_count > FAILURE_THRESHOLD, failure_count


def is_admin_suspicious(ip: str) -> tuple[bool, int]:
    """이 IP가 "관리자 로그인에 대해 수상한 상태"인지 판단한다.

    is_suspicious()와 판단 기준(초과 여부)은 동일하지만, 세는 대상이
    login_attempts가 아니라 admin_login_log다 — 관리자 로그인(/admin/login)은
    감시 대상 로그인(/login)과 완전히 별도 경로이므로, 그동안 이 판정이
    빠져있어 관리자 계정은 무제한으로 비밀번호를 시도할 수 있었다
    (18단계 보안 점검에서 발견 및 보완).
    """
    failure_count = db.count_recent_admin_failures(ip)
    return failure_count > FAILURE_THRESHOLD, failure_count


def count_distinct_usernames(ip: str) -> int:
    """soar.enforce_lockout이 잠금 알림에 "몇 개의 서로 다른 아이디가 관련됐는지"
    (Brute Force인지 Password Spraying인지) 표시할 수 있도록, db.py가 센 값을
    그대로 전달한다. is_suspicious()와 마찬가지로 login_attempts를 본다.
    """
    return db.count_recent_distinct_usernames(ip)


def count_distinct_admin_usernames(ip: str) -> int:
    """count_distinct_usernames()와 동일한 목적이지만 admin_login_log를 본다."""
    return db.count_recent_distinct_admin_usernames(ip)


def is_signup_rate_limited(ip: str) -> bool:
    """이 IP가 최근 회원가입을 너무 자주 시도해서 더 막아야 하는 상태인지 판단한다.

    is_suspicious()와 달리 "초과"가 아니라 "이상"을 기준으로 삼는다 — 로그인
    실패는 정상 사용자도 몇 번은 겪을 수 있는 일이라 여유(초과)를 주지만,
    회원가입 요청 자체는 정상 사용자가 짧은 시간에 여러 번 반복할 이유가
    거의 없으므로 더 엄격하게(기준치에 도달하면 즉시) 차단한다.
    """
    return db.count_recent_signup_attempts(ip) >= SIGNUP_RATE_LIMIT


def is_post_rate_limited(ip: str) -> bool:
    """이 IP가 최근 게시글을 너무 자주 작성해서 더 막아야 하는 상태인지 판단한다.

    is_signup_rate_limited()와 동일하게 "초과"가 아니라 "이상"을 기준으로
    삼는다 — 게시글 작성 자체가 정상 사용자가 짧은 시간에 여러 번 반복할
    이유가 거의 없으므로, 기준치에 도달하면 즉시 차단한다.
    """
    return db.count_recent_post_attempts(ip) >= POST_RATE_LIMIT


def is_comment_rate_limited(ip: str) -> bool:
    """이 IP가 최근 댓글을 너무 자주 작성해서 더 막아야 하는 상태인지 판단한다.

    is_post_rate_limited()와 판단 방식은 같지만, 댓글은 정상적인 대화에서도
    글보다 자주 달릴 수 있어 config.COMMENT_RATE_LIMIT 기본값을 더 넉넉하게 뒀다.
    """
    return db.count_recent_comment_attempts(ip) >= COMMENT_RATE_LIMIT


def is_web_scanning(ip: str) -> tuple[bool, int]:
    """이 IP가 "Web Scanning 의심 상태"인지 판단한다.

    is_suspicious()와 판단 방식(초과 여부)은 동일하지만, 세는 대상이
    login_attempts가 아니라 not_found_attempts다 — 정상 사용자도 깨진 링크
    몇 개는 우연히 밟을 수 있으므로, 로그인 실패와 마찬가지로 "초과"부터
    의심한다 (21단계, attack_response_state.md 구현 대상 #1).
    """
    count = db.count_recent_not_found_attempts(ip)
    return count > WEB_SCANNING_ALERT_THRESHOLD, count


def is_unauthorized_access_suspicious(ip: str) -> tuple[bool, int]:
    """이 IP가 "Unauthorized Access 의심 상태"인지 판단한다.

    is_web_scanning()과 판단 방식(초과 여부)은 동일하지만, unauthorized_attempts
    표를 본다 — 로그인 세션 없이 관리자 API(/api/*)를 반복 호출하는 패턴을
    탐지한다 (attack_response_state.md 구현 대상 #2).
    """
    count = db.count_recent_unauthorized_attempts(ip)
    return count > UNAUTHORIZED_ACCESS_ALERT_THRESHOLD, count


def is_page_access_suspicious(ip: str, path: str) -> tuple[bool, int]:
    """이 IP가 이 특정 경로를 "반복 접근 의심 상태"로 요청하고 있는지 판단한다.

    is_web_scanning()/is_unauthorized_access_suspicious()와 판단 방식(초과 여부)은
    같지만, 세는 대상이 "이 IP의 전체 요청"이 아니라 "이 IP가 이 경로를 요청한
    횟수"다 — 여러 페이지를 정상적으로 둘러보는 사람과, 같은 페이지 하나를
    스크립트로 반복 요청하는 패턴을 구분하기 위해서다 (attack_response_state.md
    구현 대상 #4).
    """
    count = db.count_recent_page_access_attempts(ip, path)
    return count > PAGE_ACCESS_ALERT_THRESHOLD, count


def is_locked(ip: str) -> bool:
    """이 IP가 지금 이 순간 잠긴 상태인지 True/False로 알려준다.

    실제 "잠겨있는지" 판단은 db.get_active_lockout()이 이미 하고 있으므로
    (active=True 이면서 아직 풀릴 시각이 안 지난 것만 찾아줌),
    여기서는 그 결과가 있는지(None이 아닌지)만 확인한다.
    """
    return db.get_active_lockout(ip) is not None
