# ============================================================================
# db/admin.py — admin_users / admin_login_log 표 관련 함수
# — 관리자(대시보드에 로그인하는 사람) 계정과, 그 로그인 시도 기록을 관리하는 기능
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

import os
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

import config
import db

# 타이밍 사이드채널 방지용 더미 해시 (L7 공격 보강 계획 Tier 3, db/users.py의
# _DUMMY_PASSWORD_HASH와 동일한 목적) — verify_admin_credentials 참고.
_DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing-safety")


def ensure_bootstrap_admin() -> None:
    """관리자 계정이 하나도 없으면, .env에 적힌 아이디/비밀번호로 1명을 자동으로 만든다.

    "부트스트랩(bootstrap)"이란 "맨 처음 아무것도 없는 상태에서 스스로 첫 발을
    떼게 만든다"는 뜻이다. 이 프로젝트엔 회원가입 화면을 통한 관리자 등록 기능이
    없으므로, 앱이 맨 처음 켜질 때 이 함수가 자동으로 관리자 계정 1개를 만들어준다.

    이미 관리자 계정이 1개라도 있으면 아무 일도 하지 않고 그냥 끝낸다
    (즉, 이 함수는 "앱을 여러 번 켜도 관리자가 중복으로 계속 만들어지지 않게" 안전장치 역할도 함).
    """
    res = db.get_client().table("admin_users").select("id").limit(1).execute()
    if res.data:
        return  # 이미 관리자가 1명 이상 있으므로 새로 만들 필요 없음
    username = os.environ["ADMIN_USERNAME"]
    password = os.environ["ADMIN_PASSWORD"]
    # 비밀번호를 그대로 저장하지 않고, generate_password_hash로 "되돌릴 수 없는
    # 암호화된 문자열"로 바꾼 뒤에 저장한다 (이유는 verify_admin_credentials 설명 참고).
    db.get_client().table("admin_users").insert(
        {"username": username, "password_hash": generate_password_hash(password)}
    ).execute()


def verify_admin_credentials(username: str, password: str) -> bool:
    """관리자가 로그인 화면에 입력한 아이디/비밀번호가 맞는지 확인한다.

    비밀번호는 저장할 때 이미 암호화(해시)되어 있으므로, "원래 글자를 복원"해서
    비교하는 게 아니라 "입력한 비밀번호를 똑같은 방식으로 암호화했을 때 저장된
    암호문과 글자가 일치하는가"만 확인한다 (check_password_hash가 이 비교를 해줌).

    타이밍 사이드채널 방지 (L7 공격 보강 계획 Tier 3, db/users.py의
    verify_user_credentials와 동일한 이유): 아이디가 없을 때도 더미 해시로
    항상 같은 비교 연산을 거치게 해서, "즉시 반환"과 "해시 비교 후 반환" 사이의
    응답 시간 차이로 관리자 아이디 존재 여부를 추측하지 못하게 한다.
    """
    res = (
        db.get_client()
        .table("admin_users")
        .select("password_hash")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    password_hash = res.data[0]["password_hash"] if res.data else _DUMMY_PASSWORD_HASH
    result = check_password_hash(password_hash, password)
    return result if res.data else False


def count_recent_admin_failures(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 관리자 로그인을 몇 번이나 실패했는지 센다.

    count_recent_failures()와 완전히 같은 패턴이지만, login_attempts가 아니라
    admin_login_log 표를 본다 — 감시 대상 로그인(/login)과 관리자 로그인
    (/admin/login)은 서로 다른 표에 기록되므로, 관리자 로그인 브루트포스를
    탐지하려면 이 표를 따로 세어야 한다(18단계 보안 점검에서 발견된 공백).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("admin_login_log")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .eq("success", False)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


def count_recent_distinct_admin_usernames(
    ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """count_recent_distinct_usernames()와 완전히 같은 목적이지만, admin_login_log
    표를 본다 — 관리자 로그인과 감시 대상 로그인은 서로 다른 표에 기록되므로
    (count_recent_admin_failures와 마찬가지 이유), 여기서도 전용 함수가 필요하다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("admin_login_log")
        .select("username")
        .eq("ip_address", ip)
        .eq("success", False)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return len({row["username"] for row in res.data})


def log_admin_attempt(username: str, success: bool, ip: str) -> None:
    """관리자 로그인 시도(성공이든 실패든) 한 건을 admin_login_log 표에 기록한다.

    "누가 언제 관리자 화면에 들어오려 했는지" 감사(audit) 기록을 남겨서,
    나중에 대시보드에서 확인할 수 있게 한다.
    """
    db.get_client().table("admin_login_log").insert(
        {"username": username, "success": success, "ip_address": ip}
    ).execute()


def list_admin_login_log(page: int = 1, page_size: int = 20) -> tuple[list[dict], int]:
    """관리자 로그인 시도 기록을 최신순으로 `page`번째 페이지만 가져오고, 전체 건수도
    함께 돌려준다 (대시보드 표시용). list_recent_attempts()와 동일한 이유로
    select(..., count="exact") + range()를 한 번에 쓴다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("admin_login_log")
        .select("*", count="exact")
        .order("attempted_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0
