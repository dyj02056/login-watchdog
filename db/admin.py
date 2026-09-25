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


def get_admin_role(username: str) -> str | None:
    """이 관리자 아이디의 role(security_viewer/security_admin/super_admin)을 돌려준다.

    Track B guide26에서 helpers.require_permission()이 요청마다 이 함수를 호출해서
    "지금 이 관리자가 어떤 역할인지"부터 확인한다. has_permission()과 마찬가지로
    캐싱하지 않고 매번 조회한다 — super_admin이 다른 관리자의 role을 바꾸거나
    회수했을 때(guide28 권한회수), 그 관리자가 로그아웃하지 않아도 바로 다음
    요청부터 새 role이 적용되어야 하기 때문이다.

    계정이 없으면(이미 삭제됐거나 오타) None을 돌려준다 — 호출부(require_permission)는
    None을 "아무 권한도 없음"으로 취급한다.
    """
    res = (
        db.get_client()
        .table("admin_users")
        .select("role")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    return res.data[0]["role"] if res.data else None


def list_admin_users() -> list[dict]:
    """전체 관리자 계정 목록을 id/username/role/created_at만 골라 돌려준다
    (Track B guide26 후속, 대시보드 "관리자 계정 관리" 카드용).

    db/users.py의 list_users()와 같은 이유로 password_hash 칸은 애초에
    select하지 않는다 — 화면에 내보낼 이유가 없는 값은 조회 단계에서부터 뺀다.
    """
    res = db.get_client().table("admin_users").select("id, username, role, created_at").execute()
    return res.data


def get_admin_role_by_id(admin_id: int) -> str | None:
    """id로 관리자 계정의 role을 조회한다. get_admin_role()은 username으로
    찾지만(require_permission이 세션의 아이디로 조회), 대시보드의 "계정 삭제"
    버튼은 행의 기본키(id)만 들고 있으므로 이 조회가 따로 필요하다.

    routes/admin.py가 삭제 전에 이 함수로 대상이 super_admin인지 먼저 확인해
    "이 화면에서는 super_admin을 지울 수 없다"는 규칙을 지킨다.
    """
    res = db.get_client().table("admin_users").select("role").eq("id", admin_id).limit(1).execute()
    return res.data[0]["role"] if res.data else None


def create_admin_user(username: str, password: str, role: str) -> bool:
    """새 관리자 계정을 role과 함께 만든다.

    scripts/create_admin.py(터미널 스크립트)와 대시보드 "관리자 계정 관리"
    (routes/admin.py)가 둘 다 이 함수를 통해서만 계정을 만든다 — insert 로직이
    두 곳에 따로 있으면 한쪽만 고치고 잊어버리는 사고가 나기 쉽다.

    아이디가 이미 있으면(unique 제약) 아무것도 만들지 않고 False를 돌려준다.
    """
    existing = (
        db.get_client().table("admin_users").select("id").eq("username", username).limit(1).execute()
    )
    if existing.data:
        return False

    db.get_client().table("admin_users").insert(
        {"username": username, "password_hash": generate_password_hash(password), "role": role}
    ).execute()
    return True


def delete_admin_user(admin_id: int) -> bool:
    """관리자 계정을 하나 삭제한다.

    super_admin을 지우면 안 되는 규칙(login_watchdog_expansion_plan.md 논의 —
    super_admin은 1명만 두기로 결정)은 여기가 아니라 호출부(routes/admin.py)가
    delete_admin_user 호출 전에 get_admin_role_by_id로 먼저 확인한다 — 이 함수는
    db/users.py의 delete_user()와 동일하게 "삭제 실행"에만 집중한다.
    """
    res = db.get_client().table("admin_users").delete().eq("id", admin_id).execute()
    return len(res.data) > 0


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
