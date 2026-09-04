# ============================================================================
# db.py — 데이터베이스(Supabase)와 대화하는 유일한 창구
#
# 이 프로그램의 다른 파일(detector.py, soar.py, app.py 등)은 데이터베이스에
# 직접 말을 걸지 않고, 항상 이 파일의 함수를 통해서만 데이터를 읽고 씁니다.
# 그래야 "데이터를 어떻게 저장/조회하는지"에 대한 규칙이 한 곳에만 있어서
# 관리하기 쉬워집니다.ㄴㅇㄹㄴㅇㄹㅇㄴㄹㄴㅇㄹㄴㄷㅁㄹ
# ============================================================================

import os
from datetime import datetime, timedelta, timezone

from supabase import Client, create_client
from werkzeug.security import check_password_hash, generate_password_hash

import config

# 프로그램 전체에서 Supabase 연결을 딱 하나만 만들어서 재사용하기 위한 변수.
# 처음엔 비어있다가(None), 처음 필요할 때 한 번만 실제 연결을 만듭니다.
_client: Client | None = None


def get_client() -> Client:
    """Supabase(데이터베이스)에 접속하는 연결 객체를 돌려준다.

    이미 한 번 접속해뒀다면 새로 접속하지 않고 기존 연결을 재사용한다
    (전화를 걸 때마다 새로 다이얼하지 않고, 이미 연결된 통화선을 계속 쓰는 것과 비슷함).
    """
    global _client
    if _client is None:
        # .env 파일에 적어둔 주소(URL)와 비밀 열쇠(KEY)를 읽어와서 접속을 시도한다.
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_KEY"]
        _client = create_client(url, key)
    return _client


def _now_iso() -> str:
    """지금 이 순간의 시각을 데이터베이스가 알아듣는 표준 문자열 형식으로 돌려준다.

    이름 앞의 밑줄(_)은 "이 함수는 이 파일 안에서만 쓰는 내부용 도구"라는 표시.
    """
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# login_attempts 표 관련 함수
# — "누가 언제 어떤 IP에서 로그인에 성공/실패했는지"를 기록하고 조회하는 기능
# ============================================================================

def log_attempt(ip: str, username: str, success: bool) -> None:
    """로그인 시도 한 건을 login_attempts 표에 새 줄로 저장한다.

    CCTV처럼 "누가 지나갔다"는 기록을 계속 쌓기만 하고, 절대 지우거나 덮어쓰지 않는다.
    """
    get_client().table("login_attempts").insert(
        {"ip_address": ip, "username": username, "success": success}
    ).execute()


def count_recent_failures(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 번이나 로그인에 실패했는지 센다.

    동작 순서:
    1. "지금 시각 - 60초"를 계산해서 "이 시각 이후의 기록만 보겠다"는 기준선을 만든다.
    2. login_attempts 표에서 "이 IP" + "실패(success=False)" + "기준선 이후"인 줄만 골라
       개수를 센다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("login_attempts")
        .select("id", count="exact")   # 실제 내용은 필요없고 "개수"만 알면 되므로 id만 요청
        .eq("ip_address", ip)          # 조건 1: IP가 일치하는 것만
        .eq("success", False)          # 조건 2: 실패한 시도만
        .gte("attempted_at", cutoff)   # 조건 3: 기준 시각 이후에 일어난 것만
        .execute()
    )
    return res.count or 0  # 만약 count가 없으면(None) 0으로 처리


def count_recent_distinct_usernames(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 개의 서로 다른 아이디로 로그인
    실패를 시도했는지 센다.

    count_recent_failures()는 "몇 번" 두드렸는지만 알려주지만, 이 값은 "몇 개의
    서로 다른 문(아이디)"을 두드렸는지를 알려준다 — 1개면 계정 하나를 노린
    전형적인 Brute Force, 2개 이상이면 여러 계정을 돌아가며 시도하는 Password
    Spraying으로 의심할 수 있다 (soar.enforce_lockout이 Slack 알림에 이 값을
    함께 표시해서 두 패턴을 구분해준다).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("login_attempts")
        .select("username")
        .eq("ip_address", ip)
        .eq("success", False)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return len({row["username"] for row in res.data})


def list_recent_attempts(limit: int = 50) -> list[dict]:
    """가장 최근 로그인 시도 기록을 최신순으로 최대 `limit`개 가져온다.

    관리자 대시보드 화면에 "최근 로그인 기록" 목록을 보여줄 때 쓰인다.
    """
    res = (
        get_client()
        .table("login_attempts")
        .select("*")                      # 이 줄의 모든 칸(id, ip, username 등) 전부 요청
        .order("attempted_at", desc=True) # 시각 기준으로 내림차순(최신이 맨 위) 정렬
        .limit(limit)
        .execute()
    )
    return res.data


def list_attempts_since(hours: int = 24) -> list[dict]:
    """지난 `hours`시간(기본 24시간) 동안의 로그인 시도 전체를 가져온다.

    count_recent_failures()와 비슷한 "기준 시각 이후만" 패턴을 쓰지만, 특정
    IP나 성공/실패로 좁히지 않고 전체를 가져온다는 점이 다르다 — scripts/
    daily_report.py가 "오늘 하루 전체 통계"를 계산할 때 쓴다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        get_client()
        .table("login_attempts")
        .select("*")
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.data


def list_lockouts_since(hours: int = 24) -> list[dict]:
    """지난 `hours`시간 동안 새로 걸린 잠금 전체를 가져온다 (현재 풀렸는지와 무관하게).

    list_active_lockouts()는 "지금 이 순간 잠긴 것만" 보여주지만, 일일 리포트는
    "오늘 하루 동안 몇 번이나 잠금이 발생했는지"가 궁금한 것이므로 active 여부로
    거르지 않고 locked_at 기준으로만 걸러온다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        get_client()
        .table("lockouts")
        .select("*")
        .gte("locked_at", cutoff)
        .execute()
    )
    return res.data


def list_attempts_by_username(username: str, limit: int = 20) -> list[dict]:
    """특정 아이디의 로그인 시도 기록만 최신순으로 가져온다.

    list_recent_attempts()와 거의 똑같지만, 관리자용(전체 IP/전체 사용자)이 아니라
    회원 본인이 "내가 언제 로그인을 시도했는지"만 볼 수 있게 아이디로 걸러낸다는
    점이 다르다. 회원 대시보드의 "최근 로그인 기록" 화면에서 쓰인다.
    """
    res = (
        get_client()
        .table("login_attempts")
        .select("*")
        .eq("username", username)
        .order("attempted_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data


# ============================================================================
# lockouts 표 관련 함수
# — "지금 어떤 IP가 잠겨있고, 언제 풀리는지"라는 "현재 상태"를 관리하는 기능
# (login_attempts가 "지나간 일의 기록"이라면, lockouts는 "지금 이 순간의 상태판")
# ============================================================================

def create_lockout(
    ip: str, failure_count: int, duration_seconds: int = config.LOCKOUT_DURATION_SECONDS
) -> None:
    """이 IP를 지금부터 `duration_seconds`(기본 300초=5분) 동안 잠근다.

    upsert(업서트)란 "이미 그 IP의 잠금 기록이 있으면 덮어쓰고,
    없으면 새로 만든다"는 뜻의 합성어(update + insert)다.
    같은 IP가 두 번 잠기는 것을 걱정하지 않고 그냥 호출하면 되도록 설계했다.
    """
    now = datetime.now(timezone.utc)
    unlock_at = now + timedelta(seconds=duration_seconds)  # "풀려날 시각" = 지금 + 5분
    get_client().table("lockouts").upsert(
        {
            "ip_address": ip,
            "locked_at": now.isoformat(),
            "unlock_at": unlock_at.isoformat(),
            "failure_count": failure_count,  # 몇 번 실패해서 잠겼는지 같이 기록
            "active": True,                  # "지금 잠긴 상태다"라는 표시
        },
        on_conflict="ip_address",  # ip_address가 이미 표에 있으면 새로 만들지 않고 덮어씀
    ).execute()


def get_active_lockout(ip: str) -> dict | None:
    """이 IP가 "지금 이 순간" 실제로 잠겨있는지 확인하고, 잠겨있다면 그 잠금 정보를 돌려준다.

    조건이 두 가지 다 맞아야 "진짜로 잠긴 상태"로 인정한다:
    - active가 True (아직 해제되지 않았고)
    - unlock_at(풀리는 시각)이 지금보다 미래 (아직 시간이 안 지났고)

    두 조건을 만족하는 기록이 없으면 None(없음)을 돌려준다.
    """
    res = (
        get_client()
        .table("lockouts")
        .select("*")
        .eq("ip_address", ip)
        .eq("active", True)
        .gt("unlock_at", _now_iso())  # gt = greater than = "~보다 미래"
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None  # 결과가 있으면 첫 번째 줄, 없으면 None


def release_lockout(ip: str) -> None:
    """이 IP의 잠금을 해제한다 (active 칸을 False로 바꿈).

    줄을 지우는 게 아니라 "해제됨" 표시만 남겨서, 나중에 "언제 잠겼다가 언제 풀렸는지"
    이력을 되짚어볼 수 있게 한다. 관리자가 수동으로 풀 때나, 5분이 지나 자동으로
    풀릴 때나 똑같이 이 함수 하나를 쓴다.
    """
    get_client().table("lockouts").update({"active": False}).eq("ip_address", ip).execute()


def list_active_lockouts() -> list[dict]:
    """지금 잠겨있는(active=True) IP 목록 전체를 가져온다.

    관리자 대시보드에서 "현재 잠긴 IP 카드" 목록을 보여줄 때 쓰인다.
    """
    res = (
        get_client()
        .table("lockouts")
        .select("*")
        .eq("active", True)
        .order("locked_at", desc=True)  # 가장 최근에 잠긴 것부터 보여줌
        .execute()
    )
    return res.data


def list_expired_active_lockouts() -> list[dict]:
    """"5분이 지났는데도 아직 active=True로 남아있는" 잠금 목록을 찾는다.

    이 목록이 바로 "지금 당장 자동으로 풀어줘야 할 IP들"이다.
    이 함수 자체는 아무것도 풀지 않고, "풀어야 할 목록"만 알려준다
    (실제로 푸는 실행은 soar.py의 try_release_expired_lockouts()가 담당).
    """
    res = (
        get_client()
        .table("lockouts")
        .select("*")
        .eq("active", True)
        .lte("unlock_at", _now_iso())  # lte = less than or equal = "~보다 과거이거나 같음"
        .execute()
    )
    return res.data


# ============================================================================
# admin_users / admin_login_log 표 관련 함수
# — 관리자(대시보드에 로그인하는 사람) 계정과, 그 로그인 시도 기록을 관리하는 기능
# ============================================================================

def ensure_bootstrap_admin() -> None:
    """관리자 계정이 하나도 없으면, .env에 적힌 아이디/비밀번호로 1명을 자동으로 만든다.

    "부트스트랩(bootstrap)"이란 "맨 처음 아무것도 없는 상태에서 스스로 첫 발을
    떼게 만든다"는 뜻이다. 이 프로젝트엔 회원가입 화면을 통한 관리자 등록 기능이
    없으므로, 앱이 맨 처음 켜질 때 이 함수가 자동으로 관리자 계정 1개를 만들어준다.

    이미 관리자 계정이 1개라도 있으면 아무 일도 하지 않고 그냥 끝낸다
    (즉, 이 함수는 "앱을 여러 번 켜도 관리자가 중복으로 계속 만들어지지 않게" 안전장치 역할도 함).
    """
    res = get_client().table("admin_users").select("id").limit(1).execute()
    if res.data:
        return  # 이미 관리자가 1명 이상 있으므로 새로 만들 필요 없음
    username = os.environ["ADMIN_USERNAME"]
    password = os.environ["ADMIN_PASSWORD"]
    # 비밀번호를 그대로 저장하지 않고, generate_password_hash로 "되돌릴 수 없는
    # 암호화된 문자열"로 바꾼 뒤에 저장한다 (이유는 verify_admin_credentials 설명 참고).
    get_client().table("admin_users").insert(
        {"username": username, "password_hash": generate_password_hash(password)}
    ).execute()


def verify_admin_credentials(username: str, password: str) -> bool:
    """관리자가 로그인 화면에 입력한 아이디/비밀번호가 맞는지 확인한다.

    비밀번호는 저장할 때 이미 암호화(해시)되어 있으므로, "원래 글자를 복원"해서
    비교하는 게 아니라 "입력한 비밀번호를 똑같은 방식으로 암호화했을 때 저장된
    암호문과 글자가 일치하는가"만 확인한다 (check_password_hash가 이 비교를 해줌).
    """
    res = (
        get_client()
        .table("admin_users")
        .select("password_hash")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    if not res.data:
        return False  # 그런 아이디의 관리자가 아예 없음
    return check_password_hash(res.data[0]["password_hash"], password)


def count_recent_admin_failures(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 관리자 로그인을 몇 번이나 실패했는지 센다.

    count_recent_failures()와 완전히 같은 패턴이지만, login_attempts가 아니라
    admin_login_log 표를 본다 — 감시 대상 로그인(/login)과 관리자 로그인
    (/admin/login)은 서로 다른 표에 기록되므로, 관리자 로그인 브루트포스를
    탐지하려면 이 표를 따로 세어야 한다(18단계 보안 점검에서 발견된 공백).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
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
        get_client()
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
    get_client().table("admin_login_log").insert(
        {"username": username, "success": success, "ip_address": ip}
    ).execute()


def list_admin_login_log(limit: int = 20) -> list[dict]:
    """관리자 로그인 시도 기록을 최신순으로 최대 `limit`개 가져온다 (대시보드 표시용)."""
    res = (
        get_client()
        .table("admin_login_log")
        .select("*")
        .order("attempted_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data


# ============================================================================
# users 표 관련 함수 (회원가입 기능)
# — 감시 대상이 되는 가짜 로그인 화면(/login)에 실제로 가입해서 로그인하는
#   "일반 사용자" 계정을 관리하는 기능. 관리자(admin_users)와는 완전히 별개 개념.
# ============================================================================

def get_user_by_username(username: str) -> dict | None:
    """아이디로 사용자 한 명을 찾는다. 없으면 None을 돌려준다."""
    res = (
        get_client()
        .table("users")
        .select("*")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def get_user_by_id(user_id: int) -> dict | None:
    """회원 번호(id)로 사용자 한 명을 찾는다.

    로그인 세션에는 아이디(username) 문자열뿐 아니라 이 id도 함께 저장해둔다
    (app.py의 login_submit() 참고) — 프로필을 수정할 때 "어느 행을 고칠지"를
    아이디가 아니라 변하지 않는 id로 정확히 짚어내기 위해서다.
    """
    res = get_client().table("users").select("*").eq("id", user_id).limit(1).execute()
    return res.data[0] if res.data else None


def create_user(username: str, email: str, password: str) -> bool:
    """새 사용자 계정을 만든다 (회원가입).

    같은 아이디나 같은 이메일로 이미 가입한 사람이 있으면 실패(False)를 돌려주고
    아무것도 저장하지 않는다. 문제없으면 비밀번호를 암호화해서 저장하고 True를 돌려준다.

    반환값:
        True  - 회원가입 성공
        False - 아이디 또는 이메일이 이미 사용 중이라 가입 실패
    """
    # 1) 아이디 중복 확인
    existing_username = (
        get_client().table("users").select("id").eq("username", username).limit(1).execute()
    )
    if existing_username.data:
        return False
    # 2) 이메일 중복 확인
    existing_email = (
        get_client().table("users").select("id").eq("email", email).limit(1).execute()
    )
    if existing_email.data:
        return False
    # 3) 문제 없으면 비밀번호를 암호화해서 새 계정 저장
    get_client().table("users").insert(
        {"username": username, "email": email, "password_hash": generate_password_hash(password)}
    ).execute()
    return True


def verify_user_credentials(username: str, password: str) -> bool:
    """사용자가 로그인 화면에 입력한 아이디/비밀번호가 맞는지 확인한다.

    동작 원리는 verify_admin_credentials와 동일 — 저장된 암호문과
    "지금 입력한 비밀번호를 암호화한 결과"가 일치하는지만 비교한다.
    """
    user = get_user_by_username(username)
    if user is None:
        return False  # 그런 아이디로 가입한 사람이 없음
    return check_password_hash(user["password_hash"], password)


def update_user_profile(user_id: int, name: str, email: str) -> bool:
    """회원 본인이 프로필 화면에서 "표시 이름"과 이메일을 수정할 때 쓰인다.

    이메일은 users 표에서 unique(고유값)로 걸려있으므로, 다른 사람이 이미 쓰고
    있는 이메일로 바꾸려고 하면 실패(False)를 돌려주고 아무것도 바꾸지 않는다.
    (본인이 원래 쓰던 이메일 그대로 "수정"하는 경우는 "다른 사람의" 이메일이
    아니므로 문제없이 통과한다 — 그래서 자기 자신의 id는 검사에서 제외한다.)
    """
    existing_email = (
        get_client()
        .table("users")
        .select("id")
        .eq("email", email)
        .neq("id", user_id)  # neq = not equal = "이 값과 다른 것만" — 본인 행은 제외
        .limit(1)
        .execute()
    )
    if existing_email.data:
        return False

    get_client().table("users").update({"name": name, "email": email}).eq("id", user_id).execute()
    return True


def list_users(limit: int = 100) -> list[dict]:
    """가입된 회원 목록을 최신 가입순으로 가져온다 (관리자 대시보드 표시용).

    password_hash 칸은 일부러 요청하지 않는다 — 암호화된 값이라 그 자체로는
    안전하지만, 화면에 굳이 내보낼 이유가 없는 값은 애초에 조회 단계에서부터
    빼두는 게 "혹시 모를 실수로 노출되는 사고"를 막는 가장 확실한 방법이다.
    """
    res = (
        get_client()
        .table("users")
        .select("id, username, email, created_at")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data


def delete_user(user_id: int) -> bool:
    """회원 계정을 하나 삭제한다 (관리자 전용 기능).

    삭제된 사람의 과거 로그인 시도 기록(login_attempts)은 그대로 남는다 —
    그 표는 username을 문자열로만 저장하고 users 표와 연결(FK)되어 있지 않기
    때문이다(3단계 설명 참고). 즉 계정을 지워도 "이 아이디가 예전에 시도했던
    기록" 자체는 감사 로그로 계속 남는다.

    반환값: 실제로 삭제된 행이 있었으면 True, 애초에 그런 id가 없었으면 False.
    """
    res = get_client().table("users").delete().eq("id", user_id).execute()
    return len(res.data) > 0


# ============================================================================
# app_settings 표 관련 함수 — 서버 전체가 공유하는 설정값 (지금은 회원가입 On/Off 하나)
# ============================================================================

def get_signup_enabled() -> bool:
    """지금 회원가입을 받고 있는지(True) 막아뒀는지(False) 확인한다.

    이 값을 파이썬 변수(메모리)에만 저장해두면 안 되는 이유: 이 프로젝트는
    로컬 컴퓨터, Vercel 등 여러 곳에서 서버가 동시에 돌아갈 수 있는데, 메모리는
    각 서버(프로세스)마다 따로따로 존재한다. 관리자가 한 곳에서 "회원가입 끄기"를
    눌러도 다른 곳에서 돌고 있는 서버는 그 사실을 전혀 모른다. 그래서 모두가
    공유해서 보는 단 하나의 장소인 Supabase에 이 값을 저장해둔다.
    """
    res = get_client().table("app_settings").select("signup_enabled").eq("id", 1).limit(1).execute()
    if not res.data:
        return True  # 설정 행이 아직 없다면(예외 상황) 기본값은 "허용"으로 안전하게 처리
    return res.data[0]["signup_enabled"]


def set_signup_enabled(enabled: bool) -> None:
    """회원가입 허용 여부를 켜거나 끈다 (관리자가 대시보드에서 호출)."""
    get_client().table("app_settings").update({"signup_enabled": enabled}).eq("id", 1).execute()


# ============================================================================
# signup_attempts 표 관련 함수 — 회원가입 요청 빈도 제한 (18단계 보안 점검 보완)
# — login_attempts와 별도 표를 쓰는 이유: 회원가입은 성공/아이디 값과 무관하게
#   "이 IP가 얼마나 자주 두드렸는가"만 세면 되므로, 더 가벼운 구조로 분리했다.
# ============================================================================

def log_signup_attempt(ip: str) -> None:
    """회원가입 POST 요청 한 건을 signup_attempts 표에 기록한다 (성공/실패 무관)."""
    get_client().table("signup_attempts").insert({"ip_address": ip}).execute()


def count_recent_signup_attempts(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 회원가입을 몇 번이나 시도했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("signup_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


# ============================================================================
# ip_locations 표 관련 함수 — IP 위치 조회 결과 캐시 (13단계)
# ============================================================================

def get_cached_ip_locations(ips: list[str]) -> dict[str, dict]:
    """IP 목록을 한꺼번에 캐시에서 찾아온다.

    IP 하나마다 따로따로 물어보지 않고 .in_()으로 "이 목록에 있는 IP들만 한
    번에 줘"라고 요청하는 이유: 관리자 대시보드는 10초마다 최근 로그인 시도
    최대 50건을 다시 그리는데, 그 50건 각각에 대해 캐시 조회를 따로 하면
    Supabase 요청이 50개씩 늘어난다(9단계에서 겪었던 쿼터 문제와 같은 유형의
    실수). 딱 1번의 쿼리로 필요한 IP들을 전부 가져오면 이 문제를 피할 수 있다.

    반환값은 {"1.2.3.4": {...캐시된 행...}, ...} 형태의 딕셔너리다 — "이 IP는
    캐시에 있는가?"를 코드에서 바로 찾아보기 쉽게 하기 위해서다.
    """
    if not ips:
        return {}
    res = get_client().table("ip_locations").select("*").in_("ip_address", ips).execute()
    return {row["ip_address"]: row for row in res.data}


def save_ip_location(
    ip: str, country: str | None, region_name: str | None, city: str | None, lookup_failed: bool
) -> None:
    """방금 새로 조회한 IP 위치 결과를 캐시 표에 저장한다.

    조회에 실패한 경우(lookup_failed=True, 예: 127.0.0.1 같은 사설 IP)도
    똑같이 저장해둔다 — 그래야 다음에 같은 IP가 또 나왔을 때, "저번에도 안
    됐던 IP구나"를 캐시만 보고 바로 알 수 있고, 매번 다시 ip-api.com에
    헛수고로 물어보지 않는다.
    """
    get_client().table("ip_locations").upsert(
        {
            "ip_address": ip,
            "country": country,
            "region_name": region_name,
            "city": city,
            "lookup_failed": lookup_failed,
        }
    ).execute()


# ============================================================================
# posts 표 관련 함수 — 게시판 글 (docs/board-comment/plan_board.md 참고)
# — login_attempts와 동일한 관례로 users와 FK를 걸지 않고 author_username을
#   텍스트로만 저장한다 (회원 탈퇴 후에도 글은 흔적만 남기고 유지, 결정 #4).
# ============================================================================

def create_post(author_username: str, title: str, body: str) -> dict:
    """새 게시글을 만든다. 생성된 행(id 포함)을 그대로 돌려준다.

    상세 화면으로 바로 이동시키려면(app.py의 post_new_submit) 새로 생긴 글의
    id가 필요하므로, insert 결과를 그대로 반환한다.
    """
    res = (
        get_client()
        .table("posts")
        .insert({"author_username": author_username, "title": title, "body": body})
        .execute()
    )
    return res.data[0]


def get_post(post_id: int) -> dict | None:
    """글 번호(id)로 게시글 한 건을 찾는다. 없으면 None을 돌려준다."""
    res = get_client().table("posts").select("*").eq("id", post_id).limit(1).execute()
    return res.data[0] if res.data else None


def list_posts(page: int, page_size: int) -> list[dict]:
    """게시글 목록을 최신순으로 `page`번째 페이지만 가져온다 (1부터 시작).

    supabase-py의 .range(start, end)는 PostgREST의 offset 기반 페이지네이션을
    그대로 감싼 것이라, 별도 페이지네이션 라이브러리 없이 이 한 줄로 구현된다
    (docs/board-comment/plan_board.md 7절 "기술 스택 선택과 이유" 참고).
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        get_client()
        .table("posts")
        .select("*")
        .order("created_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data


def count_posts() -> int:
    """전체 게시글 개수를 센다. 목록 화면에서 "전체 페이지 수"를 계산할 때 쓴다."""
    res = get_client().table("posts").select("id", count="exact").execute()
    return res.count or 0


def update_post(post_id: int, title: str, body: str) -> None:
    """게시글의 제목/본문을 수정한다. updated_at도 지금 시각으로 함께 갱신한다."""
    get_client().table("posts").update(
        {"title": title, "body": body, "updated_at": _now_iso()}
    ).eq("id", post_id).execute()


def delete_post(post_id: int) -> bool:
    """게시글을 삭제한다. comments 표가 on delete cascade로 걸려있으므로,
    이 글에 달린 댓글도 Supabase가 알아서 함께 지운다 (docs/schema.sql 참고).

    반환값: 실제로 삭제된 행이 있었으면 True, 애초에 그런 id가 없었으면 False.
    """
    res = get_client().table("posts").delete().eq("id", post_id).execute()
    return len(res.data) > 0


def list_recent_posts(limit: int = 20) -> list[dict]:
    """가장 최근 게시글을 최신순으로 가져온다 (관리자 대시보드 "게시글 관리" 표시용)."""
    res = (
        get_client()
        .table("posts")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data


# ============================================================================
# comments 표 관련 함수 — 게시글에 달리는 댓글 (단일 depth, 대댓글 없음)
# ============================================================================

def create_comment(post_id: int, author_username: str, body: str) -> None:
    """게시글 하나에 댓글 한 건을 새로 단다."""
    get_client().table("comments").insert(
        {"post_id": post_id, "author_username": author_username, "body": body}
    ).execute()


def get_comment(comment_id: int) -> dict | None:
    """댓글 번호(id)로 댓글 한 건을 찾는다. 없으면 None을 돌려준다.

    댓글 삭제 라우트(app.py의 board_comment_delete)가 "이 댓글이 정말 본인
    것인지" 확인할 때 쓴다 — get_post()와 대칭되는 함수.
    """
    res = get_client().table("comments").select("*").eq("id", comment_id).limit(1).execute()
    return res.data[0] if res.data else None


def list_comments_by_post(post_id: int) -> list[dict]:
    """특정 게시글에 달린 댓글 전체를 오래된 순(등록 순서대로)으로 가져온다."""
    res = (
        get_client()
        .table("comments")
        .select("*")
        .eq("post_id", post_id)
        .order("created_at", desc=False)
        .execute()
    )
    return res.data


def delete_comment(comment_id: int) -> bool:
    """댓글을 하나 삭제한다.

    반환값: 실제로 삭제된 행이 있었으면 True, 애초에 그런 id가 없었으면 False.
    """
    res = get_client().table("comments").delete().eq("id", comment_id).execute()
    return len(res.data) > 0


def get_latest_comment_info(post_id: int) -> dict:
    """이 글에 지금까지 달린 댓글 개수와, 가장 최근 댓글이 달린 시각을 돌려준다.

    board.js의 "새로운 댓글이 추가되었습니다" 배너가 15초마다 이 함수를 통해
    받은 값을 페이지 로드 시점 값과 비교한다 — 값이 달라졌을 때만 배너를
    띄우면 되므로, 댓글 내용 전체가 아니라 이 두 값만 가볍게 돌려준다.
    """
    res = (
        get_client()
        .table("comments")
        .select("id, created_at", count="exact")
        .eq("post_id", post_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    latest_at = res.data[0]["created_at"] if res.data else None
    return {"count": res.count or 0, "latest_at": latest_at}


def list_recent_comments(limit: int = 20) -> list[dict]:
    """가장 최근 댓글을 최신순으로 가져온다 (관리자 대시보드 "게시글 관리" 표시용)."""
    res = (
        get_client()
        .table("comments")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data


# ============================================================================
# post_attempts / comment_attempts 표 관련 함수
# — 게시글·댓글 도배(스팸) 방지용 요청 빈도 제한 로그. signup_attempts와
#   완전히 동일한 구조와 목적(성공/실패 무관, "이 IP가 얼마나 자주 두드렸는가").
# ============================================================================

def log_post_attempt(ip: str) -> None:
    """게시글 작성 POST 요청 한 건을 post_attempts 표에 기록한다 (성공/실패 무관)."""
    get_client().table("post_attempts").insert({"ip_address": ip}).execute()


def count_recent_post_attempts(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 게시글을 몇 번이나 작성 시도했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("post_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


def log_comment_attempt(ip: str) -> None:
    """댓글 작성 POST 요청 한 건을 comment_attempts 표에 기록한다 (성공/실패 무관)."""
    get_client().table("comment_attempts").insert({"ip_address": ip}).execute()


def count_recent_comment_attempts(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 댓글을 몇 번이나 작성 시도했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("comment_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


# ============================================================================
# not_found_attempts 표 관련 함수 — Web Scanning(존재하지 않는 경로 반복 요청)
# 탐지용 로그. signup_attempts/post_attempts와 같은 구조이지만, 어떤 경로를
# 요청했는지(path)도 함께 남긴다 (21단계, attack_response_state.md 구현 대상 #1).
# ============================================================================

def log_not_found_attempt(ip: str, path: str) -> None:
    """404가 발생한 요청 한 건을 not_found_attempts 표에 기록한다."""
    get_client().table("not_found_attempts").insert({"ip_address": ip, "path": path}).execute()


def count_recent_not_found_attempts(
    ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 번이나 404를 유발했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("not_found_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


# ============================================================================
# unauthorized_attempts 표 관련 함수 — 관리자 API(/api/*)에 로그인 세션 없이
# 접근을 시도한 반복 요청 탐지용 로그. not_found_attempts와 완전히 동일한
# 구조다 (attack_response_state.md 구현 대상 #2).
# ============================================================================

def log_unauthorized_attempt(ip: str, path: str) -> None:
    """세션 없이 관리자 API에 접근한 요청 한 건을 unauthorized_attempts 표에 기록한다."""
    get_client().table("unauthorized_attempts").insert({"ip_address": ip, "path": path}).execute()


def count_recent_unauthorized_attempts(
    ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 번이나 세션 없이 관리자 API를 두드렸는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("unauthorized_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


# ============================================================================
# page_access_attempts 표 관련 함수 — 반복 페이지 접근(같은 IP가 같은 GET
# 경로를 반복 요청) 탐지용 로그. not_found_attempts/unauthorized_attempts와
# 구조는 같지만, "이 IP의 전체 요청"이 아니라 "이 IP가 이 경로를 요청한
# 횟수"를 세야 하므로 카운트할 때 path도 함께 필터링한다
# (attack_response_state.md 구현 대상 #4).
# ============================================================================

def log_page_access_attempt(ip: str, path: str) -> None:
    """GET 페이지 요청 한 건을 page_access_attempts 표에 기록한다."""
    get_client().table("page_access_attempts").insert({"ip_address": ip, "path": path}).execute()


def count_recent_page_access_attempts(
    ip: str, path: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 이 경로를 몇 번이나 요청했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client()
        .table("page_access_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .eq("path", path)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0
