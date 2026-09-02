# ============================================================================
# db.py — 데이터베이스(Supabase)와 대화하는 유일한 창구
#
# 이 프로그램의 다른 파일(detector.py, soar.py, app.py 등)은 데이터베이스에
# 직접 말을 걸지 않고, 항상 이 파일의 함수를 통해서만 데이터를 읽고 씁니다.
# 그래야 "데이터를 어떻게 저장/조회하는지"에 대한 규칙이 한 곳에만 있어서
# 관리하기 쉬워집니다.
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
