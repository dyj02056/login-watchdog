# 3단계 — `db.py` (데이터베이스와 대화하는 창구 만들기)

[◀ 2단계](guide02_schema.md) · [전체 목차](beginner-guide.md) · [4단계 ▶](guide04_response.md)


### 우리가 한 일
1. [db.py](../../db.py) 파일에 "Supabase와 주고받는 모든 대화"를 함수 단위로 정리
2. 실제 데이터를 넣었다 빼면서(스모크 테스트) 함수들이 진짜로 작동하는지 확인
3. 테스트에 쓴 가짜 데이터를 다시 삭제해서 표를 깨끗한 상태로 되돌림

### 왜 했는가 (쉬운 설명)

**왜 "db.py 하나"에 몰아넣나?**
프로그램의 다른 부분(로그인 화면, 잠금 판정 로직, 대시보드 등)이 각자 Supabase에 직접 말을 걸게 하면, 같은 종류의 요청을 여러 곳에서 조금씩 다르게 작성하게 되어 실수가 생기기 쉽습니다. 그래서 "데이터베이스에 무언가를 묻거나 저장하고 싶으면 반드시 `db.py`를 거쳐라"라는 규칙을 만들었습니다. 마치 회사에서 "외부 업체와의 연락은 전부 총무팀을 통해서만 한다"고 창구를 하나로 정해두는 것과 같습니다. 이렇게 하면 나중에 Supabase 사용법이 바뀌어도 `db.py` 한 파일만 고치면 됩니다.

**함수(function)가 뭔가?**
"IP별 최근 실패 횟수를 세어줘" 같은 자주 반복되는 작업 하나하나에 이름을 붙여서 미리 만들어둔 "미니 프로그램 조각"입니다. 예를 들어 `count_recent_failures(ip)`라는 함수는 "이 IP가 최근 60초 안에 몇 번 실패했는지" 세는 일을 전담합니다. 다른 코드는 이 함수 이름만 부르면 되고, 내부에서 정확히 어떻게 세는지는 몰라도 됩니다 — 마치 자판기 버튼을 누르면 안에서 어떻게 동전을 인식하는지 몰라도 음료가 나오는 것과 비슷합니다.

**이번에 만든 함수들을 역할별로 묶으면:**
- **로그인 시도 기록**: 시도를 저장하고(`log_attempt`), 최근 실패 횟수를 세고(`count_recent_failures`), 최근 기록 목록을 가져오는(`list_recent_attempts`) 함수
- **IP 잠금 상태 관리**: 잠그고(`create_lockout`), 지금 잠겨있는지 확인하고(`get_active_lockout`), 풀어주고(`release_lockout`), 현재 잠긴 목록을 가져오는(`list_active_lockouts`) 함수. 잠금 시간이 다 지났는데 아직 "잠김"으로 표시된 것들을 찾는 함수(`list_expired_active_lockouts`)도 추가했는데, 이건 원래 계획 문서엔 없었지만 다음 단계(자동 해제 기능)를 만들려면 꼭 필요해서 보충했습니다.
- **관리자 계정**: 관리자 계정이 하나도 없으면 `.env`의 아이디/비밀번호로 자동으로 1명 만들어주고(`ensure_bootstrap_admin`), 로그인할 때 아이디·비밀번호가 맞는지 확인하고(`verify_admin_credentials`), 로그인 시도를 기록하고(`log_admin_attempt`), 그 기록을 불러오는(`list_admin_login_log`) 함수
- **회원가입 계정(이번에 새로 추가한 기능)**: 계정을 만들고(`create_user`, 아이디·이메일 중복이면 실패 처리), 아이디로 계정을 찾고(`get_user_by_username`), 로그인 시 비밀번호가 맞는지 확인하는(`verify_user_credentials`) 함수

**비밀번호를 그대로 저장하지 않는 이유 — "해시(hash)"란?**
비밀번호를 데이터베이스에 그냥 글자 그대로 저장해두면, 만에 하나 데이터베이스가 해킹당했을 때 모든 사용자의 실제 비밀번호가 그대로 유출됩니다. 그래서 비밀번호를 저장할 때 **해시 함수**라는 걸 거칩니다. 이건 원래 글자를 "절대 거꾸로 되돌릴 수 없는 암호 같은 문자열"로 바꿔주는 수학적인 변환입니다(예: `Passw0rd!` → `pbkdf2:sha256:...` 같은 긴 문자열). 로그인할 때는 사용자가 입력한 비밀번호를 같은 방식으로 다시 변환해서, 저장된 해시값과 "문자열이 똑같은지"만 비교합니다 — 원래 비밀번호가 무엇이었는지는 저장된 값만 봐서는 절대 알아낼 수 없습니다. 이 프로젝트에서는 `werkzeug.security`라는, Flask에 기본 포함된 도구의 `generate_password_hash`(저장할 때)와 `check_password_hash`(확인할 때) 함수를 그대로 썼습니다.

**스모크 테스트(smoke test)가 뭔가?**
"불이 나면 연기부터 난다"는 말에서 따온 표현으로, 본격적인 정밀 검사 전에 "일단 켰을 때 연기가 안 나는지, 기본적으로는 작동하는지"를 빠르게 확인하는 테스트입니다. 여기서는 진짜 Supabase 데이터베이스에 가짜 IP(`203.0.113.99`)와 가짜 계정(`smoketest_user`)으로 실제 데이터를 만들어보고, 실패 횟수 세기·잠금·해제·회원가입·중복 가입 거부·비밀번호 확인이 전부 의도대로 동작하는지 확인했습니다. 확인이 끝난 뒤에는 이 가짜 데이터를 전부 지워서, 실제 서비스에 쓸 표들을 다시 빈 상태로 되돌려놨습니다.

### 실제 코드 함께 보기

아래는 [db.py](../../db.py)에 실제로 들어있는 코드입니다. 코드 안의 `#`으로 시작하는 줄은 "주석"이라고 부르는데, 프로그램이 실행할 때는 무시되고 오직 사람이 읽으라고 남겨둔 설명글입니다. 함수별로 어떤 일을 하는지 주석과 함께 보면, 앞서 말로 풀어쓴 설명이 코드의 어느 줄에 대응하는지 알 수 있습니다.

**로그인 시도 기록 (log_attempt, count_recent_failures, list_recent_attempts)**
```python
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
```
`.eq(...)`, `.gte(...)` 처럼 점(`.`)을 찍고 이어붙인 부분들은 "조건을 하나씩 덧붙인다"는 뜻입니다. 한국어로 풀면 "login_attempts 표에서, IP가 이것과 같고, 성공 여부가 거짓이고, 시각이 기준선 이후인 줄만 골라줘"라는 문장을 코드로 옮겨 적은 것입니다.

**IP 잠금 상태 관리 (create_lockout, get_active_lockout, release_lockout)**
```python
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
    return res.data[0] if res.data else None


def release_lockout(ip: str) -> None:
    """이 IP의 잠금을 해제한다 (active 칸을 False로 바꿈).

    줄을 지우는 게 아니라 "해제됨" 표시만 남겨서, 나중에 이력을 되짚어볼 수 있게 한다.
    """
    get_client().table("lockouts").update({"active": False}).eq("ip_address", ip).execute()
```
`upsert`처럼 낯선 영어 단어가 코드에 자주 등장하는데, 대부분 "업데이트(update, 고치기) + 인서트(insert, 새로 넣기)"처럼 두 영어 단어를 합쳐 만든 프로그래밍 업계 용어입니다. 처음엔 낯설어도, 코드 옆에 달린 주석을 같이 보면 뜻을 유추할 수 있습니다.

**회원가입 (create_user, verify_user_credentials)**
```python
def create_user(username: str, email: str, password: str) -> bool:
    """새 사용자 계정을 만든다 (회원가입).

    같은 아이디나 같은 이메일로 이미 가입한 사람이 있으면 실패(False)를 돌려주고
    아무것도 저장하지 않는다. 문제없으면 비밀번호를 암호화해서 저장하고 True를 돌려준다.
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

    저장된 암호문과 "지금 입력한 비밀번호를 암호화한 결과"가 일치하는지만 비교한다.
    """
    user = get_user_by_username(username)
    if user is None:
        return False  # 그런 아이디로 가입한 사람이 없음
    return check_password_hash(user["password_hash"], password)
```
`if ... return False` 처럼 "만약 ~라면, 여기서 함수를 끝내고 False를 돌려줘라"는 문장이 코드 곳곳에 반복되는데, 이게 바로 "중복 아이디면 가입 거부", "가입 안 한 아이디면 로그인 거부" 같은 규칙이 실제 코드로 옮겨진 모습입니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [db.py](../../db.py) (신규 작성 — 13개 함수)
- Supabase 표 데이터는 테스트 후 전부 원상 복구(0건)되어 실제로는 코드 파일만 변경됨
