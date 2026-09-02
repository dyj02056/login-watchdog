# 로그인 워치독 — 비전공자용 진행 해설서

> 이 문서는 `plan.md`의 각 단계를 진행할 때마다, "우리가 방금 무엇을 했고 왜 했는지"를 개발 지식이 없어도 이해할 수 있게 풀어서 기록합니다.
> 단계가 끝날 때마다 새 섹션이 추가됩니다.

---

## 1단계 — 개발 환경 준비

### 우리가 한 일
1. `config.py` 파일 생성 — 프로그램 곳곳에서 쓰일 "숫자 규칙"을 한 곳에 모아둠
2. `.env.example` 파일 정리 — 비밀번호 같은 민감 정보를 어떤 이름으로 저장할지 목록만 적어둠
3. `.gitignore` 파일 확인/수정 — 깃(Git)에 절대 올리면 안 되는 파일 목록 지정
4. `requirements.txt` 작성 — 이 프로그램이 필요로 하는 외부 도구(라이브러리) 목록
5. 가상환경(venv) 생성 + 그 안에 라이브러리 설치

### 왜 했는가 (쉬운 설명)

**`config.py`가 왜 필요한가?**
이 프로그램은 "60초 안에 5번 틀리면 5분 동안 잠근다" 같은 규칙으로 동작합니다. 이 "5번", "60초", "5분" 같은 숫자를 여러 파일에 따로따로 적어두면, 나중에 규칙을 하나 바꿀 때 파일을 여러 개 찾아다니며 고쳐야 하고 하나라도 빠뜨리면 버그가 생깁니다. 그래서 이 숫자들을 `config.py` 한 파일에만 적어두고, 다른 모든 파일은 여기서 값을 "빌려다" 씁니다.

**`.env`와 `.env.example`은 뭐가 다른가?**
- `.env` : 실제 비밀번호, API 키 같은 **진짜 민감한 값**이 들어있는 파일. 절대 외부에 공개되면 안 됨(깃허브에 올리면 안 됨).
- `.env.example` : `.env`에 어떤 **이름의 항목이 필요한지**만 적어둔 견본. 값은 비워둠. 이건 깃에 올려도 안전하고, 새로 합류하는 팀원이 "아, 이런 값들을 채워야 하는구나"를 알 수 있게 해주는 안내문 역할.

비유하자면 `.env.example`은 "빈 신청서 양식"이고, `.env`는 "내가 실제로 작성해서 서랍에 넣어둔 신청서"입니다. 양식은 공유해도 되지만, 내가 적은 개인정보가 담긴 실제 신청서는 남에게 보여주면 안 되죠.

**`.gitignore`는 뭘 하는 파일인가?**
깃(Git)은 코드를 변경할 때마다 기록을 남기는 도구인데, 기본적으로는 폴더 안의 모든 파일을 기록 대상으로 삼습니다. `.gitignore`에 파일/폴더 이름을 적어두면 "이건 기록하지 마"라고 지정하는 것입니다. 여기엔 4가지를 등록했습니다.
- `.env` — 위에서 설명한 비밀 정보 파일
- `__pycache__/`, `*.pyc` — 파이썬이 자동으로 만드는 임시 캐시 파일(사람이 직접 만든 게 아니라 컴퓨터가 실행 속도를 위해 자동 생성하는 부산물)
- `.pytest_cache/` — 테스트 도구가 자동으로 만드는 임시 폴더
- `venv/` — 아래에서 설명할 가상환경 폴더(용량이 크고, 각 컴퓨터마다 새로 만들어야 해서 공유할 필요가 없음)

**가상환경(venv)이 뭔가?**
컴퓨터 한 대에는 여러 프로그램이 설치될 수 있는데, 프로그램마다 필요한 "부품"(라이브러리) 버전이 다를 수 있습니다. 만약 모든 프로그램이 컴퓨터에 딱 하나만 있는 공용 부품함을 같이 쓰면, A 프로그램은 부품 1.0 버전이 필요하고 B 프로그램은 2.0 버전이 필요할 때 충돌이 납니다.

**가상환경**은 이 프로젝트 전용의 "독립된 부품함"을 폴더 하나로 만들어주는 기능입니다(`venv` 폴더). 이 안에 설치한 라이브러리는 오직 이 프로젝트에서만 쓰이고, 다른 프로그램이나 컴퓨터 전체 설정에는 전혀 영향을 주지 않습니다. 그래서 **PC마다, 그리고 팀원마다 각자 자기 컴퓨터에 새로 만들어야** 합니다 — 부품함 자체는 공유하는 게 아니라, "어떤 부품이 필요한지 적은 목록"(`requirements.txt`)만 공유하고 각자 그 목록을 보고 설치하는 방식입니다.

**`requirements.txt`와 `pip install`은 뭘 하는 건가?**
`requirements.txt`는 이 프로그램을 돌리는 데 필요한 외부 도구 이름 목록입니다(예: 웹 서버를 만들어주는 `flask`, 데이터베이스와 통신하는 `supabase` 등). `pip`는 파이썬의 "라이브러리 설치 프로그램"이고, `pip install -r requirements.txt`는 "이 목록에 있는 걸 전부 설치해줘"라는 명령입니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [config.py](../config.py) (신규 작성)
- [.env.example](../.env.example) (내용 갱신)
- [.gitignore](../.gitignore) (`venv/` 추가)
- [requirements.txt](../requirements.txt) (신규 작성)
- `venv/` 폴더 (신규 생성, 깃에는 올라가지 않음)

---

## 2단계 — 데이터베이스(Supabase) 스키마 만들기

### 우리가 한 일
1. [docs/schema.sql](schema.sql) 파일에 "표(테이블) 설계도" 5개를 작성
2. Supabase 웹사이트의 SQL Editor에서 이 설계도를 실행해 실제 표를 만듦
3. `.env`에 `SUPABASE_URL`(주소)과 `SUPABASE_KEY`(비밀 열쇠)를 채워넣음
4. 파이썬 코드로 실제 연결이 되는지, 5개 표가 다 잘 만들어졌는지 확인(검증)

### 왜 했는가 (쉬운 설명)

**데이터베이스(Supabase)가 왜 필요한가?**
이 프로그램은 "누가 언제 로그인에 실패했는지", "어떤 IP가 지금 잠겨있는지" 같은 정보를 기억해야 합니다. 프로그램을 껐다 켜도 이 기록이 사라지면 안 되고, 팀원 4명이 각자 컴퓨터에서 서버를 켜도 같은 기록을 같이 봐야 합니다. 이런 "오래 기억해야 하고, 여러 사람이 같이 봐야 하는 데이터"를 저장하는 곳이 데이터베이스이고, 이 프로젝트는 Supabase라는 서비스(구글 스프레드시트의 훨씬 강력한 사촌 같은 것)를 씁니다.

**표(테이블)가 5개인 이유**
| 표 이름 | 무엇을 기억하는가 | 비유 |
|---|---|---|
| `users` | 일반 사용자가 회원가입한 계정 정보 | 회원 명부 |
| `login_attempts` | `/login` 페이지에서 시도된 모든 로그인 기록(성공/실패 포함) | CCTV 녹화 로그 — 지우지 않고 계속 쌓임 |
| `lockouts` | 지금 잠겨 있는 IP와 언제 풀리는지 | "지금 문 잠긴 방" 현황판 — 최신 상태만 있음(기록이 아니라 현재 상태) |
| `admin_users` | 관리자 계정(대시보드에 로그인하는 사람) | 직원 명부 |
| `admin_login_log` | 관리자가 언제 로그인했는지 성공/실패 기록 | 직원 출입 기록 |

`login_attempts`(녹화 로그)와 `lockouts`(현재 상태판)를 굳이 나눈 이유: "지금 잠겨 있는지 아닌지"를 알려면 녹화 로그 전체를 매번 처음부터 훑어봐야 해서 느리고 번거롭습니다. 그래서 "현재 상태"만 따로 요약해두는 표를 하나 더 만든 것입니다.

**SQL이 뭔가?**
SQL은 데이터베이스에게 "이런 모양의 표를 만들어줘", "이 데이터를 넣어줘/찾아줘" 같은 지시를 내리는 전용 언어입니다. `docs/schema.sql`에 적힌 `create table users (...)` 같은 문장이 "users라는 이름의 표를 만들고, 그 안에 username, email 같은 칸(열)을 만들어라"는 지시입니다.

**API URL / API Key가 뭔가?**
Supabase에 있는 내 데이터베이스에 프로그램이 접속하려면 두 가지가 필요합니다.
- **URL(주소)**: 내 데이터베이스가 인터넷 어디에 있는지 가리키는 주소 (예: `https://xxxx.supabase.co`)
- **Key(열쇠)**: 그 주소에 아무나 못 들어오게 막아둔 문을 열 수 있는 비밀번호 같은 것

Supabase는 열쇠를 2종류로 나눠줍니다.
- `anon public` key : "손님용 카드키" — 정해둔 규칙(RLS) 안에서만 출입 가능. 브라우저(사용자 화면)에 노출돼도 되도록 설계됨.
- `service_role` key : "마스터키" — 모든 문을 다 열 수 있음. **절대 사용자 화면에 노출되면 안 되고**, 오직 우리 서버(눈에 안 보이는 뒷단) 코드에서만 사용.

이 프로젝트는 서버(Flask, 사용자 눈에 안 보이는 뒷단 프로그램)에서만 데이터베이스에 접속하고, 손님 출입 규칙(RLS)을 따로 안 만들었기 때문에 **마스터키(`service_role`)**를 `.env`에 넣었습니다. `.env`는 1단계에서 설명했듯 깃에 올라가지 않으므로 안전합니다.

**"검증"에서 실제로 한 일**
파이썬 코드로 `.env`에 적힌 주소와 열쇠를 가지고 실제로 Supabase에 접속해서, 5개 표 각각에 "지금 몇 줄(행)이 들어있어?"라고 물어봤습니다. 5개 다 "0줄"(아직 아무 기록도 없지만 표 자체는 존재함)이라고 정상 응답이 와서, 표가 잘 만들어졌고 우리 프로그램이 거기 잘 접속할 수 있다는 게 확인된 것입니다.

**중간에 발생했던 문제**
처음에 `SUPABASE_URL`에 `/rest/v1/`이라는 부분까지 같이 적혀 있어서 접속이 실패했습니다. 이 부분은 프로그램이 자동으로 덧붙이는 부분이라, `.env`에는 순수 주소(`https://xxxx.supabase.co`)만 적어야 합니다. 이걸 지우고 나니 정상 접속됐습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](schema.sql) (신규 작성, Supabase에 실제 실행됨)
- `.env` (`SUPABASE_URL`, `SUPABASE_KEY` 값 채움 — 이 파일은 깃에 없음)
- Supabase 프로젝트 안에 실제 표 5개 생성됨(코드 파일이 아니라 외부 서비스 안의 변화)

---

## 3단계 — `db.py` (데이터베이스와 대화하는 창구 만들기)

### 우리가 한 일
1. [db.py](../db.py) 파일에 "Supabase와 주고받는 모든 대화"를 함수 단위로 정리
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

아래는 [db.py](../db.py)에 실제로 들어있는 코드입니다. 코드 안의 `#`으로 시작하는 줄은 "주석"이라고 부르는데, 프로그램이 실행할 때는 무시되고 오직 사람이 읽으라고 남겨둔 설명글입니다. 함수별로 어떤 일을 하는지 주석과 함께 보면, 앞서 말로 풀어쓴 설명이 코드의 어느 줄에 대응하는지 알 수 있습니다.

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
- [db.py](../db.py) (신규 작성 — 13개 함수)
- Supabase 표 데이터는 테스트 후 전부 원상 복구(0건)되어 실제로는 코드 파일만 변경됨

---

## 4단계 — `detector.py` / `soar.py` / `alert.py` (판정 → 조치 → 알림)

### 우리가 한 일
1. [detector.py](../detector.py) — "지금 이 IP가 수상한가? 지금 잠겨있는가?"만 **판단**하는 파일
2. [soar.py](../soar.py) — 판단 결과를 받아서 실제로 **잠그고, 알림을 보내고, 풀어주는 실행** 파일
3. [alert.py](../alert.py) — Slack으로 **메시지를 실제로 전송**하는 파일
4. 세 파일을 실제 데이터로 이어붙여서(수상 판정 → 잠금 → 알림 → 수동 해제) 전체 흐름이 맞물려 돌아가는지 확인

### 왜 했는가 (쉬운 설명)

**왜 "판단"과 "실행"과 "알림"을 세 파일로 쪼갰나?**
한 파일에 다 몰아넣으면 "수상한지 확인하는 코드"와 "Slack에 보내는 코드"가 뒤엉켜서, 나중에 "Slack 대신 이메일로 알림을 바꾸고 싶다"처럼 하나만 바꾸고 싶어도 전체 파일을 다시 읽어야 합니다. 세 역할로 나눠두면 각자 독립적으로 이해하고 고칠 수 있습니다.
- `detector.py` = **판사**: "이 IP, 유죄인가 무죄인가?"만 판단. 판결 후에 어떻게 처벌할지는 관여 안 함.
- `soar.py` = **집행관**: 판사의 판결을 받아서 실제로 "문을 잠그고, 관련 부서에 통보하라"를 지시.
- `alert.py` = **전화 교환원**: "통보하라"는 지시를 받으면 실제로 Slack에 전화를 걸어 메시지를 전달. 전화를 어떻게 거는지(웹훅 URL, 네트워크 요청)는 이 파일만 알면 됨.

(참고로 SOAR라는 이름은 보안 분야 용어 "Security Orchestration, Automation and Response"의 줄임말로, "이상 징후 판단 후 자동으로 대응 조치를 실행한다"는 개념을 가리킵니다.)

**`detector.py` 함수 설명**
- `is_suspicious(ip)`: `db.py`에서 만든 "최근 실패 횟수 세기" 함수를 불러서, 그 횟수가 기준(5회)을 넘었는지 True/False로 알려줍니다. 몇 번 실패했는지 숫자도 같이 돌려줍니다.
- `is_locked(ip)`: 이 IP가 지금 잠긴 상태인지 True/False로 알려줍니다.

이 두 함수는 **묻기만 하고 아무것도 바꾸지 않습니다.** 데이터베이스에 아무 것도 쓰지 않고, 그냥 "지금 상태가 어떤지"만 조회해서 답합니다.

**`soar.py` 함수 설명**
- `enforce_lockout(ip, failure_count)`: 실제로 잠금을 겁니다(`db.create_lockout`) → 곧바로 Slack 알림을 보냅니다(`alert.send_lockout_alert`). "판단"이 아니라 "실행"이라서 호출되는 순간 실제로 데이터베이스와 Slack에 변화가 생깁니다.
- `try_release_expired_lockouts()`: "잠근 지 5분이 지났는데 아직 잠김 상태로 남아있는" IP들을 찾아서 전부 풀어줍니다. 이 함수는 별도의 자동 타이머 없이, `/login` 요청이나 대시보드 새로고침이 들어올 때마다 "혹시 풀어줄 게 있나?" 하고 확인하는 방식으로 동작합니다(4-4절 "다음 요청 시 지연 정리" 방식).
- `manual_release(ip)`: 관리자가 대시보드에서 "즉시 해제" 버튼을 눌렀을 때 호출됩니다. 실제로 잠긴 상태였다면 풀어주고 `True`, 애초에 잠긴 게 없었다면 아무 일도 안 하고 `False`를 돌려줍니다. **"이 사람이 관리자가 맞는지" 확인하는 건 이 함수의 역할이 아닙니다** — 그건 5단계에서 만들 `app.py`가 담당합니다(권한 확인과 실행 로직을 분리).

**`alert.py` 함수 설명**
- `send_lockout_alert(ip, failure_count, locked_at)`: "시각 / 시도 IP / 실패 횟수 / 조치 결과"를 한 문장으로 조립해서 Slack 웹훅 주소로 전송합니다.
- **Slack 웹훅(Incoming Webhook)이 뭔가?** Slack이 채널마다 발급해주는 "이 주소로 메시지를 던지면 그 채널에 자동으로 글이 올라온다"는 전용 URL입니다. 복잡한 로그인 절차 없이, 그 주소에 `{"text": "메시지 내용"}`이라는 짧은 데이터만 던지면 끝나서 구현이 매우 간단합니다.
- `.env`의 `SLACK_WEBHOOK_URL`이 아직 비어있는 상태(팀이 어느 워크스페이스를 쓸지 아직 안 정함, plan.md 1절 결정 #4 보류)이므로, 지금은 실제 전송 대신 **터미널 화면에 메시지를 그대로 출력**하도록 만들어뒀습니다. 나중에 워크스페이스가 정해져서 `.env`에 URL만 채워 넣으면, 코드를 전혀 안 고쳐도 자동으로 진짜 Slack 전송으로 바뀝니다.
- 만약 Slack 전송이 네트워크 문제 등으로 실패하더라도, 이 실패 때문에 로그인 기능 자체가 멈추면 안 되므로 오류를 붙잡아서(예외 처리) 콘솔에 로그만 남기고 넘어가도록 만들었습니다 — "알림 보내기 실패"가 "사용자 로그인 불가"로 번지지 않게 하는 안전장치입니다.

**실제로 테스트한 흐름**
가짜 IP로 실패 기록을 6번 쌓고(임계값 5 초과) → `is_suspicious`가 `True, 6`을 정확히 돌려주는지 → `enforce_lockout` 호출 후 `is_locked`가 `True`로 바뀌는지 → `manual_release`로 풀었을 때 `is_locked`가 다시 `False`로 바뀌고, 이미 풀린 IP를 또 풀려고 하면 `False`(할 일 없음)를 정확히 돌려주는지까지 전부 확인했습니다. 테스트에 쓴 가짜 데이터는 확인 후 바로 삭제했습니다.

### 실제 코드 함께 보기

**[detector.py](../detector.py) 전체 — "판사"는 코드도 짧습니다 (딱 2개 함수, 아무것도 저장하지 않음)**
```python
import db
from config import FAILURE_THRESHOLD


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


def is_locked(ip: str) -> bool:
    """이 IP가 지금 이 순간 잠긴 상태인지 True/False로 알려준다."""
    return db.get_active_lockout(ip) is not None
```
`failure_count > FAILURE_THRESHOLD`는 "실패 횟수가 기준치보다 크다"는 부등호 비교를 그대로 코드로 옮긴 것입니다. 이 한 줄이 "5번까지는 봐주고, 6번째부터 수상하다고 판단한다"는 규칙 전체를 담당합니다 — `config.py`에서 `FAILURE_THRESHOLD` 값만 바꾸면 이 규칙도 자동으로 같이 바뀝니다(1단계에서 설명한 "숫자를 한 곳에 모아두는" 설계가 여기서 실제로 힘을 발휘하는 지점입니다).

**[soar.py](../soar.py) 전체 — 판정 결과를 실제 조치로 옮기는 3개 함수**
```python
from datetime import datetime, timezone

import alert
import db


def enforce_lockout(ip: str, failure_count: int) -> None:
    """이 IP에 실제로 잠금을 걸고, 그 사실을 Slack으로 알린다.

    1. db.create_lockout()으로 "이 IP는 지금부터 5분간 잠김"을 데이터베이스에 저장
    2. alert.send_lockout_alert()로 "IP, 실패 횟수, 조치 내용"을 담은 알림을 전송
    """
    db.create_lockout(ip, failure_count)
    alert.send_lockout_alert(ip, failure_count, datetime.now(timezone.utc))


def try_release_expired_lockouts() -> None:
    """"5분이 지났는데 아직 안 풀린" 잠금들을 찾아서 전부 풀어준다.

    별도의 자동 타이머 프로그램 없이, `/login` 요청이나 대시보드 새로고침이
    들어올 때마다 "혹시 지금 풀어줘야 할 게 있나?"를 확인하는 방식으로 동작한다.
    """
    for lockout in db.list_expired_active_lockouts():
        db.release_lockout(lockout["ip_address"])


def manual_release(ip: str) -> bool:
    """관리자가 대시보드의 "즉시 해제" 버튼을 눌렀을 때 호출되는 함수.

    1. 지금 잠겨있는 IP 목록 안에 이 ip가 있는지 확인한다.
    2. 있다면 실제로 풀어주고 True(성공)를 돌려준다.
    3. 애초에 잠긴 적이 없다면 아무것도 하지 않고 False(할 일 없음)를 돌려준다.
    """
    active_ips = {row["ip_address"] for row in db.list_active_lockouts()}
    if ip not in active_ips:
        return False
    db.release_lockout(ip)
    return True
```
`for lockout in db.list_expired_active_lockouts():` 부분은 "만료된 잠금 목록을 하나씩 꺼내면서, 그때마다 아래 줄(`db.release_lockout(...)`)을 반복 실행해라"는 뜻의 "반복문"입니다. 목록에 3개가 들어있으면 3번, 0개면 0번(즉 아무 일도 안 함) 실행됩니다.

**[alert.py](../alert.py) 전체 — Slack에 실제로 메시지를 보내는 함수 1개**
```python
def send_lockout_alert(ip: str, failure_count: int, locked_at: datetime) -> None:
    minutes = config.LOCKOUT_DURATION_SECONDS // 60

    message = (
        ":rotating_light: 로그인 워치독 알림\n"
        f"시각: {locked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"시도 IP: {ip}\n"
        f"실패 횟수: {failure_count}회\n"
        f"조치: {minutes}분간 IP 잠금 처리"
    )

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if not webhook_url:
        # 웹훅 주소가 비어있다 = 아직 Slack 채널이 정해지지 않음 → 콘솔 출력으로 대체
        print(f"[alert] SLACK_WEBHOOK_URL 미설정 - 콘솔 로그로 대체 전송:\n{message}")
        return

    try:
        # 실제로 Slack 서버에 "이 메시지를 채널에 올려줘"라고 요청을 보낸다.
        response = requests.post(webhook_url, json={"text": message}, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        # 네트워크가 끊겼거나 Slack 쪽에서 오류가 났을 때: 프로그램을 중단시키지 않고
        # 문제가 있었다는 사실만 콘솔에 남긴다.
        print(f"[alert] Slack 알림 전송 실패: {e}")
```
`try:` ~ `except requests.RequestException as e:` 부분이 "일단 시도해보고(try), 만약 도중에 문제(네트워크 오류 등)가 생기면(except) 프로그램이 멈추지 않고 이 블록 안의 코드로 넘어가라"는 안전장치입니다. 한국어로 풀면 "Slack에 메시지 보내기를 시도하되, 혹시 실패하면 에러로 프로그램을 죽이지 말고 그냥 콘솔에 '실패했다'고만 적고 넘어가라"는 뜻입니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [detector.py](../detector.py) (신규 작성 — 판정 함수 2개)
- [soar.py](../soar.py) (신규 작성 — 조치 함수 3개)
- [alert.py](../alert.py) (신규 작성 — Slack 알림 함수 1개)
- Supabase 표 데이터는 테스트 후 전부 원상 복구(0건)

---

## 5단계 — `app.py` (모든 부품을 실제 웹사이트로 엮는 "정문")

### 우리가 한 일
1. [app.py](../app.py)에 지금까지 만든 부품(db, detector, soar, alert)을 실제 화면 주소(URL)와 연결
2. `.env`에 남아있던 값들(`SECRET_KEY`, 관리자 아이디/비밀번호)을 채워넣음
3. 서버를 실제로 켜서, 회원가입 → 로그인 → 브루트포스 잠금 → 관리자 대시보드 → 수동 해제 → 로그아웃까지 전체 흐름을 브라우저로 직접 눌러보며 검증

### 왜 했는가 (쉬운 설명)

**Flask의 핵심 개념 4가지**
- **라우트(route)**: "이 주소(URL)로 요청이 오면 이 함수를 실행해라"는 연결 규칙. `@app.route("/login")`처럼 함수 위에 붙인다.
- **세션(session)**: 서버가 "이 브라우저는 로그인된 상태다"를 기억하는 저장 공간. 로그인에 성공하면 `session["admin_username"] = "soung1009"`처럼 값을 넣어두고, 이후 같은 브라우저의 요청마다 Flask가 자동으로 이 값을 되살려준다. 로그아웃(`session.clear()`)하면 지워진다.
- **플래시(flash) 메시지**: "잠긴 계정입니다" 같은 안내 문구를 딱 한 번만 화면에 보여주고 사라지게 만드는 기능. `flash("메시지")`로 남겨두면, 다음 화면을 그릴 때 템플릿이 `get_flashed_messages()`로 그 메시지를 꺼내 보여준다.
- **데코레이터(decorator)**: 함수 앞에 `@문지기이름`을 붙여서, 그 함수가 실행되기 전에 미리 검문을 시키는 문법. 이 프로젝트에서는 `@login_required`가 "이 화면은 로그인된 관리자만 볼 수 있다"는 검문소 역할을 한다.

**왜 `.env`에 값을 더 채워야 했나? (이번 단계에서 새로 채운 값들)**

이번 단계에서 `.env` 파일에 `SLACK_WEBHOOK_URL`, `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `TRUST_FORWARDED_FOR` 5개 줄을 한꺼번에 추가했습니다. 이 중 `SLACK_WEBHOOK_URL`은 여전히 빈 값(4단계에서 설명했듯 Slack 채널이 아직 안 정해져서 콘솔 대체 중), `TRUST_FORWARDED_FOR`도 `false`(운영 안전을 위한 기본값, `app.py`의 `get_request_ip()` 설명 참고)로 그대로 두었으므로, 실제로 "새로 결정해서 채운" 값은 아래 두 종류입니다.

- **`SECRET_KEY`란 무엇이고 왜 필요한가?**
  Flask는 "이 브라우저는 로그인된 상태다"라는 정보를 사용자의 브라우저에 쿠키(작은 데이터 조각) 형태로 저장해둡니다. 그런데 쿠키는 사용자의 컴퓨터에 저장되는 데이터라서, 나쁜 마음을 먹은 사람이 쿠키 내용을 마음대로 조작해서 "나는 이미 로그인된 관리자다"라고 서버를 속일 위험이 있습니다.

  이걸 막기 위해 Flask는 쿠키를 저장할 때 `SECRET_KEY`라는 비밀 값으로 **서명(signature)**을 같이 붙여둡니다. 서명이란 편지 봉투에 찍는 봉랍 도장과 비슷합니다 — 도장(SECRET_KEY)을 모르는 사람은 편지 내용을 위조해도 진짜처럼 보이는 도장을 다시 찍을 수 없습니다. 서버는 쿠키가 돌아올 때마다 "이 서명이 내가 아는 SECRET_KEY로 찍은 게 맞는지" 확인하고, 조금이라도 다르면 그 세션을 무효로 처리합니다. 그래서 `SECRET_KEY`가 없으면 애초에 로그인 상태를 안전하게 기억하는 기능 자체가 성립하지 않습니다.

  이 값은 사람이 외우거나 의미를 부여할 필요가 전혀 없는, "그냥 아무도 못 맞히면 되는" 무작위 문자열이라 `secrets.token_hex(32)`(파이썬 표준 라이브러리의 "안전한 난수를 만들어주는 도구")로 64자리 임의의 16진수 문자열을 생성해서 채워넣었습니다. `SUPABASE_KEY`가 "데이터베이스 문을 여는 열쇠"라면, `SECRET_KEY`는 "우리 서버가 발급한 쿠키가 진짜인지 확인하는 도장"이라는 점에서 용도가 다릅니다 — 둘 다 `.env`에만 있어야 하고 절대 깃에 올라가면 안 된다는 점은 동일합니다.

- **`ADMIN_USERNAME` / `ADMIN_PASSWORD`는 어떻게 쓰이는가?**
  이 두 값은 3단계에서 만든 `db.ensure_bootstrap_admin()` 함수가 사용합니다. 서버가 켜질 때(`app.py` 맨 위에서 이 함수를 호출) "관리자 계정이 하나도 없으면, `.env`의 이 아이디/비밀번호로 1명을 자동으로 만들어라"는 규칙이 실행됩니다. 실제로 서버를 처음 켜자 `admin_users` 표에 `soung1009` 계정이 생긴 것을 5단계 검증 과정에서 직접 확인했습니다.

  아이디·비밀번호는 사용자님이 직접 정한 `soung1009` / `tjddnjs0`을 그대로 반영했습니다. 관리자 계정처럼 "누가 로그인할 수 있는가"를 정하는 값은 프로그램이 임의로 정하기보다 사용자가 직접 고르는 게 맞다고 판단해 확인 후 반영했습니다.

  **여기서 한 가지 헷갈리기 쉬운 부분**: `.env`에는 `ADMIN_PASSWORD=tjddnjs0`처럼 비밀번호가 암호화되지 않은 "평문" 그대로 적혀 있습니다. 그런데 3단계에서는 분명 "비밀번호를 암호화(해시)해서 저장한다"고 설명했는데, 왜 여기는 평문일까요?
  - `.env`에 적힌 값은 "앱이 맨 처음 켜질 때 딱 한 번, 계정을 새로 만들기 위해 참고하는 원본 재료"입니다. `ensure_bootstrap_admin()` 함수 안에서 이 평문을 읽자마자 곧바로 `generate_password_hash(password)`를 거쳐 암호화한 뒤, 그 **암호화된 결과만** `admin_users` 표에 저장합니다(3단계 코드 참고).
  - 즉 실제로 데이터베이스에 영구히 남는 값은 언제나 암호화된 해시뿐이고, 평문 비밀번호는 `.env` 파일 안에만(그리고 이 파일은 절대 깃에 올라가지 않으므로) 잠깐 존재할 뿐입니다. 로그인할 때 실제로 비교되는 것도 "입력한 비밀번호를 암호화한 값"과 "표에 저장된 암호화된 값"이지, `.env`의 평문과는 무관합니다.

**"경로 분리로 IP 잠금 예외를 해결한다"는 게 실제로 뭘 의미하나?**
`/login`(감시 대상)과 `/admin/login`(관리자)은 코드에서 완전히 다른 함수, 다른 주소다. `detector.is_locked()` 호출은 `login_submit()` 함수 안에만 있고, `admin_login_submit()` 함수 안에는 아예 존재하지 않는다. 그래서 관리자가 같은 컴퓨터(같은 IP)를 쓰더라도, 감시 대상 로그인이 아무리 잠겨도 관리자 로그인 화면은 전혀 영향을 받지 않는다 — "허용 목록"이라는 별도 장치를 만들 필요 없이, 애초에 그 로직을 쳐다보지도 않는 코드 경로로 설계한 것이다.

### 실제 코드 함께 보기

**IP 판별 — `get_request_ip()`**
```python
def get_request_ip() -> str:
    """이번 요청을 보낸 사람의 IP 주소를 알아낸다.

    보통은 request.remote_addr(브라우저가 서버에 직접 연결한 진짜 주소)를 쓴다.
    다만 config.TRUST_FORWARDED_FOR가 켜져 있을 때만(데모/시연 전용 설정) 예외적으로
    X-Forwarded-For 헤더 값을 대신 신뢰한다.
    """
    if config.TRUST_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr
```
실제 테스트에서는 이 값이 계속 `127.0.0.1`(내 컴퓨터 자신을 가리키는 특수 주소)로 찍혔습니다 — 브라우저와 서버가 같은 컴퓨터에서 돌고 있기 때문에 당연한 결과입니다.

**문지기 — `login_required` 데코레이터**
```python
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "admin_username" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "로그인이 필요합니다."}), 401
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)
    return wrapped_view
```
`@login_required`를 붙인 함수(`dashboard`, `api_status`, `api_unlock`, `admin_logout`)는 실행되기 전에 항상 이 코드를 먼저 통과해야 합니다. 실제로 로그아웃 상태에서 각 주소에 요청을 보내봤더니:
- `/dashboard` → 302(리다이렉트) 응답과 함께 `/admin/login`으로 이동
- `/api/status`, `/api/unlock` → 401 상태 코드와 `{"error": "로그인이 필요합니다."}` JSON

정확히 코드에 적힌 그대로 동작하는 걸 실제 요청으로 확인했습니다.

**핵심 흐름 — `login_submit()`**
```python
def login_submit():
    soar.try_release_expired_lockouts()
    ip = get_request_ip()

    if detector.is_locked(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    success = db.verify_user_credentials(username, password)
    db.log_attempt(ip, username, success)

    if success:
        flash("로그인 성공")
        return render_template("login.html")

    suspicious, failure_count = detector.is_suspicious(ip)
    if suspicious:
        soar.enforce_lockout(ip, failure_count)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
    else:
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login.html")
```
지금까지 만든 4개 부품 파일(db, detector, soar)이 전부 이 함수 안에서 순서대로 호출되는 걸 볼 수 있습니다. 이 함수 하나가 사실상 이 프로젝트 전체의 핵심입니다.

### 실제로 테스트한 흐름과 배운 점

브라우저와 서버를 실제로 띄워서 아래 흐름을 전부 눈으로 확인했습니다.

1. **회원가입** → `/signup`에서 `demo_user` 계정 생성 → 자동으로 `/login`으로 이동하며 "회원가입이 완료되었습니다" 메시지 표시
2. **정상 로그인** → "로그인 성공" 메시지 확인
3. **브루트포스 탐지** → 짧은 시간 안에 6번 연속으로 틀린 비밀번호를 보내자 "잠긴 계정입니다" 응답 + 콘솔에 Slack 알림 메시지(IP, 실패 횟수, 조치 내용) 출력
4. **관리자 대시보드** → 로그인 안 한 상태로 `/dashboard` 접속 시 자동으로 관리자 로그인 화면으로 이동 확인 → `soung1009` 계정으로 로그인 → 잠긴 IP 카드, 최근 로그인 시도 표, 관리자 로그인 기록 표가 모두 실제 데이터로 채워지는 것 확인
5. **즉시 해제** → 대시보드 카드의 버튼을 눌러 잠금 해제 → 카드가 즉시 사라짐
6. **로그아웃 후 접근 차단** → `/dashboard`, `/api/status`, `/api/unlock`에 다시 접근 시 전부 차단되는 것 확인

**테스트 중 발견한 흥미로운 점 (버그 아님, 설계가 의도대로 작동한 증거)**
브라우저를 마우스로 직접 클릭하며 느리게(한 번에 15~40초씩 걸리며) 6번 틀렸을 때는 잠기지 않았습니다. 왜냐하면 `count_recent_failures`는 "최근 60초 안의 실패"만 세는데, 클릭 속도가 느려서 처음 틀린 기록들이 60초가 지나 "최근"에서 밀려났기 때문입니다. 파이썬 스크립트로 빠르게 연속 요청을 보내자(1초 간격) 정확히 6번째에 잠겼습니다. 이건 버그가 아니라 "60초 이내에 5회 초과"라는 원래 설계가 정확히 의도대로 동작한 증거였습니다.

**테스트 중 고친 것 — `alert.py`에 `flush=True` 추가**
콘솔 알림 메시지가 로그에 바로 안 보이는 문제가 있었는데, 이는 파이썬이 화면 출력을 잠깐 모아뒀다가 한꺼번에 내보내는 "버퍼링" 때문이었습니다. `print(..., flush=True)`로 바꿔서 메시지가 지연 없이 즉시 출력되도록 고쳤습니다(4단계에서 만든 파일을 5단계 테스트 중 개선한 사례).

### 이 단계에서 만들어지거나 바뀐 파일
- [app.py](../app.py) (신규 작성 — 라우트 11개 + 문지기 함수 1개)
- [alert.py](../alert.py) (콘솔 출력에 `flush=True` 추가)
- `.env` (`SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` 값 채움)
- `.claude/launch.json` (신규 — 브라우저 미리보기로 서버를 켜기 위한 설정)
- Supabase에 실제 관리자 계정(`soung1009`) 1명 생성됨, 테스트용 데이터는 확인 후 정리

---

## 6단계 — 화면(템플릿/스타일/스크립트) 만들기

### 우리가 한 일
1. [templates/login.html](../templates/login.html), [signup.html](../templates/signup.html), [admin_login.html](../templates/admin_login.html), [dashboard.html](../templates/dashboard.html) — 4개 화면의 HTML
2. [static/css/auth.css](../public/css/auth.css), [static/css/dashboard.css](../public/css/dashboard.css) — 화면 스타일
3. [static/js/dashboard.js](../public/js/dashboard.js) — 대시보드를 실시간으로 갱신시키는 자바스크립트

### 왜 했는가 (쉬운 설명)

**HTML 파일 안에 파이썬이 섞여 있다? — Jinja2 템플릿**
`templates/` 폴더의 `.html` 파일들은 순수한 HTML이 아니라 "Jinja2"라는 템플릿 문법이 섞여 있습니다.
- 이중 중괄호로 감싼 부분(예: URL을 만들어주는 부분)은 **파이썬 값을 그 자리에 끼워넣으라**는 뜻입니다.
- 중괄호+퍼센트로 감싼 부분(예: `with`, `if`, `for`)은 **조건문·반복문 같은 로직**을 쓸 때 씁니다.

`app.py`가 `render_template("login.html")`을 호출하는 순간, Flask가 이 특수 문법을 전부 실제 값으로 바꿔서 "완성된 순수 HTML"을 만들어 브라우저로 보냅니다. 그래서 브라우저는 이 특수 문법을 전혀 모릅니다.

**`url_for()`를 계속 쓰는 이유**
`href="/login"`처럼 주소를 직접 문자열로 적어도 화면은 똑같이 동작합니다. 하지만 `url_for('login')`처럼 "이 이름을 가진 라우트 함수의 주소를 찾아줘"라고 쓰면, 나중에 `app.py`에서 그 주소를 `/login`에서 `/signin`으로 바꾸더라도 템플릿 파일들은 전혀 고칠 필요가 없습니다 — 항상 최신 주소를 자동으로 찾아주기 때문입니다.

**static 폴더가 뭔가?**
`templates/`가 "매번 데이터에 따라 내용이 바뀌는 화면"을 담아두는 곳이라면, `static/`은 CSS·자바스크립트·이미지처럼 "누가 접속하든 내용이 똑같은 파일"을 담아두는 곳입니다. `url_for('static', filename='css/auth.css')`는 이 폴더 안의 파일 경로를 찾아주는 역할을 합니다.

**대시보드는 왜 HTML에 데이터가 하나도 없나? — "동적으로 화면을 그린다"는 것**
`dashboard.html`을 열어보면 표(`<table>`) 안에 실제 로그 데이터가 전혀 적혀있지 않고 빈 틀만 있습니다. 대신 `dashboard.js`가 화면이 열리자마자 서버의 `/api/status`에 "최신 데이터 줘"라고 물어본 뒤, 그 답을 가지고 자바스크립트 코드로 `<tr>`(표의 한 줄) 태그들을 직접 만들어 끼워넣습니다. 이렇게 하면 화면을 다시 불러오지(새로고침하지) 않고도 2.5초마다 표 내용만 최신 상태로 계속 바꿀 수 있습니다.

### 실제 코드 함께 보기

**dashboard.js — 2.5초마다 최신 상태를 가져오는 부분**
```javascript
async function fetchStatus() {
    const response = await fetch("/api/status");

    if (response.status === 401) {
        // 세션이 만료되었거나 로그아웃된 상태 → 로그인 화면으로 돌려보낸다
        window.location.href = "/admin/login";
        return;
    }

    const data = await response.json();
    renderLockoutCards(data.active_lockouts);
    renderAttemptsTable(data.recent_attempts);
    renderAdminLoginLog(data.admin_login_log);
}

fetchStatus();                    // 화면이 열리자마자 한 번 즉시 실행
setInterval(fetchStatus, 2500);   // 이후 2.5초마다 계속 반복 실행
```
`async`와 `await`는 "서버에 물어보고 답이 올 때까지 기다렸다가 다음 줄로 넘어가라"는 뜻입니다. `setInterval(함수, 2500)`은 "이 함수를 2500밀리초(2.5초)마다 계속 반복 실행해라"는 자바스크립트의 표준 기능입니다.

**dashboard.js — "즉시 해제" 버튼 클릭을 처리하는 부분**
```javascript
async function unlockIp(ip) {
    await fetch("/api/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip }),
    });
    fetchStatus();
}

// 버튼은 fetchStatus()가 실행될 때마다 새로 만들어지므로, 항상 존재하는
// 부모 요소(lockout-list)에 클릭 이벤트를 걸어두고 "클릭된 게 해제 버튼이
// 맞는지" 그때그때 확인한다 (이벤트 위임).
document.getElementById("lockout-list").addEventListener("click", (event) => {
    if (event.target.classList.contains("unlock-btn")) {
        const ip = event.target.getAttribute("data-ip");
        unlockIp(ip);
    }
});
```
실제로 대시보드에서 "즉시 해제" 버튼을 눌러봤을 때, 클릭하자마자 `/api/unlock`에 요청이 가고, 곧바로 `fetchStatus()`가 다시 호출되어 카드가 화면에서 바로 사라지는 것을 확인했습니다(2.5초를 기다리지 않고도 즉시 반영되도록 일부러 이렇게 만든 부분입니다).

**login.html — 서버가 보내는 안내 메시지를 화면에 뿌리는 부분**
```html
{% with messages = get_flashed_messages() %}
    {% if messages %}
        <ul class="flash-list">
            {% for message in messages %}
                <li>{{ message }}</li>
            {% endfor %}
        </ul>
    {% endif %}
{% endwith %}
```
`app.py`의 `flash("잠긴 계정입니다...")`처럼 서버가 남겨둔 메시지를, 이 부분이 화면에 노란 박스로 꺼내 보여줍니다. 실제로 브루트포스 테스트 중 "잠긴 계정입니다" 문구가 정확히 이 코드를 통해 화면에 나타나는 것을 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [templates/login.html](../templates/login.html), [templates/signup.html](../templates/signup.html), [templates/admin_login.html](../templates/admin_login.html), [templates/dashboard.html](../templates/dashboard.html) (신규 작성)
- [static/css/auth.css](../public/css/auth.css), [static/css/dashboard.css](../public/css/dashboard.css) (신규 작성)
- [static/js/dashboard.js](../public/js/dashboard.js) (신규 작성)
- 브라우저로 전체 화면 흐름(회원가입~로그아웃)을 직접 클릭하며 검증 완료

---

## 7단계 — Slack 실제 연동 (콘솔 대체를 진짜 알림으로 전환)

### 우리가 한 일
1. Slack 워크스페이스에서 Incoming Webhook(웹훅) 주소를 직접 발급받아 `.env`의 `SLACK_WEBHOOK_URL`에 채워넣음
2. 서버를 재시작해서 새 값을 반영
3. 실제로 잠금을 3번 발생시켜, Slack 채널에 진짜 알림 메시지가 도착하는지 확인
4. 테스트 도중 발견한 사소한 문제 2가지(포트 충돌, 테스트 스크립트의 오탐)를 확인하고 정리

### 왜 했는가 (쉬운 설명)

**왜 `alert.py` 코드를 하나도 안 고쳤는데 동작이 바뀌었나?**
4단계에서 `alert.py`를 만들 때 이미 "웹훅 주소가 있으면 진짜 전송, 없으면 콘솔 출력"이라는 분기를 만들어뒀습니다(`if not webhook_url: ... return` 부분). 그래서 `.env`의 `SLACK_WEBHOOK_URL` 값 하나만 채워 넣으면, 코드는 그대로인데 동작만 자동으로 "콘솔 출력 모드"에서 "진짜 Slack 전송 모드"로 바뀌는 것입니다. 미리 두 가지 경우를 다 대비해서 코드를 짜두면, 나중에 조건(여기서는 "웹훅 주소가 정해졌는가")이 바뀌었을 때 코드를 다시 고칠 필요가 없다는 걸 실제로 보여주는 사례입니다.

**Incoming Webhook 주소가 왜 "비밀번호처럼" 취급되어야 하나?**
이 주소를 아는 사람은 누구나 그 주소로 데이터를 던지기만 하면 해당 Slack 채널에 원하는 메시지를 마음대로 올릴 수 있습니다. 로그인 절차 같은 별도 인증이 없기 때문입니다. 그래서 이 주소가 유출되면 낯선 사람이 우리 팀 채널에 스팸이나 가짜 알림을 올릴 수 있게 됩니다. `.env`에만 넣고 `.gitignore`로 보호하는 이유가 바로 이것입니다(1단계에서 설명한 것과 같은 원칙).

**왜 서버를 "재시작"까지 해야 했나?**
`app.py`는 서버가 켜지는 바로 그 순간에 `load_dotenv()`로 `.env` 파일을 딱 한 번 읽어서, 그 값들을 파이썬의 "환경변수"라는 메모리 공간에 복사해둡니다. 이후 서버가 계속 켜져 있는 동안 `.env` 파일 내용을 사람이 손으로 바꿔도, 이미 실행 중인 프로그램은 그 변경을 스스로 알아채지 못합니다(마치 이미 인쇄된 신문은 나중에 원본 기사를 고쳐도 저절로 다시 인쇄되지 않는 것과 비슷합니다). 그래서 새 `SLACK_WEBHOOK_URL`을 실제로 쓰게 하려면 서버를 껐다 다시 켜서 `.env`를 처음부터 다시 읽게 만들어야 했습니다.

**테스트 중 겪은 사소한 문제 2가지**
- **포트 충돌**: 서버가 쓰려는 5000번 "포트"(프로그램이 인터넷 연결을 주고받는 통로 번호)를 이미 다른 프로그램이 쓰고 있어서 재시작이 실패했습니다. 어느 프로그램인지 정확히 알 수 없는 상태에서 함부로 그 프로그램을 강제 종료하기보다, 우리 서버가 다른 빈 포트를 자동으로 찾아 쓰도록 `app.py`를 고쳤습니다(아래 코드 참고). 남의 프로그램을 건드리지 않고 우리 쪽만 유연하게 만드는 게 더 안전한 해결책이기 때문입니다.
- **테스트 스크립트의 착각**: 잠금이 몇 번째 시도부터 걸리는지 확인하려고 "응답 안에 '잠긴'이라는 글자가 있는가"로 판정하는 검사 스크립트를 짰는데, 계속 "1번째부터 이미 잠김"으로 나왔습니다. 원인을 찾아보니 `login.html`의 설명 주석 안에 제가 적어둔 예시 문장(`flash("잠긴 계정입니다...")`)에도 우연히 "잠긴"이라는 글자가 들어있어서, 진짜 잠금 여부와 상관없이 항상 검사에 걸린 것이었습니다. 실제 화면의 "안내 메시지 영역"만 정확히 짚어서 다시 확인하니, 1~5번째는 정상적으로 "아이디 또는 비밀번호가 올바르지 않습니다", 6번째만 "잠긴 계정입니다"로 정확히 동작했습니다 — **앱 코드는 처음부터 문제없었고, 제 검사 방법이 허술했던 것**입니다. (검사 도구를 만들 때도 "진짜로 확인하고 싶은 것"을 정확히 짚어야 한다는, 개발에서 자주 겪는 교훈입니다.)

### 실제 코드 함께 보기

**`app.py` — 포트 충돌에 대비한 부분**
```python
if __name__ == "__main__":
    # PORT 환경변수가 있으면 그 포트를, 없으면 기본값 5000을 쓴다
    # (다른 프로그램이 이미 5000번을 쓰고 있을 때 충돌 없이 다른 포트로 띄우기 위함).
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)
```
`os.environ.get("PORT", 5000)`은 "PORT라는 환경변수가 있으면 그 값을 쓰고, 없으면 5000을 기본값으로 써라"는 뜻입니다. 덕분에 5000번이 막혀있는 컴퓨터에서도 다른 포트로 자동으로 서버를 띄울 수 있게 됐습니다.

**실제 전송 검증에 쓴 스크립트 (직접 함수 호출)**
```python
from datetime import datetime, timezone
import alert

alert.send_lockout_alert('203.0.113.50', 6, datetime.now(timezone.utc))
```
`alert.py`를 다른 파일에서 부품처럼 그대로 가져다 쓸 수 있다는 걸 보여주는 예시이기도 합니다 — 4단계에서 "역할을 나눠두면 나중에 재사용하기 쉽다"고 설명했던 것이 실제로 이렇게 쓰인 사례입니다. 이 호출 한 줄로 실제 Slack 채널에 테스트 메시지가 도착하는지 바로 확인할 수 있었습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- `.env` (`SLACK_WEBHOOK_URL`에 실제 웹훅 주소 채움)
- [app.py](../app.py) (`PORT` 환경변수를 지원하도록 서버 시작 부분 수정)
- [.claude/launch.json](../.claude/launch.json) (`autoPort` 옵션 추가)
- Slack 채널에 실제 알림 메시지 3건 전송 확인, 테스트 데이터는 정리

---

## 8단계 — pytest 단위 테스트 (진짜 서버 없이 코드만 자동으로 검증하기)

### 우리가 한 일
1. [tests/test_config.py](../tests/test_config.py), [tests/test_detector.py](../tests/test_detector.py), [tests/test_soar.py](../tests/test_soar.py), [tests/test_db.py](../tests/test_db.py) 4개 파일에 총 16개의 테스트 작성
2. `pytest` 명령 한 번으로 16개를 전부 자동 실행 → 전부 통과 확인
3. 회귀 테스트가 진짜로 실수를 잡아내는지 보여주기 위해, `config.py`의 숫자를 일부러 하나 틀리게 바꿔서 테스트가 실패하는 것까지 확인한 뒤 원상 복구

### 왜 했는가 (쉬운 설명)

**지금까지 방식과 무엇이 다른가**
5~7단계에서는 실제로 서버를 켜고 브라우저를 조작하거나, 파이썬 스크립트로 진짜 Supabase에 데이터를 넣었다 빼며 확인했습니다. 이 방식은 "실제로 다 연결된 상태에서 진짜처럼 확인한다"는 확실한 장점이 있지만, 매번 서버를 켜야 하고 네트워크 응답을 기다려야 하고 테스트 데이터를 치워야 하는 수고가 듭니다.

**단위 테스트(unit test)**는 프로그램을 이루는 작은 부품(함수) 하나하나를 떼어내서, "이런 입력을 주면 이런 결과가 나와야 정상이다"라는 규칙을 코드로 미리 적어두고 자동으로 확인하는 방식입니다. `pytest`는 이런 테스트 코드 파일들을 모아 한 번에 실행하고 결과를 보고해주는 도구입니다.

**"가짜로 바꿔치기한다"(monkeypatch)는 게 정확히 뭔가**
`detector.is_suspicious(ip)`를 예로 들면, 이 함수는 내부적으로 `db.count_recent_failures(ip)`를 호출해서 진짜 Supabase에 묻습니다. 그런데 우리가 확인하고 싶은 건 "숫자가 6이면 True를 돌려주는가"라는 **판정 로직**이지, Supabase 연결 자체가 아닙니다. 그래서 테스트 코드 안에서 pytest가 제공하는 `monkeypatch`라는 도구로 "`db.count_recent_failures`가 호출되면 진짜 DB에 묻지 말고, 내가 정해준 숫자(6)를 그냥 즉시 돌려줘"라고 잠깐 바꿔치기해둡니다. 테스트가 끝나면 pytest가 자동으로 원래 함수로 되돌려놓아서, 다른 테스트나 실제 프로그램에는 전혀 영향을 주지 않습니다.

이걸 비유하면, 자동차 브레이크 성능을 확인할 때 매번 진짜 도로에 나가 운전하는 대신 브레이크만 떼어내 실험실 기계에 걸어놓고 "이만큼 힘을 주면 이만큼 멈추는가"만 확인하는 것과 같습니다. 도로(진짜 Supabase) 상태와 무관하게 브레이크(판정 로직) 자체만 순수하게 검사할 수 있습니다.

**4개 테스트 파일이 각각 확인하는 것**
- **`test_config.py`(회귀 테스트)**: 기획서가 정한 숫자(실패 5회, 60초, 300초)가 코드에도 정확히 그대로 박혀 있는지 확인합니다. 로직을 검사하는 게 아니라 "숫자 자체"를 지키는 안전장치입니다. 누군가 나중에 실수로 `config.py`의 숫자를 잘못 고치면, 다음에 `pytest`를 돌렸을 때 바로 빨간 글씨로 알려줍니다.
- **`test_detector.py`**: 실패 횟수가 4/5/6일 때 `is_suspicious()`가 각각 정확히 False/False/True를 돌려주는지 "경계값(boundary)"을 촘촘히 확인합니다. 5는 아직 봐주고 6부터 잠근다는 규칙이 코드에도 정확히 그렇게 박혀 있는지 확인하는 것입니다.
- **`test_soar.py`**: `enforce_lockout()`이 "잠그기 → 알리기" 순서를 지키는지, `try_release_expired_lockouts()`가 만료된 IP만 정확히 풀어주고 안 만료된 건 건드리지 않는지, `manual_release()`가 잠긴 IP는 풀고(True) 안 잠긴 IP는 아무 일도 안 하는지(False) 확인합니다.
- **`test_db.py`**: `verify_admin_credentials()`가 맞는 비밀번호는 통과시키고(True), 틀린 비밀번호나 존재하지 않는 아이디는 거부하는지(False) 확인합니다. Supabase 클라이언트인 척하는 가짜 객체(`_FakeQuery`)를 직접 만들어서 `db.get_client()`를 바꿔치기했습니다.

### 실제 코드 함께 보기

**경계값 테스트 — `test_detector.py`**
```python
def test_is_suspicious_false_at_exact_threshold(monkeypatch):
    # 정확히 5번 실패한 "경계값"에서는 아직 수상하지 않아야 한다
    # (기획서 규칙: "5회 초과"부터 수상함, 5회 자체는 아직 봐준다).
    monkeypatch.setattr(db, "count_recent_failures", lambda ip: 5)

    suspicious, count = detector.is_suspicious("1.2.3.4")

    assert suspicious is False
    assert count == 5
```
`monkeypatch.setattr(db, "count_recent_failures", lambda ip: 5)`가 바꿔치기 그 자체입니다. `lambda ip: 5`는 "어떤 IP를 받든 무조건 5를 돌려주는 즉석 가짜 함수"를 뜻합니다. `assert`는 "이 조건이 참이 아니면 테스트를 실패로 처리해라"는 pytest의 기본 문법입니다.

**호출 순서까지 확인하는 테스트 — `test_soar.py`**
```python
def test_enforce_lockout_creates_lockout_then_sends_alert(monkeypatch):
    calls = []  # 호출된 순서를 기록해둘 리스트

    def fake_create_lockout(ip, failure_count):
        calls.append(("create_lockout", ip, failure_count))

    def fake_send_lockout_alert(ip, failure_count, locked_at):
        calls.append(("send_lockout_alert", ip, failure_count))

    monkeypatch.setattr(db, "create_lockout", fake_create_lockout)
    monkeypatch.setattr(alert, "send_lockout_alert", fake_send_lockout_alert)

    soar.enforce_lockout("9.9.9.9", 6)

    assert calls == [
        ("create_lockout", "9.9.9.9", 6),
        ("send_lockout_alert", "9.9.9.9", 6),
    ]
```
가짜 함수들이 실제 작업(DB 저장, Slack 전송) 대신 "내가 호출됐다"는 사실만 `calls` 리스트에 순서대로 적어둡니다. 테스트 마지막에 이 리스트의 순서가 "잠그기 다음에 알리기"인지 정확히 확인합니다 — 4단계에서 "알림은 잠그는 순간에만, 잠근 다음에 보낸다"고 설계했던 규칙이 실제로 지켜지는지를 코드로 증명하는 셈입니다.

**Supabase인 척하는 가짜 객체 — `test_db.py`**
```python
class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def table(self, *args, **kwargs):
        return self

    def select(self, *args, **kwargs):
        return self

    def eq(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def execute(self):
        return _FakeResult(self._rows)
```
`db.py`가 `.table().select().eq().limit().execute()`처럼 메서드를 사슬(체인)처럼 이어 부르는 걸 흉내내려고, `table`/`select`/`eq`/`limit`은 전부 "그냥 나 자신을 다시 돌려줘라"고 만들어서 체인이 끊기지 않게 하고, 맨 마지막 `execute()`에서만 미리 준비해둔 가짜 데이터를 내놓습니다. 이렇게 하면 진짜 `db.verify_admin_credentials()` 코드를 한 글자도 안 고치고 그대로 실행시키면서, 그 아래 깔린 "진짜 Supabase 연결"만 가짜로 바꿔치기할 수 있습니다.

### 회귀 테스트가 실수를 잡아내는 모습을 실제로 확인

`config.py`의 `FAILURE_THRESHOLD` 기본값을 5에서 6으로 일부러 잘못 바꾼 뒤 `pytest`를 돌려봤습니다.
```
tests/test_config.py::test_failure_threshold_is_5 FAILED
    assert config.FAILURE_THRESHOLD == 5
E   assert 6 == 5
```
정확히 "5여야 하는데 6이다"라고 콕 짚어 실패를 알려줬습니다. 값을 다시 5로 되돌리자 16개 테스트가 전부 통과했습니다. 이게 바로 회귀 테스트의 존재 이유입니다 — 사람이 매번 눈으로 `config.py`를 들여다보지 않아도, 실수를 즉시, 자동으로 잡아낼 수 있습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [tests/test_config.py](../tests/test_config.py), [tests/test_detector.py](../tests/test_detector.py), [tests/test_soar.py](../tests/test_soar.py) (기존 빈 뼈대 파일에 내용 작성)
- [tests/test_db.py](../tests/test_db.py) (신규 작성)
- `pytest tests/` 실행 결과 16개 테스트 전부 통과, 실제 Supabase 데이터는 전혀 건드리지 않음

---

## 9단계 — 쿼터 점검 (Supabase 무료 사용량 한도 확인)

### 우리가 한 일
1. 대시보드를 실제로 열어두고, 2.5분 동안 `/api/status` 요청이 몇 번 발생하는지 실측
2. 실측치와 "이론상 최대치"를 계산해서 Supabase 무료 요금제 한도(월 5만 건)와 비교
3. 계산 결과를 근거로 대시보드의 자동 새로고침 주기를 2.5초 → 10초로 변경

### 왜 했는가 (쉬운 설명)

**"쿼터(quota)"란?**
Supabase 같은 외부 서비스는 무료로 봐주는 사용량에 한도를 둡니다. 이 프로젝트가 쓰는 무료 요금제는 한 달에 API 요청 약 5만 건까지만 무료입니다. 이 한도를 넘기면 서비스가 막히거나 유료 결제가 필요해집니다. 마치 통신사의 "무료 데이터 5GB"와 비슷한 개념입니다 — 다 쓰면 느려지거나 추가 요금이 붙는 것처럼요.

**왜 우리 프로젝트가 이 한도에 걸릴 위험이 있었나?**
대시보드([dashboard.js](../public/js/dashboard.js))는 화면이 열려있는 동안 계속 `/api/status`를 자동으로 반복 호출합니다. 그런데 `/api/status` 한 번을 처리할 때마다 서버([app.py](../app.py))는 Supabase에 **4번** 따로 요청을 보냅니다(만료 잠금 정리 1번 + 최근 로그인 시도 조회 1번 + 현재 잠금 목록 조회 1번 + 관리자 로그인 기록 조회 1번). 대시보드를 오래 켜놓을수록 이 요청이 계속 쌓이기 때문에, "이걸 그냥 계속 켜놔도 괜찮은가?"를 실제로 재봐야 했습니다.

**측정하면서 발견한 뜻밖의 사실 — "브라우저 탭 스로틀링(throttling)"**
2.5분 동안 실제로 재보니, 원래 2.5초 간격이면 나와야 할 약 73번보다 훨씬 적은 26번만 발생했습니다. 이건 코드 버그가 아니라, **브라우저가 화면에 보이지 않는(백그라운드) 탭의 타이머 실행 속도를 자동으로 늦추는 절전 기능** 때문이었습니다. 사람이 실수로 대시보드 탭을 다른 창 뒤에 방치해두면 오히려 요청이 줄어드는 셈입니다. 하지만 관리자가 실제로 화면을 보면서 작업 중이라면(탭이 활성 상태) 원래 설정한 간격 그대로 동작하므로, 안전하게 계산할 때는 "최선의 경우"가 아니라 "관리자가 계속 지켜보고 있는 최악의 경우"를 기준으로 삼아야 합니다.

**계산 — 왜 "위험하다"고 판단했나?**
관리자 1명이 대시보드를 계속 지켜보는 상태(2.5초 간격 그대로)를 기준으로 계산하면:
- 분당 `/api/status` 호출: `60초 ÷ 2.5초 = 24회`
- 분당 Supabase 요청: `24회 × 4번 = 96건`
- 시간당 Supabase 요청: `96 × 60 = 5,760건`
- **한 달 무료 한도(5만 건)를 다 쓰는 데 걸리는 시간**: `50,000 ÷ 5,760 ≈ 8.7시간`

즉 관리자 한 명이 대시보드를 하루 8시간 정도만 켜놓고 있어도, 팀 전체가 한 달 동안 쓸 수 있는 무료 한도를 혼자서 거의 다 써버릴 수 있다는 계산이 나왔습니다. plan.md가 원래 예상했던 "30분당 600~900건"보다 실제(이론치)는 3~4배 더 많이 나왔는데, 이건 원래 예상이 "표 하나로 묶어서 한 번에 조회"를 가정했지만 실제 구현은 표 4개를 각각 따로 조회하기 때문입니다.

**그래서 무엇을 바꿨나**
폴링 주기를 2.5초에서 10초로 늘렸습니다. 계산식의 분모(주기)가 4배 커지면 요청량은 정확히 4분의 1로 줄어듭니다 — 시간당 5,760건이 아니라 약 1,440건이 되어, 하루 8시간씩 켜놔도 한 달 한도 안에 여유 있게 들어옵니다. 화면이 최신 상태로 갱신되기까지 최대 10초가 걸릴 수 있다는 단점은 있지만, 실시간 CCTV가 아니라 팀 데모/개발용 모니터링 화면이라는 이 프로젝트의 목적을 고려하면 충분히 감수할 수 있는 지연입니다.

### 실제 코드 함께 보기

**변경 전 → 변경 후 — `dashboard.js`**
```javascript
// 변경 전
setInterval(fetchStatus, 2500); // 2.5초마다

// 변경 후
setInterval(fetchStatus, 10000); // 10초마다
```
숫자 하나(밀리초 단위, `10000` = 10초)만 바꿨을 뿐인데 실제 Supabase 사용량은 4분의 1로 줄어듭니다. 이렇게 "숫자 하나로 전체 시스템의 부하를 조절할 수 있게 설계해두는 것"이 좋은 설계의 한 예입니다.

### 측정 후 실제로 확인한 것
코드를 바꾼 뒤 브라우저에서 다시 대시보드를 열어, 서버 로그에 찍히는 실제 요청 시각을 확인했습니다.
```
22:43:51 GET /api/status
22:44:01 GET /api/status   (정확히 10초 후)
22:44:11 GET /api/status   (또 정확히 10초 후)
```
설정한 대로 정확히 10초 간격으로 요청이 오는 것을 실제 서버 로그로 확인했습니다.

### 상황에 따라 폴링 주기를 다시 조절하는 방법

10초는 "평소 개발/데모 중 오래 켜놔도 쿼터가 안전한" 값으로 정한 것이지, 절대 바꾸면 안 되는 고정값이 아닙니다. **실제 시연(데모) 당일처럼 "화면 반응이 빠르게 보이는 게 더 중요한 짧은 시간 동안"**은 오히려 주기를 짧게 줄이는 게 낫습니다 — 시연은 보통 몇 분 안에 끝나기 때문에, 그 짧은 시간 동안은 쿼터를 걱정할 필요가 거의 없습니다.

**바꾸는 방법 (매우 간단합니다)**
1. [static/js/dashboard.js](../public/js/dashboard.js) 파일을 엽니다.
2. 맨 아래쪽 `setInterval(fetchStatus, 10000);` 줄을 찾습니다.
3. 괄호 안의 숫자(밀리초 단위 — 1000이 1초)만 원하는 값으로 바꿉니다. 예를 들어 시연 중 "즉각 반응하는 것처럼" 보이게 하려면:
   ```javascript
   setInterval(fetchStatus, 1000); // 시연용: 1초마다 (평소엔 쓰지 않음)
   ```
4. 파일을 저장하고, 브라우저에서 대시보드 화면을 **새로고침**만 하면 바로 적용됩니다(서버를 껐다 켤 필요 없음 — `static/` 폴더 파일은 서버가 매 요청마다 그 시점의 최신 파일 내용을 그대로 보내주기 때문입니다).

**주의할 점**
- 1초 주기는 시연이 진행되는 짧은 시간(예: 10~20분) 동안만 쓰는 걸 권장합니다. 계산해보면 1초 주기는 10초 주기보다 쿼터 소모가 10배 빠릅니다(9단계 앞부분의 계산식과 같은 방식 — 분모인 주기가 10분의 1이 되면 요청량은 10배가 됩니다).
- **시연이 끝나면 반드시 10000(10초)으로 다시 되돌려놓아야 합니다.** 짧게 켜뒀다 끄는 개인 시연이라면 큰 문제가 안 되지만, 그대로 며칠씩 켜두면 9단계에서 계산했던 "8.7시간 만에 한 달 쿼터 소진" 위험이 그대로 재현됩니다.
- 팀원 여러 명이 각자 다른 값으로 테스트하고 있다면, 시연 전에 "지금 몇 초로 되어 있는지" 서로 확인하고 맞추는 게 좋습니다 — 이 값은 `.env`가 아니라 코드(`dashboard.js`) 안에 직접 적혀 있어서, 깃에 커밋하면 팀원 전체에게 그대로 반영됩니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [static/js/dashboard.js](../public/js/dashboard.js) (폴링 주기 2.5초 → 10초로 변경, 이후 10단계에서 `public/js/dashboard.js`로 폴더명이 바뀜)
- 새 파일을 만드는 단계는 아니었지만, "실측 → 계산 → 근거 있는 설계 변경"으로 이어진 사례

---

## 10단계 — Vercel 배포 준비 및 배포

### 우리가 한 일
1. `static/` 폴더 이름을 `public/`으로 바꿈 (Vercel이 정적 파일을 찾는 규칙에 맞춤)
2. [app.py](../app.py)의 Flask 앱 생성 코드를 한 줄 수정해서, 템플릿 코드는 전혀 안 고치고도 로컬 개발 환경과 Vercel 배포 환경이 똑같은 주소 구조를 쓰게 만듦
3. 로컬 서버(자동 테스트 + 실제 브라우저)로 화면이 안 깨지는지 확인
4. 실제 배포는 Vercel 계정 로그인이 필요해 사용자가 직접 진행 (아래 "배포 단계" 참고)

### 왜 했는가 (쉬운 설명)

**"정적 파일"과 "실행되는 코드"는 왜 다르게 취급되나?**
`app.py`는 요청이 올 때마다 파이썬이 그 내용을 실제로 **실행**해서 결과를 만들어내는 코드입니다(예: "이 아이디/비밀번호가 맞는지 데이터베이스에 물어봐라"). 반면 `auth.css`, `dashboard.js` 같은 파일은 실행되는 게 아니라 **내용 그대로 브라우저에 전달**되고, 브라우저가 스스로 해석해서 화면을 꾸미거나 동작시킵니다.

Vercel은 이 둘을 완전히 다른 방식으로 서빙합니다. `app.py`처럼 실행되는 코드는 "함수(Function)"로 등록해서 요청이 올 때마다 파이썬을 돌리고, `public/` 폴더 안의 정적 파일은 아예 파이썬을 거치지 않고 **CDN**(전 세계 여러 곳에 파일을 미리 복사해두고, 사용자와 가장 가까운 곳에서 즉시 내려주는 시스템)에서 바로 전달합니다. 정적 파일을 매번 파이썬으로 처리하면 느리고 낭비이기 때문에, "이 폴더 안의 건 그냥 파일 그대로 빨리 내려줘라"고 미리 분리해두는 것입니다. 그 "이 폴더"의 이름이 Vercel에서는 관례상 `public/`으로 정해져 있어서, 우리도 여기에 맞췄습니다.

**템플릿을 하나도 안 고치고 해결한 방법**
`static_folder="public", static_url_path=""`이라는 옵션 하나를 Flask 앱 생성 코드에 추가했습니다. 원래 Flask는 기본값으로 "static이라는 이름의 폴더를 /static/파일명이라는 주소로 서빙해라"는 규칙을 갖고 있는데, 이 옵션으로 "public이라는 이름의 폴더를 /파일명(맨 앞에 static 안 붙임)이라는 주소로 서빙해라"로 바꿔치기한 것입니다. 템플릿 안의 `url_for('static', filename='css/auth.css')` 코드는 그대로 두었는데도, 이 설정 덕분에 자동으로 `/css/auth.css`라는 Vercel 방식 주소를 만들어냅니다 — 템플릿 파일을 4개나 일일이 찾아 고치는 대신, 설정 한 줄로 전체가 한 번에 맞춰진 것입니다.

**로컬 개발과 배포 환경이 "일치"해야 하는 이유**
만약 로컬에서는 `/static/css/auth.css`로 접속하고 Vercel에서는 `/css/auth.css`로 접속해야 한다면, 로컬에서는 멀쩡하던 화면이 배포하고 나서야 CSS가 깨진 채로 발견될 수 있습니다. 이런 사고를 막으려고, 로컬 Flask 서버도 처음부터 Vercel과 똑같은 주소 구조(`/css/auth.css`)로 파일을 내려주도록 맞춰뒀습니다. 그래서 "로컬에서 잘 되면 배포해서도 잘 된다"는 확신을 가질 수 있습니다.

### 실제 코드 함께 보기

**`app.py` — Flask 앱 생성 부분**
```python
# static_folder="public", static_url_path="": 기본값이면 Flask가 "static/" 폴더를
# "/static/파일명" 주소로 서빙하는데, Vercel은 CSS/JS 같은 정적 파일을 "public/" 폴더에서
# 찾아 "/파일명" 형태의 루트 경로로 서빙하는 게 규칙이다.
# 로컬 개발 서버와 Vercel 배포본이 똑같은 주소 구조를 쓰도록, Flask도 처음부터
# "public/" 폴더를 "/파일명" 경로로 서빙하게 맞춰뒀다 — 이러면 템플릿 코드는
# 하나도 안 고쳐도 된다(url_for('static', ...)가 알아서 "/css/auth.css" 형태로 바뀜).
app = Flask(__name__, static_folder="public", static_url_path="")
```

**변경 후 실제로 확인한 것 (자동 테스트)**
```python
r = c.get('/css/auth.css')
print(r.status_code, r.content_type)   # 200 text/css; charset=utf-8

r = c.get('/static/css/auth.css')      # 예전 주소
print(r.status_code)                    # 404 (의도대로 더 이상 존재하지 않음)
```
Flask 테스트 클라이언트(진짜 브라우저 없이 요청/응답을 흉내내는 도구)로 새 주소(`/css/auth.css`)는 정상 응답하고, 예전 주소(`/static/css/auth.css`)는 사라졌는지 확인했습니다. 이어서 실제 브라우저로 `/login` 화면을 열어 스타일이 깨지지 않고 그대로인 것도 눈으로 확인했습니다. `pytest tests/`도 16개 전부 그대로 통과해서, 이번 변경이 판정 로직 쪽에는 전혀 영향을 주지 않았다는 것도 재확인했습니다.

### 배포 단계 (Vercel 계정 로그인이 필요해 직접 진행)

Vercel 배포는 사용자님의 Vercel 계정으로 GitHub 저장소를 연결해야 해서, 이 부분은 직접 진행해주셔야 합니다.

1. [vercel.com](https://vercel.com)에 GitHub 계정으로 로그인
2. **Add New... → Project** 클릭
3. **Import Git Repository**에서 `dyj02056/login-watchdog` 선택
4. Vercel이 `requirements.txt`를 보고 자동으로 "Flask 프로젝트"로 인식합니다(별도 설정 파일 없이도 인식되는 걸 "제로 설정(zero-configuration)"이라고 부릅니다)
5. **Environment Variables** 섹션에서 로컬 `.env`에 있는 값들을 그대로 하나씩 입력:
   `SUPABASE_URL`, `SUPABASE_KEY`, `SLACK_WEBHOOK_URL`, `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `TRUST_FORWARDED_FOR`
   (이 화면은 Vercel이 안전하게 암호화해서 보관하는 곳으로, `.env` 파일이 깃에 안 올라가는 것과 같은 이유로 여기서만 따로 입력합니다)
6. **Deploy** 클릭 → 몇 분 뒤 `https://프로젝트이름.vercel.app` 같은 실제 주소가 발급됩니다

### 배포 후 확인해야 할 것

- 배포된 주소로 접속해 `/login`, `/signup`, `/admin/login`이 화면 깨짐 없이 뜨는지 확인
- 관리자 로그인 → 대시보드 접근 → 최근 로그인 시도/잠금 목록이 정상 표시되는지 확인
- `TRUST_FORWARDED_FOR`는 여전히 `false`로 유지 — Vercel 뒤에서도 IP 스푸핑 위험은 그대로이므로, 이 값을 함부로 켜면 안 됨(5단계 `get_request_ip()` 설명 참고). 다만 Vercel처럼 리버스 프록시 뒤에 배포하면 `request.remote_addr`가 실제 방문자 IP가 아니라 Vercel 내부망 주소로 찍힐 수 있는데, 이 문제의 정확한 해결 방법(신뢰할 수 있는 프록시 헤더만 선택적으로 신뢰하는 방식)은 이번 단계 범위 밖이라 실제 배포 후 IP 잠금이 의도대로 동작하는지 별도로 확인이 필요합니다
- 첫 접속 시 "콜드 스타트"로 응답이 살짝 느릴 수 있음(서버리스 함수가 방금 깨어난 경우) — 이후 요청은 빨라짐

### 이 단계에서 만들어지거나 바뀐 파일
- `static/` → [public/](../public/) 폴더 이름 변경 (내용은 그대로, 파일 3개)
- [app.py](../app.py) (`Flask()` 생성 옵션에 `static_folder`/`static_url_path` 추가)
- 템플릿 파일들은 **변경 없음** (설정만으로 해결됨)

---
