# 로그인 워치독 — 비전공자용 진행 해설서

> 이 문서는 `plan.md`의 각 단계를 진행할 때마다, "우리가 방금 무엇을 했고 왜 했는지"를 개발 지식이 없어도 이해할 수 있게 풀어서 기록합니다.
> 단계가 끝날 때마다 새 섹션이 추가됩니다.

---

## 목차

1. [1단계 — 개발 환경 준비](guide01_setup.md)
2. [2단계 — 데이터베이스(Supabase) 스키마 만들기](guide02_schema.md)
3. [3단계 — `db.py` (데이터베이스와 대화하는 창구 만들기)](guide03_db.md)
4. [4단계 — `detector.py` / `soar.py` / `alert.py` (판정 → 조치 → 알림)](guide04_response.md)
5. [5단계 — `app.py` (모든 부품을 실제 웹사이트로 엮는 "정문")](guide05_app.md)
6. [6단계 — 화면(템플릿/스타일/스크립트) 만들기](guide06_templates.md)
7. [7단계 — Slack 실제 연동 (콘솔 대체를 진짜 알림으로 전환)](guide07_alert.md)
8. [8단계 — pytest 단위 테스트 (진짜 서버 없이 코드만 자동으로 검증하기)](guide08_testing.md)
9. [9단계 — 쿼터 점검 (Supabase 무료 사용량 한도 확인)](guide09_quota.md)
10. [10단계 — Vercel 배포 준비 및 배포](guide10_deploy.md)
11. [11단계 — 관리자/일반 로그인 화면을 겉보기에 하나로 통합](guide11_merge.md)
12. [12단계 — 관리자 대시보드에 회원 관리 기능 추가](guide12_usermanagement.md)
13. [13단계 — 회원 전용 대시보드 (`/dashboard`) 추가](guide13_member.md)
14. [14단계 — 로그인 IP의 국가·도시 표시 (ip-api.com 연동)](guide14_geoip.md)
15. [15단계 — 화면 리디자인 (색상 토큰 + 자연스러운 페이지 전환)](guide15_design.md)
16. [16단계 — 다크모드 지원](guide16_darkmode.md)

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
- [config.py](../../config.py) (신규 작성)
- [.env.example](../../.env.example) (내용 갱신)
- [.gitignore](../../.gitignore) (`venv/` 추가)
- [requirements.txt](../../requirements.txt) (신규 작성)
- `venv/` 폴더 (신규 생성, 깃에는 올라가지 않음)

---

## 2단계 — 데이터베이스(Supabase) 스키마 만들기

### 우리가 한 일
1. [docs/schema.sql](../schema.sql) 파일에 "표(테이블) 설계도" 5개를 작성
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
- [docs/schema.sql](../schema.sql) (신규 작성, Supabase에 실제 실행됨)
- `.env` (`SUPABASE_URL`, `SUPABASE_KEY` 값 채움 — 이 파일은 깃에 없음)
- Supabase 프로젝트 안에 실제 표 5개 생성됨(코드 파일이 아니라 외부 서비스 안의 변화)

---

## 3단계 — `db.py` (데이터베이스와 대화하는 창구 만들기)

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

---

## 4단계 — `detector.py` / `soar.py` / `alert.py` (판정 → 조치 → 알림)

### 우리가 한 일
1. [detector.py](../../detector.py) — "지금 이 IP가 수상한가? 지금 잠겨있는가?"만 **판단**하는 파일
2. [soar.py](../../soar.py) — 판단 결과를 받아서 실제로 **잠그고, 알림을 보내고, 풀어주는 실행** 파일
3. [alert.py](../../alert.py) — Slack으로 **메시지를 실제로 전송**하는 파일
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

**[detector.py](../../detector.py) 전체 — "판사"는 코드도 짧습니다 (딱 2개 함수, 아무것도 저장하지 않음)**
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

**[soar.py](../../soar.py) 전체 — 판정 결과를 실제 조치로 옮기는 3개 함수**
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

**[alert.py](../../alert.py) 전체 — Slack에 실제로 메시지를 보내는 함수 1개**
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
- [detector.py](../../detector.py) (신규 작성 — 판정 함수 2개)
- [soar.py](../../soar.py) (신규 작성 — 조치 함수 3개)
- [alert.py](../../alert.py) (신규 작성 — Slack 알림 함수 1개)
- Supabase 표 데이터는 테스트 후 전부 원상 복구(0건)

---

## 5단계 — `app.py` (모든 부품을 실제 웹사이트로 엮는 "정문")

### 우리가 한 일
1. [app.py](../../app.py)에 지금까지 만든 부품(db, detector, soar, alert)을 실제 화면 주소(URL)와 연결
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
- [app.py](../../app.py) (신규 작성 — 라우트 11개 + 문지기 함수 1개)
- [alert.py](../../alert.py) (콘솔 출력에 `flush=True` 추가)
- `.env` (`SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` 값 채움)
- `.claude/launch.json` (신규 — 브라우저 미리보기로 서버를 켜기 위한 설정)
- Supabase에 실제 관리자 계정(`soung1009`) 1명 생성됨, 테스트용 데이터는 확인 후 정리

---

## 6단계 — 화면(템플릿/스타일/스크립트) 만들기

### 우리가 한 일
1. [templates/login.html](../../templates/login.html), [signup.html](../../templates/signup.html), [admin_login.html](../../templates/admin_login.html), [dashboard.html](../../templates/dashboard.html) — 4개 화면의 HTML
2. [static/css/auth.css](../../public/css/auth.css), [static/css/dashboard.css](../../public/css/dashboard.css) — 화면 스타일
3. [static/js/dashboard.js](../../public/js/dashboard.js) — 대시보드를 실시간으로 갱신시키는 자바스크립트

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
- [templates/login.html](../../templates/login.html), [templates/signup.html](../../templates/signup.html), [templates/admin_login.html](../../templates/admin_login.html), [templates/dashboard.html](../../templates/dashboard.html) (신규 작성)
- [static/css/auth.css](../../public/css/auth.css), [static/css/dashboard.css](../../public/css/dashboard.css) (신규 작성)
- [static/js/dashboard.js](../../public/js/dashboard.js) (신규 작성)
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
- [app.py](../../app.py) (`PORT` 환경변수를 지원하도록 서버 시작 부분 수정)
- [.claude/launch.json](../../.claude/launch.json) (`autoPort` 옵션 추가)
- Slack 채널에 실제 알림 메시지 3건 전송 확인, 테스트 데이터는 정리

---

## 8단계 — pytest 단위 테스트 (진짜 서버 없이 코드만 자동으로 검증하기)

### 우리가 한 일
1. [tests/test_config.py](../../tests/test_config.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_soar.py](../../tests/test_soar.py), [tests/test_db.py](../../tests/test_db.py) 4개 파일에 총 16개의 테스트 작성
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
- [tests/test_config.py](../../tests/test_config.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_soar.py](../../tests/test_soar.py) (기존 빈 뼈대 파일에 내용 작성)
- [tests/test_db.py](../../tests/test_db.py) (신규 작성)
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
대시보드([dashboard.js](../../public/js/dashboard.js))는 화면이 열려있는 동안 계속 `/api/status`를 자동으로 반복 호출합니다. 그런데 `/api/status` 한 번을 처리할 때마다 서버([app.py](../../app.py))는 Supabase에 **4번** 따로 요청을 보냅니다(만료 잠금 정리 1번 + 최근 로그인 시도 조회 1번 + 현재 잠금 목록 조회 1번 + 관리자 로그인 기록 조회 1번). 대시보드를 오래 켜놓을수록 이 요청이 계속 쌓이기 때문에, "이걸 그냥 계속 켜놔도 괜찮은가?"를 실제로 재봐야 했습니다.

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
1. [static/js/dashboard.js](../../public/js/dashboard.js) 파일을 엽니다.
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
- [static/js/dashboard.js](../../public/js/dashboard.js) (폴링 주기 2.5초 → 10초로 변경, 이후 10단계에서 `public/js/dashboard.js`로 폴더명이 바뀜)
- 새 파일을 만드는 단계는 아니었지만, "실측 → 계산 → 근거 있는 설계 변경"으로 이어진 사례

---

## 10단계 — Vercel 배포 준비 및 배포

### 우리가 한 일
1. `static/` 폴더 이름을 `public/`으로 바꿈 (Vercel이 정적 파일을 찾는 규칙에 맞춤)
2. [app.py](../../app.py)의 Flask 앱 생성 코드를 한 줄 수정해서, 템플릿 코드는 전혀 안 고치고도 로컬 개발 환경과 Vercel 배포 환경이 똑같은 주소 구조를 쓰게 만듦
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

### 실제 배포 사이트로 최종 검증한 결과

`https://login-watchdog.vercel.app` 실제 주소로 4단계 스모크 테스트를 처음부터 끝까지 다시 돌려봤습니다.

1. 회원가입 → 정상
2. 60초 안에 6번 연속 틀리게 로그인 → Supabase `lockouts` 표에 실제 방문자 IP(`112.150.15.124`) 기준으로 잠금 생성 확인
3. 관리자로 로그인 후 `/api/status`를 직접 호출 → 방금 생긴 잠금이 정확히 조회됨
4. `/api/unlock`으로 즉시 해제 → 재조회 시 잠금 목록이 비어있는 것까지 확인
5. **Slack 채널에도 실제로 알림이 도착** — 시각·IP·실패 횟수·조치 내용이 테스트 데이터와 정확히 일치하는 메시지를 사용자가 직접 캡처해서 확인해줌

**걱정했던 부분이 실제로는 문제없었던 점**: 배포 전엔 "Vercel처럼 프록시 뒤에 서면 방문자의 진짜 IP 대신 Vercel 내부 주소가 찍힐 수 있다"고 우려했는데, 실제로는 `request.remote_addr`에 진짜 방문자 IP가 정상적으로 들어왔습니다. 즉 `TRUST_FORWARDED_FOR`를 계속 `false`로 둔 채로도(안전한 기본값을 유지한 채로도) IP 기반 잠금이 정확하게 동작한다는 걸 확인했습니다.

### 배포 후 발견: "/" 접속 시 404 대신 /login으로 안내

배포 후 사용자가 직접 사이트에 접속해보니, 도메인 주소만 입력했을 때(`https://login-watchdog.vercel.app/`, 경로 없이) 404 오류 화면이 떴습니다. 원래 이 프로젝트는 "/"에 아무 화면도 만들어두지 않았기 때문에(첫 화면은 `/login`), 라우트가 없는 주소로 들어오면 Flask가 자동으로 404를 보여주는 게 기본 동작입니다 — 로컬에서도 똑같이 재현되는 걸 배포 전에 미리 확인했었지만, "실제 방문자가 도메인만 치고 들어올 수 있다"는 점까지는 미리 감안하지 못했습니다.

**고친 방법**: `/` 주소에 대한 라우트를 하나 추가해서, 들어오자마자 `/login`으로 돌려보내게 했습니다.
```python
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))
```
`redirect(url_for("login"))`은 "화면을 직접 그리지 말고, 브라우저에게 '/login으로 다시 가봐'라고 알려줘라"는 뜻입니다. 브라우저는 이 안내를 받으면 자동으로 `/login`에 새 요청을 보내고, 사용자 눈에는 그냥 로그인 화면이 바로 뜨는 것처럼 보입니다. 코드 한 줄로 해결되는 문제였고, 실제로 재배포 후 도메인 주소만 입력해도 정상적으로 로그인 화면이 뜨는 것까지 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- `static/` → [public/](../../public/) 폴더 이름 변경 (내용은 그대로, 파일 3개)
- [app.py](../../app.py) (`Flask()` 생성 옵션에 `static_folder`/`static_url_path` 추가, `/` 라우트 1개 추가)
- 템플릿 파일들은 **변경 없음** (설정만으로 해결됨)
- Vercel에 실제 배포 완료: `https://login-watchdog.vercel.app`

---

## 11단계 — 관리자/일반 로그인 화면을 겉보기에 하나로 통합

### 우리가 한 일
1. `/login`(일반 계정) 화면 제목에서 "(감시 대상)"이라는 문구 제거
2. `login.html`과 `admin_login.html` 두 파일을 [templates/login_form.html](../../templates/login_form.html) 하나로 합침
3. 실제 인증 로직(어느 표와 비교하는지, IP 잠금이 적용되는지)은 **전혀 건드리지 않고** 그대로 유지

### 왜 이렇게 했는가 (쉬운 설명)

**요청과 실제 설계 사이의 충돌**
사용자가 "관리자랑 일반 계정을 같은 로그인 화면으로 로그인하게 해달라"고 요청했는데, 이걸 문자 그대로 "완전히 하나의 처리 로직으로 합친다"로 받아들이면 안 되는 이유가 있었습니다. 4단계에서 설명했듯, 이 프로젝트는 IP가 60초 안에 5번 넘게 틀리면 잠기는데, 이 잠금이 **관리자에게는 적용되지 않도록** 일부러 `/login`과 `/admin/login`을 완전히 다른 경로·다른 표(`users` vs `admin_users`)로 분리해뒀습니다(plan.md에 "팀 합의 완료"로 명시된 결정). 만약 두 로그인을 진짜로 하나의 처리 로직으로 합치면, 공격자가 브루트포스를 시도하는 동안 관리자도 같은 IP 잠금에 걸려서 정작 대시보드에 들어가 잠금을 풀어줘야 할 사람이 못 들어가는 모순이 생깁니다.

그래서 "화면 생김새만 완전히 똑같게 하고, 뒤에서 처리하는 로직(어느 라우트가 받는지, 어느 표와 비교하는지)은 그대로 분리해서 유지"하는 방식으로 절충했습니다 — 방문자 입장에서는 두 로그인 화면을 구분할 수 없지만, 서버 안에서는 여전히 완전히 다른 두 갈래 길로 처리됩니다.

**"화면 파일을 하나로 합친다"는 게 왜 중요한가**
예전에는 `login.html`과 `admin_login.html`이 거의 똑같은 내용을 각자 따로 갖고 있었습니다. 이렇게 파일이 두 벌로 나뉘어 있으면, 나중에 디자인을 하나만 고치고 다른 하나를 깜빡 잊는 실수가 생기기 쉽습니다(예: 버튼 색은 바꿨는데 한쪽 파일만 놓치는 식). 그래서 아예 파일을 [login_form.html](../../templates/login_form.html) 하나로 합치고, "이 폼을 어디로 제출할지"(`form_action`)만 파이썬 쪽에서 다르게 넘겨주는 방식으로 바꿨습니다. 이러면 두 화면이 "우연히 똑같다"가 아니라 "구조적으로 항상 똑같을 수밖에 없다"가 됩니다.

### 실제 코드 함께 보기

**`templates/login_form.html` — 폼 제출 주소만 변수로 받는 부분**
```html
<form method="post" action="{{ form_action }}">
    <label for="username">아이디</label>
    <input type="text" id="username" name="username" required>
    ...
</form>
```
`form_action`이라는 자리에 실제로 어떤 주소가 들어갈지는 이 파일이 아니라, 이 파일을 불러오는 `app.py`의 라우트가 결정합니다.

**`app.py` — 같은 화면을 서로 다른 주소로 렌더링하는 부분**
```python
@app.route("/login", methods=["GET"])
def login():
    return render_template("login_form.html", form_action=url_for("login_submit"))

@app.route("/admin/login", methods=["GET"])
def admin_login():
    if "admin_username" in session:
        return redirect(url_for("dashboard"))
    return render_template("login_form.html", form_action=url_for("admin_login_submit"))
```
`render_template("login_form.html", form_action=...)`처럼 템플릿 이름 뒤에 `이름=값`을 붙이면, 그 값이 템플릿 안의 `{{ form_action }}` 자리에 그대로 끼워 넣어집니다. 두 함수가 **같은 화면 파일**을 부르지만, **다른 주소**를 넘겨주기 때문에 "겉보기엔 같은데 실제로는 다른 곳으로 제출되는" 화면 두 개가 만들어집니다.

### 실제로 확인한 것
자동 테스트로 두 화면의 HTML을 통째로 비교해봤습니다(`difflib`라는 "두 텍스트의 차이만 콕 짚어주는" 파이썬 도구 사용).
```
- <form method="post" action="/login">
+ <form method="post" action="/admin/login">
```
딱 이 한 줄(제출 주소)만 다르고 나머지는 100% 동일하다는 것을 확인했습니다. 브라우저로 직접 두 화면을 열어봐도 "로그인"이라는 제목과 "아이디"/"비밀번호" 문구까지 완전히 똑같이 보이는 것도 확인했습니다. `pytest tests/`도 16개 그대로 통과해서, 판정 로직(누가 잠기고 안 잠기는지)에는 전혀 손대지 않았다는 것도 재확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [templates/login_form.html](../../templates/login_form.html) (신규 — `login.html` + `admin_login.html`을 대체)
- `templates/login.html`, `templates/admin_login.html` (삭제 — `login_form.html`로 통합됨)
- [app.py](../../app.py) (`login()`, `login_submit()`, `admin_login()`, `admin_login_submit()`이 공유 템플릿을 쓰도록 수정 — 인증 로직 자체는 변경 없음)

---

## 12단계 — 관리자 대시보드에 회원 관리 기능 추가

### 우리가 한 일
1. Supabase에 `app_settings`라는 표를 하나 새로 추가 (딱 1행만 쓰는 "전역 설정" 표)
2. [db.py](../../db.py)에 `list_users`, `delete_user`, `get_signup_enabled`, `set_signup_enabled` 4개 함수 추가
3. 대시보드에 "등록된 회원" 목록(삭제 버튼 포함)과 "회원가입 설정"(켜기/끄기 토글) 두 섹션 추가
4. `/signup` 화면이 회원가입이 꺼져있을 때는 폼 대신 안내 문구만 보여주도록 수정
5. 새 기능들을 실제로 브라우저와 자동 테스트로 검증하고, 도중에 발견한 실수 하나를 바로 고침

### 왜 했는가 (쉬운 설명)

**회원 목록을 조회할 때 비밀번호 칸은 왜 아예 요청하지 않았나?**
`list_users()`는 `select("id, username, email, created_at")`처럼 필요한 칸만 콕 집어서 요청합니다. `password_hash`(암호화된 비밀번호)는 요청 목록에 아예 넣지 않았습니다 — 암호화된 값이라 그 자체를 봐도 원래 비밀번호를 알아낼 수는 없지만, "화면에 굳이 필요 없는 민감한 값은 애초에 서버가 가져오지도 않게 만든다"는 원칙을 지키면, 나중에 실수로 화면에 잘못 표시하는 사고 자체가 원천적으로 불가능해집니다.

**"회원가입 On/Off"를 왜 파이썬 변수가 아니라 Supabase 표에 저장했나?**
가장 간단한 방법은 `app.py`에 `signup_enabled = True`같은 변수를 하나 두고 관리자가 누르면 이 값을 바꾸는 것처럼 보일 수 있습니다. 하지만 이 프로젝트는 로컬 컴퓨터, Vercel 등 **여러 곳에서 서버가 동시에 돌아갈 수 있습니다**(10단계에서 실제로 배포까지 했습니다). 파이썬 변수(메모리)는 그 서버 프로세스 하나에만 존재하는 값이라서, 로컬에서 "회원가입 끄기"를 눌러도 Vercel에서 돌고 있는 서버는 전혀 모릅니다. 그래서 다시 한번 "모두가 함께 보는 단 하나의 장소"인 Supabase에 이 값을 저장해서, 서버가 몇 개든 항상 같은 값을 보게 만들었습니다. (9~10단계에서 이미 비슷한 이유로 대시보드 데이터를 Supabase에 저장했던 것과 같은 원리입니다.)

`app_settings` 표는 일부러 딱 1행만 쓰도록 만들었습니다(`id`가 항상 1이어야 한다는 조건을 표에 직접 걸어둠). 여러 설정값이 생길 걸 대비해 표 하나를 "설정 보관함"처럼 쓰는 흔한 패턴입니다.

**삭제 버튼에 "정말 삭제할까요?" 확인창을 넣은 이유**
회원 삭제는 되돌릴 수 없는 작업입니다. 버튼을 실수로 잘못 눌러도 곧바로 데이터가 사라지면 위험하므로, 자바스크립트의 `confirm()`이라는 기본 팝업으로 한 번 더 확인을 받습니다. 사용자가 "취소"를 누르면 아무 요청도 서버에 보내지 않습니다.

**계정을 지워도 로그인 시도 기록은 왜 안 지워지나?**
`login_attempts` 표는 `username`을 문자열로만 저장하고, `users` 표와 연결(외래키)되어 있지 않습니다(3단계에서 이미 이렇게 설계했습니다). 그래서 회원을 삭제해도 "이 아이디가 예전에 시도했던 로그인 기록"은 CCTV 녹화본처럼 그대로 남습니다 — 감사(audit) 목적의 로그는 계정 존재 여부와 무관하게 보존되어야 한다는 원칙을 그대로 지킨 것입니다.

**회원가입 화면을 왜 "폼을 숨기는 것"과 "서버에서 다시 막는 것" 두 겹으로 처리했나?**
브라우저 화면에서 폼을 안 보여주는 건 어디까지나 "보기 좋으라고" 하는 조치일 뿐, 개발자 도구 등으로 누군가 `/signup`에 직접 데이터를 보내버리면 화면의 안내 문구는 아무 의미가 없습니다. 그래서 `signup_submit()` 함수 맨 앞에서 `db.get_signup_enabled()`를 다시 한번 확인해서, 화면을 거치지 않은 요청도 똑같이 막아둡니다. "눈속임"과 "진짜 방어"를 구분해서, 진짜 방어는 항상 서버 쪽에 두는 게 원칙입니다.

### 실제 코드 함께 보기

**`db.py` — 비밀번호 칸을 빼고 조회하는 부분**
```python
def list_users(limit: int = 100) -> list[dict]:
    res = (
        get_client()
        .table("users")
        .select("id, username, email, created_at")  # password_hash는 여기 없음
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data
```

**`db.py` — 회원가입 On/Off를 Supabase에서 읽고 쓰는 부분**
```python
def get_signup_enabled() -> bool:
    res = get_client().table("app_settings").select("signup_enabled").eq("id", 1).limit(1).execute()
    if not res.data:
        return True  # 설정 행이 아직 없다면 기본값은 "허용"으로 안전하게 처리
    return res.data[0]["signup_enabled"]


def set_signup_enabled(enabled: bool) -> None:
    get_client().table("app_settings").update({"signup_enabled": enabled}).eq("id", 1).execute()
```
설정 행이 없을 때 기본값을 "막힘"이 아니라 "허용"으로 정한 것도 의도적인 선택입니다. 만약 반대로 했다면, 표를 새로 만드는 과정에서 뭔가 실수가 생겼을 때 회원가입이 원인도 모른 채 막혀버리는 사고로 이어질 수 있습니다.

**`public/js/dashboard.js` — 삭제 전 확인창**
```javascript
async function deleteUser(userId, username) {
    const confirmed = confirm(`"${username}" 회원을 정말 삭제할까요? 이 작업은 되돌릴 수 없습니다.`);
    if (!confirmed) {
        return;  // "취소"를 누르면 여기서 함수가 끝나고, fetch는 아예 실행되지 않는다
    }
    await fetch("/api/users/delete", { ... });
    fetchStatus();
}
```

### 실제로 테스트한 것

1. 회원가입 → 대시보드 "등록된 회원" 목록에 정확히 나타나는지 확인
2. "삭제" 버튼 클릭 → 확인창이 뜨고, 취소하면 실제로 아무 일도 안 일어나는지 확인(이 프로젝트 검증에 쓰는 자동화 브라우저는 확인창을 자동으로 "취소" 처리하도록 되어 있어서, 오히려 "취소했을 때 정말 안전한지"를 확인하기 좋은 기회였습니다) → API를 직접 호출해서 "확인"을 눌렀을 때의 삭제 동작도 별도로 검증
3. "회원가입 끄기" 토글 → 상태 문구와 버튼 글자가 즉시 바뀌는지 확인 → `/signup`에 실제로 들어가서 폼 대신 안내 문구만 뜨는지 확인 → 폼을 우회해서 직접 데이터를 보내도(개발자 도구를 쓰는 것과 같은 상황을 흉내냄) 서버가 막는지 확인 → 다시 "켜기"로 원상복구

**테스트 중 발견해서 바로 고친 실수**: `signup.html`에 새로 추가한 HTML 주석 안에 `{% if %}`라는 글자를 실제 예시처럼 그대로 적어놨는데, Jinja2가 이걸 "진짜 조건문 태그"로 착각해서 화면이 아예 안 뜨는 오류가 났습니다(6단계에서 `login.html`을 만들 때 겪었던 것과 정확히 같은 종류의 실수를 이번에 또 저질렀습니다). HTML 주석 안에서는 Jinja 문법을 예시로 보여줄 때 `{{`, `{%` 같은 기호를 그대로 쓰면 안 되고, "조건문"처럼 말로 풀어 써야 안전하다는 걸 다시 한번 확인했습니다. 실제 화면(브라우저 스크린샷)으로 확인하는 절차가 없었다면 이 오류를 놓치고 지나갔을 수도 있습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`app_settings` 표 추가, Supabase에 실제 실행됨)
- [db.py](../../db.py) (`list_users`, `delete_user`, `get_signup_enabled`, `set_signup_enabled` 4개 함수 추가)
- [app.py](../../app.py) (`/signup` GET·POST에 On/Off 검사 추가, `/api/status`에 `users`·`signup_enabled` 포함, `/api/users/delete`·`/api/settings/signup` 라우트 신규 추가)
- [templates/dashboard.html](../../templates/dashboard.html) ("회원가입 설정", "등록된 회원" 섹션 추가)
- [templates/signup.html](../../templates/signup.html) (회원가입 꺼짐 상태일 때의 안내 문구 추가)
- [public/js/dashboard.js](../../public/js/dashboard.js) (`renderUsersTable`, `renderSignupStatus`, `deleteUser`, `toggleSignup` 추가)
- [public/css/dashboard.css](../../public/css/dashboard.css), [public/css/auth.css](../../public/css/auth.css) (새 버튼/안내 문구 스타일 추가)
- [tests/test_db.py](../../tests/test_db.py) (새 함수 4개에 대한 단위 테스트 7개 추가, 총 22개 통과)

---

## 13단계 — 회원 전용 대시보드 (`/dashboard`) 추가

### 우리가 한 일
1. 관리자 대시보드 주소를 `/dashboard` → `/admin/dashboard`로 옮김 (`/admin/login`, `/admin/logout`과 같은 묶음으로 정리)
2. `/dashboard` 주소를 **회원 전용** 화면으로 새로 만듦 — 인사말 + "최근 로그인 기록" · "프로필 보기·수정" 두 버튼
3. `users` 표에 `name`(표시 이름) 칸을 새로 추가
4. `/login` 로그인 성공 시 이제 실제로 "로그인 상태"가 만들어지도록 회원용 세션을 도입 (예전엔 성공해도 그냥 메시지만 보여주고 끝이었음)
5. [db.py](../../db.py)에 `get_user_by_id`, `update_user_profile`, `list_attempts_by_username` 3개 함수 추가

### 왜 했는가 (쉬운 설명)

**이번 요청에서 가장 큰 변화 — "로그인 성공"이 진짜 로그인이 됨**
1~12단계까지, `/login`에서 아이디·비밀번호가 맞아도 실제로는 "성공했다"는 메시지 하나만 보여주고 브라우저는 아무 상태도 기억하지 못했습니다(관리자 로그인만 `session`에 저장돼서 "로그인 유지"가 됐습니다). 이건 이 프로젝트의 원래 목적이 "브루트포스를 감지하는 것"이지 "실사용 회원 서비스를 만드는 것"이 아니었기 때문입니다. 그런데 이번에 "로그인하면 내 대시보드로 이동한다"는 기능을 요청받으면서, `/login`도 관리자처럼 진짜 세션을 만들어야 하는 상황이 됐습니다.

**관리자 세션과 회원 세션을 완전히 다른 이름으로 나눈 이유**
`session["admin_username"]`(관리자)과 `session["username"]`(회원)이라는 서로 다른 이름(키)을 씁니다. 같은 브라우저의 `session`이라는 저장 공간 자체는 하나지만, 그 안에 서로 다른 이름표를 붙인 값을 각각 넣어둘 수 있습니다 — 마치 사물함 하나 안에 "관리자용 열쇠"와 "회원용 열쇠"를 따로 걸어두는 것과 같습니다. 그래서 관리자가 자기 컴퓨터에서 테스트 삼아 회원으로도 로그인해보면, 그 브라우저는 "관리자이면서 동시에 회원"인 상태가 됩니다 — 실제로 이 프로젝트를 검증할 때 이 상황이 그대로 재현됐고, 문제없이 각자 자기 대시보드에만 접근되는 걸 확인했습니다.

**"문지기"(데코레이터)를 왜 하나 더 만들었나 — `member_login_required`**
5단계에서 만든 `login_required`는 `session["admin_username"]`만 확인합니다. 이걸 그대로 회원 페이지에도 쓰면, 회원으로만 로그인한 사람이 관리자 페이지에 들어가려다 막히는 게 아니라 애초에 회원 페이지조차 관리자 로그인을 요구하게 되는 문제가 생깁니다. 그래서 구조는 완전히 똑같지만 **확인하는 세션 키만 다른** `member_login_required`를 새로 만들었습니다. "판정 로직 하나를 여러 곳에서 재사용"이 아니라 "비슷하지만 다른 규칙 두 개를 각자 명확하게 분리"한 사례입니다.

**주소를 왜 이렇게 다시 정리했나 — `/dashboard`와 `/admin/dashboard`**
사용자가 요청한 그대로 `/dashboard`는 회원용, `/admin/dashboard`는 관리자용으로 나눴습니다. 원래 `/admin/login`, `/admin/logout`처럼 관리자 관련 주소는 전부 `/admin/` 아래 모여있었는데, 유일하게 대시보드만 `/dashboard`라는 이름을 쓰고 있어서 이번 기회에 `/admin/dashboard`로 옮겨 통일성도 함께 맞췄습니다.

**"표시 이름"을 로그인 아이디와 다른 칸으로 따로 만든 이유**
로그인 아이디(`username`)는 `login_attempts`(로그인 시도 기록) 등 여러 표에서 문자열 그대로 서로 연결해 쓰이는 값입니다. 만약 이 값을 회원이 자유롭게 바꿀 수 있게 하면, 바꾸기 전의 기록과 바꾼 후의 기록이 서로 다른 사람처럼 보이게 되어 감사 기록이 뒤죽박죽됩니다. 그래서 로그인 아이디는 그대로 고정해두고, 화면에 보여줄 "표시 이름"만 별도 칸으로 추가해서 자유롭게 수정할 수 있게 했습니다. 프로필 화면에서 아이디 입력창을 `readonly`(읽기 전용)로 만들어둔 것도 같은 이유입니다.

**본인 로그인 기록만 보여줄 때, "전체를 가져와서 걸러내기"가 아니라 "처음부터 본인 것만 물어보기"를 쓴 이유**
`list_attempts_by_username(username)`은 Supabase에 "이 아이디의 기록만 줘"라고 조건을 걸어서 물어봅니다. 만약 대신 "전체 기록을 다 가져온 뒤, 화면에서 본인 것만 추려서 보여준다"는 방식을 썼다면, 코드에 실수가 하나만 생겨도 다른 회원의 기록이 그대로 노출될 위험이 있습니다. "애초에 서버가 본인 것만 데이터베이스에 물어보게" 만들면 이런 실수 자체가 구조적으로 불가능해집니다 — 12단계에서 `list_users()`가 비밀번호 칸을 아예 요청하지 않았던 것과 같은 원칙입니다.

### 실제 코드 함께 보기

**`app.py` — 관리자 문지기와 회원 문지기를 나란히 놓고 비교**
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


def member_login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view
```
확인하는 세션 키(`admin_username` vs `username`)와 로그인 화면으로 보내는 주소(`admin_login` vs `login`)만 다르고, 나머지 구조는 완전히 같습니다.

**`app.py` — 로그인 성공 시 회원 세션을 만드는 부분**
```python
if success:
    user = db.get_user_by_username(username)
    session["username"] = username
    session["user_id"] = user["id"]
    return redirect(url_for("member_dashboard"))
```
`user_id`를 따로 저장해두는 이유는, 프로필을 수정할 때 "아이디 문자열"이 아니라 "변하지 않는 회원 번호"로 정확히 어느 행을 고칠지 짚어내기 위해서입니다(아이디가 바뀌지 않는 지금 구조에서는 둘 다 써도 되지만, 번호가 더 안전한 습관입니다).

**`db.py` — 이메일 중복을 "본인 제외"하고 확인하는 부분**
```python
def update_user_profile(user_id: int, name: str, email: str) -> bool:
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
```
`.neq("id", user_id)`가 없으면, 회원이 원래 자기 이메일 그대로 "수정"(사실상 변경 없음)만 눌러도 "이미 다른 사람이 쓰고 있다"는 이상한 오류가 뜨게 됩니다. 본인은 검사 대상에서 빼줘야 한다는 걸 놓치기 쉬운, 실제로 자주 나오는 실수 유형입니다.

**`app.py` — Jinja 필터로 시각 표시를 다듬는 부분**
```python
def format_kr_time(iso_string: str) -> str:
    return datetime.fromisoformat(iso_string).strftime("%Y-%m-%d %H:%M:%S")

app.jinja_env.filters["kr_time"] = format_kr_time
```
```html
<td>{{ attempt.attempted_at | kr_time }}</td>
```
관리자 대시보드는 시각 표시를 자바스크립트(`formatTime()`)로 다듬었지만, 회원 화면은 폴링 없이 서버가 한 번에 그려주는 방식이라 자바스크립트가 필요 없습니다. 대신 파이썬 쪽에 "필터"라는 재사용 가능한 변환 함수를 등록해서, 템플릿에서 `| kr_time`처럼 파이프(`|`) 기호로 간단히 적용할 수 있게 했습니다.

### 실제로 테스트한 것
1. 회원가입 → 로그인 → 이제는 메시지만 뜨는 대신 `/dashboard`로 실제 이동해서 "안녕하세요, OOO님 반갑습니다" 인사말이 뜨는지 확인
2. "최근 로그인 기록 보기" → 본인 시도만 정확히 나오는지(다른 회원 기록이 안 섞이는지) 확인
3. "프로필 보기·수정" → 표시 이름과 이메일을 실제로 바꾸고 저장 → Supabase에 정확히 그 값이 저장됐는지 직접 조회로 재확인
4. 이미 다른 회원이 쓰고 있는 이메일로 바꾸려고 시도 → 정확히 거부되는지 확인
5. 회원 로그아웃 → 다시 `/dashboard` 접근 시 `/login`으로 돌아가는지 확인
6. **양방향 격리 확인**: 회원 세션으로 `/admin/dashboard`·`/api/status`에 접근 시도 → 차단됨. 관리자 세션(회원 로그인은 안 한 상태)으로 `/dashboard` 접근 시도 → `/login`으로 돌아감. 둘 다 의도대로 서로의 영역을 침범하지 못하는 것을 확인
7. `pytest tests/` 27개 전부 통과 확인, 테스트 데이터는 확인 후 정리

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`users` 표에 `name` 칸 추가, Supabase에는 `alter table`로 반영)
- [db.py](../../db.py) (`get_user_by_id`, `update_user_profile`, `list_attempts_by_username` 3개 함수 추가)
- [app.py](../../app.py) (`member_login_required` 신규, `/login` 성공 시 세션 생성, `/admin/dashboard`로 관리자 대시보드 이전, `/dashboard`·`/dashboard/history`·`/dashboard/profile`·`/dashboard/logout` 회원 라우트 신규, `kr_time` Jinja 필터 추가)
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html) (`dashboard.html`에서 이름 변경 + 제목을 "관리자 대시보드"로 명확화)
- [templates/member_dashboard.html](../../templates/member_dashboard.html), [templates/member_history.html](../../templates/member_history.html), [templates/member_profile.html](../../templates/member_profile.html) (신규)
- [public/css/member.css](../../public/css/member.css) (신규 — 회원 화면 전용 스타일)
- [tests/test_db.py](../../tests/test_db.py) (새 함수 3개에 대한 단위 테스트 5개 추가, 총 27개 통과)

### 실사용 중 발견한 버그 2개 수정

바로 위 내용을 만든 직후, 실제로 화면을 써보다가 두 가지 문제가 나와서 바로 고쳤습니다.

### 문제 1 — 회원 대시보드 카드가 화면 위쪽에 붙어있음
`main { max-width: 480px; margin: 0 auto; }`는 카드를 **가로**로만 가운데 정렬할 뿐, **세로**로는 그냥 topbar 바로 아래부터 시작하는 위치에 그려집니다. 로그인 화면(`auth.css`)은 애초에 `body`를 `display: flex; align-items: center;`로 만들어서 세로 중앙까지 잡아뒀는데, 회원 화면(`member.css`)에는 이 처리가 빠져 있었습니다.

**고친 방법**: `body`를 세로(topbar + main)로 쌓는 flex 컨테이너로 만들고, `main`이 `flex: 1`로 남은 세로 공간을 전부 차지하게 한 뒤 그 안에서 카드를 가로·세로 모두 중앙에 배치했습니다.
```css
body {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
}
main {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
}
```

### 문제 2 — 프로필에서 "표시 이름"을 바꿔도 인사말에 안 보임
원인은 저장이 안 된 게 아니라(프로필 화면에는 새 이름이 정확히 떠 있었습니다), **인사말이 애초에 `name`이 아니라 로그인 아이디(`session["username"]`)만 보도록 만들어져 있었기 때문**입니다. 바로 위에서 "표시 이름"을 만들 때, 인사말은 여전히 예전 방식(아이디) 그대로 두고 넘어갔던 게 원인입니다.

**고친 방법**: `member_dashboard()`가 이제 실제 회원 정보를 다시 조회해서, 표시 이름이 설정돼 있으면 그 이름을, 비어있으면(기본값 `''`) 그때만 아이디로 대신 보여줍니다.
```python
user = db.get_user_by_id(session["user_id"])
display_name = user["name"] if user["name"] else session["username"]
```

### 검증 도중 발견한 세 번째 문제(덤) — 삭제된 회원의 세션이 그대로 남아있으면 화면이 그냥 에러로 죽음
이 문제를 확인하려고 실제 브라우저로 테스트하다가, 우연히 **관리자가 이미 삭제해버린 계정으로 로그인된 브라우저 탭**에서 `/dashboard`에 들어가니 화면 전체가 파이썬 에러(`TypeError: 'NoneType' object is not subscriptable`)로 멈추는 걸 발견했습니다. `db.get_user_by_id()`가 `None`을 돌려주는데, 코드가 "당연히 회원 정보가 있을 것"이라고 가정하고 `user["name"]`처럼 바로 꺼내 쓰려다가 터진 것입니다.

12단계에서 만든 "회원 삭제" 기능과 정확히 맞물리는 상황입니다 — 관리자가 회원을 지운 그 순간에도, 그 회원이 다른 탭에서는 여전히 "로그인된 상태"인 세션 쿠키를 들고 있을 수 있습니다. 그래서 `member_dashboard()`, `member_profile()`처럼 회원 정보를 직접 조회하는 화면마다 "혹시 못 찾으면 세션을 지우고 다시 로그인하라고 안내"하는 코드를 추가했습니다.
```python
def _logout_missing_member():
    session.pop("username", None)
    session.pop("user_id", None)
    flash("계정 정보를 찾을 수 없습니다. 다시 로그인해주세요.")
    return redirect(url_for("login"))
```
`member_login_required`(문지기)는 "세션에 값이 들어있는지"만 확인하지, 그 값이 가리키는 회원이 **지금도 실제로 존재하는지**는 확인하지 않습니다. 그래서 문지기를 통과한 뒤에도 각 화면이 한 번 더 실제 데이터를 확인하고, 없으면 이 함수로 안전하게 빠져나가도록 만들었습니다. 이 버그는 사용자가 요청한 내용에 포함되지 않았지만, 두 가지를 검증하는 과정에서 우연히 발견해서 함께 고쳤습니다.

**버그 수정으로 추가·변경된 파일**
- [public/css/member.css](../../public/css/member.css) (`body`/`main`을 flex 기반 중앙 정렬로 변경)
- [templates/member_dashboard.html](../../templates/member_dashboard.html) (`username` → `display_name`으로 변경)
- [app.py](../../app.py) (`member_dashboard()`가 표시 이름을 반영하도록 수정, `_logout_missing_member()` 신규 + `member_dashboard()`·`member_profile()`에 적용)

---

## 14단계 — 로그인 IP의 국가·도시 표시 (ip-api.com 연동)

### 우리가 한 일
1. Supabase에 `ip_locations`라는 "IP 위치 조회 결과 캐시" 표를 새로 추가
2. [geoip.py](../../geoip.py)라는 새 파일을 만들어 ip-api.com(무료 IP 위치 조회 서비스)과의 통신을 전담시킴
3. 회원 본인의 로그인 기록(`/dashboard/history`), 관리자 대시보드의 "최근 로그인 시도" 표 양쪽에 **위치** 칸 추가

### 왜 했는가 (쉬운 설명)

**alert.py와 완전히 같은 패턴 — 외부 서비스 하나당 파일 하나**
4단계에서 Slack과 대화하는 일을 `alert.py` 하나에 몰아넣었던 것과 똑같은 이유로, ip-api.com과 대화하는 일도 `geoip.py`라는 새 파일 하나에 몰아넣었습니다. `db.py`(Supabase 전담), `alert.py`(Slack 전담), `geoip.py`(ip-api.com 전담) — "외부 서비스 하나당 파일 하나"라는 규칙이 이 프로젝트 전체에 일관되게 적용되고 있는 셈입니다.

**왜 굳이 "캐시 표"까지 새로 만들었나 — 9단계의 교훈을 그대로 적용**
관리자 대시보드의 "최근 로그인 시도" 표는 **10초마다** 최대 50줄을 다시 그립니다. 만약 이 50줄 하나하나에 대해 매번 ip-api.com에 새로 물어본다면, ip-api.com의 무료 사용 한도(분당 45건)를 순식간에 넘깁니다. 9단계에서 "Supabase 쿼터를 지키려고 폴링 주기를 늘렸던" 것과 똑같은 종류의 문제가, 이번엔 Supabase가 아니라 ip-api.com을 상대로 또 발생할 뻔한 것입니다.

그래서 한 번 조회한 IP는 Supabase의 `ip_locations` 표에 저장해두고, 다음부터는 ip-api.com 대신 이 저장값을 먼저 확인합니다. 브루트포스 공격은 보통 같은 IP에서 반복되기 때문에(같은 컴퓨터가 계속 틀리게 로그인을 시도하는 것이므로), 실제로는 새로운 IP를 조회하는 일이 생각보다 훨씬 적습니다.

**"IP 하나씩" 대신 "IP 목록을 통째로" 캐시에 물어본 이유**
`db.get_cached_ip_locations(ips)`는 IP 목록 전체를 `.in_()`이라는 조건으로 **한 번의 쿼리**로 조회합니다. 만약 대신 IP 50개를 하나씩 50번 따로 물어봤다면, ip-api.com 호출은 아꼈어도 이번엔 Supabase 요청이 50배로 늘어나서 결국 같은 문제를 다른 곳(Supabase)에 옮겨놓은 꼴이 됩니다. "여러 개를 조회할 땐 하나씩 묻지 말고 한꺼번에 물어봐라"는 원칙이 이번에도 그대로 적용됐습니다.

**조회에 실패한 IP도 캐시해두는 이유**
`127.0.0.1`(로컬 개발 중 계속 나오는 주소)은 ip-api.com에 물어봐도 항상 "reserved range"(예약된 사설 주소라 위치가 없음) 응답만 돌아옵니다. 이걸 캐시하지 않으면, 로컬 개발 중 대시보드를 열어둘 때마다 `127.0.0.1`에 대해 "안 되는 걸 알면서도" 계속 헛되이 ip-api.com에 새로 물어보게 됩니다. 그래서 "실패했다"는 사실 자체도 캐시에 저장해서, 같은 실패를 반복하지 않게 했습니다.

### 실제 코드 함께 보기

**`geoip.py` — 캐시를 먼저 확인하고, 없는 것만 새로 조회하는 핵심 로직**
```python
def get_locations(ips: list[str]) -> dict[str, dict]:
    unique_ips = list(dict.fromkeys(ips))  # 순서는 유지하면서 중복만 제거
    cached = db.get_cached_ip_locations(unique_ips)

    result = {}
    for ip in unique_ips:
        if ip in cached:
            result[ip] = cached[ip]
            continue
        location = _fetch_location(ip)
        db.save_ip_location(ip, location["country"], location["region_name"], location["city"], location["lookup_failed"])
        result[ip] = location
    return result
```
`dict.fromkeys(ips)`는 "리스트 안의 중복된 값을 지우되, 원래 순서는 그대로 유지해라"는 파이썬의 흔한 관용구입니다(딕셔너리는 같은 키를 두 번 넣어도 하나만 남기는 성질을 이용한 것). 캐시에 있으면(`if ip in cached`) 바로 꺼내 쓰고, 없을 때만 `_fetch_location()`으로 진짜 외부 API를 호출합니다.

**`app.py` — 회원 화면과 관리자 화면이 똑같은 함수를 공유**
```python
def _attach_locations(attempts: list[dict]) -> list[dict]:
    ips = [attempt["ip_address"] for attempt in attempts]
    locations = geoip.get_locations(ips)
    for attempt in attempts:
        attempt["location"] = geoip.format_location(locations[attempt["ip_address"]])
    return attempts
```
이 함수 하나를 `member_history()`(회원 본인 기록, 최대 20줄)와 `api_status()`(관리자 대시보드, 최대 50줄) 양쪽에서 그대로 가져다 씁니다. "로그인 시도 목록에 위치 정보를 붙인다"는 동작은 두 화면에서 완전히 똑같기 때문에, 코드를 두 번 쓰지 않고 한 곳에만 만들어뒀습니다.

### 실제로 테스트한 것
로컬 개발 환경은 전부 `127.0.0.1`이라 실제 위치가 안 나오므로, `TRUST_FORWARDED_FOR`(5단계에서 만든 데모 전용 플래그)를 잠깐 켜서 "나는 1.1.1.1에서 접속했다"고 가짜 헤더를 보내는 방식으로 검증했습니다.
1. 회원가입 → 가짜 IP(`1.1.1.1`)로 로그인 → `/dashboard/history`에 실제로 "Australia · South Brisbane"이 표시되는지 확인
2. 같은 IP로 두 번째 요청을 보냈을 때, ip-api.com을 또 부르지 않고 캐시에서 바로 가져오는지 (`test_get_locations_uses_cache_and_skips_external_call` 단위 테스트로 확인 + `ip_locations` 표에 실제로 값이 저장된 것도 직접 조회로 재확인)
3. 관리자 대시보드의 "최근 로그인 시도" 표에도 **위치** 칸이 추가되어, 과거에 쌓여있던 진짜 로그인 기록들의 위치까지 한꺼번에 조회되어 표시되는지 확인 — 신기하게도 예전 기록(스키마 변경 전에 이미 저장돼 있던 것들)도 IP만 있으면 새로 조회가 되어 자연스럽게 위치가 채워졌습니다
4. `pytest tests/` 36개 전부 통과 확인(신규 10개: `test_db.py` 4개 + `test_geoip.py` 6개), 테스트에 쓴 캐시 데이터는 확인 후 정리

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`ip_locations` 표 추가, Supabase에 실제 실행됨)
- [geoip.py](../../geoip.py) (신규 — ip-api.com 연동 전담 파일)
- [db.py](../../db.py) (`get_cached_ip_locations`, `save_ip_location` 2개 함수 추가)
- [app.py](../../app.py) (`_attach_locations()` 신규, `member_history()`·`api_status()`에 적용)
- [templates/member_history.html](../../templates/member_history.html), [templates/admin_dashboard.html](../../templates/admin_dashboard.html) (위치 칸 추가)
- [public/js/dashboard.js](../../public/js/dashboard.js) (`renderAttemptsTable`에 위치 칸 추가)
- [public/css/member.css](../../public/css/member.css) (표가 카드보다 넓어질 경우를 위한 가로 스크롤 처리 추가)
- [tests/test_geoip.py](../../tests/test_geoip.py) (신규 — 캐시 활용 여부, 문자열 조립 검증), [tests/test_db.py](../../tests/test_db.py) (캐시 조회/저장 함수 테스트 추가)

## 15단계 — 화면 리디자인 (색상 토큰 + 자연스러운 페이지 전환)

### 우리가 한 일
1. Claude Artifact로 새 디자인(색상·글꼴·화면 전환)을 먼저 미리보기로 만들어서 확인받음
2. [public/css/tokens.css](../../public/css/tokens.css)라는 새 파일을 만들어 색상·글꼴·전환 효과를 한 곳에 모음
3. `auth.css`/`dashboard.css`/`member.css`가 하드코딩된 색 대신 `tokens.css`의 값을 가져다 쓰도록 전부 수정
4. 템플릿 6개에 `tokens.css`를 새로 링크
5. 실제 페이지 이동이 자연스럽게 넘어가도록 `@view-transition` 규칙 추가 (새 라이브러리 없음)

### 왜 했는가 (쉬운 설명)

**코드를 짜기 전에 "미리보기"부터 만든 이유**
디자인은 "말로 설명 듣고 상상하기"보다 "직접 보고 결정하기"가 훨씬 정확합니다. 그래서 실제 프로젝트 파일을 건드리기 전에, Claude의 Artifact 기능으로 새 색상·글꼴이 적용된 화면과 전환 효과를 미리 만들어서 먼저 확인받았습니다. "마음에 든다"는 답을 받은 뒤에야 실제 코드에 반영했습니다 — 큰 폭의 디자인 변경을 코드로 먼저 만들었다가 "역시 별로다"라며 되돌리는 것보다 훨씬 안전한 순서입니다.

**왜 `tokens.css`라는 파일을 새로 만들었나**
3단계에서 "임계값·윈도우·잠금시간 같은 숫자를 `config.py` 한 곳에 모아두면, 나중에 하나만 고쳐도 전체에 반영된다"고 설명했던 것과 똑같은 원리를 색상에 적용했습니다. 예전에는 `#2563eb`(파랑) 같은 색이 `auth.css`, `dashboard.css`, `member.css` 세 파일에 흩어져 있었는데, 이러면 "포인트 색을 바꾸고 싶다"는 요청 하나에도 세 파일을 전부 찾아다니며 고쳐야 하고 하나라도 빠뜨리면 화면마다 색이 미묘하게 달라지는 사고가 납니다. 지금은 `tokens.css`의 `--accent: #0f9b8b;` 한 줄만 바꾸면 로그인·회원·관리자 화면 전체의 포인트 색이 한꺼번에 바뀝니다.

**CSS 변수(`var(--이름)`)가 정확히 뭘 하는 건가**
`tokens.css`에 `--accent: #0f9b8b;`라고 적어두면, 다른 CSS 파일에서 `background: var(--accent);`라고 쓸 때마다 그 자리에 `#0f9b8b`가 그대로 대입됩니다. 마치 코드에서 상수 하나를 여러 곳에서 재사용하는 것과 같은 개념을, CSS 안에서도 쓸 수 있게 해주는 문법입니다. 이 방식이 통하려면 `tokens.css`를 각 페이지의 실제 스타일 파일(`auth.css` 등)보다 **먼저** `<link>`로 걸어둬야 합니다 — 그래야 변수가 정의된 다음에 그 변수를 쓰는 코드가 실행되는 순서가 맞습니다. 그래서 템플릿마다 `tokens.css` 링크를 `auth.css`/`dashboard.css`/`member.css` 링크보다 한 줄 위에 추가했습니다.

**IP·시각에 왜 다른 글꼴(고정폭 글꼴)을 따로 지정했나**
`203.0.113.14`처럼 숫자가 나열되는 값은 일반 글꼴로 쓰면 숫자마다 폭이 달라서 여러 줄을 세로로 비교하기 불편합니다. "고정폭(monospace) 글꼴"은 모든 글자가 같은 너비를 차지해서, 표에서 자릿수를 눈으로 맞춰보기 쉬워집니다. 처음에는 "표의 몇 번째 칸"으로 지정하려고 했는데, 표마다(최근 로그인 시도/회원 목록/관리자 로그인 기록) 칸 순서가 달라서 잘못된 칸에 적용될 뻔했습니다 — 그래서 "몇 번째 칸인가"가 아니라 `.mono`라는 이름의 클래스를 실제 IP·시각 값을 그리는 자바스크립트·템플릿 쪽에서 직접 붙이는 방식으로 바꿨습니다. "위치에 의존하지 말고 의미에 의존하라"는, 흔히 저지르는 실수를 피하는 방법입니다.

**"화면 전환"에 자바스크립트 라이브러리를 안 쓴 이유**
페이지가 바뀔 때 자연스럽게 넘어가는 효과를 만드는 방법은 여러 가지가 있는데, 그중 일부(예: barba.js 같은 도구)는 실제 페이지 이동을 가로채서 자바스크립트로 흉내 내는 방식이라, 로그인 폼 제출(POST 요청)처럼 "진짜 페이지 이동이 필요한 동작"과 부딪힐 위험이 있습니다. 대신 이번에 쓴 **View Transitions API**는 브라우저에 이미 내장된 기능이라 CSS 세 줄만 추가하면 되고, `/login` → `/dashboard`처럼 진짜로 새 페이지를 요청하는 이동에도 그대로 적용됩니다.
```css
@view-transition {
    navigation: auto;
}
```
이 기능을 아직 모르는 구형 브라우저는 이 규칙을 그냥 못 알아듣고 넘어갈 뿐이라서, "지원 안 하면 어떡하지?"를 걱정하지 않고 켜둘 수 있습니다(점진적 향상 — progressive enhancement).

### 실제로 확인한 것
1. 로그인·회원가입·회원 대시보드·로그인 기록·프로필·관리자 대시보드 6개 화면 전부 새 팔레트가 적용되는지 브라우저로 확인
2. 콘솔에 폰트 로딩 실패 등 오류가 없는지 확인
3. `getComputedStyle()`로 실제 적용된 글꼴이 의도한 대로(`Sora`, `Public Sans`)인지 코드로 재확인
4. `document.startViewTransition`이 실제로 함수로 존재하는지(브라우저가 View Transitions API를 지원하는지) 확인
5. `pytest tests/` 36개 재실행 — 색·글꼴만 바꿨을 뿐 파이썬 로직은 손대지 않았으므로 전부 그대로 통과

**테스트 중 우연히 발견해서 고친 문제**: 이번 작업과 무관하게, 이전 단계에서 검증용으로 껐던 "회원가입" 설정이 켜지지 않은 채로 남아있던 걸 발견했습니다. 로컬과 라이브 사이트가 같은 Supabase를 쓰기 때문에, 이 상태로는 실제 배포 사이트에서도 회원가입이 막혀 있었던 것입니다. 바로 다시 켜뒀습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [public/css/tokens.css](../../public/css/tokens.css) (신규 — 색상·글꼴·전환 효과 토큰)
- [public/css/auth.css](../../public/css/auth.css), [public/css/dashboard.css](../../public/css/dashboard.css), [public/css/member.css](../../public/css/member.css) (하드코딩된 색 → `var(--이름)`으로 전환)
- [public/js/dashboard.js](../../public/js/dashboard.js) (IP·시각 칸에 `.mono` 클래스 추가)
- [templates/login_form.html](../../templates/login_form.html), [templates/signup.html](../../templates/signup.html), [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [templates/member_dashboard.html](../../templates/member_dashboard.html), [templates/member_history.html](../../templates/member_history.html), [templates/member_profile.html](../../templates/member_profile.html) (`tokens.css` 링크 추가, `member_history.html`은 `.mono` 클래스도 추가)
- Supabase `app_settings.signup_enabled`를 다시 `true`로 되돌림 (이번 작업과 무관한 발견)

## 16단계 — 다크모드 지원

### 우리가 한 일
1. `tokens.css`에 `@media (prefers-color-scheme: dark)` 블록을 추가해, 방문자의 OS/브라우저가 "어두운 화면" 설정이면 자동으로 어두운 배색이 적용되게 함
2. 상단바(topbar) 전용 색 토큰(`--topbar-bg`, `--topbar-ink`)을 새로 분리
3. 버튼 눌림(hover) 배경색을 `--accent-ink`가 아니라 새로 만든 `--accent-strong`으로 바꿈

### 왜 했는가 (쉬운 설명)

**토큰을 이미 나눠뒀던 덕분에, 다크모드는 한 파일만 고치면 끝났다**
15단계에서 색을 전부 `tokens.css`의 `var(--이름)`으로 통일해뒀던 게 여기서 그대로 힘을 발휘했습니다. `auth.css`/`dashboard.css`/`member.css`는 "이 값이 라이트 모드 값인지 다크 모드 값인지" 전혀 몰라도 됩니다 — 그냥 `var(--canvas)`라고만 적어두면, 지금 어떤 모드인지에 따라 `tokens.css`가 알아서 다른 값을 넣어줍니다. 만약 색을 각 CSS 파일에 직접 적어뒀다면, 다크모드를 넣기 위해 세 파일을 전부 다시 고쳐야 했을 것입니다.

**작업 중 발견한 문제 — "글자색"과 "배경색"을 같은 토큰으로 재사용했던 실수**
관리자·회원 화면 상단의 어두운 막대(topbar)가 `var(--ink)`(원래 "글자색"을 담아두려고 만든 토큰)를 배경색으로 재사용하고 있었습니다. 라이트 모드에서는 `--ink`가 어두운 색이라 우연히 잘 어울렸지만, 다크모드에서는 `--ink`가 "밝은" 글자색으로 뒤집히기 때문에 그 값을 그대로 배경에 쓰면 상단바가 하얗게 깨져버립니다. 그래서 상단바 전용 색(`--topbar-bg`, `--topbar-ink`)을 따로 만들어서, 테마가 바뀌어도 상단바만큼은 항상 같은 색을 유지하도록 분리했습니다.

**또 다른 문제 — 한 토큰이 "글자색"과 "버튼 눌림 배경색" 두 가지 역할을 겸하고 있었음**
`--accent-ink`는 원래 "옅은 배경 위에 놓이는 글자색"(예: 링크 색)으로 쓰려고 만든 토큰인데, 로그인 버튼을 마우스로 누르고 있을 때(`:hover`) 배경색으로도 재사용되고 있었습니다. 다크모드에서 `--accent-ink`를 밝은 색으로 바꾸면, "글자색"으로 쓰일 땐 잘 어울리지만 "버튼 눌림 배경"으로 쓰일 땐 그 위에 항상 흰 글자(`color: white`)가 얹혀 있어서 밝은 배경 + 흰 글자 = 안 보이는 조합이 되어버립니다. 그래서 "버튼 배경으로만 쓰이는 진한 틸 색"을 `--accent-strong`이라는 별도 이름으로 떼어내고, 테마가 바뀌어도 이 값은 고정해뒀습니다.

**색 하나를 두 가지 역할로 겸용하면 안 되는 이유**
이번 두 문제 모두 같은 원인에서 나왔습니다 — "지금 당장 색이 비슷해 보인다"는 이유로 서로 다른 목적(글자색 vs 배경색, 상단바 vs 일반 텍스트)에 같은 토큰을 재사용한 것입니다. 라이트 모드 하나만 있을 때는 문제가 드러나지 않다가, 다크모드처럼 "값이 뒤집히는" 상황이 추가되자마자 바로 깨졌습니다. 그래서 토큰 이름은 "지금 어떤 색인가"가 아니라 "어떤 역할로 쓰이는가"를 기준으로 지어야 안전합니다.

### 실제로 확인한 것
브라우저의 "다크모드로 보기" 기능으로 화면 6개(로그인/회원가입/회원 대시보드/로그인 기록/프로필/관리자 대시보드) 전부를 다시 확인했습니다. 상단바가 라이트모드와 똑같이 짙은 색으로 유지되는지, 버튼에 얹힌 흰 글자가 모든 상태(기본/눌림)에서 잘 읽히는지, 표의 "성공"/"실패" 색이 어두운 배경에서도 구분되는지까지 눈으로 확인했습니다. `pytest tests/` 36개는 색만 바뀐 것이라 그대로 통과했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [public/css/tokens.css](../../public/css/tokens.css) (다크모드 팔레트 추가, `--topbar-bg`/`--topbar-ink`/`--accent-strong` 신규)
- [public/css/dashboard.css](../../public/css/dashboard.css), [public/css/member.css](../../public/css/member.css) (`.topbar`가 새 토큰을 쓰도록 수정)
- [public/css/auth.css](../../public/css/auth.css), [public/css/member.css](../../public/css/member.css) (버튼 눌림 배경을 `--accent-strong`으로 수정)
