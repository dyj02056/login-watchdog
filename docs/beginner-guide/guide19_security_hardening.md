# 19단계 — 추가 보안 점검 (관리자 로그인 방어 · 버전 고정 · 가입 빈도 제한)

[◀ 18단계](guide18_security_review.md) · [전체 목차](beginner-guide.md) · [20단계 ▶](guide20_board.md)

> 18단계에서 보안 점검 8건을 고친 뒤, 프로젝트 전체를 다시 한번 훑어보며 그때 놓쳤던 부분이 없는지 재점검했습니다. 이번엔 3건을 찾아 전부 고쳤습니다. 특히 1번은 **18단계에서 "로그인 브루트포스 방어"를 그렇게 열심히 만들어놓고도, 정작 관리자 로그인 화면 자체에는 그 방어를 붙이는 걸 깜빡했던** 큰 구멍이었습니다.

### 우리가 한 일 (발견 → 수정 순서)

| # | 문제 | 심각도 | 성격 |
|---|---|---|---|
| 1 | 관리자 로그인(`/admin/login`)에 브루트포스 방어 전무 | 🔴 긴급 | 4단계·5단계 보완 |
| 2 | `requirements.txt` 버전 미고정 | 🟡 보통 | 1단계 보완 |
| 3 | `/signup`에 요청 빈도 제한 없음 | 🟡 보통 | 5단계 보완 |

---

## 1. 관리자 로그인은 무제한으로 비밀번호를 시도할 수 있었다

### 무엇이 문제였는가
[app.py](../../app.py)의 `admin_login_submit()`은 로그인 시도를 `admin_login_log` 표에 기록만 할 뿐, `detector.is_suspicious()`나 `soar.enforce_lockout()`을 전혀 호출하지 않았습니다. 감시 대상인 `/login`은 같은 IP가 60초 안에 5회 초과 실패하면 5분간 잠기는데, 정작 더 중요한 관리자 로그인 화면(`/admin/login`)에는 이 방어가 하나도 붙어있지 않았습니다.

5단계에서 "관리자 로그인과 감시 대상 로그인을 완전히 다른 코드 경로로 분리했다"고 설명했었는데, 그때는 "관리자가 잠기면 안 되니까 일부러 분리했다"는 의도였습니다. 그런데 이게 지나쳐서, **잠금 자체가 필요 없다는 뜻이 아니라 관리자 로그인용 잠금 판정을 아예 안 만들었다**는 게 이번에 드러난 진짜 문제였습니다.

### 왜 위험한가
이 프로젝트에서 관리자 계정 하나가 뚫리면 벌어질 수 있는 일은 이렇습니다.
- `/api/users/delete`로 회원 전체 삭제
- `/api/unlock`으로 잠긴 공격자 IP를 스스로 풀어주기
- `/api/settings/signup`으로 회원가입을 꺼서 서비스 자체를 막기

정문(회원 로그인)은 5번 틀리면 막아두면서, 이 모든 걸 할 수 있는 금고실 문(관리자 로그인)은 하루 종일 몇만 번을 두드려도 아무도 막지 않는 것과 같은 상태였습니다. 짧은 비밀번호나 흔한 비밀번호를 썼다면 자동화된 사전 대입 공격(dictionary attack)만으로도 뚫릴 수 있는 구조였습니다.

### 어떻게 고쳤는가
`/login`(`login_submit()`)과 완전히 같은 3단계 흐름을 `/admin/login`(`admin_login_submit()`)에도 그대로 적용했습니다.

```python
# app.py
@app.route("/admin/login", methods=["POST"])
def admin_login_submit():
    soar.try_release_expired_lockouts()
    ip = get_request_ip()

    if detector.is_locked(ip):
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
        return render_template("login_form.html", form_action=url_for("admin_login_submit"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    success = db.verify_admin_credentials(username, password)
    db.log_admin_attempt(username, success, ip)

    if success:
        session["admin_username"] = username
        return redirect(url_for("admin_dashboard"))

    suspicious, failure_count = detector.is_admin_suspicious(ip)
    if suspicious:
        soar.enforce_lockout(ip, failure_count)
        flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")
    else:
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template("login_form.html", form_action=url_for("admin_login_submit"))
```

여기서 한 가지 막힌 부분이 있었습니다 — 기존 `detector.is_suspicious(ip)`를 그대로 재사용하면 안 됐습니다. 왜냐하면 그 함수는 `login_attempts`(감시 대상 로그인 기록) 표만 세는데, 관리자 로그인 실패는 `admin_login_log`라는 **다른** 표에 쌓이기 때문입니다. 그래서 관리자 전용 판정 함수를 하나 더 만들었습니다.

```python
# db.py — admin_login_log 표를 세는 전용 함수
def count_recent_admin_failures(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
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
```
```python
# detector.py — is_suspicious()와 판단 기준(초과 여부)은 동일, 보는 표만 다름
def is_admin_suspicious(ip: str) -> tuple[bool, int]:
    failure_count = db.count_recent_admin_failures(ip)
    return failure_count > FAILURE_THRESHOLD, failure_count
```

한편 **"지금 잠긴 상태인가"**(`detector.is_locked`)는 감시 대상 로그인과 똑같은 `lockouts` 표를 그대로 씁니다 — IP 단위 잠금이라는 이 프로젝트의 기존 설계(알려진 제한사항, README 참고) 그대로, 관리자 로그인으로 잠긴 IP는 회원 로그인에서도 함께 막히고 그 반대도 마찬가지입니다. "누구를 어떻게 잠글지 판단하는 재료(실패 횟수)"는 경로마다 따로 세지만, "잠겼다는 사실 자체"는 하나의 상태판을 공유하는 셈입니다.

### 실제로 확인한 것
`pytest tests/test_app.py`에 관리자 로그인 전용 테스트 3개를 추가해 확인했습니다.
1. IP가 이미 잠긴 상태라면 `verify_admin_credentials`가 아예 호출되지 않고 곧바로 "잠긴 계정입니다"가 뜨는지
2. 실패 횟수가 임계값을 넘기면 `soar.enforce_lockout`이 정확히 1번 호출되는지
3. 방어 로직을 추가하고도 정상적인 관리자 로그인(올바른 비밀번호)은 여전히 세션이 만들어지고 대시보드로 이동하는지

`pytest tests/ -v` 전체(59개)를 돌려 전부 통과하는 것도 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [db.py](../../db.py) (`count_recent_admin_failures` 신규 추가)
- [detector.py](../../detector.py) (`is_admin_suspicious` 신규 추가)
- [app.py](../../app.py) (`admin_login_submit()`에 잠금 판정·실행 로직 추가)
- [tests/test_app.py](../../tests/test_app.py), [tests/test_detector.py](../../tests/test_detector.py) (관련 테스트 추가)

---

## 2. `requirements.txt`에 라이브러리 버전이 고정돼 있지 않았다

### 무엇이 문제였는가
[requirements.txt](../../requirements.txt)에는 `flask`, `flask-wtf`, `supabase`처럼 이름만 적혀 있고, 정확히 몇 번 버전을 쓸지는 지정돼 있지 않았습니다.

### 왜 필요한가
`pip install -r requirements.txt`를 실행하는 시점마다 "그 순간 가장 최신인 버전"이 설치됩니다. 오늘 내 컴퓨터에 설치한 버전과, 몇 달 뒤 다른 팀원이 새로 설치한 버전이 서로 다를 수 있다는 뜻입니다. 라이브러리 쪽에서 동작 방식이 조금이라도 바뀌면(흔히 있는 일입니다), "내 컴퓨터에서는 되는데 다른 사람 컴퓨터에서는 안 되는" 원인을 찾기 어려운 문제가 생길 수 있습니다. 8단계에서 만든 CI([.github/workflows/tests.yml](../../.github/workflows/tests.yml))도 매번 새로 설치하는 방식이라 이 위험에서 자유롭지 않았습니다.

### 어떻게 고쳤는가
로컬에서 실제로 설치해서 `pytest tests/` 51개가 전부 통과하는 걸 확인한 버전 그대로, `==`로 정확히 못박았습니다.

```
# 수정 전
flask
flask-wtf
supabase
...
```
```
# 수정 후
flask==3.1.3
flask-wtf==1.3.0
supabase==2.31.0
python-dotenv==1.2.3
requests==2.34.2
pytest==9.1.1
gunicorn==26.2.0
```

이렇게 해두면 언제, 어느 컴퓨터에서 설치하든 항상 똑같은 버전 조합이 깔리므로 "버전 차이 때문에 생긴 문제인지 아닌지"를 원천적으로 고민할 필요가 없어집니다.

### 실제로 확인한 것
버전을 고정한 뒤 `pytest tests/ -v`를 다시 실행해 59개(1번 항목에서 추가된 8개 포함) 전부 통과하는 것을 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [requirements.txt](../../requirements.txt) (전체 7개 패키지 버전 고정)

---

## 3. 회원가입(`/signup`)에는 요청 빈도 제한이 전혀 없었다

### 무엇이 문제였는가
[app.py](../../app.py)의 `signup_submit()`은 아이디 형식, 이메일 형식, 비밀번호 길이(18단계 5번 항목)까지는 검증하지만, "**같은 사람이 짧은 시간에 몇 번이나 가입을 시도했는지**"는 전혀 세지 않았습니다.

### 왜 필요한가
검증 규칙이 아무리 꼼꼼해도, 그 검증을 통과하는 값을 자동으로 계속 만들어내는 스크립트를 막을 방법이 없다는 뜻입니다. 예를 들어 `user0001`, `user0002`, `user0003`... 처럼 규칙에 맞는 아이디를 자동 생성해서 1초에 수십 번씩 `/signup`에 쏘면, `users` 표가 가짜 계정으로 순식간에 가득 찰 수 있습니다. `/login`은 5회 초과 실패에 잠긴다는 방어가 있는데, 계정을 만드는 문 자체는 무제한으로 열려있던 셈입니다.

### 어떻게 고쳤는가
로그인 브루트포스 탐지(`login_attempts` + `count_recent_failures`)와 똑같은 구조를, 회원가입 전용으로 하나 더 만들었습니다. 다만 대상이 다릅니다 — 로그인은 "실패만" 세지만, 가입 시도는 성공/실패 여부와 무관하게 "시도 자체"를 셉니다(가입 검증에 계속 걸리는 값을 반복 제출하는 것도 남용이기 때문입니다).

```sql
-- docs/schema.sql에 추가
create table signup_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);
create index idx_signup_attempts_ip_time on signup_attempts (ip_address, attempted_at);
```
```python
# config.py
SIGNUP_RATE_LIMIT = int(os.environ.get("SIGNUP_RATE_LIMIT", 5))
```
```python
# db.py
def log_signup_attempt(ip: str) -> None:
    get_client().table("signup_attempts").insert({"ip_address": ip}).execute()

def count_recent_signup_attempts(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
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
```
```python
# detector.py
def is_signup_rate_limited(ip: str) -> bool:
    return db.count_recent_signup_attempts(ip) >= SIGNUP_RATE_LIMIT
```

로그인 판정(`is_suspicious`)은 "초과(>)"부터 수상하다고 봐줬지만(정상 사용자도 비밀번호를 몇 번은 틀릴 수 있으므로), 가입 시도 판정(`is_signup_rate_limited`)은 "이상(>=)"이면 바로 막습니다 — 정상적인 사용자가 짧은 시간에 가입 화면을 5번 넘게 제출할 이유는 거의 없기 때문에, 더 엄격한 기준을 적용했습니다.

```python
# app.py — signup_submit()
if not db.get_signup_enabled():
    flash("현재 회원가입이 잠시 중단되어 있습니다.")
    return render_template("signup.html", signup_enabled=False)

ip = get_request_ip()
if detector.is_signup_rate_limited(ip):
    flash("너무 많은 가입 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
    return render_template("signup.html", signup_enabled=True)
db.log_signup_attempt(ip)

username = request.form.get("username", "").strip()
# ... (이후 검증 로직은 그대로)
```

### 실제로 확인한 것
`tests/test_detector.py`에 경계값 테스트(4번은 통과, 5번째부터 차단)를 추가하고, `tests/test_app.py`에는 "빈도 제한에 걸리면 `log_signup_attempt`조차 호출되지 않고 즉시 안내 메시지가 뜨는지" 확인하는 통합 테스트를 추가했습니다. 기존에 있던 `/signup` 검증 테스트 3개도 새로 추가된 `is_signup_rate_limited`/`log_signup_attempt` 호출을 가짜로 채워넣도록 손봐야 했는데(그렇게 안 하면 진짜 Supabase로 요청이 나가려고 시도해 테스트가 실패합니다), 이것도 4단계에서 배운 것과 같은 패턴(monkeypatch로 "이 테스트가 실제로 거치는 것만" 최소한으로 막기)을 그대로 적용했습니다.

**Supabase 반영 — 코드만으로는 끝나지 않는 마지막 단계**: `signup_attempts` 표는 [docs/schema.sql](../schema.sql)에 SQL로 적어두는 것과, 실제로 운영 중인 Supabase 프로젝트 안에 그 표가 존재하는 것이 서로 다른 일입니다(2단계에서 설명한 것과 같은 이유 — 코드 배포가 데이터베이스 표까지 자동으로 만들어주지는 않습니다). 그래서 Supabase 대시보드에 직접 들어가서 아래 순서로 반영했습니다.
1. **SQL Editor** → **New query**에 `docs/schema.sql`의 `signup_attempts` 부분(표 생성 + 인덱스 생성 SQL 2줄)만 붙여넣고 실행(Run)
2. **Table Editor**에서 `signup_attempts`가 표 목록에 새로 나타난 것을 확인
3. 이미 만들어져 있던 다른 7개 표는 건드리지 않았습니다 — `docs/schema.sql` 전체를 다시 실행하면 "표가 이미 존재한다"는 오류가 나므로, 이번에 새로 추가된 부분만 골라서 실행해야 합니다.

이 단계까지 마치고 나서야 실제 배포된 사이트에서도 `/signup` 요청 빈도 제한이 완전히 동작합니다 — 코드(`app.py`/`db.py`/`detector.py`)는 이미 완성돼 있었지만, 그 코드가 의존하는 표가 실제 데이터베이스에 없으면 `/signup` 요청 자체가 "그런 표가 없다"는 오류로 실패했을 것입니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`signup_attempts` 표 추가, Supabase 프로젝트에도 SQL Editor로 직접 반영 완료)
- [config.py](../../config.py) (`SIGNUP_RATE_LIMIT` 추가)
- [db.py](../../db.py) (`log_signup_attempt`, `count_recent_signup_attempts` 추가)
- [detector.py](../../detector.py) (`is_signup_rate_limited` 추가)
- [app.py](../../app.py) (`signup_submit()`에 빈도 제한 체크 추가)
- [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py) (관련 테스트 추가)

---

## 이번 단계에서 얻은 교훈

18단계에서 "로그인 브루트포스 방어"를 주제로 프로젝트를 점검했으면서도, 정작 관리자 로그인이라는 **같은 주제의 사각지대**를 놓쳤다는 게 이번 점검의 가장 큰 배움이었습니다. 보안 점검은 "이 기능이 있는가"만 볼 게 아니라 "이 기능이 있어야 할 자리에 전부 다 있는가"까지 확인해야 한다는 걸 보여주는 사례였습니다. `/login`과 `/admin/login`처럼 겉모습은 같은데 속 코드가 분리된 화면일수록, 한쪽만 고치고 다른 쪽은 빠뜨리기 쉽습니다.

또한 3번 항목에서는 "코드를 고쳤다고 끝이 아니라, 그 코드가 의존하는 데이터베이스 표까지 실제 운영 환경에 반영해야 완성"이라는 2단계의 교훈을 다시 한번 확인했습니다.

### 이 단계 전체에서 바뀐 파일 모음
- [app.py](../../app.py), [config.py](../../config.py), [db.py](../../db.py), [detector.py](../../detector.py)
- [docs/schema.sql](../schema.sql)
- [requirements.txt](../../requirements.txt)
- [tests/test_app.py](../../tests/test_app.py), [tests/test_detector.py](../../tests/test_detector.py)
- [README.md](../../README.md) (schema.sql 테이블 개수 안내를 실제 개수에 맞게 수정)
