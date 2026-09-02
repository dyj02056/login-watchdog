# 5단계 — `app.py` (모든 부품을 실제 웹사이트로 엮는 "정문")

[◀ 4단계](guide04_response.md) · [전체 목차](beginner-guide.md) · [6단계 ▶](guide06_templates.md)


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
