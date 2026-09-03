# 18단계 — 오류 발견 및 해결 (보안 점검 8건 수정)

[◀ 17단계](guide17_theme.md) · [전체 목차](beginner-guide.md)

> 지금까지의 단계는 전부 "새 기능을 만든다"는 방향이었습니다. 이 단계는 처음으로 방향이 다릅니다 — **이미 만들어둔 코드를 되짚어보며 "어디가 잘못됐는가"를 찾고 고치는 단계**입니다. 보안 관점에서 프로젝트 전체를 점검(리뷰)해서 문제 8건을 찾아냈고, 심각한 것부터 순서대로 전부 수정했습니다.
>
> 이 중 3건(2, 3, 8번)은 지금까지 어떤 단계에서도 다룬 적 없는 **완전히 새로운 주제**입니다 — 그래서 이 단계 안에서 별도 절로 나눠 자세히 설명합니다. 나머지 5건은 이전 단계에서 이미 만든 코드를 보완하는 성격이라, 해당 단계와 연결해서 설명합니다.

### 우리가 한 일 (발견 → 수정 순서)

| # | 문제 | 심각도 | 성격 |
|---|---|---|---|
| 1 | 관리자 대시보드 Stored XSS | 🔴 긴급 | 6단계·12단계 보완 |
| 2 | CSRF 방어 전무 | 🔴 긴급 | **신규 주제** |
| 3 | 검증 스크립트(`bruteforce_sim.py`, `daily_report.py`) 미구현 | 🟠 중요 | **신규 주제** |
| 4 | `app.py` 통합 테스트 부재 | 🟠 중요 | 8단계 보완 |
| 5 | 회원가입 입력 검증 부족 | 🟡 보통 | 3단계·5단계 보완 |
| 6 | 세션 쿠키 보안 옵션 미설정 | 🟡 보통 | 5단계 보완 |
| 7 | 개발용 서버로 운영 배포 위험 | 🟡 보통 | 5단계·10단계 보완 |
| 8 | CI(자동 테스트) 파이프라인 없음 | 🟡 보통 | **신규 주제** |

아래에서 각 항목을 "무엇이 문제였는가 → 왜 위험한가 → 어떻게 고쳤는가 → 실제로 확인한 것" 순서로 설명합니다.

---

## 1. Stored XSS — 관리자 대시보드에서 스크립트가 실행되는 문제

### 무엇이 문제였는가
[public/js/dashboard.js](../../public/js/dashboard.js)의 `renderAttemptsTable`, `renderUsersTable` 같은 함수들이 서버에서 받아온 값(로그인 시도의 `username`, 회원 목록의 `username`/`email`)을 아무 가공 없이 `innerHTML`에 문자열 그대로 끼워넣고 있었습니다.

```js
// 수정 전
tbody.innerHTML = attempts.map((attempt) => `
    <tr>
        <td>${attempt.username}</td>
        ...
```

### 왜 위험한가
`innerHTML`은 넘겨준 문자열을 "글자"가 아니라 "HTML 태그"로 해석합니다. 만약 `username` 값이 `<img src=x onerror="...">` 같은 문자열이라면, 브라우저는 이걸 진짜 `<img>` 태그로 만들고 `onerror` 안의 자바스크립트를 실제로 실행해버립니다. 그런데 이 `username`은 원래 회원가입 폼이나 `/login` 로그인 시도에 누구나 자유롭게 입력할 수 있는 값입니다 — 즉 **로그인조차 성공할 필요 없이**, 로그인 실패 시도의 아이디 칸에 이런 문자열만 넣어도 `login_attempts` 표에 그대로 저장되고, 관리자가 대시보드를 열람하는 순간 **관리자의 로그인 세션으로 스크립트가 실행**됩니다. 그 스크립트는 관리자가 볼 수 있는 모든 API(`/api/unlock`, `/api/users/delete`, `/api/settings/signup`)를 관리자 대신 호출할 수 있습니다 — 공격자가 회원 전체를 삭제하거나, 자기 IP의 잠금을 몰래 풀거나, 회원가입을 꺼버리는 것도 가능해집니다.

### 어떻게 고쳤는가
"악성 문자열이 애초에 저장되지 않게 막는다"보다 근본적인 방어는 **"화면에 그릴 때 절대 태그로 해석되지 않게 만든다"**입니다(입력을 아무리 열심히 막아도 놓치는 경로가 항상 있을 수 있으므로, 출력 시점의 방어가 최종 안전망입니다). `<`, `>`, `&`, `"`, `'`처럼 HTML에서 특별한 의미를 갖는 글자를 각각의 "문자 이름"(HTML 엔티티)으로 바꿔주는 `escapeHtml()` 함수를 만들어, 표에 꽂아넣는 모든 사용자 데이터(아이디, 이메일, IP, 위치 문자열)를 이 함수에 반드시 통과시켰습니다.

```js
function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}
```
```js
// 수정 후
<td>${escapeHtml(attempt.username)}</td>
```
`&lt;`는 브라우저에게 "이건 태그를 여는 `<`가 아니라, 그냥 화면에 `<`라는 글자를 보여달라는 뜻이다"라고 알려주는 표기법입니다. 그래서 `<img src=x onerror=...>`라는 값이 오더라도 브라우저는 이걸 진짜 이미지 태그로 만들지 않고, 사용자 눈에 "`<img src=x onerror=...>`"라는 글자 그대로 보여줍니다 — 여전히 표에는 보이지만, 더 이상 "실행되는 코드"가 아니라 "읽기만 하는 텍스트"가 됩니다.

### 실제로 확인한 것
1. 로컬 서버를 띄우고 `/login`에 아이디를 `<img src=x onerror=alert(String.fromCharCode(88,83,83))>`로, 비밀번호는 아무거나 넣어 로그인을 실패시켰습니다(회원가입을 거칠 필요조차 없었습니다 — 5번 항목의 입력 검증은 회원가입에만 적용되고, `/login` 시도 기록에는 원래부터 제한이 없었기 때문에, 이 경로가 오히려 XSS를 확인하기에 더 정확한 재현 방법이었습니다).
2. 관리자로 로그인해서 대시보드를 열어보니, "최근 로그인 시도" 표에 그 문자열이 **글자 그대로** 나타났습니다. 브라우저 개발자 도구로 `document.querySelectorAll('#attempts-table-body img').length`를 확인해보니 `0`— 실제 `<img>` 태그는 단 하나도 만들어지지 않았고, 얼럿(alert) 창도 뜨지 않았습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [public/js/dashboard.js](../../public/js/dashboard.js) (`escapeHtml()` 신규 추가, 4개 렌더 함수의 모든 사용자 데이터 삽입 지점에 적용)

---

## 2. CSRF 방어 전무 (신규 주제)

### CSRF가 뭔가요?
CSRF(Cross-Site Request Forgery, "사이트 간 요청 위조")는 "로그인된 사람이 자기도 모르게 원치 않는 요청을 보내게 만드는" 공격입니다. 브라우저는 어떤 사이트로 요청을 보내든, 그 사이트의 쿠키(로그인 세션 정보)를 **자동으로 함께** 실어 보냅니다 — 이게 "로그인 유지"가 되는 원리이기도 하지만, 동시에 악용될 여지이기도 합니다.

비유하자면 이렇습니다. 회사 정문에 "직원증(세션 쿠키)을 소지한 사람만 통과"라는 규칙만 있다고 상상해보세요. 누군가 여러분의 직원증을 몰래 복사한 게 아니라, **여러분이 직접 그 직원증을 목에 걸고** 다른 건물(악성 웹사이트)에 잠깐 들어갔는데, 그 건물 안의 누군가가 여러분 몰래 여러분의 손을 잡아 우리 회사 정문 버튼을 눌러버린 것과 같습니다 — 문지기(로그인 여부 확인)는 직원증을 보고 "본인이 맞다"고 통과시켜주지만, 실제로 그 행동을 하려고 "의도"한 건 여러분이 아니었습니다.

### 무엇이 문제였는가
[templates/](../../templates)의 모든 POST 폼(로그아웃, 로그인, 회원가입, 프로필 수정)과 대시보드가 자바스크립트로 호출하는 JSON API(`/api/unlock`, `/api/users/delete`, `/api/settings/signup`) 어디에도 "이 요청이 정말 우리 화면에서 나온 게 맞는지" 확인하는 장치가 전혀 없었습니다. `requirements.txt`에도 CSRF를 막아주는 라이브러리(Flask-WTF 등)가 아예 없었습니다.

### 왜 위험한가
관리자가 대시보드에 로그인된 상태로(로그아웃하지 않은 채) 다른 탭에서 악성 페이지를 열었다고 가정해봅시다. 그 페이지 안에 눈에 안 보이는 폼이나 스크립트가 `fetch("https://우리사이트/api/users/delete", {method: "POST", body: JSON.stringify({user_id: 3})})`처럼 우리 사이트를 향해 요청을 보내도록 숨겨져 있다면, 브라우저는 "이 요청이 우리사이트로 가는구나"라고만 판단하고 관리자의 세션 쿠키를 자동으로 함께 실어 보냅니다. 서버 입장에서는 "로그인된 관리자의 요청"과 구분이 안 되므로 그대로 실행해버립니다 — 관리자가 그 페이지를 열어봤다는 사실 자체 말고는 아무것도 하지 않았는데도 회원이 삭제될 수 있습니다.

### 어떻게 고쳤는가
`Flask-WTF`라는 라이브러리의 `CSRFProtect`를 도입했습니다. 동작 원리는 이렇습니다.

1. 서버가 화면(HTML)을 그려줄 때마다, 그 방문자의 세션에 묶인 무작위 토큰(`csrf_token`)을 하나 발급해서 화면 안에 몰래 심어둡니다.
2. 그 화면에서 나가는 모든 POST 요청은 이 토큰 값을 함께 제출해야 합니다.
3. 서버는 요청이 들어올 때마다 "이 토큰이, 이 세션에게 내가 방금 발급해준 진짜 토큰이 맞는지" 확인합니다.

악성 페이지는 애초에 우리 서버가 그 방문자에게 무슨 토큰을 발급했는지 알아낼 방법이 없습니다(다른 사이트가 우리 사이트의 페이지 내용을 읽어올 수 없도록 브라우저가 원천적으로 막아두기 때문입니다). 그래서 위조된 요청은 토큰이 아예 없거나 틀린 값이 되어 자동으로 거부됩니다.

```python
# app.py
from flask_wtf import CSRFProtect

csrf = CSRFProtect(app)
```

**일반 폼(HTML `<form>`)**에는 눈에 안 보이는 숨김 입력창 하나만 추가하면 됩니다 — 브라우저가 폼을 제출할 때 다른 입력 칸들과 함께 자동으로 이 값도 실어 보내줍니다.
```html
<form method="post" action="{{ url_for('member_logout') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button type="submit">로그아웃</button>
</form>
```

**자바스크립트 `fetch()` API 호출**은 폼이 아니라서 숨김 입력창을 쓸 수 없습니다. 대신 화면 어딘가에 토큰 값을 심어두고(`<meta>` 태그), 자바스크립트가 그 값을 읽어서 요청의 헤더(`X-CSRFToken`)에 실어 보내도록 했습니다.
```html
<!-- admin_dashboard.html의 <head> -->
<meta name="csrf-token" content="{{ csrf_token() }}">
```
```js
// dashboard.js
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

await fetch("/api/unlock", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
    body: JSON.stringify({ ip: ip }),
});
```

토큰이 없거나 틀렸을 때 사용자에게 그냥 딱딱한 오류 화면(기본값)을 보여주는 대신, 이 프로젝트의 다른 화면들과 통일된 방식(flash 메시지 + 이전 화면으로 안내)으로 처리하도록 오류 처리기도 추가했습니다.
```python
@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    flash("보안 토큰이 만료되었거나 올바르지 않습니다. 다시 시도해주세요.")
    return redirect(request.referrer or url_for("login")), 400
```

### 실제로 확인한 것
1. 토큰 없이 `curl`로 `/login`에 직접 POST를 보내봤더니 `400 Bad Request`로 즉시 거부되는 것을 확인했습니다 — 위조된 요청이 로그인 로직에 도달하지도 못한다는 뜻입니다.
2. 화면을 먼저 정상적으로 GET으로 받아와 그 안의 진짜 토큰을 꺼내 함께 보내면, 이전과 동일하게 정상 동작하는 것도 확인했습니다.
3. **이 수정 때문에 실제로 다른 스크립트 하나가 고장 나는 걸 발견하고 같이 고쳤습니다** — 아래 3번 항목의 `bruteforce_sim.py`가 CSRF 토큰 없이 `/login`에 직접 POST를 보내고 있어서, 이 수정 이후로는 전부 400으로 막혀 시뮬레이션 자체가 실패했습니다. 이건 "새 보안 장치가 실제로 작동하고 있다"는 방증이기도 했지만, 동시에 그 스크립트도 브라우저처럼 먼저 화면을 열어 토큰을 받아오도록 고쳐야 했습니다 (3번 항목 참고).

### 이 단계에서 만들어지거나 바뀐 파일
- [requirements.txt](../../requirements.txt) (`flask-wtf` 추가)
- [app.py](../../app.py) (`CSRFProtect` 등록, `CSRFError` 처리기 추가)
- [templates/login_form.html](../../templates/login_form.html), [templates/signup.html](../../templates/signup.html), [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [templates/member_dashboard.html](../../templates/member_dashboard.html), [templates/member_history.html](../../templates/member_history.html), [templates/member_profile.html](../../templates/member_profile.html) (폼 7개에 `csrf_token` 숨김 필드 추가, 대시보드에는 `<meta>` 태그 추가)
- [public/js/dashboard.js](../../public/js/dashboard.js) (`fetch()` 3곳에 `X-CSRFToken` 헤더 추가)

---

## 3. 검증 스크립트 미구현 (신규 주제)

### 무엇이 문제였는가
`plan.md`는 "`bruteforce_sim.py`로 6번째 시도에서 계정이 잠기는지 검증한다"는 절차를 명시하고 있었지만, [scripts/bruteforce_sim.py](../../scripts/bruteforce_sim.py)와 [scripts/daily_report.py](../../scripts/daily_report.py) 둘 다 실제로는 **0바이트(빈 파일)**였습니다. 즉 문서에는 "이렇게 검증한다"고 적혀있는데 실제로 그 검증을 자동으로 돌려볼 방법이 없었고, 데모 시나리오를 재현하려면 매번 사람이 로그인 폼에 직접 6번 틀린 비밀번호를 입력해야 했습니다.

### 왜 필요한가
사람이 직접 6번 클릭해서 확인하는 건 매번 번거롭고, 무엇보다 "정말 6번째에 잠기는지" 같은 **경계값**은 사람이 셀 때 실수하기 쉽습니다. 자동화된 스크립트가 있으면 코드를 수정할 때마다(예: `FAILURE_THRESHOLD` 값을 바꾸거나, `login_submit()` 로직을 리팩터링할 때) 매번 똑같은 조건으로 빠르게 재검증할 수 있습니다.

### 어떻게 고쳤는가

**`bruteforce_sim.py`** — `research.md`에 이미 적혀있던 스펙(`/login`에 5회 순차 실패 요청 후, 6번째 응답에 "잠긴 계정" 문구가 포함되는지 확인)대로 만들었습니다. `requests` 라이브러리로 `/login`에 틀린 비밀번호를 반복 제출하고, 응답 본문에 잠금 문구가 있는지 확인합니다.

```python
def run(base_url: str, username: str, attempts: int) -> bool:
    session = requests.Session()
    csrf_token = fetch_csrf_token(session, base_url)  # 2번 항목의 CSRF 토큰을 먼저 받아옴

    response = None
    for i in range(1, attempts + 1):
        response = attempt_login(session, base_url, username, "wrong-password-on-purpose", csrf_token)
        ...

    if response is not None and LOCKED_MESSAGE in response.text:
        print(f"[OK] {attempts}번째 시도에서 '{LOCKED_MESSAGE}' 문구를 확인했습니다.")
        return True
    ...
```

`research.md`에 명시된 안전 원칙("팀이 소유한 로컬 서버만 대상으로 하며, 실제 서비스에는 절대 사용 금지")도 코드로 강제했습니다 — `--host`로 `localhost`/`127.0.0.1`이 아닌 주소를 지정하면, `--i-know-what-im-doing`이라는 명시적인 플래그 없이는 아예 실행을 거부합니다.
```python
if not is_local_host(args.host) and not args.i_know_what_im_doing:
    print("[FAIL] 이 스크립트는 팀이 소유한 로컬 서버만 대상으로 실행하도록 만들어졌습니다. ...", file=sys.stderr)
    sys.exit(2)
```

**`daily_report.py`** — 원래 기획(`research.md` 질문 8)은 "LLM(AI)이 로그를 읽고 자연어로 요약해주는" 기능이었지만, `plan.md`에 "프롬프트 설계 등 세부 사양이 정해지지 않아 이번 계획 범위에서 제외"라고 **의도적으로 미뤄둔 결정**이 이미 있었습니다. 그 결정 자체를 뒤집을 근거는 없었으므로, AI 연동까지 구현하지는 않았습니다. 다만 파일이 0바이트로 방치된 것과 "AI 요약이 아직 없다"는 것은 별개의 문제라고 판단해, **AI 없이도 바로 쓸 수 있는 숫자 집계 기반 요약**을 우선 채워넣었습니다(전체 시도 수, 성공/실패 수, 가장 실패가 많았던 IP 상위 5개, 이 기간에 잠긴 IP 목록). 이 집계 로직은 나중에 LLM 연동을 붙일 때도 "요약할 원본 데이터를 모으는 부분"으로 그대로 재사용할 수 있습니다.

이 스크립트가 필요로 하는 조회 함수 2개(`list_attempts_since`, `list_lockouts_since`)는 db.py의 원칙("데이터베이스 접근은 반드시 db.py를 거친다", 3단계 참고)을 지켜서 `db.py`에 추가했습니다.

```python
# db.py
def list_attempts_since(hours: int = 24) -> list[dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = get_client().table("login_attempts").select("*").gte("attempted_at", cutoff).execute()
    return res.data
```

### 실제로 확인한 것
1. `bruteforce_sim.py`를 처음 실행했을 때 **모든 시도가 400으로 실패**하는 걸 발견했습니다 — 원인은 방금 만든 2번 항목의 CSRF 방어였습니다. 스크립트가 브라우저처럼 먼저 화면을 GET으로 열어 토큰을 받아오도록 고친 뒤 재실행하니, 6번째 시도에서 정확히 "잠긴 계정입니다" 문구가 확인되고 종료 코드도 `0`(성공)으로 나왔습니다.
2. Windows 콘솔(cp949 코드페이지)에서 실행하면 `—`(줄표)나 `✔`/`✘` 같은 특수 유니코드 기호가 `UnicodeEncodeError`로 스크립트 자체를 죽여버리는 것도 발견했습니다 — 이 프로젝트가 Windows 환경에서 개발되고 있으므로 실제 사용 환경에서 바로 재현되는 문제였습니다. 모든 출력 문구를 일반 ASCII 문자(`-`, `[OK]`, `[FAIL]`)로 바꿔서 해결했습니다.
3. `daily_report.py`를 처음 실행했을 때 `ModuleNotFoundError: No module named 'db'`가 발생하는 것도 발견했습니다 — `scripts/` 폴더 안에서 실행하면 파이썬이 프로젝트 루트에 있는 `db.py`를 못 찾기 때문이었습니다. 스크립트 맨 위에서 프로젝트 루트를 `sys.path`에 직접 추가하도록 고쳐서 해결했고, 이후 재실행하니 실제 Supabase 데이터를 정상적으로 집계해서 리포트를 출력하는 것을 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [scripts/bruteforce_sim.py](../../scripts/bruteforce_sim.py) (신규 구현)
- [scripts/daily_report.py](../../scripts/daily_report.py) (신규 구현 — 숫자 집계 버전)
- [db.py](../../db.py) (`list_attempts_since`, `list_lockouts_since` 추가)
- [tests/test_db.py](../../tests/test_db.py) (위 두 함수에 대한 단위 테스트 추가)

---

## 4. `app.py` 통합 테스트 부재

### 무엇이 문제였는가
8단계에서 만든 테스트는 `detector`/`db`/`soar`/`geoip`/`config` 각각의 함수 하나하나를 따로 검증하는 **단위 테스트**뿐이었습니다(그 단계에서 "진짜 서버 없이 코드만 자동으로 검증"으로 범위를 의도적으로 그렇게 한정했습니다). 하지만 부품 하나하나가 멀쩡해도 "조립"이 잘못되면(예: 라우트에 `@login_required`를 빼먹거나, 세션 키 이름을 잘못 씀) 단위 테스트는 여전히 전부 통과합니다 — 실제로 오늘 고친 XSS·CSRF 같은 문제도 "조립된 상태"에서만 드러나는 종류였습니다.

### 어떻게 고쳤는가
Flask가 제공하는 `test_client()`를 이용해, 진짜 서버를 띄우지 않고도 실제 라우트에 요청을 보내볼 수 있는 통합 테스트를 [tests/test_app.py](../../tests/test_app.py)에 추가했습니다. `app.py`는 모듈을 불러오는(import하는) 순간 `os.environ["SECRET_KEY"]`를 곧바로 읽고 `db.ensure_bootstrap_admin()`으로 실제 Supabase 접속까지 시도하기 때문에, [tests/conftest.py](../../tests/conftest.py)에 가짜 환경변수를 채우고 그 함수를 무력화하는 `flask_app` fixture를 만들어 이 문제를 먼저 해결했습니다.

```python
# tests/conftest.py
@pytest.fixture
def flask_app(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-only-secret-key")
    ...
    import db
    monkeypatch.setattr(db, "ensure_bootstrap_admin", lambda: None)
    sys.modules.pop("app", None)
    import app as app_module
    app_module.app.config.update(TESTING=True)
    yield app_module.app
```

추가한 테스트는 login_required 문지기가 실제로 막아주는지, 로그인 성공/실패/잠금 흐름이 세션과 잠금 함수를 정확히 호출하는지, 회원가입 검증(5번 항목)이 실제로 악성 아이디를 걸러내는지, CSRF 토큰이 없으면 정말 400으로 막히는지까지 12개 테스트로 확인합니다.

### 실제로 확인한 것
`pytest tests/ -v`로 전체 51개(기존 39개 + 신규 12개)를 실행해 전부 통과하는 것을 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [tests/conftest.py](../../tests/conftest.py) (신규 — `flask_app`/`client` fixture)
- [tests/test_app.py](../../tests/test_app.py) (신규 — 통합 테스트 12개)

---

## 5. 회원가입 입력 검증 부족

### 무엇이 문제였는가
[app.py](../../app.py)의 `signup_submit()`은 "칸이 비어있지 않은지"와 "비밀번호 확인이 일치하는지"만 확인했습니다. 이메일이 진짜 이메일 형식인지, 비밀번호가 너무 짧지 않은지, 아이디에 이상한 문자가 들어있지 않은지는 전혀 확인하지 않았습니다 — 1번 항목(XSS)의 근본 원인 중 하나이기도 했습니다.

### 어떻게 고쳤는가
정규식(regex) 패턴 3개를 만들어 `signup_submit()`에서 순서대로 검사하도록 했습니다.
```python
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")  # 영문/숫자/밑줄만, 3~20자
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")  # "글자@글자.글자" 최소 형식
MIN_PASSWORD_LENGTH = 8
```
아이디에 영문자·숫자·밑줄만 허용함으로써, `<`나 `"` 같은 HTML 특수문자가 애초에 회원 계정에 저장될 수 없게 됩니다 — 1번 항목(출력 시점 이스케이프)과 이번 항목(입력 시점 검증)을 함께 적용하는 것을 "심층 방어(defense in depth)"라고 부릅니다. 다만 이 검증은 회원가입 폼에만 적용되고 `/login` 시도 기록에는 적용되지 않으므로(로그인 시도는 실패해도 기록은 남아야 하기 때문에 형식 제한을 걸 수 없습니다), 1번 항목의 출력 시점 이스케이프가 여전히 최종 방어선입니다.

### 실제로 확인한 것
통합 테스트(4번 항목)로 `<img src=x onerror=...>` 형태의 아이디, 8자 미만 비밀번호가 각각 정확한 안내 메시지와 함께 거부되고 `db.create_user()`가 아예 호출되지 않는 것을 확인했습니다. 정상적인 입력은 그대로 통과해서 계정이 생성되는 것도 함께 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [app.py](../../app.py) (`USERNAME_PATTERN`/`EMAIL_PATTERN`/`MIN_PASSWORD_LENGTH` 및 `signup_submit()` 검증 로직 추가)

---

## 6. 세션 쿠키 보안 옵션 미설정

### 무엇이 문제였는가
`app.py`는 `SECRET_KEY`만 설정하고, 세션 쿠키의 세부 보안 옵션(`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAMESITE` 등)은 전혀 손대지 않아 Flask 기본값에만 의존하고 있었습니다.

### 어떻게 고쳤는가
```python
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
```
- `HTTPONLY`: 자바스크립트(`document.cookie`)가 세션 쿠키를 읽지 못하게 막습니다(Flask 기본값도 True지만, "당연히 켜져 있겠지"에 기대지 않고 명시적으로 적어뒀습니다).
- `SAMESITE="Lax"`: 다른 사이트에서 시작된 요청에는 쿠키를 잘 안 실어 보내게 만들어, 2번 항목(CSRF)의 보조 방어선 역할을 합니다.
- `SECURE`: HTTPS 연결에서만 쿠키를 전송하도록 강제합니다. 로컬 개발 서버는 보통 HTTP(암호화 없음)로 뜨기 때문에, 로컬에서까지 이 값을 켜두면 쿠키가 아예 전달되지 않아 로그인 자체가 깨집니다 — 그래서 `FLASK_ENV=production`일 때(Vercel 배포 환경)만 켜지도록 조건을 걸었습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [app.py](../../app.py) (세션 쿠키 설정 3줄 추가)

---

## 7. 개발용 서버로 운영 배포 위험

### 무엇이 문제였는가
`app.py` 맨 아래 `app.run(debug=True, port=port)`가 무조건 `debug=True`로 켜져 있었습니다. Flask 공식 문서는 디버그 모드의 대화형 디버거가 "브라우저에서 임의의 파이썬 코드를 실행할 수 있는 콘솔"을 열어준다고 명시하며, 운영 환경에서 절대 켜두면 안 된다고 경고합니다.

### 어떻게 고쳤는가
```python
debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
port = int(os.environ.get("PORT", 5000))
app.run(debug=debug, port=port)
```
기본값을 항상 꺼진(`False`) 상태로 바꾸고, 로컬에서 디버그 모드가 필요할 때만 `FLASK_DEBUG=true`를 명시적으로 켜도록 했습니다.

**참고로 이 프로젝트가 실제로 배포되는 Vercel(10단계)은 이 `if __name__ == "__main__":` 블록을 아예 거치지 않습니다** — Vercel은 `app` 객체를 서버리스 함수로 직접 실행하기 때문에, 원래도 이 debug 설정과는 무관했습니다. 다만 Vercel이 아닌 곳(자체 서버 등)에 배포할 가능성을 대비해, `requirements.txt`에 프로덕션 WSGI 서버인 `gunicorn`도 추가하고 그 사용법(`gunicorn app:app --bind 0.0.0.0:5000`)을 코드 주석으로 남겨뒀습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [app.py](../../app.py) (`FLASK_DEBUG` 환경변수로 기본값 `False` 전환)
- [requirements.txt](../../requirements.txt) (`gunicorn` 추가)

---

## 8. CI 파이프라인 없음 (신규 주제)

### CI가 뭔가요?
CI(Continuous Integration, "지속적 통합")는 "코드가 바뀔 때마다 자동으로 검증을 돌려주는 로봇 조수"라고 생각하면 됩니다. 지금까지는 `pytest tests/`를 개발자가 직접 로컬에서 실행해봐야만 "테스트를 통과하는지" 알 수 있었습니다 — 누군가 깜빡하고 실행을 안 해본 채로 GitHub에 커밋을 올리면, 망가진 코드가 그대로 들어갈 수 있었습니다.

### 무엇이 문제였는가
저장소에 `.github/workflows` 폴더 자체가 없어서, PR이나 커밋마다 자동으로 `pytest`가 돌아가고 그 결과를 확인할 방법이 전혀 없었습니다.

### 어떻게 고쳤는가
GitHub Actions 워크플로우 파일 [.github/workflows/tests.yml](../../.github/workflows/tests.yml)을 추가했습니다. `main` 브랜치로 push되거나 PR이 열릴 때마다, GitHub이 자동으로 깨끗한 가상 환경을 하나 만들어서 `pip install -r requirements.txt` → `pytest tests/ -v`를 실행하고, 그 결과(성공/실패)를 PR 화면에 초록/빨강 체크마크로 보여줍니다.

```yaml
name: pytest

on:
  push:
    branches: ["main"]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v
```

**진짜 Supabase 자격 증명은 여기 전혀 필요 없습니다.** 4번 항목에서 만든 `tests/conftest.py`의 `flask_app` fixture가 가짜 환경변수를 스스로 채워넣고 `db.ensure_bootstrap_admin()`도 무력화해두었기 때문에, 테스트는 진짜 네트워크 접속을 한 번도 시도하지 않습니다. 이게 바로 4번 항목의 테스트를 "CI에서도 그대로 돌아갈 수 있게" 처음부터 설계해둔 이유입니다 — CI를 나중에 붙이려고 보니 테스트를 다시 고쳐야 하는 상황을 피할 수 있었습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [.github/workflows/tests.yml](../../.github/workflows/tests.yml) (신규)

---

## 이번 단계에서 얻은 교훈

이번 점검에서 특히 인상 깊었던 건, **수정 하나가 다른 곳의 숨은 문제를 스스로 드러내 준 경우**가 여러 번 있었다는 점입니다.
- 2번(CSRF)을 고치자마자 3번(`bruteforce_sim.py`)이 전부 400으로 실패하면서 고장 났습니다 — 새 보안 장치가 실제로 작동한다는 증거였지만, 동시에 그 장치에 맞춰 다른 스크립트도 같이 고쳐야 한다는 걸 알려줬습니다.
- 3번을 구현하는 과정에서 Windows 콘솔 인코딩 문제와 `sys.path` 문제라는, 애초의 보안 점검 목록에는 없던 실제 버그 2개를 추가로 발견해서 함께 고쳤습니다.

이런 연쇄는 "고쳤다고 끝이 아니라, 고친 뒤 실제로 다시 돌려봐야 한다"는 걸 잘 보여줍니다. 이번 단계의 모든 수정은 전부 로컬 서버를 실제로 띄우고, 브라우저로 관리자 대시보드를 열어보고, `pytest`와 각 스크립트를 직접 실행해서 확인을 마쳤습니다.

### 이 단계 전체에서 바뀐 파일 모음
- [app.py](../../app.py), [db.py](../../db.py), [public/js/dashboard.js](../../public/js/dashboard.js)
- [templates/login_form.html](../../templates/login_form.html), [templates/signup.html](../../templates/signup.html), [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [templates/member_dashboard.html](../../templates/member_dashboard.html), [templates/member_history.html](../../templates/member_history.html), [templates/member_profile.html](../../templates/member_profile.html)
- [scripts/bruteforce_sim.py](../../scripts/bruteforce_sim.py), [scripts/daily_report.py](../../scripts/daily_report.py)
- [tests/conftest.py](../../tests/conftest.py), [tests/test_app.py](../../tests/test_app.py), [tests/test_db.py](../../tests/test_db.py)
- [.github/workflows/tests.yml](../../.github/workflows/tests.yml)
- [requirements.txt](../../requirements.txt)
