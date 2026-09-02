# 6단계 — 화면(템플릿/스타일/스크립트) 만들기

[◀ 5단계](guide05_app.md) · [전체 목차](beginner-guide.md) · [7단계 ▶](guide07_alert.md)


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
