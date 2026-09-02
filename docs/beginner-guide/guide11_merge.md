# 11단계 — 관리자/일반 로그인 화면을 겉보기에 하나로 통합

[◀ 10단계](guide10_deploy.md) · [전체 목차](beginner-guide.md) · [12단계 ▶](guide12_usermanagement.md)


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
