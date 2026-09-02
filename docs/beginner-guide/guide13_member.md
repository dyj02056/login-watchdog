# 13단계 — 회원 전용 대시보드 (`/dashboard`) 추가

[◀ 12단계](guide12_usermanagement.md) · [전체 목차](beginner-guide.md) · [14단계 ▶](guide14_geoip.md)


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
