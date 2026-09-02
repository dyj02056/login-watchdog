# 12단계 — 관리자 대시보드에 회원 관리 기능 추가

[◀ 11단계](guide11_merge.md) · [전체 목차](beginner-guide.md) · [13단계 ▶](guide13_member.md)


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
