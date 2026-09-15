# 파일 분리 작업 (2026-09-15) — app.py / db.py / public/js/dashboard.js

## 배경과 목표

프로젝트가 커지면서 실행 코드 파일 중 세 개가 200줄을 훌쩍 넘겼다.

| 파일 | 분리 전 줄 수 |
|---|---|
| `app.py` | 1,108 |
| `db.py` | 1,030 |
| `public/js/dashboard.js` | 558 |

세 파일 모두 기능이 늘어날 때마다 그 안에 계속 함수를 추가해온 결과였고,
다행히 파일 내부에 이미 `# ====` 구분선 주석으로 섹션이 나뉘어 있어서(예:
"로그인 시도 관련 함수", "게시판 관련 함수"), 그 경계를 그대로 따라가면
자연스럽게 여러 파일로 쪼갤 수 있는 상태였다.

목표는 두 가지였다:
1. 한 파일에 너무 많은 책임이 몰려 있어 원하는 함수를 찾기 어려운 문제를 해결한다.
2. **기존 동작과 테스트를 절대 깨뜨리지 않는다** — 이번 작업은 순수 리팩터링이고,
   새 기능을 추가하거나 API 응답/URL 경로를 바꾸지 않는다.

테스트 파일(`tests/test_app.py`, `tests/test_db.py` 등)은 이번 분리 대상에서
제외했다 — 소스가 이미 도메인별로 나뉘었으니 테스트를 다시 나누는 건 별도
작업으로 미뤄뒀다.

## 1. `db.py` → `db/` 패키지

### 구조

```
db/
  __init__.py         # 하위 모듈 함수를 전부 다시 내보내기(re-export)
  _client.py          # get_client(), _now_iso() — Supabase 연결
  attempts.py         # login_attempts (로그인 시도 기록)
  lockouts.py         # lockouts (IP 잠금 현재 상태), list_lockouts_since
  admin.py            # admin_users, admin_login_log (관리자 계정/로그인 기록)
  users.py            # users (회원 계정)
  settings.py         # app_settings, signup_attempts (설정값, 가입 빈도 제한)
  geoip_cache.py       # ip_locations (IP 위치 조회 캐시)
  board.py            # posts, comments, post_attempts, comment_attempts (게시판)
  security_events.py  # not_found/unauthorized/page_access_attempts, security_events
```

### 핵심 결정: 호출부 코드를 한 줄도 바꾸지 않는다

`app.py`, `detector.py`, `soar.py`, `scripts/*.py`, 테스트 코드 전부가
`import db` 후 `db.log_attempt(...)`, `db.create_lockout(...)`처럼 쓰고
있었다. 이 호출 방식을 그대로 유지하기 위해, `db/__init__.py`가 각 하위
모듈의 함수를 전부 이름으로 다시 내보낸다(`from .attempts import log_attempt, ...`).
그래서 다른 파일 입장에서는 `db`가 패키지로 바뀌었는지조차 알 필요가 없다.

### 까다로웠던 부분: `monkeypatch.setattr(db, "get_client", ...)`

`tests/test_db.py`는 이렇게 `db` 모듈의 `get_client`를 가짜 함수로 바꿔치기한
뒤, `db.log_attempt(...)`처럼 실제 함수를 호출해서 그 가짜 클라이언트가
쓰였는지 검증한다. 문제는, 만약 `db/attempts.py`가 최상단에서
`from ._client import get_client`처럼 값을 복사해 가져오면, 그 함수
안에서는 `attempts.py` 자신의 이름 공간에 묶인 원래 함수를 계속 쓰게
되어 테스트의 바꿔치기가 반영되지 않는다(파이썬 import는 "값 복사"이지
"패키지 속성 참조"가 아니기 때문).

그래서 각 하위 모듈은 값을 직접 가져오는 대신 `import db`로 패키지 자체를
참조해두고, 함수 안에서 `db.get_client()` / `db._now_iso()`처럼 **패키지
속성으로** 호출한다. 이러면 테스트가 `db.get_client`를 바꿔치기했을 때
그 바뀐 값을 하위 모듈도 그대로 보게 된다 — 분리 전과 똑같은 monkeypatch
동작이 보장된다.

(패키지 내부에서 `import db`로 자기 자신을 다시 가져오는 게 이상해
보일 수 있는데, `db/__init__.py`가 하위 모듈을 import하는 시점에는 이미
`sys.modules`에 `db`가 등록돼 있어서 순환 참조 오류 없이 동작한다 —
실제 속성 접근은 함수가 "나중에 호출될 때" 일어나므로 초기화 순서 문제도 없다.)

## 2. `app.py` → `app.py`(축소) + `helpers.py` + `routes/` 4개 Blueprint

### 왜 Vercel 배포 제약을 신경 썼는가

이 프로젝트는 `vercel.json` 없이 Vercel의 Python 런타임 자동 감지(루트의
`app.py` 안 `app` 객체)에 의존하는 것으로 보여서, `app.py` 파일 자체는
그대로 두고 그 **내용**만 축소했다 — 라우트 등록은 여전히 이 파일에서
일어나고, 실제 라우트 함수만 `routes/`로 옮겼다.

### 구조

```
app.py                 # Flask() 생성, 세션/CSRF 설정, 에러 핸들러,
                        # before_request(track_page_access), index(), blueprint 등록
helpers.py              # get_request_ip, _attach_locations,
                        # login_required, member_login_required
routes/
  auth.py               # auth_bp: /signup, /login
  admin.py              # admin_bp: /admin/login, /admin/dashboard, /api/* (관리자용)
  board.py              # board_bp: /board/*
  member.py             # member_bp: /dashboard/*
```

### 까다로웠던 부분: Flask Blueprint의 엔드포인트 이름

Flask에서 `@app.route(...)`로 등록한 라우트의 "엔드포인트 이름"은 함수
이름 그대로(`login`)지만, `Blueprint`로 등록하면 항상
`<블루프린트 이름>.<함수 이름>`(`auth.login`) 형태로 바뀐다 — 이건 Flask가
강제하는 규칙이라 피할 방법이 없다. `url_for("login")`처럼 옛날 이름을
쓰는 코드는 전부 `werkzeug.routing.BuildError`로 터진다.

이 프로젝트는 `url_for()`를 파이썬 라우트 코드뿐 아니라 템플릿
(`templates/*.html`)에서도 16곳 넘게 쓰고 있었다. 그래서 분리 작업의
상당 부분은 다음을 하나하나 맞추는 일이었다:

- `helpers.py`의 `login_required`/`member_login_required` 데코레이터 —
  `url_for("admin_login")` → `url_for("admin.admin_login")`,
  `url_for("login")` → `url_for("auth.login")`
- 각 `routes/*.py` 안에서 다른 블루프린트의 화면으로 이동하는 모든
  `url_for()`/`redirect()` 호출
- `templates/*.html` 안의 `url_for()` 호출 16곳(로그인/회원가입/게시판/
  회원 대시보드 링크와 폼 action)

`url_for('static', ...)`는 영향받지 않는다 — Flask 앱 자체의 정적 파일
엔드포인트(`static`)는 블루프린트에 속하지 않고 그대로 유지된다.

실제 URL 경로(`/login`, `/admin/dashboard` 등)는 블루프린트에
`url_prefix`를 주지 않았으므로 **분리 전과 완전히 동일하다** — 바뀐 건
`url_for()`에 넘기는 이름뿐이라, 테스트(`tests/test_app.py`)가 실제
경로(`client.get("/login")`)로 요청하는 방식이라 전혀 영향받지 않았다.

### 또 하나 놓치기 쉬웠던 부분: `_PAGE_ACCESS_EXCLUDED_ENDPOINTS`

`app.py`의 `track_page_access()`는 자동 폴링 API(`/api/status`,
`/api/board/<id>/comments/latest`)를 "반복 접근 의심" 판정에서 제외하려고
`request.endpoint`를 문자열 집합과 비교한다. 이 집합이 예전 이름
(`"api_status"`)을 그대로 들고 있으면, 블루프린트 분리 이후
`request.endpoint`는 `"admin.api_status"`가 되므로 더 이상 일치하지 않아
정상적인 자동 폴링이 "수상한 반복 접근"으로 잘못 판정될 뻔했다 — 이 집합도
`{"static", "admin.api_status", "board.api_board_comments_latest"}`로
함께 갱신했다.

## 3. `public/js/dashboard.js` → `public/js/dashboard/` ES 모듈 6개

### 구조

```
public/js/dashboard/
  state.js    # 공유 상태 (CSRF 토큰, 폴링 주기, 페이지 번호, 회원가입 토글 상태)
  utils.js    # escapeHtml, formatTime, renderPagination (범용 헬퍼)
  render.js   # 서버 데이터 → 표/카드 HTML을 그리는 함수들
  api.js      # fetch()로 서버와 주고받는 함수들 (조회 폴링 + 상태 변경 요청)
  events.js   # 버튼 클릭 등 이벤트를 api.js 함수와 연결 (부수효과 모듈)
  main.js     # 진입점 — 위 조각을 조립하고 최초 fetchStatus() 실행
```

`templates/admin_dashboard.html`의 스크립트 태그를
`<script src="js/dashboard.js">`에서
`<script type="module" src="js/dashboard/main.js">`로 바꿨다 — 브라우저가
`main.js`의 `import` 구문을 따라가며 나머지 5개 파일을 자동으로 불러온다.

### 까다로웠던 부분: ES 모듈의 `import` 바인딩은 읽기 전용

원래 `dashboard.js`는 `let attemptsPage = 1;`처럼 여러 함수가 공유하는
변수를 파일 최상단에 두고, `fetchStatus()`와 페이지네이션 버튼 클릭
핸들러가 이 변수를 직접 재대입했다. ES 모듈에서 `export let x`를
다른 파일이 `import { x } from ...`로 가져오면, 그 바인딩은 **읽기
전용 참조**라서 가져온 쪽에서 `x = 2`처럼 재대입하면 문법 오류가 난다.

그래서 `state.js`는 낱개 변수 대신 **객체 하나**를 내보내는 방식을 썼다
(`export const pages = { attempts: 1, users: 1, ... }`,
`export const signupState = { enabled: true }`). 객체 바인딩 자체는
바뀌지 않고 그 프로퍼티만 바뀌므로(`pages.attempts = 2`), 어느 모듈에서
가져다 쓰든 항상 같은 객체를 보게 되어 상태 공유가 정상적으로 동작한다.

## 검증

1. **자동 테스트** — 세 파일을 분리할 때마다 `pytest`를 전체 실행해서 항상
   160개 테스트가 전부 통과하는 것을 확인했다 (`db.py` 분리 직후 1개 실패 —
   `list_lockouts_since()` 함수를 옮기는 걸 처음에 빠뜨렸던 것을 바로 발견하고 수정).
2. **브라우저 수동 확인** — 로컬 개발 서버(`python app.py`)를 띄워서
   - `/` → `/login` 리다이렉트
   - `/signup`, `/admin/login` 화면 렌더링 (템플릿의 `url_for()` 정상 동작 확인)
   - 실제 관리자 계정으로 로그인 → `/admin/dashboard` 진입, `/api/status` 폴링으로
     보안 이벤트/로그인 시도(IP 위치 정보 포함)/회원가입 설정 표가 정상적으로 채워짐
   - 관리자 대시보드의 페이지네이션(다음 페이지) 클릭 동작 확인
   - 로그아웃 버튼(`admin.admin_logout` 엔드포인트) 클릭 → `/login`으로 정상 이동
   - 브라우저 콘솔/네트워크 탭에서 `public/js/dashboard/` 6개 모듈이 전부 200으로
     로드되는 것, 관련 JS 에러가 없는 것을 확인

   (한 가지 함정: Flask가 기본적으로 컴파일된 템플릿을 캐시해서, 템플릿 파일을
   고친 뒤에도 개발 서버가 예전 `<script>` 태그를 계속 내려주는 현상이 있었다 —
   개발 서버를 재시작하니 해결됐다. `TEMPLATES_AUTO_RELOAD`를 켜두지 않은
   상태라면 템플릿을 고칠 때마다 재시작이 필요하다는 뜻이므로 참고.)

## 바뀐 파일 요약

| 이전 | 이후 |
|---|---|
| `db.py` (1,030줄) | `db/` 패키지 9개 파일 (각 38~213줄) |
| `app.py` (1,108줄) | `app.py`(232줄) + `helpers.py`(100줄) + `routes/` 4개 파일(115~312줄) |
| `public/js/dashboard.js` (558줄) | `public/js/dashboard/` 6개 파일 (37~226줄) |

`templates/*.html` 9개 파일의 `url_for()` 호출을 블루프린트 이름에 맞게
갱신했고, `templates/admin_dashboard.html`의 스크립트 로딩 방식을
ES 모듈로 바꿨다. `tests/`는 이번 작업에서 건드리지 않았고 전부 그대로
통과한다.
