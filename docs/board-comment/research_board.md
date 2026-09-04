# 게시판·댓글 기능 — 구현 전 분석

> 작성 기준일: 2026-09-04 / 브랜치: `main`
> 목적: 기존 코드베이스(로그인 워치독)에 게시판/댓글 기능을 얹기 전에, 현재 구조·관례·위험요소를 파악하고 결정이 필요한 지점을 정리한다.

---

## 1. 현재 구조 설명

### 1-1. 기능 동작 흐름 정리

이 프로젝트는 "판단(detector) → 실행(soar) → 알림(alert)"을 분리한 3계층 구조 위에, `db.py`를 유일한 데이터 접근 창구로 두는 방식으로 짜여 있다.

```
브라우저
  │
  ▼
app.py (라우트 등록 + 세션/CSRF/입력검증)
  ├─ detector.py  → 조회만 하는 "판사" (DB를 바꾸지 않음)
  ├─ soar.py      → 판정 결과를 실행하는 "집행관" (DB를 바꿈, alert 호출)
  │     ├─ db.py    → Supabase 읽기/쓰기 전담 (유일한 DB 접근 지점)
  │     └─ alert.py → Slack 알림 전송 (미설정 시 콘솔 로그 대체)
  └─ geoip.py     → IP→위치 조회 + db.py를 통한 캐싱
```

**요청 처리 흐름 (예: `/login` POST)**
1. `app.py`의 라우트 함수가 요청을 받는다 (`login_submit()`).
2. 먼저 `soar.try_release_expired_lockouts()`로 만료된 상태를 정리한다 (지연 정리 방식, 별도 스케줄러 없음).
3. `detector.py`로 "지금 상태가 어떤가"만 물어본다 (부작용 없음).
4. 상태에 따라 `db.py` 함수를 직접 호출하거나(`log_attempt`, `verify_user_credentials`) `soar.py`를 통해 실행한다(`enforce_lockout`).
5. `flash()` 메시지 + `render_template`/`redirect`로 응답한다.

**화면 렌더링 방식이 두 갈래로 나뉜다**
- **서버 사이드 렌더링(SSR)**: 회원 화면(`/dashboard`, `/dashboard/history`, `/dashboard/profile`)은 Jinja2가 서버에서 데이터를 채워 완성된 HTML을 내려준다. 실시간성이 필요 없는 화면.
- **클라이언트 폴링 + 동적 렌더링**: 관리자 대시보드(`/admin/dashboard`)는 빈 HTML 뼈대만 내려주고, `dashboard.js`가 `/api/status`를 10초마다 호출해 JSON을 받아 `innerHTML`로 표를 직접 그린다. 실시간 감시가 필요한 화면.

**인증/세션은 두 종류가 완전히 분리**
- 관리자: `session["admin_username"]`, `login_required` 데코레이터, `/admin/*` 경로.
- 일반 회원: `session["username"]` + `session["user_id"]`, `member_login_required` 데코레이터, `/dashboard*` 경로.
- 두 세션 키가 다르므로 한 브라우저에서 동시에 관리자+회원으로 로그인될 수 있으며, 이는 의도된 설계다.

### 1-2. 관련 파일 목록

| 파일 | 역할 | 게시판/댓글과의 관계 |
|---|---|---|
| [app.py](../../app.py) | 라우트·세션·CSRF·입력검증 등록의 "정문" | 새 라우트(`/board`, `/board/<id>`, `/board/<id>/comments` 등)를 여기에 추가하게 됨 |
| [db.py](../../db.py) | Supabase와 대화하는 유일한 창구 | 게시글/댓글 CRUD 함수를 여기에 추가 |
| [config.py](../../config.py) | 임계값·상수 중앙 관리 | 페이지당 글 수, 게시글 빈도 제한 등 새 상수를 추가할 자리 |
| [detector.py](../../detector.py) / [soar.py](../../soar.py) | 판정/실행 분리 패턴 (브루트포스 전용) | 게시글은 "수상한지 판단→잠금"류 로직이 없어 이 패턴이 그대로 맞지 않음 (2-3절 참고) |
| [docs/schema.sql](../schema.sql) | Supabase 테이블 정의 (문서 기록용, 실제 실행은 Supabase SQL Editor) | `posts`, `comments` 테이블 설계를 추가해야 함 |
| [templates/*.html](../../templates) | Jinja2 템플릿 | `board_list.html`, `board_detail.html` 등 새 템플릿 필요 |
| [public/css/tokens.css](../../public/css/tokens.css) | 색상/폰트 CSS 변수 (라이트/다크 공용) | 새 화면도 이 토큰만 사용해야 다크모드·디자인이 자동으로 맞음 |
| [public/css/member.css](../../public/css/member.css) | 회원 화면 공통 스타일 | 게시판이 회원 전용이라면 이 파일을 확장하거나 `board.css` 신설 |
| [public/js/dashboard.js](../../public/js/dashboard.js) | fetch+CSRF+escapeHtml 패턴의 실제 예시 | 댓글을 폴링/동적 렌더링한다면 이 패턴을 그대로 따라야 함 |
| [tests/test_app.py](../../tests/test_app.py) | Flask test_client 기반 라우트 통합 테스트, CSRF 토큰 획득 헬퍼 포함 | 새 라우트 테스트를 같은 스타일로 추가 |
| [tests/conftest.py](../../tests/conftest.py) | Supabase 접속을 막고 가짜 client 주입 | 게시판 테스트도 이 fixture를 그대로 재사용 |

### 1-3. 수정 가능 파일 + 이유

| 파일 | 수정 가능 여부 | 이유 |
|---|---|---|
| `app.py` | ✅ 적극 수정 | 새 라우트를 추가하는 것이 정상 확장 방식. 기존 라우트(`/login`, `/admin/*`)는 건드릴 필요 없음 |
| `db.py` | ✅ 적극 수정 (함수 추가만) | "DB 접근은 db.py를 거친다"는 규칙이 명확하므로, 새 함수를 이 파일 하단에 추가하는 게 맞음. 기존 함수는 게시판과 무관하므로 손댈 필요 없음 |
| `config.py` | ✅ 필요시 상수 추가 | 기존 패턴(환경변수 + 기본값)을 그대로 따라 게시글 관련 상수만 추가 |
| `docs/schema.sql` | ✅ 테이블 추가 (기존 테이블 불변) | 이 파일은 "실행되는 마이그레이션"이 아니라 기록용 문서. 실제로는 Supabase SQL Editor에서 별도로 실행해야 함 — **DB 변경은 이 저장소 코드만으로는 반영되지 않는다는 점을 반드시 인지해야 함** |
| `templates/`, `public/css/`, `public/js/` | ✅ 신규 파일 추가 위주 | 기존 파일 스타일(변수명, CSRF 처리, escapeHtml)을 그대로 모방해서 새 파일 작성 |
| `detector.py`, `soar.py`, `alert.py` | ⚠️ 원칙적으로 손대지 않는 것을 권장 | 이 세 파일은 "브루트포스 판정→조치→알림"이라는 하나의 도메인 전용으로 설계됨. 게시판 기능을 여기 억지로 끼워넣으면 "판사가 게시글도 심사한다"는 개념적 혼동이 생김 (2-3절 참고) |
| `users` 테이블 스키마 자체 | ⚠️ 신중히 | 이미 `login_attempts`, `admin_login_log` 등 여러 곳에서 `username`을 참조. 컬럼 추가는 안전하지만 기존 컬럼 변경/삭제는 회귀 위험 큼 |

---

## 2. 기존 규칙

### 2-1. 네이밍

- **Python 함수/변수**: `snake_case`. DB 접근 함수는 동사로 시작 (`create_user`, `get_user_by_id`, `list_active_lockouts`, `count_recent_failures`). `list_*`은 목록 조회, `get_*`은 단건 조회(없으면 `None`), `create_*`/`update_*`/`delete_*`는 쓰기, `count_*`는 개수.
- **Supabase 테이블명**: 복수형 스네이크케이스 (`users`, `login_attempts`, `lockouts`). 단, `app_settings`는 싱글턴이라 단수 개념.
- **Flask 라우트 함수명**: URL 구조를 그대로 반영 (`member_dashboard` → `/dashboard`, `member_profile_submit` → `/dashboard/profile` POST). GET/POST가 같은 URL을 공유할 때는 `_submit` 접미사로 POST 처리 함수를 구분 (`signup`/`signup_submit`, `login`/`login_submit`).
- **API 엔드포인트**: 전부 `/api/` 접두사, 명사+동사 조합 (`/api/unlock`, `/api/users/delete`, `/api/settings/signup`). `login_required`가 `/api/`로 시작하는 경로만 골라 401 JSON을 돌려주므로 **이 접두사 규칙은 인증 처리 동작에 실제로 영향을 준다**.
- **JS 함수명**: `camelCase`, "무엇을 하는가"를 동사로 시작 (`fetchStatus`, `renderUsersTable`, `unlockIp`, `escapeHtml`). 렌더링 함수는 `render*` 접두사로 통일.
- **CSS**: 케밥 케이스 클래스명(`.lockout-card`, `.data-table`, `.empty-state`), 색상/폰트는 반드시 `tokens.css`의 CSS 변수(`var(--ink)`, `var(--canvas)` 등)를 통해서만 사용.

### 2-2. 상태 관리

- **서버 세션이 유일한 클라이언트 상태 저장소**. 프론트엔드에 별도 상태관리 라이브러리 없음(순수 JS + DOM).
- **여러 서버 인스턴스가 공유해야 하는 값은 반드시 Supabase에 저장**한다. `app_settings` 테이블(회원가입 on/off)이 그 예시 — "메모리에 저장하면 로컬/Vercel 등 여러 인스턴스가 다른 값을 보게 된다"는 이유가 `db.py`에 명시되어 있음. 게시판의 전역 설정(예: 게시판 열람 제한 등)이 필요하다면 같은 패턴을 따라야 함.
- **DB 캐싱 패턴**: `geoip.py` + `ip_locations` 테이블처럼, 외부 API 호출 결과를 Supabase에 캐싱해 쿼터를 아낀다. IP 목록을 한 번에 조회하는 `get_cached_ip_locations(ips: list)` 같은 "N+1 쿼리 방지" 패턴이 이미 정착되어 있음.
- **읽기 전용 판정과 상태 변경 실행을 분리**(`detector.py` vs `soar.py`)하는 것이 이 프로젝트의 핵심 설계 원칙.

### 2-3. API 호출

- 서버 상태를 바꾸는 요청은 항상 **POST**로 보낸다 (로그아웃도 링크가 아니라 폼 버튼 — "GET은 조회만" 원칙 명시).
- **CSRF 토큰 처리 2가지 패턴**:
  - 일반 HTML 폼 제출: `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`
  - JS `fetch()` 요청: `<meta name="csrf-token" content="{{ csrf_token() }}">`를 심어두고 JS가 읽어 `X-CSRFToken` 헤더에 실어 보냄
  - 새 API를 만들 때 이 두 패턴 중 화면 성격에 맞는 쪽을 그대로 재사용해야 함.
- `fetch()` 요청은 `{ "Content-Type": "application/json", "X-CSRFToken": csrfToken }` 헤더 + JSON body가 표준 형태.
- API 응답은 `jsonify({...})`로 통일, 성공 시 `{"success": true, ...}` 형태를 관례로 사용 (`api_unlock`, `api_users_delete`, `api_settings_signup` 전부 동일 패턴).
- 인증이 필요한 라우트는 전부 `@login_required` 또는 `@member_login_required` 데코레이터를 함수 위에 붙인다 — **권한 확인 로직을 함수 본문에 직접 작성하지 않는다.**

### 2-3-부칙. detector/soar 패턴이 게시판에 그대로 적용되지 않는 이유

`detector.py`/`soar.py`는 "임계값을 넘었는가 → 자동으로 조치" 라는 브루트포스 탐지 전용 개념이다. 게시판/댓글에는 이런 "판정→자동 조치" 흐름이 기본적으로 없다(스팸 탐지 등을 넣지 않는 한). 따라서 게시판 CRUD는 `db.py`에 함수를 추가하고 `app.py`에서 바로 호출하는, `member_profile_submit()`과 같은 더 단순한 패턴을 따르는 것이 이 코드베이스의 관례에 더 가깝다.

### 2-4. 에러 처리

- **사용자에게 보여줄 오류**: `flash("메시지")` + `render_template`으로 같은 화면을 다시 보여주는 패턴. 예외를 던지고 500 에러 페이지로 보내는 방식은 쓰지 않음.
- **정보 노출 최소화**: 로그인 실패 시 "아이디가 없는지 비밀번호가 틀렸는지" 구분하지 않고 항상 같은 문구("아이디 또는 비밀번호가 올바르지 않습니다")로 통일 — 공격자에게 힌트를 주지 않기 위함. 게시판에서도 "존재하지 않는 글"과 "권한 없는 글"을 구분해서 안내할지 신중히 결정해야 함(4절 질문 참고).
- **외부 연동 실패는 흡수**: `alert.py`의 Slack 전송 실패는 `try/except`로 감싸 콘솔 로그만 남기고 넘어간다 — "부가 기능 실패가 핵심 기능(로그인)을 막으면 안 된다"는 원칙.
- **이중 검증**: 화면에서 폼을 숨기거나 비활성화해도, 서버 라우트 함수 내부에서 다시 한번 조건을 검사한다 (`signup_submit()`의 `db.get_signup_enabled()` 재확인이 대표 사례) — 개발자 도구로 우회한 요청까지 방어.
- **입력 검증은 정규식 화이트리스트 방식**: `USERNAME_PATTERN`, `EMAIL_PATTERN`처럼 "허용하는 모양"을 먼저 정의하고, 통과 못 하면 DB 함수를 아예 호출하지 않는다 — "위험한 값이 DB에 저장되는 것 자체를 막는" 심층 방어. 게시글 제목/본문도 같은 원칙을 적용할지 결정 필요.
- **XSS 방어는 출력 시점에서 확실히**: Jinja2 SSR 화면은 auto-escape가 기본이라 안전하지만, `dashboard.js`처럼 JS가 `innerHTML`로 직접 그리는 화면은 `escapeHtml()`을 반드시 거치도록 관례화되어 있음(실제로 6단계에서 이 부분의 Stored XSS 취약점이 발견되어 수정된 이력이 있음).

---

## 3. 위험요소

### 3-1. 중복 구현 / 패턴 불일치

- **새 모듈이 필요한가?** 게시판은 "판정→조치" 개념이 없으므로 `detector.py`/`soar.py` 패턴을 억지로 재사용하면 오히려 혼란을 준다. `db.py`에 함수 추가 + `app.py`에 라우트 추가라는 더 단순한 기존 패턴(`member_profile_submit` 계열)을 따르는 편이 일관적이다. 다만 파일이 하나로 계속 커지고 있어(`app.py` 669줄, `db.py` 557줄) 게시판까지 더하면 상당히 비대해진다 — 파일 분리 여부는 논의가 필요하다(4절 질문).
- **댓글 렌더링 방식 중복 위험**: 관리자 대시보드는 폴링+JS 렌더링, 회원 화면은 SSR. 댓글을 실시간으로 보여주고 싶다면 `dashboard.js`의 fetch+escapeHtml+render 패턴을 그대로 복붙하게 될 텐데, 로직이 비슷한 여러 `render*` 함수가 파일마다 흩어질 위험이 있다.
- **CSRF 토큰 추출 로직 중복**: `test_app.py`의 `get_csrf_token()` 헬퍼처럼 테스트 쪽에도 이미 재사용 패턴이 있으니, 게시판 테스트도 새로 만들지 말고 그대로 가져다 써야 한다.

### 3-2. 정합성 (데이터 일관성)

- **`users` 삭제와 게시글의 관계**: 현재 `login_attempts`는 `users`와 FK를 걸지 않고 `username`을 문자열로만 저장한다("회원을 삭제해도 로그인 기록은 감사 로그로 남는다"는 명시적 설계). 게시글/댓글도 같은 정책(작성자 삭제돼도 글은 남기되 "탈�출한 회원" 등으로 표시)을 따를지, 아니면 FK + `on delete cascade`로 같이 지울지는 **완전히 새로운 결정**이 필요하다. 지금 관례를 그대로 따르면 "탈퇴 회원이 쓴 글"이 영구히 남는데, 게시판 성격상 이게 맞는지는 불명확하다.
- **`admin/api_users_delete` 확장 필요성**: 현재 회원 삭제 API(`/api/users/delete`)는 게시글/댓글 정리를 전혀 모른다. 게시판을 추가하면 이 API가 회원 삭제 시 그 회원의 글/댓글을 어떻게 처리할지 몰라 데이터 정합성이 깨질 수 있다 — 이 함수를 반드시 다시 봐야 한다.
- **`app_settings` 확장 시 스키마 충돌**: 회원가입 on/off처럼 게시판 관련 전역 설정(예: 게시판 잠금)을 추가하려면 `app_settings` 테이블에 컬럼을 추가해야 하는데, 이 테이블은 `id=1` 싱글턴 제약이 걸려 있어 구조 확장 시 마이그레이션을 신중히 다뤄야 한다.

### 3-3. 권한

- **작성자 판별 기준**: 회원 세션은 `session["user_id"]`를 갖고 있으므로 "본인 글만 수정/삭제 가능"은 구현 가능하다. 다만 관리자가 모든 게시글/댓글을 삭제할 수 있어야 하는지(현재 관리자는 회원 삭제 권한만 있음)는 별도 API·권한 체크가 필요하다.
- **`login_required` vs `member_login_required` 재사용**: 게시판을 회원 전용으로 할지, 비로그인도 열람 가능하게 할지에 따라 어떤 데코레이터를 쓸지, 혹은 "열람은 누구나·쓰기는 회원만" 같은 세 번째 패턴이 필요할지 결정해야 한다. 현재 코드베이스에는 이런 "부분 공개" 패턴이 없다.
- **XSS 표면 확대**: 게시판은 로그인 폼보다 훨씬 자유로운 텍스트 입력(제목, 본문, 댓글)을 받는다. 현재 `USERNAME_PATTERN` 같은 엄격한 화이트리스트 방식을 그대로 쓸 수 없고(글 내용에 임의 문자를 허용해야 하므로), Jinja2 auto-escape에 의존하는 SSR과 `escapeHtml()`에 의존하는 JS 렌더링 중 어느 쪽을 쓸지, 그리고 줄바꿈/링크 같은 최소한의 서식을 허용할지에 따라 XSS 방어 전략이 완전히 달라진다.
- **CSRF 예외 없음 확인**: 새 게시글/댓글 POST 라우트는 `CSRFProtect(app)`이 앱 전역에 걸려 있으므로 자동으로 보호되지만, 만약 파일 업로드 등 `multipart/form-data`를 쓰게 되면 CSRF 토큰 처리 방식을 다시 확인해야 한다.

### 3-4. 성능

- **Supabase 무료 쿼터 이력**: 이 프로젝트는 9단계에서 이미 "폴링 주기를 2.5초→10초로 늘려야 했던" 쿼터 초과 경험이 있다(`guide09_quota.md`). 게시판 목록/댓글까지 폴링 대상에 추가하면 쿼터 소진 속도가 다시 빨라질 수 있다.
- **N+1 쿼리 위험**: `get_cached_ip_locations(ips: list)`처럼 "목록을 한 번에 조회"하는 패턴이 이미 정착돼 있다. 댓글을 게시글 목록과 함께 보여줄 때(예: "댓글 수" 표시) 게시글마다 따로 쿼리를 날리면 같은 실수를 반복하게 된다.
- **페이지네이션 부재**: 현재 `list_recent_attempts(limit=50)`, `list_users(limit=100)`처럼 전부 "최근 N개만" 방식이고 진짜 페이지네이션(offset/cursor)이 없다. 게시글이 누적되면 이 방식만으로는 "다음 페이지"를 구현할 수 없어 새로운 패턴이 필요하다.
- **인덱스 설계**: `login_attempts`는 `(ip_address, attempted_at)` 복합 인덱스를 걸어뒀다(`schema.sql`). 게시글/댓글도 목록 조회·정렬 컬럼(예: `created_at`, `post_id`)에 인덱스를 미리 설계해야 나중에 데이터가 쌓였을 때 문제가 없다.

---

## 4. 구현 전 질문 (결정이 필요한 모호한 사항)

1. **접근 범위**: 게시판은 회원(`/dashboard` 로그인) 전용인가, 비로그인 사용자도 글 목록/내용을 열람할 수 있는가? 관리자도 별도 UI 없이 회원과 동일하게 이용하는가, 아니면 관리자 대시보드에 "게시글 관리" 섹션이 별도로 필요한가?
2. **작성/수정/삭제 권한**: 본인 글만 수정 가능한가? 삭제는 본인 + 관리자 둘 다 가능한가? 댓글도 동일한 권한 규칙을 따르는가, 아니면 게시글 작성자가 자기 글에 달린 남의 댓글을 지울 수 있는가(일반 커뮤니티에서 흔한 정책)?
3. **댓글 구조**: 단일 depth(대댓글 없음)인가, 대댓글(reply)까지 지원하는가? 후자라면 `parent_comment_id` 자기참조 FK가 필요해 스키마가 복잡해진다.
4. **회원 탈퇴/삭제 시 게시글·댓글 처리**: 기존 `login_attempts`처럼 "글쓴이 흔적은 남기고 텍스트만 남긴다"인가, 아니면 회원 삭제 시 그 회원의 글/댓글도 함께 삭제(cascade)하는가? (3-2절 정합성 위험과 직결)
5. **입력 허용 범위**: 게시글 본문에 줄바꿈만 허용하는 순수 텍스트인가, 마크다운/간단한 서식을 허용하는가? 후자라면 XSS 방어 전략(sanitize 라이브러리 도입 여부 등)을 별도로 설계해야 한다.
6. **목록 표시 방식**: 회원 화면처럼 SSR로 페이지 단위 렌더링할 것인가, 관리자 대시보드처럼 폴링+JS 동적 렌더링(실시간성)을 쓸 것인가? 실시간 댓글이 꼭 필요한 기능인지도 함께 결정해야 함(불필요하다면 SSR + 새로고침이 훨씬 단순하고 쿼터도 아낀다).
7. **빈도 제한 필요 여부**: 회원가입에 `signup_attempts` 기반 요청 빈도 제한이 있는 것처럼, 게시글/댓글 도배(스팸) 방지를 위한 동일한 패턴(`post_attempts` 등)을 처음부터 넣을 것인가?
8. **파일/이미지 첨부**: 필요한가? 필요하다면 Supabase Storage 연동이 새로 필요해 현재 스택(테이블 CRUD만 하던 `db.py`)의 범위를 넘어선다.
9. **페이지네이션 정책**: 페이지 번호 방식인가 무한 스크롤인가? 한 페이지당 몇 개를 보여줄지 `config.py`에 상수로 추가할 값도 정해야 한다.
10. **라우트/URL 네이밍**: `/board`, `/posts` 중 어느 쪽을 쓸지, 상세 글은 `/board/<id>`인지 `/board/posts/<id>`인지 등 프로젝트의 기존 네이밍(`/dashboard/history`, `/dashboard/profile`처럼 명사 계층 구조)과 통일할 방식을 먼저 정해야 이후 파일명·함수명이 일관된다.
11. **파일 구조 확장 여부**: `app.py`/`db.py`가 이미 상당히 커진 상태에서, 게시판 기능을 같은 파일에 계속 추가할지 아니면 이 시점에 Blueprint(`board.py`) 같은 파일 분리를 도입할지 — 이건 "지금 규칙을 따를지, 규칙 자체를 바꿀지"의 문제라 사용자 확인이 필요하다.

---

## 5. 문서 구조 제안에 대한 의견

`docs/` 밑에 `board-comment/`라는 새 폴더를 만들어 이 문서를 넣는 방식에 대한 제 생각입니다.

- **찬성하는 이유**: `docs/beginner-guide/`가 이미 "단계별 진행 기록"이라는 하나의 목적으로 폴더화되어 있어서, 이번처럼 새 기능(게시판/댓글) 단위로 별도 폴더를 두는 게 기존 구조와 자연스럽게 어울립니다. 나중에 "설계 결정 기록", "구현 완료 후 회고" 같은 문서가 늘어나도 `docs/board-comment/02-...`, `03-...` 식으로 이어붙이기 쉽고, 다른 기능(예: 알림 기능 확장)을 또 추가할 때도 같은 패턴(기능별 폴더)을 반복하면 됩니다.
- **주의할 점**: `beginner-guide`는 "완료된 작업을 사후에 해설"하는 문서인 반면, 이 문서는 "착수 전 분석"입니다. 나중에 실제로 구현이 끝나면 `beginner-guide` 쪽에도 관례상 `guide20_board.md` 같은 해설 항목이 하나 더 필요할 수 있다는 점을 감안해주세요 — 이 폴더가 그 자리를 대신하는 건 아닙니다.
- **결론**: 이번 분석 문서용으로는 `docs/board-comment/01-pre-implementation-analysis.md`처럼 새 폴더 + 번호 접두사 방식을 그대로 쓰는 것을 추천합니다(이미 이 경로로 파일을 만들어뒀습니다). 이후 4절의 질문들에 답이 정해지면 같은 폴더에 `02-design-decisions.md` 형태로 이어서 기록하면 프로젝트 전체 문서 스타일과 잘 맞을 것 같습니다.
