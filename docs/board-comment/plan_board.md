# 게시판·댓글 기능 — 구현 계획

> 작성 기준일: 2026-09-04 / 브랜치: `main`
> 근거 문서: [research_board.md](research_board.md)(구현 전 분석) + [02-design-decisions.md](02-design-decisions.md)(11개 질문 결정 사항)
> 참고: 이 저장소에는 별도의 "스키마/라우트 설계" 문서가 없었으며, 이 문서가 그 역할을 겸한다(하단 각 절 참고).

---

## 1. 구현 목표

로그인 워치독의 회원 전용 화면(`/dashboard`)에 **게시판·댓글 기능**을 추가한다.

- 로그인한 회원이 글을 쓰고, 목록/상세를 보고, 댓글을 달 수 있다.
- 본인 글/댓글은 본인이, 전체 글/댓글은 관리자가 삭제할 수 있다.
- 새 댓글이 달리면 페이지를 새로고침하지 않아도 가벼운 배너로 알 수 있다.
- 스팸(도배) 방지를 위한 요청 빈도 제한을 갖춘다.
- 기존 코드베이스의 관례(네이밍, 세션 기반 인증, CSRF, `db.py` 단일 창구, flash 메시지 에러 처리)를 그대로 따르고, 새로운 아키텍처 패턴(Blueprint 분리, 프론트 프레임워크, 실시간 웹소켓 등)은 도입하지 않는다.

---

## 2. 변경할 파일 경로

### 2-1. 수정(기존 파일에 추가)

| 파일 | 변경 종류 |
|---|---|
| [app.py](../../app.py) | 게시판 라우트 8개 + 관리자용 게시글 관리 API 2개 추가 |
| [db.py](../../db.py) | 게시글/댓글/빈도제한 관련 함수 약 14개 추가 |
| [detector.py](../../detector.py) | `is_post_rate_limited`, `is_comment_rate_limited` 판정 함수 2개 추가 |
| [config.py](../../config.py) | `POST_RATE_LIMIT`, `COMMENT_RATE_LIMIT`, `BOARD_PAGE_SIZE` 상수 3개 추가 |
| [docs/schema.sql](../schema.sql) | `posts`, `comments`, `post_attempts`, `comment_attempts` 테이블 4개 추가 (문서 기록용 — 실제 반영은 Supabase SQL Editor에서 별도 실행) |
| [templates/admin_dashboard.html](../../templates/admin_dashboard.html) | "게시글 관리" 섹션(표 2개: 최근 게시글, 최근 댓글) 추가 |
| [public/js/dashboard.js](../../public/js/dashboard.js) | `renderPostsTable`, `renderCommentsTable`, `deletePost`, `deleteComment` 함수 추가, `fetchStatus()`가 새 데이터도 반영하도록 확장 |
| [tests/test_app.py](../../tests/test_app.py) | 게시판 라우트 통합 테스트 추가 |
| [tests/test_db.py](../../tests/test_db.py) | 게시글/댓글 DB 함수 단위 테스트 추가 |
| [tests/test_detector.py](../../tests/test_detector.py) | 빈도 제한 판정 경계값 테스트 추가 |

### 2-2. 신규 생성

| 파일 | 용도 |
|---|---|
| `templates/board_list.html` | 게시글 목록 (페이지네이션 포함) |
| `templates/board_detail.html` | 게시글 상세 + 댓글 목록 + 댓글 작성 폼 + "새 댓글" 알림 배너 자리 |
| `templates/board_form.html` | 글 작성/수정 공용 폼 (`login_form.html`이 `form_action`을 받아 GET/POST 화면을 공유하는 것과 동일한 패턴) |
| `public/css/board.css` | 게시판 전용 스타일 (`tokens.css` 변수만 사용, `member.css`와 톤 통일) |
| `public/js/board.js` | 게시글 상세 화면에서 "새 댓글이 추가되었습니다" 배너를 위한 가벼운 폴링 스크립트 |

---

## 3. 파일별 수정 내용

### 3-1. `docs/schema.sql` (신규 테이블 4개)

```sql
-- 게시판 글 (login_attempts와 동일한 관례: users와 FK를 걸지 않고 작성자를 텍스트로만 저장
-- → 회원 탈퇴 후에도 글은 흔적만 남기고 유지된다, 결정 #4)
create table posts (
  id bigint generated always as identity primary key,
  author_username text not null,
  title text not null,
  body text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index idx_posts_created_at on posts (created_at desc);

-- 댓글 (단일 depth, 결정 #3 — 대댓글 없음이라 자기참조 FK 불필요).
-- post_id는 posts를 FK로 참조하며 on delete cascade — "글이 지워지면 그 글의 댓글도
-- 함께 지워진다"는 자연스러운 종속 관계이지, 회원 탈퇴 cascade(결정 #4, 하지 않기로 함)와는 별개다.
create table comments (
  id bigint generated always as identity primary key,
  post_id bigint not null references posts(id) on delete cascade,
  author_username text not null,
  body text not null,
  created_at timestamptz not null default now()
);
create index idx_comments_post_id_created_at on comments (post_id, created_at);

-- 게시글 작성 빈도 제한 (signup_attempts와 완전히 동일한 구조, 결정 #7)
create table post_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);
create index idx_post_attempts_ip_time on post_attempts (ip_address, attempted_at);

-- 댓글 작성 빈도 제한
create table comment_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);
create index idx_comment_attempts_ip_time on comment_attempts (ip_address, attempted_at);
```

### 3-2. `config.py` (상수 3개 추가)

```python
# 게시판 한 페이지에 보여줄 글 개수 (결정 #9 — 페이지 번호 방식 페이지네이션)
BOARD_PAGE_SIZE = int(os.environ.get("BOARD_PAGE_SIZE", 10))

# 게시글/댓글 작성 빈도 제한 (signup과 동일한 개념, 결정 #7)
POST_RATE_LIMIT = int(os.environ.get("POST_RATE_LIMIT", 5))
COMMENT_RATE_LIMIT = int(os.environ.get("COMMENT_RATE_LIMIT", 10))
```

### 3-3. `db.py` (함수 추가)

기존 파일의 섹션 구분 관례(`# === ○○ 표 관련 함수 ===`)를 그대로 따라 하단에 3개 섹션을 추가한다.

- **posts 표 관련**: `create_post`, `get_post`, `list_posts(page, page_size)`, `count_posts`, `update_post`, `delete_post`, `list_recent_posts(limit)`(관리자용)
- **comments 표 관련**: `create_comment`, `list_comments_by_post`, `delete_comment`, `get_latest_comment_info(post_id)`(폴링 배너용 — `{"count": N, "latest_at": iso}` 반환), `list_recent_comments(limit)`(관리자용)
- **post_attempts / comment_attempts 관련**: `log_post_attempt`, `count_recent_post_attempts`, `log_comment_attempt`, `count_recent_comment_attempts` (signup_attempts 함수들과 완전히 동일한 패턴 복제)

### 3-4. `detector.py` (함수 추가)

```python
def is_post_rate_limited(ip: str) -> bool:
    return db.count_recent_post_attempts(ip) >= POST_RATE_LIMIT

def is_comment_rate_limited(ip: str) -> bool:
    return db.count_recent_comment_attempts(ip) >= COMMENT_RATE_LIMIT
```
`is_signup_rate_limited`와 동일 패턴("초과"가 아니라 "이상"이면 즉시 차단).

### 3-5. `app.py` (라우트 추가)

| 라우트 | 메서드 | 데코레이터 | 설명 |
|---|---|---|---|
| `/board` | GET | `member_login_required` | 게시글 목록 (페이지네이션) |
| `/board/new` | GET | `member_login_required` | 글쓰기 폼 |
| `/board/new` | POST | `member_login_required` | 글쓰기 제출 (빈도 제한 검사 포함) |
| `/board/<int:post_id>` | GET | `member_login_required` | 상세 + 댓글 목록 + 댓글 폼 |
| `/board/<int:post_id>/edit` | GET | `member_login_required` | 수정 폼 (본인 글 아니면 리다이렉트+flash) |
| `/board/<int:post_id>/edit` | POST | `member_login_required` | 수정 제출 |
| `/board/<int:post_id>/delete` | POST | `member_login_required` | 본인 글 삭제 |
| `/board/<int:post_id>/comments` | POST | `member_login_required` | 댓글 작성 (빈도 제한 검사 포함) |
| `/board/<int:post_id>/comments/<int:comment_id>/delete` | POST | `member_login_required` | 본인 댓글 삭제 |
| `/api/board/<int:post_id>/comments/latest` | GET | `member_login_required` | 폴링용 — 최신 댓글 개수/시각만 JSON으로 반환 |
| `/api/board/posts/delete` | POST | `login_required`(관리자) | 관리자가 임의 글 삭제 |
| `/api/board/comments/delete` | POST | `login_required`(관리자) | 관리자가 임의 댓글 삭제 |

기존 `api_status()`도 확장해 `recent_posts`, `recent_comments`를 함께 내려주고, `admin_dashboard.html` + `dashboard.js`가 이를 표로 그린다(기존 회원 목록 표와 동일한 패턴).

### 3-6. 템플릿/CSS/JS

- `board_list.html`, `board_detail.html`, `board_form.html`은 `member_dashboard.html`/`member_profile.html`의 구조(상단 `topbar` + `tokens.css`/`member.css` 링크 + `theme.js`)를 그대로 복제.
- 본문 줄바꿈은 `nl2br` 같은 `|safe` 필터를 쓰지 않고, **CSS `white-space: pre-wrap`**으로 처리한다 — Jinja2 auto-escape를 그대로 유지하면서 줄바꿈만 보존하는 방식(6절 기술 스택 이유 참고).
- `board.js`는 `board_detail.html`에서만 로드되며, `setInterval`로 `/api/board/<id>/comments/latest`를 짧은 주기(예: 15초)로 확인해 값이 바뀌면 배너를 노출한다. 표 전체를 다시 그리는 `dashboard.js`와 달리 이 배너는 클릭하면 페이지를 새로고침(`location.reload()`)하는 방식으로 단순하게 구현한다.

---

## 4. 필요한 함수, 컴포넌트

**`db.py`** — `create_post`, `get_post`, `list_posts`, `count_posts`, `update_post`, `delete_post`, `list_recent_posts`, `create_comment`, `list_comments_by_post`, `delete_comment`, `get_latest_comment_info`, `list_recent_comments`, `log_post_attempt`, `count_recent_post_attempts`, `log_comment_attempt`, `count_recent_comment_attempts` (총 16개)

**`detector.py`** — `is_post_rate_limited`, `is_comment_rate_limited` (총 2개)

**`app.py`** — 위 3-5절 표의 라우트 함수 12개 + 권한 검사 헬퍼 `_is_post_owner(post, session)` 같은 소규모 내부 함수(선택적)

**JS(`dashboard.js` 추가분)** — `renderPostsTable`, `renderCommentsTable`, `deletePost`, `deleteComment`

**JS(`board.js`, 신규)** — `checkForNewComments`, `showNewCommentBanner`

---

## 5. 예상 코드 흐름

### 5-1. 글 작성 (`POST /board/new`)
1. `member_login_required`가 세션에 `username`이 있는지 확인.
2. `detector.is_post_rate_limited(ip)`로 도배 여부 판정 → 초과 시 flash + 폼 재표시.
3. `db.log_post_attempt(ip)`로 시도 자체를 기록 (성공/실패 무관, `signup_submit`과 동일 원칙).
4. 제목/본문 길이 검증(빈 값·과도한 길이 차단) → 실패 시 flash + 폼 재표시.
5. `db.create_post(session["username"], title, body)` 호출 → 성공 시 상세 페이지로 redirect.

### 5-2. 댓글 작성 (`POST /board/<id>/comments`)
1. `member_login_required` 통과.
2. `detector.is_comment_rate_limited(ip)` 판정 → 초과 시 flash.
3. `db.log_comment_attempt(ip)` 기록.
4. `db.get_post(post_id)`로 글 존재 확인 → 없으면 404류 처리.
5. `db.create_comment(post_id, session["username"], body)` → `/board/<id>`로 redirect(Post-Redirect-Get 패턴, `member_profile_submit`과 동일).

### 5-3. 본인 글 삭제 (`POST /board/<id>/delete`)
1. `member_login_required` 통과.
2. `db.get_post(post_id)` 조회 → 없으면 flash.
3. `post["author_username"] != session["username"]`이면 삭제 거부(flash + redirect) — **관리자가 아닌 이상 본인 글만 지울 수 있다는 규칙을 라우트 함수 안에서 명시적으로 검사**(기존 `login_required`/`member_login_required`는 "로그인 여부"만 확인하고 "소유권"은 확인하지 않으므로 이 부분은 각 라우트가 직접 검사해야 함).
4. 통과 시 `db.delete_post(post_id)` → 목록으로 redirect.

### 5-4. 관리자 게시글 삭제 (`POST /api/board/posts/delete`)
1. `login_required`(관리자 세션)만 확인 — 이미 로그인된 관리자이므로 소유권 검사 없이 바로 실행(`api_users_delete`와 동일 패턴).
2. `db.delete_post(post_id)` 호출 → `{"success": true/false}` JSON 응답.

### 5-5. 새 댓글 알림 배너
1. `board_detail.html`이 로드될 때 현재 댓글 개수/최신 시각을 데이터 속성(`data-comment-count`, `data-latest-at`)에 심어둔다.
2. `board.js`가 `setInterval`로 `/api/board/<id>/comments/latest`를 호출.
3. 응답의 `count`/`latest_at`이 페이지 로드 시점 값과 다르면 배너("새로운 댓글이 추가되었습니다")를 노출.
4. 배너 클릭 시 `location.reload()`로 최신 댓글까지 포함된 SSR 화면을 다시 받아온다 — 부분 갱신(diff 렌더링) 없이 가장 단순한 방식.

---

## 6. 테스트 검증 방법

기존 테스트 구조(소스 파일 1개당 테스트 파일 1개, `conftest.py`의 Supabase 접속 차단 fixture 재사용)를 그대로 따른다 — **새 테스트 파일을 만들지 않고 기존 파일에 추가**한다.

- **`tests/test_db.py` 추가분**: `create_post`/`get_post`/`list_posts`/`update_post`/`delete_post`/`create_comment`/`list_comments_by_post`/`delete_comment`가 가짜 Supabase 클라이언트 응답을 받아 올바른 테이블/조건으로 쿼리를 구성하는지 단위 검증.
- **`tests/test_detector.py` 추가분**: `is_post_rate_limited`/`is_comment_rate_limited`가 `test_detector.py`의 기존 스타일(임계값 경계 4/5/6회 검증)과 동일하게 "제한 미만/도달/초과" 3구간을 확인.
- **`tests/test_app.py` 추가분** (Flask `test_client` + `get_csrf_token()` 헬퍼 재사용):
  - 비로그인 상태로 `/board`, `/board/new`, `/board/<id>/comments` 접근 시 `/login`으로 리다이렉트되는지 (결정 #1 검증).
  - 로그인 상태에서 글 작성 → 목록/상세에 반영되는지.
  - 본인 글이 아닌 글을 삭제 시도하면 거부되는지 (`_is_post_owner` 검증, 3-3절 권한 로직).
  - 관리자가 `/api/board/posts/delete`로 임의 글을 삭제할 수 있는지, 비관리자가 시도하면 401인지.
  - `detector.is_post_rate_limited`를 `monkeypatch`로 강제 `True`로 만들었을 때 `db.create_post`가 호출되지 않는지(`test_login_locked_ip_short_circuits_before_checking_credentials`와 동일한 "함정 monkeypatch" 기법).
  - CSRF 토큰 없이 `/board/new`에 POST하면 400으로 거부되는지.
- **수동 브라우저 검증**: `preview_start`로 로컬 서버를 띄우고, 글 작성 → 댓글 작성 → 다른 브라우저 세션(또는 시크릿창)에서 댓글을 추가로 달았을 때 첫 번째 화면에 배너가 뜨는지 실제로 확인.

---

## 7. 기술 스택 선택과 이유

| 결정 | 이유 |
|---|---|
| Flask 라우트 + Jinja2 SSR 그대로 사용 | 새 프레임워크/라이브러리를 도입하지 않고 기존 관례(`member_profile_submit` 등)와 100% 일치시키기 위함 |
| Supabase 테이블 4개 추가, 새 DB 엔진 없음 | 이미 Supabase-python client가 프로젝트 전역에 쓰이고 있어 학습·설정 비용이 0 |
| 페이지네이션은 PostgREST의 `.range()`/`.limit()` | supabase-py가 기본 제공하는 기능이라 별도 페이지네이션 라이브러리 불필요 |
| 줄바꿈은 `white-space: pre-wrap` (CSS) | `nl2br` 필터나 `|safe`를 쓰면 XSS 방어(Jinja2 auto-escape)를 부분적으로 무력화해야 함 — CSS만으로 줄바꿈을 보존하면 이스케이프를 100% 유지한 채 요구사항을 만족시킬 수 있음(결정 #5와 직결) |
| 새 댓글 알림은 `setInterval` + `fetch` (바닐라 JS) | `dashboard.js`가 이미 이 패턴(폴링)을 검증된 방식으로 쓰고 있어 그대로 재사용. 웹소켓/SSE 도입은 이 프로젝트 규모에 비해 과함 |
| 빈도 제한은 자체 테이블 + `detector.py` 판정 함수 | `signup_attempts` 패턴을 그대로 복제 — `flask-limiter` 같은 별도 라이브러리를 새로 추가하지 않아도 기존 방식으로 충분히 구현 가능 |
| 파일 구조는 기존 `app.py`/`db.py` 유지 (Blueprint 미도입) | 사용자가 `app.py`를 혼자 관리하고 있어 병합 충돌 위험이 낮다고 판단, 기존 관례와의 일관성을 우선(결정 #11 재확인) |

---

## 8. 제외할 범위

`research_board.md`/`02-design-decisions.md`에서 이미 결정된 대로, 아래 항목은 **이번 구현에 포함하지 않는다**.

- 비로그인 사용자의 게시글 열람/작성 (회원 전용으로 확정, 결정 #1)
- 대댓글(답글) 기능 — 댓글은 단일 depth (결정 #3)
- 회원 탈퇴 시 게시글/댓글 cascade 삭제 — 흔적만 남기고 유지 (결정 #4)
- 마크다운/HTML 서식, 리치 텍스트 에디터, `|safe` 필터 사용 (결정 #5)
- 실시간 웹소켓/SSE 기반 갱신 — 가벼운 폴링 배너로 대체 (결정 #6)
- 이미지/파일 첨부, Supabase Storage 연동 (결정 #8)
- 무한 스크롤 — 페이지 번호 방식으로 확정 (결정 #9)
- Blueprint 등 파일 구조 분리 (결정 #11)
- 게시글/댓글 신고·검열·태그·카테고리 분류 등 커뮤니티 부가 기능 일체 (애초에 논의된 바 없음, 범위 밖)

---

## 9. 다음 단계

이 계획대로 실제 코드(스키마 SQL, `db.py`/`detector.py`/`config.py`/`app.py` 함수, 템플릿, CSS, JS, 테스트) 작성에 착수해도 될지 확인 부탁드립니다. 계획 중 수정하고 싶은 부분이 있다면 먼저 알려주세요.
