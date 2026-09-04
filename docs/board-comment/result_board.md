# 게시판·댓글 기능 — 작업 결과 정리

> 작성 기준일: 2026-09-04 / 브랜치: `main`
> 관련 문서: [research_board.md](research_board.md)(구현 전 분석) → [02-design-decisions.md](02-design-decisions.md)(11개 질문 결정) → [plan_board.md](plan_board.md)(구현 계획)

---

## 1. 작업 개요

로그인 워치독의 회원 전용 영역에 **게시판·댓글 기능**을 신규 추가했다. 기존 코드베이스(판정/실행 분리, `db.py` 단일 창구, 세션 기반 인증, CSRF, flash 메시지 에러 처리 등)의 관례를 그대로 따르는 것을 원칙으로 진행했다.

**진행 순서**: 기존 구조 분석 → 구현 전 질문 11개 확정 → 구현 계획 수립 → 스키마/코드/템플릿/테스트 구현 → 실제 Supabase 스키마 반영(사용자 작업) → pytest + 실제 브라우저 검증 → 검증 중 발견한 버그 2건 수정 → 사용자 피드백 반영(버튼 스타일 통일, 폴링 주기 조정 및 `config.py` 이관).

---

## 2. 확정된 설계 결정 (요약)

`02-design-decisions.md`에서 확정한 11개 결정 사항을 그대로 구현에 반영했다.

| 항목 | 결정 |
|---|---|
| 접근 범위 | 회원 전용 열람/작성 + 관리자 대시보드에 별도 "게시글 관리" 섹션 |
| 삭제 권한 | 본인 + 관리자 |
| 댓글 구조 | 단일 depth (대댓글 없음) |
| 회원 탈퇴 시 처리 | 흔적은 남기고 유지 (FK 없이 텍스트로만 작성자 저장) |
| 입력 허용 범위 | 순수 텍스트 + 줄바꿈만 (마크다운/HTML 불허) |
| 목록 표시 방식 | SSR + 새 댓글 알림 배너(가벼운 폴링) |
| 빈도 제한 | 회원가입과 동일한 패턴으로 추가 |
| 파일 첨부 | 불필요 |
| 페이지네이션 | 페이지 번호 방식 |
| URL 네이밍 | `/board`, `/board/<id>`, `/board/<id>/comments` |
| 파일 구조 | 기존 `app.py`/`db.py`에 추가 (Blueprint 분리 없음) |

---

## 3. 최종 산출물

### 3-1. 신규 파일

| 파일 | 내용 |
|---|---|
| `templates/board_list.html` | 게시글 목록 + 페이지네이션 |
| `templates/board_detail.html` | 게시글 상세 + 댓글 목록/작성 + 새 댓글 알림 배너 |
| `templates/board_form.html` | 글쓰기/수정 공용 폼 |
| `public/css/board.css` | 게시판 전용 스타일 (tokens.css 변수만 사용) |
| `public/js/board.js` | 새 댓글 알림 폴링 스크립트 |
| `docs/board-comment/research_board.md` | 구현 전 구조 분석 |
| `docs/board-comment/02-design-decisions.md` | 구현 전 질문 11개 결정 기록 |
| `docs/board-comment/plan_board.md` | 구현 계획 (스키마/라우트/함수 설계 포함) |
| `docs/board-comment/result_board.md` | 이 문서 |

### 3-2. 수정 파일

| 파일 | 변경 내용 |
|---|---|
| `docs/schema.sql` | `posts`, `comments`, `post_attempts`, `comment_attempts` 4개 테이블 추가 |
| `config.py` | `BOARD_PAGE_SIZE`, `POST_RATE_LIMIT`, `COMMENT_RATE_LIMIT`, `BOARD_COMMENT_POLL_MS`, `ADMIN_DASHBOARD_POLL_MS` 상수 추가 |
| `db.py` | 게시글/댓글/빈도제한 관련 함수 17개 추가 |
| `detector.py` | `is_post_rate_limited`, `is_comment_rate_limited` 판정 함수 2개 추가 |
| `app.py` | 게시판 라우트 10개 + 관리자용 게시글/댓글 관리 API 2개 추가, `api_status()` 확장, `board_detail()`/`admin_dashboard()`가 폴링 주기 값을 템플릿에 전달 |
| `templates/admin_dashboard.html` | "게시판 관리 — 최근 게시글/댓글" 섹션 추가, `poll-interval-ms` meta 태그 추가 |
| `templates/member_dashboard.html` | "게시판 바로가기" 링크 추가 |
| `public/js/dashboard.js` | 게시글/댓글 관리용 렌더링·삭제 함수 및 이벤트 위임 추가, 폴링 주기를 meta 태그에서 읽도록 변경(하드코딩 제거) |
| `tests/test_db.py`, `tests/test_detector.py`, `tests/test_app.py` | 게시판 관련 단위/통합 테스트 추가 |

### 3-3. 라우트 목록

```
GET  /board                              게시글 목록 (페이지네이션)
GET  /board/new                          글쓰기 폼
POST /board/new                          글쓰기 제출
GET  /board/<id>                         게시글 상세 + 댓글
GET  /board/<id>/edit                    수정 폼 (본인 글만)
POST /board/<id>/edit                    수정 제출
POST /board/<id>/delete                  본인 글 삭제
POST /board/<id>/comments                댓글 작성
POST /board/<id>/comments/<cid>/delete   본인 댓글 삭제
GET  /api/board/<id>/comments/latest     새 댓글 폴링용 (가벼운 개수/시각만)
POST /api/board/posts/delete             관리자 전용 — 임의 글 삭제
POST /api/board/comments/delete          관리자 전용 — 임의 댓글 삭제
```

---

## 4. 테스트 및 검증 결과

### 4-1. 자동화 테스트

```
pytest tests/  →  94 passed
```

- `tests/test_db.py`: 게시글/댓글 CRUD 함수가 Supabase 쿼리를 올바른 조건으로 구성하는지 (가짜 클라이언트로 단위 검증)
- `tests/test_detector.py`: 게시글/댓글 빈도 제한 판정의 경계값 검증
- `tests/test_app.py`: 회원 전용 접근 제어, 소유권 검사(본인 글/댓글만 수정·삭제), 빈도 제한 시 요청 단락 처리, 관리자 전용 API의 인증/CSRF 검증

### 4-2. 실제 브라우저 검증

로컬 서버(`preview_start`)를 띄우고 실제 Supabase(사용자가 반영한 스키마)에 연결한 상태로 아래 흐름을 눈으로 직접 확인했다.

- 회원가입 → 로그인 → 회원 대시보드 "게시판 바로가기" 진입
- 게시글 작성 → 목록/상세 반영
- **XSS 방어**: 본문에 `<script>alert(1)</script>`를 입력해도 `&lt;script&gt;`로 이스케이프되어 실제 `<script>` 요소가 생성되지 않음을 DOM에서 직접 확인
- **줄바꿈 보존**: `white-space: pre-wrap`으로 `|safe` 필터 없이 줄바꿈만 정상 표시
- 댓글 작성 → 새로고침 없이 "새로운 댓글이 추가되었습니다" 배너 노출 확인
- 게시글 수정, 댓글 삭제(본인), 게시글 삭제(본인 — 연결된 댓글도 `on delete cascade`로 함께 삭제됨을 확인)
- 관리자 대시보드 "게시판 관리" 섹션에서 임의 게시글/댓글 삭제 확인
- 검증에 사용한 테스트 계정·게시글은 확인 후 정리

---

## 5. 검증 중 발견해 수정한 이슈

작업 계획대로 구현한 뒤 실제 브라우저 검증 과정에서 발견한 실제 버그 2건을 그 자리에서 수정했다.

### 5-1. 새 댓글 배너 오탐 (board.js)

**증상**: 댓글이 하나도 없는 글에서도 폴링할 때마다 "새로운 댓글이 추가되었습니다" 배너가 잘못 떴다.

**원인**: 댓글이 0개일 때 서버 API(`get_latest_comment_info`)는 `latest_at: null`을 내려주는데, 페이지가 처음 그려질 때의 기준값은 빈 문자열(`""`)이었다. `null !== ""`이라 타입이 달라 항상 "값이 바뀌었다"고 오판했다.

**수정**: `board.js`에서 API 응답의 `latest_at`을 `data.latest_at || ""`로 정규화해 항상 문자열끼리 비교하도록 변경.

### 5-2. "수정"/"삭제" 버튼 스타일 불일치 (board.css)

**증상**: 게시글 상세 화면에서 "수정" 링크와 "삭제" 버튼의 크기·색상이 서로 다르게 보였다(사용자 스크린샷으로 확인).

**원인**: `member.css`의 전역 규칙 `.member-card button[type="submit"]`(상세도 0-2-1)이 `.board-post-actions button`(상세도 0-1-1)보다 상세도가 높아 `<button>`(삭제)에만 적용되고, `<a>` 태그인 "수정"에는 적용되지 않아 서로 다른 모양이 됐다.

**수정**: `board.css`의 선택자를 `.board-card .board-post-actions button`으로 조정해 상세도를 동일하게 맞추고, `board.css`가 `member.css`보다 나중에 로드되므로 캐스케이드 순서상 이 규칙이 최종 적용되도록 함(`!important` 없이 해결). 두 버튼 모두 동일한 accent 배경 + 흰 글씨 스타일로 통일.

---

## 6. 사용자가 직접 수행한 작업

- Supabase SQL Editor에서 `docs/schema.sql`의 신규 테이블 4개(`posts`, `comments`, `post_attempts`, `comment_attempts`) 실행 — 이 저장소의 코드만으로는 실제 데이터베이스에 반영되지 않으며, 이 작업이 완료된 뒤에야 `/board` 라우트가 정상 동작함을 실제로 확인했다.

---

## 7. 후속 개선 — 사용자 피드백 반영

초기 구현 완료 뒤, 사용자 피드백을 반영해 세 가지를 추가로 작업했다.

### 7-1. 새 댓글 배너 폴링 주기 조정 (15초 → 5초)

관리자 대시보드(10초, 쿼리 7개 묶음)와 달리 게시글 상세의 새 댓글 배너는 `/api/board/<id>/comments/latest` 하나짜리 가벼운 쿼리이고, 사용자가 그 글을 보고 있는 동안에만 도는 것이라 여유가 있다고 판단해 5초로 조정했다. 서버 로그(`12:04:46 → 51 → 56`)로 정확히 5초 간격 폴링을 실제로 확인했다.

### 7-2. 폴링 주기 값을 `config.py`로 이관

`board.js`(5000ms)와 `dashboard.js`(10000ms) 각 파일에 하드코딩돼 있던 값을 `config.py`의 `BOARD_COMMENT_POLL_MS`, `ADMIN_DASHBOARD_POLL_MS`로 옮기고, 각 화면(`board_detail.html`은 `data-poll-interval-ms` 속성, `admin_dashboard.html`은 `csrf-token`과 동일한 방식의 `<meta name="poll-interval-ms">`)을 통해 JS가 값을 읽어오도록 변경했다.

**변경 전 이 값이 다른 사람에게 노출되면 악용될 수 있는지 검토**: 폴링 주기는 클라이언트가 서버 상태를 얼마나 자주 확인하는지를 정하는 UX 값일 뿐, 서버가 이 값을 신뢰해서 뭔가를 허용/차단하는 보안 경계가 아니다. 게다가 `public/js/*.js`는 애초에 로그인 없이도 열람 가능한 정적 파일이라 지금도 이미 완전히 공개된 값이었다 — `config.py`로 옮겨 템플릿에 렌더링해도 노출 범위는 늘지 않는다(오히려 로그인한 화면 안에만 값이 보이므로 더 좁아짐). 실제 남용 방지는 이 값과 무관하게 서버 쪽의 `POST_RATE_LIMIT`/`COMMENT_RATE_LIMIT`과 `member_login_required`/`login_required`가 계속 담당한다.

브라우저에서 두 화면 모두 `data-poll-interval-ms`/`meta[name="poll-interval-ms"]` 값이 `config.py`와 정확히 일치하는 것, 그리고 실제 폴링 간격도 그대로 동작하는 것을 재확인했다. `pytest tests/` 94개도 그대로 통과.

### 7-3. 관리자 대시보드 삭제 버튼 스타일 통일

**증상**: 관리자 대시보드의 "게시판 관리" 섹션에서 게시글/댓글 삭제 버튼이 기존 회원 목록 삭제 버튼과 다르게(꾸미지 않은 기본 버튼 모양으로) 보인다는 지적을 받았다.

**원인**: `dashboard.js`가 게시글/댓글 삭제 버튼에 `delete-post-btn`/`delete-comment-btn` 클래스를 부여했지만, `public/css/dashboard.css`에는 이 두 클래스에 대한 스타일 규칙 자체가 없었다 — 기존 `.delete-user-btn`(회원 목록 삭제 버튼) 규칙만 있고, 게시판 관리 섹션을 추가할 때 이 규칙에 새 클래스를 합치는 걸 빠뜨렸다.

**수정**: `dashboard.css`의 `.delete-user-btn` 규칙을 `.delete-user-btn, .delete-post-btn, .delete-comment-btn`으로 합쳐 하나의 규칙으로 통일했다.
```css
.delete-user-btn,
.delete-post-btn,
.delete-comment-btn {
    background: var(--danger);
    color: white;
    border: none;
    border-radius: var(--radius-s);
    padding: 5px 10px;
    cursor: pointer;
    font-family: var(--font-body);
    font-size: 12px;
}
```
브라우저에서 실제 글/댓글을 만들고 관리자 대시보드에서 세 버튼의 `getComputedStyle`(배경색·글자색·패딩·폰트 크기)이 완전히 동일함을 확인했고, `pytest tests/` 94개도 그대로 통과했다.

---

## 8. 알려진 제한사항 / 향후 고려 사항

`research_board.md`의 결정 사항에 따라 아래는 **이번 구현 범위에서 의도적으로 제외**했다.

- 비로그인 사용자의 게시글 열람/작성
- 대댓글(답글) 기능
- 회원 탈퇴 시 게시글/댓글 cascade 삭제(흔적만 유지하는 방식 채택)
- 마크다운/HTML 서식, 리치 텍스트
- 실시간 웹소켓/SSE 기반 갱신(가벼운 폴링 배너로 대체)
- 이미지/파일 첨부
- 무한 스크롤(페이지 번호 방식 채택)
- Blueprint 등 파일 구조 분리(현재 사용자가 `app.py`/`db.py`를 혼자 관리 중이라 병합 충돌 위험이 낮다고 판단해 보류 — 협업 인원이 늘어나면 재검토 필요)
- 게시글/댓글 신고·검열·태그·카테고리 분류 등 커뮤니티 부가 기능

향후 게시글/댓글 수가 많아지면 `list_posts`/`list_comments_by_post`의 정렬·인덱스 성능, `BOARD_PAGE_SIZE` 조정, 폴링 주기(관리자 대시보드 `ADMIN_DASHBOARD_POLL_MS` 기본 10초, 새 댓글 배너 `BOARD_COMMENT_POLL_MS` 기본 5초 — 둘 다 `config.py`/환경변수로 조정 가능)로 인한 Supabase 무료 쿼터 소진 여부를 다시 점검할 필요가 있다(9단계 가이드에서 이미 한 번 겪은 문제 유형).
