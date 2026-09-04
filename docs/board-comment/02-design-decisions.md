# 게시판·댓글 기능 — 설계 결정 기록

> 작성 기준일: 2026-09-04 / 브랜치: `main`
> [research_board.md](research_board.md)의 "4. 구현 전 질문" 11개 항목에 대해 사용자와 논의해 확정한 결정 사항.

---

## 결정 사항 요약

| # | 질문 | 결정 | 비고 |
|---|---|---|---|
| 1 | 접근 범위 | **회원 전용** 열람/작성 + `/admin/dashboard`에 별도 "게시글 관리" 섹션 추가 | 비로그인 유저는 `/board` 접근 시 로그인 화면으로 리다이렉트. 관리자는 회원 게시판과 별개로 전체 글/댓글 조회·삭제 |
| 2 | 삭제 권한 | **본인 + 관리자** | 회원은 자기 글/댓글만, 관리자는 전체 |
| 3 | 댓글 구조 | **단일 depth** (대댓글 없음) | `comments` 테이블에 자기참조 FK 불필요 |
| 4 | 탈퇴 시 처리 | **흔적은 남기고 유지** | `login_attempts`와 동일한 관례 — FK 없이 작성자 표시만 유지, cascade 삭제 안 함 |
| 5 | 입력 허용 범위 | **순수 텍스트 + 줄바꿈만** | HTML/마크다운 미허용. Jinja2 auto-escape로 충분, 별도 sanitize 라이브러리 불필요 |
| 6 | 목록 표시 방식 | **SSR + 가벼운 새 댓글 알림 배너** | 기본은 서버 렌더링. 추가로 짧은 주기 폴링으로 "새로운 댓글이 추가되었습니다" 배너만 띄우는 하이브리드 (관리자 대시보드처럼 표 전체를 JS로 다시 그리지는 않음) |
| 7 | 빈도 제한 | **필요 — 회원가입과 동일 패턴으로 추가** | `signup_attempts`처럼 `post_attempts`/`comment_attempts` 테이블 + 요청 빈도 제한 |
| 8 | 파일/이미지 첨부 | **불필요** | Supabase Storage 연동 없이 텍스트만 |
| 9 | 페이지네이션 | **페이지 번호 방식** | offset 기반, SSR과 자연스럽게 어울림 |
| 10 | URL/라우트 네이밍 | **`/board`, `/board/<id>`, `/board/<id>/comments`** | 회원 전용이지만 최상위 경로 유지 (`/dashboard/board`로 종속시키지 않음) |
| 11 | 파일 구조 | **기존 `app.py`/`db.py`에 추가** | Blueprint(`board.py`) 분리 없이 현재 관례 유지 |

---

## 결정에 따른 파생 사항 (다음 설계 단계에서 구체화 필요)

- **접근 제어**: `/board*` 라우트 전체에 기존 `member_login_required` 데코레이터를 그대로 재사용. 관리자용 게시글 관리 API는 `login_required` + `/api/` 접두사 규칙(`/api/board/posts/delete` 등)을 따름.
- **스키마 초안 방향**: `posts(id, author_username, title, body, created_at)`, `comments(id, post_id, author_username, body, created_at)` — `login_attempts`와 동일하게 `author_username`은 텍스트로만 저장하고 `users`와 FK를 걸지 않음(결정 #4).
- **새 빈도 제한 테이블**: `post_attempts(ip_address, attempted_at)`, `comment_attempts(ip_address, attempted_at)` — `signup_attempts`와 동일 구조, `config.py`에 `POST_RATE_LIMIT` 같은 상수 추가 필요(결정 #7).
- **"새 댓글 알림" 폴링 API**: 전체 상태를 돌려주는 `/api/status`와 달리, 가벼운 전용 엔드포인트(예: `/api/board/<id>/comments/latest`)로 "최신 댓글 개수 또는 시각"만 확인하고, 값이 바뀌었을 때만 배너를 띄우는 방식을 다음 설계 단계에서 구체화(결정 #6).
- **페이지네이션 상수**: `config.py`에 페이지당 게시글 수 상수 추가 필요(결정 #9).

## 다음 단계 제안

이 결정들을 바탕으로 다음 문서(`03-schema-and-routes.md` 등)에서 실제 테이블 스키마(`docs/schema.sql` 추가분), 라우트 목록, `db.py` 함수 시그니처를 구체적으로 설계하는 것을 제안합니다. 이 단계까지 진행할까요, 아니면 먼저 확인하고 싶은 부분이 있으신가요?
