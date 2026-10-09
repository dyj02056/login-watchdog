// ============================================================================
// dashboard/render.js — 서버에서 받은 데이터로 표/카드를 그리는 함수 모음
//
// 원래 이 파일 하나(556줄)에 모든 표·카드 그리기 함수가 있었는데, 화면 영역별로 나눴다:
//   render/tables.js    — 로그인 시도·관리자 로그인 기록·회원·관리자 계정·게시글·댓글 표, 회원가입 상태
//   render/security.js  — 보안 이벤트·연관 사건·AI 조기 경보 표
//   render/locks.js     — 잠금 카드, 영구 잠금·복구 요청·IP 예외 표
//
// 이 파일은 위 모듈의 함수를 그대로 다시 내보내기만 한다 — 그래서 api.js는 예전처럼
// `import { renderUsersTable } from "./render.js"`로 쓴다.
// 배경 설명은 dashboard/main.js 상단 주석과 docs/refactor/2026-10-09-module-plan.md 참고.
// ============================================================================

export * from "./render/locks.js";
export * from "./render/security.js";
export * from "./render/tables.js";
