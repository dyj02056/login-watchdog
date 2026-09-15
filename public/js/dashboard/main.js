// ============================================================================
// dashboard/main.js — 대시보드 화면을 살아있게 만드는 자바스크립트의 진입점
//
// 이 화면이 하는 일은 크게 3가지다.
// 1) 주기적으로(config.py의 ADMIN_DASHBOARD_POLL_MS, 기본 10초마다) 서버의
//    /api/status에 "지금 상태 알려줘"라고 물어본다.
//    (원래는 2.5초였으나, Supabase 무료 쿼터 점검 결과 대시보드를 오래 켜두면
//    한 달 쿼터를 금방 소진할 수 있다는 걸 확인하고 10초로 늘렸다 — 8단계 이후
//    "쿼터 점검" 단계 참고)
// 2) 받아온 데이터로 화면의 표/카드를 다시 그린다.
// 3) "즉시 해제" 버튼을 누르면 /api/unlock에 "이 IP 좀 풀어줘"라고 요청을 보낸다.
//
// HTML(admin_dashboard.html)은 표의 "틀"만 가지고 있고, 실제 알맹이(데이터)는
// 전부 이 스크립트가 채워넣는다 — 이런 방식을 "화면을 자바스크립트로 동적으로
// 그린다"고 한다.
//
// 원래 dashboard.js 파일 하나(558줄)에 모든 게 들어있었다. 파일이 너무 커서
// 원하는 부분을 찾기 어려워져서, 역할별로 아래처럼 나눴다:
//   state.js   — 여러 함수가 공유하는 상태값 (페이지 번호, CSRF 토큰 등)
//   utils.js   — escapeHtml, formatTime, renderPagination (범용 헬퍼)
//   render.js  — 서버 데이터를 표/카드 HTML로 그리는 함수들
//   api.js     — fetch()로 서버와 주고받는 함수들 (조회 폴링 + 상태 변경 요청)
//   events.js  — 버튼 클릭 등 화면 이벤트를 api.js 함수와 연결
//   main.js    — (이 파일) 위 조각들을 불러와 조립하고 최초 실행을 시작
//
// 이 화면(templates/admin_dashboard.html)의 <script> 태그가 type="module"로
// 바뀌면서 이 파일 하나만 로드하면 나머지는 import 구문이 알아서 불러온다.
//
// docs/refactor/2026-09-15-file-split.md — 이 분리 작업의 배경과 계획 문서.
// ============================================================================

import { fetchStatus } from "./api.js";
import { pollIntervalMs } from "./state.js";
import "./events.js"; // 이 줄이 실행되는 순간 버튼 이벤트들이 전부 걸린다 (부수효과 import)

fetchStatus(); // 화면이 열리자마자 한 번 즉시 데이터를 가져온다.
setInterval(fetchStatus, pollIntervalMs); // 이후로는 pollIntervalMs마다 계속 반복해서 최신 상태로 갱신한다.
