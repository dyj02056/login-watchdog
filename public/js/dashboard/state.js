// ============================================================================
// dashboard/state.js — 대시보드 화면 전체가 공유하는 상태값
//
// 원래 dashboard.js 하나였던 파일을 역할별로 나누면서 분리됨. 배경 설명은
// dashboard/main.js 상단 주석 참고.
//
// 객체(pages, signupState)의 "프로퍼티"를 다른 모듈에서 바꾸는 방식을 쓴다 —
// ES 모듈의 import 바인딩은 읽기 전용이라 `import { attemptsPage } from...`
// 처럼 내보내면 다른 파일에서 재대입(attemptsPage = 2)이 안 되지만, 객체
// 하나를 내보내고 그 프로퍼티를 바꾸는 건(pages.attempts = 2) 항상 가능하다.
// ============================================================================

// admin_dashboard.html의 <meta name="csrf-token"> 태그에서 서버가 발급한 CSRF
// 토큰 값을 읽어온다. api.js가 fetch()로 서버 상태를 바꾸는 POST 요청을 보낼
// 때마다 이 값을 X-CSRFToken 헤더에 실어 보내야, 서버의 CSRFProtect가 "이
// 요청이 정말 이 화면에서 나왔다"고 확인해줄 수 있다 (CSRF 방어, app.py의
// CSRFProtect 설명 참고).
export const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

// 폴링 주기(밀리초)도 CSRF 토큰과 같은 방식으로, config.py(ADMIN_DASHBOARD_POLL_MS)
// 값을 admin_dashboard.html의 meta 태그에서 읽어온다 — 이 파일에 숫자를 직접
// 적어두지 않는다.
export const pollIntervalMs = Number(document.querySelector('meta[name="poll-interval-ms"]').content);

// 위험등급 → 배지에 쓸 한글 라벨/이모지. severity-badge 클래스 이름(소문자)도 이 값에서 만든다.
export const SEVERITY_LABELS = {
    CRITICAL: "🔴 CRITICAL",
    HIGH: "🟠 HIGH",
    MEDIUM: "🟡 MEDIUM",
};

// 표 7개(최근 로그인 시도/회원/게시글/댓글/관리자 로그인 기록/보안 이벤트/
// 연관 사건)가 지금 몇 페이지를 보고 있는지 기억해둔다. board_list.html의 URL
// 쿼리 파라미터(?page=)와 같은 역할이지만, 이 화면은 서버 렌더링이 아니라 매번
// fetch()로 다시 그리는 방식이라 URL 대신 이 객체로 상태를 들고 있는다.
export const pages = {
    attempts: 1,
    users: 1,
    posts: 1,
    comments: 1,
    adminLog: 1,
    securityEvents: 1,
    securityIncidents: 1,
};

// 회원가입 토글 버튼을 누르면 "지금 상태의 반대"로 바꿔야 하는데, 그러려면
// "지금 상태가 뭔지"를 어딘가 기억해둬야 한다. render.js의 renderSignupStatus()가
// 매번 이 값을 최신으로 갱신해둔다.
export const signupState = {
    enabled: true,
};
