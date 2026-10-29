// 서버가 쓰는 코드값(이벤트 유형·조치)을 운영자가 읽는 말로 바꾼다. 모르는 값은 그대로 보여준다.

const EVENT_TYPES: Record<string, string> = {
  BRUTE_FORCE: "브루트포스",
  DISTRIBUTED_BRUTE_FORCE: "분산 브루트포스",
  PASSWORD_SPRAYING: "패스워드 스프레이",
  ADMIN_BRUTE_FORCE: "관리자 무차별 대입",
  ADMIN_DISTRIBUTED_BRUTE_FORCE: "관리자 분산 대입",
  SIGNUP_RATE_LIMIT: "가입 도배",
  POST_RATE_LIMIT: "게시글 도배",
  COMMENT_RATE_LIMIT: "댓글 도배",
  HTTP_FLOOD: "HTTP 플러딩",
  WEB_SCANNING: "웹 스캐닝",
  UNAUTHORIZED_ACCESS: "미인증 접근",
  PAGE_ACCESS: "반복 페이지 접근",
  API_MACRO_PATTERN: "API 매크로",
  BOT_DETECTED: "봇 탐지",
  PERMANENT_LOCK: "영구 잠금 전환",
};

const ACTIONS: Record<string, string> = {
  LOCKED: "IP 잠금",
  ACCOUNT_LOCKED: "계정 잠금",
  PERMANENT_LOCKED: "영구 잠금",
  ALERTED: "알림",
  REJECTED: "요청 거부",
};

// Track D 네트워크 경보 종류(계약서 K4·K10). network_events.category 값을 운영자가 읽는 말로 바꾼다.
const NET_CATEGORIES: Record<string, string> = {
  SYN_FLOOD: "SYN 플러드",
  PORT_SCAN: "포트 스캔",
  SCANNER_UA: "스캐너 UA",
  WEB_ATTACK: "웹 공격",
  LOGIN_BURST: "로그인 폭주",
  OTHER: "기타",
  // guide57 L3 경보 — 출발지를 믿을 수 없어 차단하지 않고 기록·알림만 하는 종류
  ICMP_FLOOD: "ICMP 플러드",
  SPOOFED_SRC: "위조 출발지",
  GLOBAL_SYN_FLOOD: "전체 SYN 폭주",
};

export function eventTypeLabel(code: string): string {
  return EVENT_TYPES[code] ?? code;
}

export function netCategoryLabel(code: string): string {
  return NET_CATEGORIES[code] ?? code;
}

export function actionLabel(code: string): string {
  return ACTIONS[code] ?? code;
}
