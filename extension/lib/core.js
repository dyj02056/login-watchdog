// core.js — 미니 창의 계산만 모아 둔 곳(화면·크롬 API·네트워크를 쓰지 않는다).
//
// 화면(pip/view.js)과 백그라운드(background.js)가 같은 판단을 해야 해서 한곳에 둔다.
// 크롬 없이 Node로도 돌릴 수 있어서 test/core.test.mjs가 이 파일만 따로 검사한다.

// 서버가 쓰는 등급(web/src/lib/types.ts의 Severity)과 같은 값. 숫자가 클수록 위험하다.
export const SEVERITY_RANK = { MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

// 등급별 화면 색과 한국어 이름. "정상"은 미해결 공격이 하나도 없을 때다.
export const LEVELS = {
  NORMAL: { label: "정상", color: "#22c55e" },
  MEDIUM: { label: "MEDIUM", color: "#eab308" },
  HIGH: { label: "HIGH", color: "#f97316" },
  CRITICAL: { label: "CRITICAL", color: "#ef4444" },
};

// 서버 코드값을 운영자가 읽는 말로 바꾼다(web/src/lib/labels.ts와 같은 표 — 확장은 그 파일을
// import할 수 없어서 옮겨 적었다). 모르는 값은 그대로 보여준다.
const EVENT_TYPES = {
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
  SYN_FLOOD: "SYN 플러드",
  PORT_SCAN: "포트 스캔",
  SCANNER_UA: "스캐너 UA",
  WEB_ATTACK: "웹 공격",
  LOGIN_BURST: "로그인 폭주",
  ICMP_FLOOD: "ICMP 플러드",
  SPOOFED_SRC: "위조 출발지",
  GLOBAL_SYN_FLOOD: "전체 SYN 폭주",
  // 네트워크 계층(Track D) 이벤트는 security_events에 NET_ 이름으로 기록된다(security/net_ingest.py, correlate.py).
  NET_SYN_FLOOD: "SYN 플러드",
  NET_PORT_SCAN: "포트 스캔",
  NET_SCANNER_UA: "스캐너 UA",
  NET_WEB_ATTACK: "웹 공격",
  NET_LOGIN_BURST: "로그인 폭주",
  NET_ICMP_FLOOD: "ICMP 플러드",
  NET_BLOCKED: "네트워크 차단",
  NET_SUBNET_ATTACK: "대역 공격",
  NET_REPEAT_FLOOD: "반복 플러드",
};

export function eventTypeLabel(code) {
  return EVENT_TYPES[code] ?? code ?? "-";
}

/** 둘 중 더 위험한 등급. 없으면(null) 다른 쪽을 돌려준다. */
export function maxSeverity(a, b) {
  return (SEVERITY_RANK[a] ?? 0) >= (SEVERITY_RANK[b] ?? 0) ? (a ?? b ?? null) : b;
}

/**
 * 지금 보여줄 위협 등급("NORMAL"/"MEDIUM"/"HIGH"/"CRITICAL").
 *
 * 기준은 /api/stats의 미해결 목록이다 — 서버가 등급 높은 순으로 정렬해 주므로(db/stats.py)
 * 첫 줄이 가장 위험한 등급이다. 집계를 받은 뒤에 새로 들어온 공격(freshEvents)은 아직
 * 미해결 목록에 없으니 함께 본다. 대시보드에서 다 처리(해결)하면 다시 "정상"이 된다.
 */
export function threatLevel(stats, freshEvents = []) {
  let level = stats?.unresolved?.[0]?.severity ?? null;
  if ((stats?.kpi?.unresolved_critical ?? 0) > 0) level = "CRITICAL";
  for (const event of freshEvents) level = maxSeverity(level, event.severity);
  return level && SEVERITY_RANK[level] ? level : "NORMAL";
}

/** /api/stats의 이벤트(ip)와 /api/pip/check의 이벤트(ip_address)를 같은 모양으로 맞춘다. */
export function normalizeEvent(raw) {
  return {
    id: raw.id,
    severity: raw.severity,
    event_type: raw.event_type,
    ip: raw.ip ?? raw.ip_address ?? "-",
    count: raw.count ?? 1,
    detected_at: raw.detected_at,
  };
}

/** 이미 아는 이벤트 목록에 새 이벤트를 합친다(id로 중복 제거, 최신순, 최대 keep개). */
export function mergeEvents(known, incoming, keep = 60) {
  const byId = new Map(known.map((e) => [e.id, e]));
  for (const raw of incoming) byId.set(raw.id, normalizeEvent(raw));
  return [...byId.values()].sort((a, b) => b.id - a.id).slice(0, keep);
}

/**
 * 최근 `minutes`분을 1분 칸으로 나눠 탐지된 공격 수를 센다. 그래프의 막대 하나가 1분이다.
 * 각 칸은 { count, severity(그 1분 동안 가장 높은 등급) }이고, 맨 오른쪽 칸이 지금이다.
 * 30분 안에 공격이 서버가 주는 최근 30건보다 많이 몰리면 앞쪽 칸이 실제보다 낮게 나온다.
 */
export function minuteBuckets(events, now = Date.now(), minutes = 30) {
  const buckets = Array.from({ length: minutes }, () => ({ count: 0, severity: null }));
  const currentMinute = Math.floor(now / 60000);
  for (const event of events) {
    const t = Date.parse(event.detected_at);
    if (Number.isNaN(t)) continue;
    const index = minutes - 1 - (currentMinute - Math.floor(t / 60000));
    if (index < 0 || index >= minutes) continue;
    buckets[index].count += 1;
    buckets[index].severity = maxSeverity(buckets[index].severity, event.severity);
  }
  return buckets;
}

/** 최근 `minutes`분 안에 탐지된 공격만 고른다(목록·그래프가 "지금 일어나는 공격"만 보이게). */
export function recentEvents(events, now = Date.now(), minutes = 30) {
  const since = now - minutes * 60000;
  return events.filter((e) => {
    const t = Date.parse(e.detected_at);
    return !Number.isNaN(t) && t >= since;
  });
}

/** 오늘이면 "22:30", 다른 날이면 "11/01 22:30"처럼 짧게 보여준다. */
export function shortWhen(value, now = Date.now()) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "-";
  const hm = clock(d).slice(0, 5);
  if (d.toDateString() === new Date(now).toDateString()) return hm;
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${hm}`;
}

/** 새 이벤트 중 윈도우 알림을 띄울 것(HIGH 이상)만 고른다. MEDIUM은 화면·배지로만 알린다. */
export function eventsToNotify(events) {
  return events.filter((e) => (SEVERITY_RANK[e.severity] ?? 0) >= SEVERITY_RANK.HIGH);
}

/** 확장 아이콘 배지에 쓸 글자와 색. 확인하지 않은 새 공격 수를 보여준다. */
export function badgeFor(unseenCount, level) {
  if (!unseenCount) return { text: "", color: LEVELS.NORMAL.color };
  return { text: unseenCount > 99 ? "99+" : String(unseenCount), color: (LEVELS[level] ?? LEVELS.MEDIUM).color };
}

/** 사용자가 적은 대시보드 주소를 "https://host[:port]" 꼴로 다듬는다. 잘못된 주소면 null. */
export function normalizeBaseUrl(input) {
  try {
    const url = new URL(String(input).trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** ISO 시각을 "09:28:27"처럼 이 PC 시간대로 보여준다. */
export function clock(value = Date.now()) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
}
