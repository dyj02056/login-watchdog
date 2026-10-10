// 시각·숫자 표시. 모든 시각은 한국 시간(KST)으로 보여준다 — 관제 화면의 "오늘"은 한국 날짜 기준이다.

const KST = "Asia/Seoul";

const dateTime = new Intl.DateTimeFormat("sv-SE", {
  timeZone: KST,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const time = new Intl.DateTimeFormat("sv-SE", { timeZone: KST, hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const monthDay = new Intl.DateTimeFormat("sv-SE", { timeZone: KST, month: "2-digit", day: "2-digit" });
const weekday = new Intl.DateTimeFormat("ko-KR", { timeZone: KST, weekday: "short" });

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === "") return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** 2026-10-09 15:30:12 */
export function formatDateTime(value: string | null | undefined): string {
  const date = toDate(value);
  return date ? dateTime.format(date) : "-";
}

/** 15:30:12 */
export function formatTime(value: string | null | undefined): string {
  const date = toDate(value);
  return date ? time.format(date) : "-";
}

/** 좁은 표용: 10-09 15:30 (초까지 필요하면 withSeconds → 10-09 15:30:12) */
export function formatShortDateTime(value: string | null | undefined, withSeconds = false): string {
  const date = toDate(value);
  if (!date) return "-";
  // sv-SE 형식 "2026-10-09 15:30:12"에서 연도(앞 5자)와 필요 없는 초(뒤 3자)를 자른다
  const text = dateTime.format(date).slice(5);
  return withSeconds ? text : text.slice(0, -3);
}

// sv-SE는 월/일만 뽑으면 "09/10"(일/월)로 나오는 환경이 있어서, 부분을 직접 집어 월/일 순서로 조립한다.
function monthSlashDay(date: Date): string {
  const parts = monthDay.formatToParts(date);
  const pick = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  return `${pick("month")}/${pick("day")}`;
}

/** 날짜(YYYY-MM-DD) → "10/09" (월/일) */
export function formatMonthDay(day: string): string {
  const date = toDate(`${day}T00:00:00+09:00`);
  return date ? monthSlashDay(date) : day;
}

/** 날짜(YYYY-MM-DD) → "10/09(금)" */
export function formatDayWithWeekday(day: string): string {
  const date = toDate(`${day}T12:00:00+09:00`);
  return date ? `${monthSlashDay(date)}(${weekday.format(date)})` : day;
}

export function formatCount(value: number | null | undefined): string {
  return value === null || value === undefined ? "-" : value.toLocaleString("ko-KR");
}

/** 1200 → 1.2k, 3_400_000 → 3.4M */
export function compactCount(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return String(value);
}

export function severityLabel(severity: string): string {
  return { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" }[severity] ?? severity;
}
