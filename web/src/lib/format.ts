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

/** 날짜(YYYY-MM-DD) → "10-09" */
export function formatMonthDay(day: string): string {
  const date = toDate(`${day}T00:00:00+09:00`);
  return date ? monthDay.format(date) : day;
}

/** 날짜(YYYY-MM-DD) → "10-09(금)" */
export function formatDayWithWeekday(day: string): string {
  const date = toDate(`${day}T12:00:00+09:00`);
  return date ? `${monthDay.format(date)}(${weekday.format(date)})` : day;
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
  return { CRITICAL: "치명", HIGH: "높음", MEDIUM: "보통", LOW: "낮음" }[severity] ?? severity;
}
