// core.test.mjs — 미니 창의 계산(lib/core.js)을 크롬 없이 검사한다.
// 실행: node --test extension/test/
import assert from "node:assert/strict";
import test from "node:test";

import {
  badgeFor,
  eventsToNotify,
  maxSeverity,
  mergeEvents,
  minuteBuckets,
  normalizeBaseUrl,
  threatLevel,
} from "../lib/core.js";

test("등급 비교: 높은 쪽, 비어 있으면 다른 쪽", () => {
  assert.equal(maxSeverity("MEDIUM", "HIGH"), "HIGH");
  assert.equal(maxSeverity("CRITICAL", "HIGH"), "CRITICAL");
  assert.equal(maxSeverity(null, "MEDIUM"), "MEDIUM");
  assert.equal(maxSeverity("HIGH", null), "HIGH");
  assert.equal(maxSeverity(null, null), null);
});

test("위협 등급: 미해결이 없으면 정상", () => {
  assert.equal(threatLevel(null), "NORMAL");
  assert.equal(threatLevel({ kpi: { unresolved_critical: 0 }, unresolved: [] }), "NORMAL");
});

test("위협 등급: 서버가 등급순으로 준 미해결 목록의 첫 줄", () => {
  const stats = { kpi: { unresolved_critical: 0 }, unresolved: [{ severity: "HIGH" }, { severity: "MEDIUM" }] };
  assert.equal(threatLevel(stats), "HIGH");
});

test("위협 등급: 미해결 CRITICAL이 하나라도 있으면 CRITICAL", () => {
  assert.equal(threatLevel({ kpi: { unresolved_critical: 1 }, unresolved: [{ severity: "MEDIUM" }] }), "CRITICAL");
});

test("위협 등급: 집계 뒤에 들어온 새 공격도 반영", () => {
  const stats = { kpi: { unresolved_critical: 0 }, unresolved: [{ severity: "MEDIUM" }] };
  assert.equal(threatLevel(stats, [{ severity: "CRITICAL" }]), "CRITICAL");
  assert.equal(threatLevel(null, [{ severity: "MEDIUM" }]), "MEDIUM");
});

test("이벤트 합치기: id 중복 제거, 최신순, ip 이름 통일", () => {
  const merged = mergeEvents(
    [{ id: 1, severity: "MEDIUM", ip: "192.0.2.1", detected_at: "x" }],
    [{ id: 3, severity: "HIGH", ip_address: "192.0.2.3", detected_at: "x" }, { id: 1, severity: "MEDIUM", ip: "192.0.2.1", detected_at: "x" }],
  );
  assert.deepEqual(merged.map((e) => e.id), [3, 1]);
  assert.equal(merged[0].ip, "192.0.2.3");
});

test("1분 그래프: 30칸, 맨 오른쪽이 지금, 칸마다 가장 높은 등급", () => {
  const now = Date.parse("2026-11-02T09:30:30+09:00");
  const at = (min, sec = 0) => new Date(Date.parse("2026-11-02T09:00:00+09:00") + min * 60000 + sec * 1000).toISOString();
  const events = [
    { detected_at: at(30, 5), severity: "MEDIUM" }, // 지금 칸
    { detected_at: at(30, 20), severity: "CRITICAL" }, // 지금 칸
    { detected_at: at(29), severity: "HIGH" }, // 1분 전
    { detected_at: at(1), severity: "HIGH" }, // 29분 전 → 맨 왼쪽
    { detected_at: at(0), severity: "HIGH" }, // 30분 전 → 범위 밖
    { detected_at: "잘못된 시각", severity: "HIGH" },
  ];
  const buckets = minuteBuckets(events, now, 30);
  assert.equal(buckets.length, 30);
  assert.deepEqual(buckets[29], { count: 2, severity: "CRITICAL" });
  assert.deepEqual(buckets[28], { count: 1, severity: "HIGH" });
  assert.deepEqual(buckets[0], { count: 1, severity: "HIGH" });
  assert.equal(buckets.reduce((sum, b) => sum + b.count, 0), 4);
});

test("윈도우 알림은 HIGH 이상만", () => {
  const picked = eventsToNotify([{ severity: "MEDIUM" }, { severity: "HIGH" }, { severity: "CRITICAL" }]);
  assert.deepEqual(picked.map((e) => e.severity), ["HIGH", "CRITICAL"]);
});

test("배지: 0이면 비우고, 많으면 99+", () => {
  assert.equal(badgeFor(0, "HIGH").text, "");
  assert.equal(badgeFor(3, "HIGH").text, "3");
  assert.equal(badgeFor(3, "HIGH").color, "#f97316");
  assert.equal(badgeFor(250, "CRITICAL").text, "99+");
});

test("대시보드 주소 다듬기", () => {
  assert.equal(normalizeBaseUrl(" http://localhost:5000/admin/dashboard "), "http://localhost:5000");
  assert.equal(normalizeBaseUrl("https://example.com"), "https://example.com");
  assert.equal(normalizeBaseUrl("ftp://example.com"), null);
  assert.equal(normalizeBaseUrl("localhost"), null);
});

test("최근 30분 공격만 고른다(어젯밤 공격은 목록에서 뺀다)", async () => {
  const { recentEvents } = await import("../lib/core.js");
  const now = Date.parse("2026-11-02T10:00:00+09:00");
  const events = [
    { id: 3, detected_at: "2026-11-02T09:45:00+09:00" },
    { id: 2, detected_at: "2026-11-02T09:29:00+09:00" },
    { id: 1, detected_at: "2026-11-01T22:30:00+09:00" },
  ];
  assert.deepEqual(recentEvents(events, now, 30).map((e) => e.id), [3]);
});

test("시각 표시: 오늘은 시:분, 다른 날은 월/일까지", async () => {
  const { shortWhen } = await import("../lib/core.js");
  const now = new Date(2026, 10, 2, 10, 0).getTime();
  assert.equal(shortWhen(new Date(2026, 10, 2, 9, 5).toISOString(), now), "09:05");
  assert.equal(shortWhen(new Date(2026, 10, 1, 22, 30).toISOString(), now), "11/01 22:30");
});

test("네트워크 이벤트 이름도 한국어로", async () => {
  const { eventTypeLabel } = await import("../lib/core.js");
  assert.equal(eventTypeLabel("NET_BLOCKED"), "네트워크 차단");
  assert.equal(eventTypeLabel("NET_SYN_FLOOD"), "SYN 플러드");
  assert.equal(eventTypeLabel("UNKNOWN_THING"), "UNKNOWN_THING");
});
