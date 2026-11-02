// core.test.mjs — 미니 창의 계산(lib/core.js)을 크롬 없이 검사한다.
// 실행: node --test extension/test/core.test.mjs extension/test/monitor.test.mjs
import assert from "node:assert/strict";
import test from "node:test";

import {
  badgeFor,
  eventsToNotify,
  maxSeverity,
  mergeEvents,
  minuteBuckets,
  normalizeBaseUrl,
  recentCounts,
  recentLevel,
} from "../lib/core.js";

test("등급 비교: 높은 쪽, 비어 있으면 다른 쪽", () => {
  assert.equal(maxSeverity("MEDIUM", "HIGH"), "HIGH");
  assert.equal(maxSeverity("CRITICAL", "HIGH"), "CRITICAL");
  assert.equal(maxSeverity(null, "MEDIUM"), "MEDIUM");
  assert.equal(maxSeverity("HIGH", null), "HIGH");
  assert.equal(maxSeverity(null, null), null);
});

const NOW = Date.parse("2026-11-02T10:00:00+09:00");
const at = (hhmm, day = "02") => `2026-11-${day}T${hhmm}:00+09:00`;

test("위협 등급: 최근 30분에 공격이 없으면 정상(어젯밤 공격은 보지 않음)", () => {
  assert.equal(recentLevel([], NOW), "NORMAL");
  assert.equal(recentLevel([{ severity: "CRITICAL", detected_at: at("22:30", "01") }], NOW), "NORMAL");
  assert.equal(recentLevel([{ severity: "CRITICAL", detected_at: at("09:29") }], NOW), "NORMAL"); // 31분 전
});

test("위협 등급: 최근 30분 공격 중 가장 높은 등급", () => {
  const events = [
    { severity: "MEDIUM", detected_at: at("09:55") },
    { severity: "HIGH", detected_at: at("09:40") },
    { severity: "CRITICAL", detected_at: at("22:30", "01") },
  ];
  assert.equal(recentLevel(events, NOW), "HIGH");
});

test("최근 30분 공격 수를 등급별로 센다", () => {
  const events = [
    { severity: "CRITICAL", detected_at: at("09:59") },
    { severity: "HIGH", detected_at: at("09:50") },
    { severity: "HIGH", detected_at: at("09:45") },
    { severity: "MEDIUM", detected_at: at("09:31") },
    { severity: "CRITICAL", detected_at: at("09:00") }, // 범위 밖
  ];
  assert.deepEqual(recentCounts(events, NOW), { total: 4, CRITICAL: 1, HIGH: 2, MEDIUM: 1 });
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

test("네트워크 이벤트 이름도 한국어로", async () => {
  const { eventTypeLabel } = await import("../lib/core.js");
  assert.equal(eventTypeLabel("NET_BLOCKED"), "네트워크 차단");
  assert.equal(eventTypeLabel("NET_SYN_FLOOD"), "SYN 플러드");
  assert.equal(eventTypeLabel("UNKNOWN_THING"), "UNKNOWN_THING");
});
