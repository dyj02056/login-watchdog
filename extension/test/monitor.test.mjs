// monitor.test.mjs — 미니 창의 확인 흐름(lib/monitor.js)을 가짜 서버·가짜 시계로 검사한다.
// 핵심은 "평소엔 가벼운 확인만, 새 공격이 있을 때만 무거운 집계"가 지켜지는지다.
// 실행: node --test extension/test/
import assert from "node:assert/strict";
import test from "node:test";

import { Monitor, STATS_MIN_GAP_MS, STATS_REFRESH_MS } from "../lib/monitor.js";

function fakeServer() {
  const server = {
    admin: true,
    latest: 100,
    pending: [], // 다음 확인에서 돌려줄 새 이벤트
    unresolved: [],
    calls: { session: 0, check: 0, stats: 0 },
    loginResult: { ok: true },
    api: {
      getSession: async () => {
        server.calls.session++;
        return { admin: server.admin, admin_username: "test-admin", csrf: "x" };
      },
      checkEvents: async (after) => {
        server.calls.check++;
        if (!server.admin) return { status: 401, data: { error: "로그인이 필요합니다." } };
        if (after === null) return { status: 200, data: { latest_id: server.latest, new: [], more: false } };
        const rows = server.pending.splice(0);
        if (rows.length) server.latest = rows[rows.length - 1].id;
        return { status: 200, data: { latest_id: rows.length ? server.latest : after, new: rows, more: false } };
      },
      getStats: async () => {
        server.calls.stats++;
        return {
          status: 200,
          data: {
            kpi: { unresolved_total: server.unresolved.length, unresolved_critical: server.unresolved.filter((e) => e.severity === "CRITICAL").length, events_today: 5 },
            unresolved: server.unresolved,
            events: [],
          },
        };
      },
      login: async () => {
        if (server.loginResult.ok) server.admin = true;
        return server.loginResult;
      },
    },
  };
  return server;
}

function makeMonitor(server) {
  let clock = 1_000_000;
  const notified = [];
  const monitor = new Monitor({
    api: server.api,
    checkSeconds: 10,
    now: () => clock,
    setTimer: () => 1, // 타이머는 쓰지 않고 테스트가 tick()을 직접 부른다
    clearTimer: () => {},
    onNewEvents: (events, level) => notified.push({ count: events.length, level }),
  });
  return {
    monitor,
    notified,
    advance(ms) {
      clock += ms;
    },
  };
}

const event = (id, severity) => ({ id, severity, event_type: "BRUTE_FORCE", ip_address: "192.0.2.9", detected_at: new Date().toISOString() });

test("처음 열면 기준점을 잡고 집계를 한 번 받는다(알림 없음)", async () => {
  const server = fakeServer();
  const { monitor, notified } = makeMonitor(server);
  await monitor.tick();
  assert.equal(monitor.state.phase, "watch");
  assert.equal(monitor.lastId, 100);
  assert.equal(server.calls.stats, 1);
  assert.equal(monitor.state.level, "NORMAL");
  assert.deepEqual(notified, []);
});

test("평소에는 가벼운 확인만 하고 집계는 부르지 않는다", async () => {
  const server = fakeServer();
  const { monitor, advance } = makeMonitor(server);
  await monitor.tick();
  for (let i = 0; i < 30; i++) {
    advance(10_000);
    await monitor.tick();
  }
  assert.equal(server.calls.check, 31);
  assert.equal(server.calls.stats, 1); // 처음 한 번뿐
});

test("새 공격이 오면 등급이 바뀌고 알림, 집계는 간격을 두고 한 번", async () => {
  const server = fakeServer();
  const { monitor, notified, advance } = makeMonitor(server);
  await monitor.tick();

  advance(10_000);
  server.pending.push(event(101, "HIGH"));
  await monitor.tick();
  assert.equal(monitor.state.level, "HIGH");
  assert.deepEqual(notified, [{ count: 1, level: "HIGH" }]);
  assert.deepEqual(monitor.state.flashIds, [101]);
  assert.equal(monitor.lastId, 101);
  assert.equal(server.calls.stats, 1); // 직전 집계가 20초 안이라 아직 안 부름

  server.unresolved = [{ severity: "HIGH" }];
  advance(STATS_MIN_GAP_MS);
  await monitor.tick();
  assert.equal(server.calls.stats, 2);
  assert.equal(monitor.state.level, "HIGH");
});

test("CRITICAL이 섞여 오면 CRITICAL", async () => {
  const server = fakeServer();
  const { monitor, notified, advance } = makeMonitor(server);
  await monitor.tick();
  advance(10_000);
  server.pending.push(event(101, "MEDIUM"), event(102, "CRITICAL"));
  await monitor.tick();
  assert.equal(monitor.state.level, "CRITICAL");
  assert.equal(notified[0].level, "CRITICAL");
});

test("대시보드에서 다 처리하면 1분 안에 정상으로 돌아온다", async () => {
  const server = fakeServer();
  const { monitor, advance } = makeMonitor(server);
  await monitor.tick();
  advance(30_000);
  server.pending.push(event(101, "HIGH"));
  server.unresolved = [{ severity: "HIGH" }];
  await monitor.tick(); // 마지막 집계 후 30초 → 바로 집계
  assert.equal(monitor.state.level, "HIGH");

  server.unresolved = []; // 관리자가 대시보드에서 해결
  advance(STATS_REFRESH_MS);
  await monitor.tick();
  assert.equal(monitor.state.level, "NORMAL");
});

test("로그아웃 상태면 확인 API를 부르지 않는다(미인증 접근 기록 방지)", async () => {
  const server = fakeServer();
  server.admin = false;
  const { monitor } = makeMonitor(server);
  await monitor.tick();
  await monitor.tick();
  assert.equal(monitor.state.phase, "login");
  assert.equal(server.calls.check, 0);
  assert.equal(server.calls.stats, 0);
});

test("로그인하면 바로 관제 화면으로 바뀐다", async () => {
  const server = fakeServer();
  server.admin = false;
  const { monitor } = makeMonitor(server);
  await monitor.tick();
  assert.equal(await monitor.login("test-admin", "test-password"), true);
  assert.equal(monitor.state.phase, "watch");
});

test("로그인 실패 문구와 CSRF 차단 여부를 화면에 넘긴다", async () => {
  const server = fakeServer();
  server.admin = false;
  server.loginResult = { ok: false, message: "아이디 또는 비밀번호가 올바르지 않습니다.", csrfBlocked: false };
  const { monitor } = makeMonitor(server);
  await monitor.tick();
  assert.equal(await monitor.login("test-admin", "wrong"), false);
  assert.equal(monitor.state.message, "아이디 또는 비밀번호가 올바르지 않습니다.");
  assert.equal(monitor.state.phase, "login");
});

test("세션이 끝나 401이 오면 로그인 화면으로", async () => {
  const server = fakeServer();
  const { monitor, advance } = makeMonitor(server);
  await monitor.tick();
  server.admin = false;
  advance(10_000);
  await monitor.tick();
  assert.equal(monitor.state.phase, "login");
  assert.equal(monitor.lastId, undefined);
});

test("서버에 못 붙으면 연결 실패 화면", async () => {
  const server = fakeServer();
  server.api.getSession = async () => {
    throw new Error("network");
  };
  const { monitor } = makeMonitor(server);
  await monitor.tick();
  assert.equal(monitor.state.phase, "offline");
});

test("서버에 확인 API가 없으면(배포 전, 404) 배포가 필요하다고 알린다", async () => {
  const server = fakeServer();
  server.api.checkEvents = async () => ({ status: 404, data: null });
  const { monitor } = makeMonitor(server);
  await monitor.tick();
  assert.equal(monitor.state.phase, "offline");
  assert.match(monitor.state.message, /배포/);
});

test("서버 오류(500)는 상태 코드와 함께 알린다", async () => {
  const server = fakeServer();
  server.api.checkEvents = async () => ({ status: 500, data: null });
  const { monitor } = makeMonitor(server);
  await monitor.tick();
  assert.match(monitor.state.message, /HTTP 500/);
});
