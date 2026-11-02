// monitor.js — 미니 창이 열려 있는 동안 서버를 살피는 반복 작업(확인 → 필요할 때만 집계).
//
// Supabase 무료 플랜 부담을 줄이는 것이 이 파일의 핵심이다.
//   - 평소: checkSeconds(기본 10초)마다 /api/spa/session(DB 조회 없음) + /api/pip/check(조회 1번)
//   - 새 공격이 왔을 때만 /api/stats(조회 열 몇 번)를 받는다. 몰려 와도 STATS_MIN_GAP_MS에 한 번까지.
//   - 미해결 공격이 남아 있으면(정상이 아니면) STATS_REFRESH_MS마다 집계를 다시 받아,
//     대시보드에서 처리(해결)한 것이 미니 창에도 "정상"으로 돌아오게 한다.
// 크롬 API·화면을 직접 쓰지 않고 필요한 것을 밖에서 받는다(deps) — 그래서 Node 테스트에서
// 가짜 서버와 가짜 시계로 그대로 돌려 볼 수 있다(test/monitor.test.mjs).

import { mergeEvents, threatLevel } from "./core.js";

export const STATS_MIN_GAP_MS = 20_000;
export const STATS_REFRESH_MS = 60_000;
const LOGIN_POLL_MS = 5_000; // 로그인 화면에서 "크롬 탭에서 로그인했는지"만 보는 간격(DB 조회 없음)
const RETRY_MS = 15_000; // 서버에 못 붙었을 때 다시 시도하는 간격
const MISSING_API_RETRY_MS = 60_000; // 서버에 확인 API가 없을 때(배포 전) 다시 보는 간격
const MORE_MS = 1_000; // 새 공격이 한 번에 다 못 올 만큼 몰렸을 때 이어 받는 간격
// 서버 집계는 최대 10초 보관된 값이 올 수 있다(config.ADMIN_STATS_CACHE_SECONDS). 받은 지 이보다 오래된
// 새 공격은 그 뒤에 받은 집계에 이미 들어 있다고 보고 따로 들고 있지 않는다.
const STATS_CACHE_SLACK_MS = 15_000;

/**
 * deps:
 *   api: { getSession, checkEvents, getStats, login } — lib/api.js와 같은 모양(baseUrl은 이미 묶여 있음)
 *   checkSeconds: 확인 간격(초)
 *   now(): 현재 시각(ms), setTimer(fn, ms) / clearTimer(id): 타이머
 *   onChange(state): 상태가 바뀔 때마다 화면을 다시 그린다
 *   onNewEvents(events, level): 새 공격이 들어왔을 때(알림·배지용)
 *   onBaseline(lastId): 확인 기준 id가 바뀔 때(백그라운드와 이어 쓰려고 저장)
 */
function httpError(status) {
  return Object.assign(new Error(`HTTP ${status}`), { httpStatus: status || null });
}

export class Monitor {
  constructor(deps) {
    this.deps = deps;
    this.timer = null;
    this.stopped = false;
    this.lastId = undefined; // 아직 기준점을 못 잡음
    this.lastStatsAt = -Infinity;
    this.statsDue = false;
    this.fresh = []; // 마지막 집계 이후에 새로 들어온 공격(아직 집계의 미해결 목록에 없음)
    this.receivedAt = new Map(); // 새 공격 id → 받은 시각
    this.state = {
      phase: "loading", // loading | login | watch | offline
      level: "NORMAL",
      stats: null,
      events: [],
      flashIds: [],
      adminName: null,
      lastCheckAt: null,
      message: "",
      csrfBlocked: false,
    };
  }

  start() {
    this.stopped = false;
    this.tick();
  }

  stop() {
    this.stopped = true;
    if (this.timer !== null) this.deps.clearTimer(this.timer);
    this.timer = null;
  }

  /** 지금 바로 한 번 확인한다(로그인 직후, 다시 시도 버튼). */
  refreshNow() {
    if (this.timer !== null) this.deps.clearTimer(this.timer);
    this.timer = null;
    return this.tick();
  }

  async login(username, password) {
    this.set({ message: "", csrfBlocked: false });
    try {
      const result = await this.deps.api.login(username, password);
      if (!result.ok) {
        this.set({ message: result.message, csrfBlocked: !!result.csrfBlocked });
        return false;
      }
    } catch {
      this.set({ message: "서버에 연결하지 못했습니다. 주소 설정을 확인해 주세요." });
      return false;
    }
    await this.refreshNow();
    return true;
  }

  set(patch) {
    this.state = { ...this.state, ...patch };
    this.deps.onChange?.(this.state);
  }

  schedule(ms) {
    if (this.stopped) return;
    this.timer = this.deps.setTimer(() => {
      this.timer = null;
      this.tick();
    }, ms);
  }

  async tick() {
    if (this.stopped) return;
    let next = this.deps.checkSeconds * 1000;
    try {
      const session = await this.deps.api.getSession();
      if (!session.admin) {
        this.toLogin();
        this.schedule(LOGIN_POLL_MS);
        return;
      }
      if (this.state.phase !== "watch") this.set({ phase: "watch", message: "", adminName: session.admin_username });

      const more = this.lastId === undefined ? await this.takeBaseline() : await this.checkNew();
      if (more === null) {
        this.toLogin();
        this.schedule(LOGIN_POLL_MS);
        return;
      }
      if (more) next = MORE_MS;

      const sinceStats = this.deps.now() - this.lastStatsAt;
      const needRefresh = this.state.level !== "NORMAL" && sinceStats >= STATS_REFRESH_MS;
      if ((this.statsDue && sinceStats >= STATS_MIN_GAP_MS) || needRefresh) await this.refreshStats();
      this.set({ lastCheckAt: this.deps.now(), level: threatLevel(this.state.stats, this.fresh) });
    } catch (error) {
      // 원인마다 사용자가 할 일이 달라서 문구를 나눈다. 특히 404는 서버가 아직 이 기능이 없는 옛 버전이라는
      // 뜻이라(예: 로컬에서만 고치고 Vercel에 배포하지 않음) 기다려도 풀리지 않는다 — 그래서 자주 묻지 않는다.
      const status = error?.httpStatus;
      if (status === 404) {
        this.set({ phase: "offline", message: "이 서버에는 아직 미니 창 기능(/api/pip/check)이 없습니다. 서버를 최신 코드로 배포해 주세요." });
        next = MISSING_API_RETRY_MS;
      } else if (status) {
        this.set({ phase: "offline", message: `서버가 오류로 응답했습니다(HTTP ${status}). 잠시 후 다시 시도합니다.` });
        next = RETRY_MS;
      } else {
        this.set({ phase: "offline", message: "서버에 연결하지 못했습니다. 주소 설정과 인터넷 연결을 확인해 주세요." });
        next = RETRY_MS;
      }
    }
    this.schedule(next);
  }

  toLogin() {
    // 세션이 끝나면 기준점도 버린다 — 다시 로그인했을 때 그동안 쌓인 것을 한꺼번에 알리지 않게.
    this.lastId = undefined;
    if (this.state.phase !== "login") this.set({ phase: "login", stats: null, events: [], level: "NORMAL" });
  }

  /** 처음 열었을 때: 기준 id를 잡고 집계를 한 번 받아 화면을 채운다. 이때는 알림을 띄우지 않는다. */
  async takeBaseline() {
    const { status, data } = await this.deps.api.checkEvents(null);
    if (status === 401) return null;
    if (status !== 200 || !data) throw httpError(status);
    this.lastId = data.latest_id ?? 0;
    this.deps.onBaseline?.(this.lastId);
    await this.refreshStats();
    return false;
  }

  /** 기준 id 뒤의 새 공격만 묻는다. 반환: 더 남았는지(true/false), 로그인이 풀렸으면 null. */
  async checkNew() {
    const { status, data } = await this.deps.api.checkEvents(this.lastId);
    if (status === 401) return null;
    if (status !== 200 || !data) throw httpError(status);
    const incoming = data.new ?? [];
    if (data.latest_id !== this.lastId) {
      this.lastId = data.latest_id;
      this.deps.onBaseline?.(this.lastId);
    }
    if (incoming.length) {
      for (const e of incoming) this.receivedAt.set(e.id, this.deps.now());
      this.fresh = mergeEvents(this.fresh, incoming);
      this.statsDue = true;
      const level = threatLevel(this.state.stats, this.fresh);
      this.set({
        events: mergeEvents(this.state.events, incoming),
        flashIds: incoming.map((e) => e.id),
        level,
      });
      this.deps.onNewEvents?.(incoming, level);
    }
    return !!data.more;
  }

  async refreshStats() {
    const { status, data } = await this.deps.api.getStats();
    if (status !== 200 || !data) return; // 집계를 못 받아도 확인은 계속한다(다음 차례에 다시)
    this.lastStatsAt = this.deps.now();
    this.statsDue = false;
    const statsEvents = data.events ?? [];
    const newestInStats = statsEvents.reduce((m, e) => Math.max(m, e.id), 0);
    // 서버 집계는 잠깐(10초) 보관된 값일 수 있어서, 집계에 아직 안 보이는 최근 공격만 계속 따로 들고 있는다.
    // 오래전에 받은 공격은 집계 쪽 판단(해결됐는지)을 따른다 — 안 그러면 대시보드에서 처리해도 등급이 안 내려간다.
    const now = this.deps.now();
    this.fresh = this.fresh.filter((e) => e.id > newestInStats && now - (this.receivedAt.get(e.id) ?? 0) < STATS_CACHE_SLACK_MS);
    this.receivedAt = new Map(this.fresh.map((e) => [e.id, this.receivedAt.get(e.id)]));
    this.set({ stats: data, events: mergeEvents(this.state.events, statsEvents) });
  }
}
