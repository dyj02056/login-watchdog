// monitor.js — 미니 창이 열려 있는 동안 서버를 살피는 반복 작업.
//
// 미니 창의 목적은 "지금(최근 30분) 공격이 들어오는지"만 보는 것이다. 처리 안 된 예전 공격(미해결)은
// 관리자 대시보드에서 다루고, 미니 창의 등급은 최근 30분 동안 들어온 공격만으로 정한다.
// 그래서 서버에는 거의 묻지 않는다(Supabase 무료 플랜 부담).
//   - 창을 열 때 한 번: /api/stats(조회 열 몇 번)에서 최근 공격 목록을 받아 그래프·목록을 채운다.
//   - 그 뒤로는 checkSeconds(기본 10초)마다 /api/spa/session(DB 조회 없음) + /api/pip/check(조회 1번)만.
//   - 시간이 지나 30분이 넘은 공격은 서버에 묻지 않고 화면에서 빠지며, 그러면 저절로 "정상"이 된다.
// 크롬 API·화면을 직접 쓰지 않고 필요한 것을 밖에서 받는다(deps) — 그래서 Node 테스트에서
// 가짜 서버와 가짜 시계로 그대로 돌려 볼 수 있다(test/monitor.test.mjs).

import { WINDOW_MINUTES, mergeEvents, recentLevel } from "./core.js";

const LOGIN_POLL_MS = 5_000; // 로그인 화면에서 "크롬 탭에서 로그인했는지"만 보는 간격(DB 조회 없음)
const RETRY_MS = 15_000; // 서버에 못 붙었을 때 다시 시도하는 간격
const MISSING_API_RETRY_MS = 60_000; // 서버에 확인 API가 없을 때(배포 전) 다시 보는 간격
const MORE_MS = 1_000; // 새 공격이 한 번에 다 못 올 만큼 몰렸을 때 이어 받는 간격
// 들고 있는 공격 수. 30분 안에 이보다 많이 몰리면 오래된 쪽부터 버리므로 건수가 실제보다 적게 보인다.
const KEEP_EVENTS = 300;

function httpError(status) {
  return Object.assign(new Error(`HTTP ${status}`), { httpStatus: status || null });
}

/**
 * deps:
 *   api: { getSession, checkEvents, getStats, login } — lib/api.js와 같은 모양(baseUrl은 이미 묶여 있음)
 *   checkSeconds: 확인 간격(초)
 *   now(): 현재 시각(ms), setTimer(fn, ms) / clearTimer(id): 타이머
 *   onChange(state): 상태가 바뀔 때마다 화면을 다시 그린다
 *   onNewEvents(events, level): 새 공격이 들어왔을 때(알림·배지용)
 *   onBaseline(lastId): 확인 기준 id가 바뀔 때(백그라운드와 이어 쓰려고 저장)
 */
export class Monitor {
  constructor(deps) {
    this.deps = deps;
    this.timer = null;
    this.stopped = false;
    this.lastId = undefined; // 아직 기준점을 못 잡음
    this.state = {
      phase: "loading", // loading | login | watch | offline
      level: "NORMAL", // 최근 30분 공격 중 가장 높은 등급, 없으면 NORMAL
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

  levelNow(events = this.state.events) {
    return recentLevel(events, this.deps.now(), WINDOW_MINUTES);
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
      // 새 공격이 없어도 시간이 흐르면 30분 밖으로 밀려난 공격이 빠지므로 등급을 매번 다시 계산한다.
      this.set({ lastCheckAt: this.deps.now(), level: this.levelNow() });
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
    if (this.state.phase !== "login") this.set({ phase: "login", events: [], level: "NORMAL" });
  }

  /**
   * 처음 열었을 때: 기준 id를 잡고, 집계에서 최근 공격 목록을 한 번 받아 그래프·목록을 채운다.
   * 이때는 알림을 띄우지 않는다. 집계를 못 받아도 확인은 계속한다(목록이 빈 채로 시작할 뿐).
   */
  async takeBaseline() {
    const { status, data } = await this.deps.api.checkEvents(null);
    if (status === 401) return null;
    if (status !== 200 || !data) throw httpError(status);
    this.lastId = data.latest_id ?? 0;
    this.deps.onBaseline?.(this.lastId);
    const stats = await this.deps.api.getStats();
    if (stats.status === 200 && stats.data) {
      this.set({ events: mergeEvents(this.state.events, stats.data.events ?? [], KEEP_EVENTS) });
    }
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
      const events = mergeEvents(this.state.events, incoming, KEEP_EVENTS);
      const level = this.levelNow(events);
      this.set({ events, flashIds: incoming.map((e) => e.id), level });
      this.deps.onNewEvents?.(incoming, level);
    }
    return !!data.more;
  }
}
