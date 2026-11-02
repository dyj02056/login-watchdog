// api.js — 미니 창이 Flask 서버와 주고받는 요청 모음.
//
// 확장은 관리자 대시보드 주소에 대한 권한(host permission)을 받아 두었기 때문에, 여기서 보내는
// 요청에도 크롬에 저장된 그 사이트의 쿠키가 실린다. 그래서 미니 창에서 로그인하면 크롬 탭의
// 대시보드도 로그인된 상태가 되고, 반대로 크롬에서 이미 로그인했다면 미니 창은 로그인을 건너뛴다.
// 비밀번호는 어디에도 저장하지 않는다 — 로그인 상태는 서버의 세션 쿠키가 전부다.

// 정적 화면(web/src/lib/api.ts)과 같은 어댑터 헤더. 이 헤더가 있으면 서버가 화면 HTML 대신
// JSON 봉투({messages, csrf, redirect, status})로 답한다(helpers/spa.py).
const SPA_HEADERS = { "X-Requested-With": "login-watchdog-spa", Accept: "application/json" };

export const SETTINGS_DEFAULTS = { baseUrl: "", checkSeconds: 10 };

export async function loadSettings() {
  return { ...SETTINGS_DEFAULTS, ...(await chrome.storage.local.get(Object.keys(SETTINGS_DEFAULTS))) };
}

async function request(baseUrl, path, init = {}) {
  const response = await fetch(baseUrl + path, {
    credentials: "include",
    cache: "no-store",
    ...init,
    headers: { ...SPA_HEADERS, ...(init.headers ?? {}) },
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, ok: response.ok, body };
}

/**
 * 로그인 상태와 CSRF 토큰을 묻는다. 서버가 세션만 읽고 DB는 건드리지 않는 창구라 자주 불러도 된다.
 * 확인 API를 부르기 전에 늘 이걸 먼저 본다 — 세션 없이 /api/를 부르면 서버가 "미인증 접근"으로
 * 기록하고 반복되면 경보를 보내기 때문에(helpers/auth.py), 로그아웃 상태에서는 아예 묻지 않는다.
 */
export async function getSession(baseUrl) {
  const { ok, body } = await request(baseUrl, "/api/spa/session");
  if (!ok || !body) throw new Error("서버에 연결하지 못했습니다.");
  return body; // { csrf, admin, admin_username, ... }
}

/**
 * 관리자 로그인. 기존 관리자 로그인 화면과 똑같이 /admin/login에 폼으로 보낸다 — 서버의
 * IP 잠금·계정 잠금·허니팟 검사가 그대로 적용된다(허니팟 칸 website는 일부러 비워 보낸다).
 * 반환: { ok: true } 또는 { ok: false, message, csrfBlocked }
 */
export async function login(baseUrl, username, password) {
  const session = await getSession(baseUrl);
  const { body } = await request(baseUrl, "/admin/login", {
    method: "POST",
    headers: { "X-CSRFToken": session.csrf, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ website: "", username, password }),
  });
  if (body?.redirect && body.status !== 400) return { ok: true };
  // CSRF 검사에 걸리면 서버가 400과 함께 되돌려 보낸다. HTTPS 서버에서 확장이 보낸 요청의
  // 출처(Referer) 검사에 막힌 경우라, 화면이 "크롬 탭에서 로그인" 길을 안내한다.
  return {
    ok: false,
    message: body?.messages?.[0] ?? "로그인하지 못했습니다.",
    csrfBlocked: body?.status === 400,
  };
}

/**
 * 새 공격 확인(/api/pip/check). after가 없으면 기준점(최신 id)만 받는다.
 * 반환: { status: 200|401|..., data: {latest_id, new, more} }
 */
export async function checkEvents(baseUrl, after) {
  const query = after === null || after === undefined ? "" : `?after=${encodeURIComponent(after)}`;
  const { status, body } = await request(baseUrl, `/api/pip/check${query}`);
  return { status, data: body };
}

/** 대시보드 집계(/api/stats). 조회가 많아서 새 공격이 있을 때만 부른다. */
export async function getStats(baseUrl) {
  const { status, body } = await request(baseUrl, "/api/stats");
  return { status, data: body };
}

/** 관리자 대시보드 탭을 앞으로 가져온다. 열린 탭이 없으면 새 탭으로 연다. */
export async function openDashboard(baseUrl) {
  // url 조건으로 찾지 않고 전부 받아 거른다 — 주소에 포트(:5000)가 있으면 크롬 URL 패턴이 맞지 않을 수 있다.
  const tabs = (await chrome.tabs.query({})).filter((t) => t.url?.startsWith(`${baseUrl}/admin/`) && !t.url.includes("/admin/login"));
  const tab = tabs.find((t) => t.url?.startsWith(`${baseUrl}/admin/dashboard`)) ?? tabs[0];
  if (tab) {
    await chrome.tabs.update(tab.id, { active: true });
    await chrome.windows.update(tab.windowId, { focused: true });
    return;
  }
  const created = await chrome.tabs.create({ url: `${baseUrl}/admin/dashboard`, active: true });
  await chrome.windows.update(created.windowId, { focused: true });
}
