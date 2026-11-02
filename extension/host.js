// host.js — 항상 위 PiP 미니 창을 열고 붙잡고 있는 호스트 탭.
//
// 왜 탭이 하나 더 필요한가: 크롬은 PiP 창을 "사용자가 직접 누른 버튼"에서만 열게 하고(광고 팝업
// 방지), PiP 창은 그것을 연 문서가 닫히면 같이 닫힌다. 확장 아이콘을 누르면 뜨는 팝업은 다른 곳을
// 클릭하는 순간 닫혀서 PiP를 붙잡아 둘 수 없으므로, 고정 탭으로 이 페이지를 열어 두고 여기서 연다.
//
// PiP 창 안의 화면과 서버 확인은 모두 이 스크립트가 맡는다. 타이머는 PiP 창의 것(pip.setTimeout)을
// 쓴다 — 이 탭은 대부분 뒤에 숨어 있어서 크롬이 이 탭의 타이머를 1분에 한 번으로 늦출 수 있지만,
// 화면에 보이는 PiP 창의 타이머는 늦추지 않기 때문이다.

import { LEVELS, eventTypeLabel, eventsToNotify } from "./lib/core.js";
import * as api from "./lib/api.js";
import { Monitor } from "./lib/monitor.js";
import { createView } from "./pip/view.js";

const PIP_SIZE = { width: 340, height: 400 };

const statusEl = document.getElementById("status");
const openButton = document.getElementById("open");
let settings = null;
let ready = false;

function setStatus(text, warn = false) {
  statusEl.textContent = text;
  statusEl.classList.toggle("warn", warn);
}

async function hasHostPermission(baseUrl) {
  return chrome.permissions.contains({ origins: [`${baseUrl}/*`] });
}

async function prepare() {
  ready = false;
  settings = await api.loadSettings();
  if (!("documentPictureInPicture" in window)) {
    setStatus("이 크롬은 항상 위 미니 창(Document Picture-in-Picture)을 지원하지 않습니다. 크롬을 116 이상으로 업데이트해 주세요.", true);
    openButton.disabled = true;
    return false;
  }
  if (!settings.baseUrl || !(await hasHostPermission(settings.baseUrl))) {
    setStatus("먼저 관리자 대시보드 주소를 설정해 주세요.", true);
    openButton.textContent = "주소 설정 열기";
    return false;
  }
  setStatus(`연결할 대시보드: ${settings.baseUrl}`);
  openButton.textContent = "미니 창 열기";
  ready = true;
  return true;
}

function notify(events, level) {
  const important = eventsToNotify(events);
  if (!important.length) return;
  const top = important[important.length - 1];
  chrome.notifications.create(`pip-${top.id}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `${LEVELS[level]?.label ?? level} 공격 탐지`,
    message:
      important.length === 1
        ? `${eventTypeLabel(top.event_type)} · ${top.ip_address ?? top.ip ?? ""}`
        : `${eventTypeLabel(top.event_type)} 등 ${important.length}건`,
    priority: 2,
  });
}

function showLevelOnIcon(level) {
  // 미니 창이 열려 있으면 숫자 대신 등급 색 "!"만 띄운다(새 공격 수는 창에서 바로 보이므로).
  chrome.action.setBadgeText({ text: level === "NORMAL" ? "" : "!" });
  chrome.action.setBadgeBackgroundColor({ color: (LEVELS[level] ?? LEVELS.NORMAL).color });
}

async function openPip() {
  const pip = await documentPictureInPicture.requestWindow({ ...PIP_SIZE, disallowReturnToOpener: true });
  pip.document.title = "Watchdog";
  const css = pip.document.createElement("link");
  css.rel = "stylesheet";
  css.href = chrome.runtime.getURL("pip/pip.css");
  pip.document.head.append(css);
  try {
    pip.moveTo(0, 0); // 크롬이 PiP 창 이동을 막으면 조용히 넘어간다(그때는 사용자가 한 번 끌어 두면 된다)
  } catch {
    /* 무시 */
  }

  const baseUrl = settings.baseUrl;
  let monitor = null;
  const view = createView(pip.document, {
    onLogin: (username, password) => monitor.login(username, password),
    onOpenDashboard: () => api.openDashboard(baseUrl),
    onOpenLoginTab: () => chrome.tabs.create({ url: `${baseUrl}/admin/login`, active: true }),
    onRetry: () => monitor.refreshNow(),
  });

  let lastLevel = null;
  monitor = new Monitor({
    api: {
      getSession: () => api.getSession(baseUrl),
      checkEvents: (after) => api.checkEvents(baseUrl, after),
      getStats: () => api.getStats(baseUrl),
      login: (username, password) => api.login(baseUrl, username, password),
    },
    checkSeconds: settings.checkSeconds,
    now: () => Date.now(),
    setTimer: (fn, ms) => pip.setTimeout(fn, ms),
    clearTimer: (id) => pip.clearTimeout(id),
    onChange: (state) => {
      view.render(state);
      if (state.level !== lastLevel) {
        lastLevel = state.level;
        showLevelOnIcon(state.level);
      }
    },
    onNewEvents: notify,
    onBaseline: (lastId) => chrome.storage.local.set({ lastId }),
  });

  const clockTimer = pip.setInterval(() => view.tickClock(), 1000);
  // 미니 창이 열려 있는 동안 백그라운드는 확인을 쉰다(같은 확인을 두 군데서 하지 않게).
  await chrome.storage.session.set({ pipOpen: true });
  await chrome.storage.local.set({ unseen: 0, unseenLevel: null });

  pip.addEventListener("pagehide", () => {
    monitor.stop();
    pip.clearInterval(clockTimer);
    chrome.storage.session.set({ pipOpen: false });
    chrome.action.setBadgeText({ text: "" });
    setStatus("미니 창이 닫혔습니다. 다시 열려면 아래 버튼을 누르세요. (닫혀 있는 동안은 30초마다 확인해 알림만 보냅니다)");
    openButton.disabled = false;
  });

  monitor.start();
  openButton.disabled = true;
  setStatus("미니 창이 열려 있습니다. 이 탭은 닫지 말고 그대로 두세요.");

  // 미니 창을 열기 전에 보던 탭으로 돌려보낸다(아이콘을 누른 탭 id를 주소로 받아 둔다).
  const from = Number(new URLSearchParams(location.search).get("from"));
  if (from) chrome.tabs.update(from, { active: true }).catch(() => {});
}

// 버튼을 누른 직후에 바로 requestWindow를 불러야 한다 — 크롬은 클릭 직후 잠깐만 PiP를 허락하므로,
// 설정 확인은 미리(prepare) 해 두고 여기서는 결과(ready)만 본다.
openButton.addEventListener("click", async () => {
  if (!ready) {
    if (!openButton.disabled) chrome.runtime.openOptionsPage();
    return;
  }
  try {
    await openPip();
  } catch (error) {
    setStatus(`미니 창을 열지 못했습니다: ${error.message}`, true);
  }
});

window.addEventListener("pagehide", () => chrome.storage.session.set({ pipOpen: false }));
chrome.storage.onChanged.addListener((changes) => {
  if (changes.baseUrl) prepare();
});

prepare();
