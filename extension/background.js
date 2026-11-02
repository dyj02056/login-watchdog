// background.js — 확장의 백그라운드(서비스 워커).
//
// 하는 일
//   1) 확장 아이콘·단축키(Alt+Shift+W)를 누르면 미니 창 호스트 탭(host.html)을 열거나 앞으로 가져온다.
//   2) 미니 창이 닫혀 있는 동안 30초마다 새 공격만 확인해서, 아이콘 숫자 배지와 윈도우 알림을 띄운다.
//      (미니 창이 열려 있으면 그쪽이 10초마다 확인하므로 여기서는 쉰다 — 같은 조회를 두 번 하지 않게)
//   3) 대시보드 주소가 바뀌면, HTTPS 서버의 로그인 출처(Referer) 검사를 통과하도록 이 확장이 보내는
//      요청에만 Referer를 대시보드 주소로 맞추는 규칙을 다시 건다.
// 백그라운드는 /api/stats(무거운 집계)를 부르지 않는다. 알림에 필요한 것은 확인 API 응답으로 충분하다.

import { badgeFor, eventTypeLabel, eventsToNotify, maxSeverity } from "./lib/core.js";
import { checkEvents, getSession, loadSettings } from "./lib/api.js";

const HOST_URL = chrome.runtime.getURL("host.html");
const ALARM = "watchdog-check";
const REFERER_RULE_ID = 1;

async function findHostTab() {
  const tabs = await chrome.tabs.query({});
  return tabs.find((t) => t.url?.startsWith(HOST_URL)) ?? null;
}

async function openHost() {
  const existing = await findHostTab();
  if (existing) {
    await chrome.tabs.update(existing.id, { active: true });
    await chrome.windows.update(existing.windowId, { focused: true });
    return;
  }
  const [current] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const from = current?.id ? `?from=${current.id}` : "";
  // 고정 탭으로 연다 — 작게 왼쪽 끝에 붙어 있어 실수로 닫을 일이 적다(닫으면 미니 창도 닫힌다).
  await chrome.tabs.create({ url: HOST_URL + from, pinned: true, active: true });
}

chrome.action.onClicked.addListener(openHost);
chrome.notifications.onClicked.addListener(async (id) => {
  chrome.notifications.clear(id);
  await openHost();
});

async function updateRefererRule() {
  const { baseUrl } = await loadSettings();
  const addRules = [];
  if (baseUrl) {
    addRules.push({
      id: REFERER_RULE_ID,
      priority: 1,
      action: {
        type: "modifyHeaders",
        requestHeaders: [{ header: "Referer", operation: "set", value: `${baseUrl}/admin/login` }],
      },
      condition: {
        requestDomains: [new URL(baseUrl).hostname],
        initiatorDomains: [chrome.runtime.id], // 이 확장이 보낸 요청에만 — 사용자의 일반 탐색에는 손대지 않는다
        resourceTypes: ["xmlhttprequest"],
      },
    });
  }
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [REFERER_RULE_ID], addRules });
  } catch (error) {
    console.warn("Referer 규칙을 걸지 못했습니다(로컬 http 서버에서는 없어도 됩니다):", error);
  }
}

async function setupAlarm() {
  // 크롬이 허락하는 가장 짧은 반복 간격이 30초다.
  await chrome.alarms.create(ALARM, { periodInMinutes: 0.5 });
}

chrome.runtime.onInstalled.addListener(async (details) => {
  await setupAlarm();
  await updateRefererRule();
  const { baseUrl } = await loadSettings();
  if (details.reason === "install" || !baseUrl) chrome.runtime.openOptionsPage();
});
chrome.runtime.onStartup.addListener(async () => {
  await setupAlarm();
  await chrome.storage.session.set({ pipOpen: false });
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.baseUrl) {
    updateRefererRule();
    chrome.storage.local.remove(["lastId", "unseen"]); // 다른 서버로 바뀌면 기준점을 새로 잡는다
  }
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM) await backgroundCheck();
});

/** 미니 창이 닫혀 있을 때의 확인. 서버 부담은 세션 확인(DB 없음) + 확인 API(조회 1번)뿐이다. */
export async function backgroundCheck() {
  const { pipOpen } = await chrome.storage.session.get("pipOpen");
  if (pipOpen && (await findHostTab())) return;

  const { baseUrl } = await loadSettings();
  if (!baseUrl || !(await chrome.permissions.contains({ origins: [`${baseUrl}/*`] }))) return;

  try {
    // 로그아웃 상태면 확인 API를 부르지 않는다 — 세션 없이 부르면 서버가 "미인증 접근"으로 기록한다.
    const session = await getSession(baseUrl);
    if (!session.admin) return;

    const { lastId, unseen = 0, unseenLevel = null } = await chrome.storage.local.get(["lastId", "unseen", "unseenLevel"]);
    const { status, data } = await checkEvents(baseUrl, lastId ?? null);
    if (status !== 200 || !data) return;
    // 처음이면 기준점만 잡는다(예전 공격을 한꺼번에 알리지 않게).
    if (lastId === undefined || lastId === null) {
      await chrome.storage.local.set({ lastId: data.latest_id ?? 0 });
      return;
    }
    const incoming = data.new ?? [];
    if (!incoming.length) return;

    const level = incoming.reduce((acc, e) => maxSeverity(acc, e.severity), unseenLevel);
    const total = unseen + incoming.length;
    await chrome.storage.local.set({ lastId: data.latest_id, unseen: total, unseenLevel: level });
    const badge = badgeFor(total, level);
    await chrome.action.setBadgeText({ text: badge.text });
    await chrome.action.setBadgeBackgroundColor({ color: badge.color });

    const important = eventsToNotify(incoming);
    if (important.length) {
      const top = important[important.length - 1];
      chrome.notifications.create(`bg-${top.id}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: `${top.severity} 공격 탐지`,
        message:
          important.length === 1
            ? `${eventTypeLabel(top.event_type)} · ${top.ip_address ?? ""}\n클릭하면 미니 창을 엽니다.`
            : `${eventTypeLabel(top.event_type)} 등 ${important.length}건\n클릭하면 미니 창을 엽니다.`,
        priority: 2,
      });
    }
  } catch (error) {
    console.warn("백그라운드 확인 실패(다음 차례에 다시 시도):", error);
  }
}
