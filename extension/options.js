// options.js — 대시보드 주소와 확인 간격을 저장한다.
//
// 주소를 저장할 때 그 주소 하나에 대한 권한만 크롬에 요청한다(manifest의 optional_host_permissions).
// 처음부터 모든 사이트 권한을 받지 않는 이유: 이 확장이 다룰 사이트는 관리자 대시보드 하나뿐이다.

import { loadSettings } from "./lib/api.js";
import { normalizeBaseUrl } from "./lib/core.js";

const form = document.getElementById("form");
const baseInput = document.getElementById("baseUrl");
const secondsInput = document.getElementById("checkSeconds");
const statusEl = document.getElementById("status");

function setStatus(text, kind = "") {
  statusEl.textContent = text;
  statusEl.className = `status ${kind}`;
}

const current = await loadSettings();
baseInput.value = current.baseUrl;
secondsInput.value = current.checkSeconds;

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const baseUrl = normalizeBaseUrl(baseInput.value);
  if (!baseUrl) {
    setStatus("주소 형식이 올바르지 않습니다. http:// 또는 https:// 로 시작해야 합니다.", "warn");
    return;
  }
  const checkSeconds = Math.min(120, Math.max(5, Number(secondsInput.value) || 10));
  // 권한 요청은 버튼을 누른 직후에 해야 크롬이 창을 띄운다 — 그래서 저장보다 먼저 묻는다.
  const granted = await chrome.permissions.request({ origins: [`${baseUrl}/*`] });
  if (!granted) {
    setStatus("권한을 허용하지 않으면 미니 창이 서버에 접속할 수 없습니다.", "warn");
    return;
  }
  await chrome.storage.local.set({ baseUrl, checkSeconds });
  baseInput.value = baseUrl;
  secondsInput.value = checkSeconds;
  setStatus("저장했습니다. 확장 아이콘을 눌러 미니 창을 여세요.", "ok");
});
