// view.js — PiP 창 안의 화면(로그인 / 관제)을 그린다.
//
// PiP 창은 빈 문서로 열리고, 그 안의 화면은 호스트 페이지(host.js)의 스크립트가 직접 만든다.
// 확장 페이지는 인라인 스크립트·innerHTML 이벤트를 막는 보안 정책(CSP)이 있어서, 문자열
// HTML 대신 DOM을 하나씩 만들고 이벤트도 addEventListener로 붙인다. 서버에서 온 값(IP 등)은
// textContent로만 넣어서 혹시 이상한 글자가 와도 화면 코드로 실행되지 않게 한다.

import { LEVELS, WINDOW_MINUTES, clock, eventTypeLabel, minuteBuckets, recentCounts, recentEvents } from "../lib/core.js";

function h(doc, tag, attrs = {}, children = []) {
  const el = doc.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value);
  }
  for (const child of children) if (child) el.append(child);
  return el;
}

/**
 * handlers: { onLogin(username, password), onOpenDashboard(), onOpenLoginTab(), onRetry() }
 * 반환: { render(state), tickClock() }
 */
export function createView(doc, handlers) {
  const root = h(doc, "div", { class: "app" });
  doc.body.append(root);

  // ── 머리줄: 이름 · 위협 등급 · 시계 ───────────────────────────────────
  const levelBadge = h(doc, "span", { class: "level", text: "정상" });
  const clockEl = h(doc, "span", { class: "clock", text: clock() });
  const header = h(doc, "header", { class: "top" }, [
    h(doc, "span", { class: "brand" }, [h(doc, "span", { class: "dot" }), doc.createTextNode("LOGIN WATCHDOG")]),
    levelBadge,
    clockEl,
  ]);

  // ── 로그인 화면 ──────────────────────────────────────────────────────
  const userInput = h(doc, "input", { class: "input", placeholder: "아이디", autocomplete: "username" });
  const passInput = h(doc, "input", { class: "input", type: "password", placeholder: "비밀번호", autocomplete: "current-password" });
  const loginButton = h(doc, "button", { class: "btn primary", type: "submit", text: "로그인" });
  const loginMessage = h(doc, "p", { class: "message" });
  const loginTabLink = h(doc, "button", {
    class: "btn link hidden",
    type: "button",
    text: "크롬 탭에서 로그인하기",
    onclick: () => handlers.onOpenLoginTab(),
  });
  const loginForm = h(
    doc,
    "form",
    {
      class: "login",
      onsubmit: async (event) => {
        event.preventDefault();
        if (!userInput.value || !passInput.value) return;
        loginButton.disabled = true;
        loginButton.textContent = "확인 중…";
        await handlers.onLogin(userInput.value, passInput.value);
        passInput.value = ""; // 비밀번호는 화면에도 남기지 않는다
        loginButton.disabled = false;
        loginButton.textContent = "로그인";
      },
    },
    [h(doc, "h1", { text: "관리자 로그인" }), userInput, passInput, loginButton, loginMessage, loginTabLink],
  );

  // ── 관제 화면 ────────────────────────────────────────────────────────
  const statusTitle = h(doc, "strong", { class: "status-title" });
  const statusSub = h(doc, "span", { class: "status-sub" });
  // 숫자는 모두 최근 30분 기준이다(미해결·오늘 합계는 관리자 대시보드에서 본다).
  const kpiTotal = h(doc, "b", { text: "0" });
  const kpiCritical = h(doc, "b", { text: "0" });
  const kpiHigh = h(doc, "b", { text: "0" });
  const canvas = h(doc, "canvas", { class: "chart", width: "312", height: "64" });
  const list = h(doc, "ul", { class: "events" });
  const watch = h(doc, "section", { class: "watch" }, [
    h(doc, "div", { class: "status" }, [h(doc, "span", { class: "status-light" }), h(doc, "div", {}, [statusTitle, statusSub])]),
    h(doc, "div", { class: "kpis" }, [
      h(doc, "span", {}, [doc.createTextNode("30분 내 공격 "), kpiTotal]),
      h(doc, "span", {}, [doc.createTextNode("CRITICAL "), kpiCritical]),
      h(doc, "span", {}, [doc.createTextNode("HIGH "), kpiHigh]),
    ]),
    h(doc, "div", { class: "chart-head" }, [h(doc, "span", { text: "최근 30분 탐지 (1분 단위)" }), h(doc, "span", { class: "muted", text: "지금 →" })]),
    canvas,
    list,
  ]);

  // ── 연결 실패 화면 ────────────────────────────────────────────────────
  const offlineMessage = h(doc, "p", { class: "message" });
  const offline = h(doc, "section", { class: "offline" }, [
    h(doc, "strong", { text: "서버 연결 안 됨" }),
    offlineMessage,
    h(doc, "button", { class: "btn", type: "button", text: "다시 시도", onclick: () => handlers.onRetry() }),
  ]);

  const loading = h(doc, "section", { class: "offline" }, [h(doc, "span", { class: "muted", text: "불러오는 중…" })]);

  const footer = h(doc, "footer", {}, [
    h(doc, "button", { class: "btn primary wide", type: "button", text: "관리자 대시보드로 이동", onclick: () => handlers.onOpenDashboard() }),
  ]);

  const body = h(doc, "main");
  root.append(header, body, footer);
  let currentPhase = null;
  // 이미 한 번 깜빡인 공격 id. 목록은 확인 때마다 다시 그리므로, 기억하지 않으면 같은 줄이 계속 깜빡인다.
  const flashed = new Set();

  function drawChart(events) {
    const ctx = canvas.getContext("2d");
    const { width, height } = canvas;
    ctx.clearRect(0, 0, width, height);
    const buckets = minuteBuckets(events, Date.now(), WINDOW_MINUTES);
    const peak = Math.max(3, ...buckets.map((b) => b.count));
    const slot = width / WINDOW_MINUTES;
    ctx.fillStyle = "rgba(148,163,184,0.18)";
    ctx.fillRect(0, height - 1, width, 1); // 바닥선
    buckets.forEach((bucket, i) => {
      if (!bucket.count) return;
      const barHeight = Math.max(3, Math.round((bucket.count / peak) * (height - 4)));
      ctx.fillStyle = (LEVELS[bucket.severity] ?? LEVELS.MEDIUM).color;
      ctx.fillRect(Math.round(i * slot) + 1, height - barHeight, Math.max(2, Math.floor(slot) - 2), barHeight);
    });
  }

  function renderList(events, flashIds) {
    list.replaceChildren();
    // 집계(/api/stats)는 30일 안의 "마지막 30건"을 주므로 어젯밤 공격도 섞여 온다. 목록은 그래프와 같은
    // 최근 30분만 보여서 "지금 일어나는 공격"으로 읽히게 한다. 오래된 미해결 공격은 위 상태 줄이 알린다.
    const recent = recentEvents(events, Date.now(), WINDOW_MINUTES).slice(0, 5);
    if (!recent.length) {
      list.append(h(doc, "li", { class: "empty", text: "최근 30분 동안 탐지된 공격이 없습니다" }));
      return;
    }
    for (const event of recent) {
      const level = LEVELS[event.severity] ?? LEVELS.MEDIUM;
      const tag = h(doc, "span", { class: "tag", text: event.severity === "CRITICAL" ? "CRIT" : event.severity === "MEDIUM" ? "MED" : event.severity });
      tag.style.color = level.color;
      tag.style.borderColor = level.color;
      list.append(
        h(doc, "li", { class: flashIds.includes(event.id) && !flashed.has(event.id) ? "flash" : "" }, [
          tag,
          h(doc, "span", { class: "time", text: clock(event.detected_at).slice(0, 5) }),
          h(doc, "span", { class: "type", text: eventTypeLabel(event.event_type), title: event.event_type }),
          h(doc, "span", { class: "ip", text: event.ip }),
        ]),
      );
    }
    for (const id of flashIds) flashed.add(id);
  }

  function render(state) {
    const level = LEVELS[state.level] ?? LEVELS.NORMAL;
    root.dataset.level = state.level;
    root.style.setProperty("--level", level.color);
    levelBadge.textContent = state.phase === "watch" ? level.label : "—";

    if (state.phase !== currentPhase) {
      currentPhase = state.phase;
      body.replaceChildren(
        { login: loginForm, watch, offline, loading }[state.phase] ?? loading,
      );
      if (state.phase === "login") userInput.focus();
    }

    if (state.phase === "login") {
      loginMessage.textContent = state.message;
      loginTabLink.classList.toggle("hidden", !state.csrfBlocked && !state.message);
    } else if (state.phase === "offline") {
      offlineMessage.textContent = state.message;
    } else if (state.phase === "watch") {
      const now = Date.now();
      const counts = recentCounts(state.events, now, WINDOW_MINUTES);
      kpiTotal.textContent = String(counts.total);
      kpiCritical.textContent = String(counts.CRITICAL);
      kpiHigh.textContent = String(counts.HIGH);
      const checked = state.lastCheckAt ? `마지막 확인 ${clock(state.lastCheckAt)}` : "확인 중…";
      if (state.level === "NORMAL") {
        statusTitle.textContent = "정상 — 최근 30분 공격 없음";
        statusSub.textContent = checked;
      } else {
        const latest = recentEvents(state.events, now, WINDOW_MINUTES)[0]; // 최신순으로 들고 있다
        statusTitle.textContent = `${level.label} 공격 탐지 중`;
        statusSub.textContent = `마지막 공격 ${clock(latest?.detected_at).slice(0, 5)} · ${checked}`;
      }
      drawChart(state.events);
      renderList(state.events, state.flashIds);
    }
  }

  return {
    render,
    tickClock() {
      clockEl.textContent = clock();
    },
  };
}
