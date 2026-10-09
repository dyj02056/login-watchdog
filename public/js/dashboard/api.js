// ============================================================================
// dashboard/api.js — 서버에서 상태를 받아와 화면을 그리는 조회 함수 모음
// (전체 상태 폴링 fetchStatus, 표 하나만 다시 받는 fetchSection/goToPage)
// 서버 상태를 바꾸는 요청(잠금 해제/삭제/처리 완료 등)은 actions.js에 있다.
// 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import {
    renderAccessRequestsTable,
    renderAdminLoginLog,
    renderAdminUsersTable,
    renderAttemptsTable,
    renderCommentsTable,
    renderIpExemptions,
    renderLockoutCards,
    renderPermanentLocks,
    renderPostsTable,
    renderRecoveryRequests,
    renderSecurityEventsTable,
    renderSecurityIncidentsTable,
    renderSignupStatus,
    renderUsersTable,
} from "./render.js";
import { pages, permissionState, totalPages } from "./state.js";
import { renderPagination } from "./utils.js";

// 페이지가 있는 표 8개(guide46). 이름은 서버의 ?only=<이름>(routes/admin/status.py의 _PAGED_SECTIONS)과 같다.
//   pageKey   — state.js의 pages/totalPages에서 쓰는 키
//   rowsKey / totalKey — 서버 응답에서 이 표의 목록·전체 페이지 수 키
//   prefix    — 화면의 <tbody id="{prefix}-table-body">, <nav id="{prefix}-pagination">
export const SECTIONS = {
    attempts: { pageKey: "attempts", param: "attempts_page", rowsKey: "recent_attempts", totalKey: "attempts_total_pages", prefix: "attempts", render: renderAttemptsTable },
    users: { pageKey: "users", param: "users_page", rowsKey: "users", totalKey: "users_total_pages", prefix: "users", render: renderUsersTable },
    posts: { pageKey: "posts", param: "posts_page", rowsKey: "recent_posts", totalKey: "posts_total_pages", prefix: "posts", render: renderPostsTable },
    comments: { pageKey: "comments", param: "comments_page", rowsKey: "recent_comments", totalKey: "comments_total_pages", prefix: "comments", render: renderCommentsTable },
    admin_log: { pageKey: "adminLog", param: "admin_log_page", rowsKey: "admin_login_log", totalKey: "admin_log_total_pages", prefix: "admin-log", render: renderAdminLoginLog },
    security_events: { pageKey: "securityEvents", param: "security_events_page", rowsKey: "security_events", totalKey: "security_events_total_pages", prefix: "security-events", render: renderSecurityEventsTable },
    security_incidents: { pageKey: "securityIncidents", param: "security_incidents_page", rowsKey: "security_incidents", totalKey: "security_incidents_total_pages", prefix: "security-incidents", render: renderSecurityIncidentsTable },
    access_requests: { pageKey: "accessRequests", param: "access_requests_page", rowsKey: "access_requests", totalKey: "access_requests_total_pages", prefix: "access-requests", render: renderAccessRequestsTable },
};

// 가장 최근에 보낸 전체 상태 조회의 번호. 요청 여러 개가 동시에 나가 응답 순서가 뒤바뀌어도,
// 늦게 도착한 옛 응답이 최신 화면을 덮어쓰지 않게 마지막 요청의 응답만 그린다.
let latestStatusRequest = 0;
// 표마다 "사용자가 페이지를 바꾼 횟수"(guide46). 전체 조회가 출발한 뒤 사용자가 그 표의 페이지를
// 넘겼다면, 늦게 도착한 전체 조회가 그 표를 이전 페이지로 되돌려 놓지 않게 그 표만 건너뛴다.
const sectionEpoch = Object.fromEntries(Object.keys(SECTIONS).map((name) => [name, 0]));
// 표마다 가장 최근에 보낸 표 단위 조회의 번호 — 위 latestStatusRequest와 같은 역할.
const latestSectionRequest = Object.fromEntries(Object.keys(SECTIONS).map((name) => [name, 0]));

/** 표의 이번 페이지·전체 페이지 수를 그리고 "불러오는 중" 표시를 걷는다. */
function drawSection(name, rows, total) {
    const section = SECTIONS[name];
    totalPages[section.pageKey] = total;
    section.render(rows);
    renderPagination(`${section.prefix}-pagination`, pages[section.pageKey], total);
    document.getElementById(`${section.prefix}-table-body`).classList.remove("is-loading");
}

/**
 * 페이지 버튼을 누른 순간 화면을 먼저 바꾼다(guide46) — 서버 응답을 기다리지 않고 페이지 번호를
 * 새로 그리고 표를 흐리게 한 뒤, 그 표만 서버에 요청한다(fetchSection).
 * @param {string} name - SECTIONS의 키
 * @param {number} page - 새 페이지 번호(1 미만이면 1, 전체 페이지 수를 넘으면 마지막 페이지로)
 */
export function goToPage(name, page) {
    const section = SECTIONS[name];
    const total = totalPages[section.pageKey] || 1;
    pages[section.pageKey] = Math.min(Math.max(1, page), total);
    sectionEpoch[name] += 1;
    renderPagination(`${section.prefix}-pagination`, pages[section.pageKey], total, { loading: true });
    document.getElementById(`${section.prefix}-table-body`).classList.add("is-loading");
    return fetchSection(name);
}

/** 표 하나의 지금 페이지만 서버에서 받아 그린다(/api/status?only=<이름>). */
export async function fetchSection(name) {
    const section = SECTIONS[name];
    const requestId = ++latestSectionRequest[name];
    const params = new URLSearchParams({ only: name, [section.param]: pages[section.pageKey] });
    const response = await fetch(`/api/status?${params}`);
    if (requestId !== latestSectionRequest[name]) {
        return; // 이 응답을 기다리는 동안 같은 표의 더 새로운 요청이 나갔다
    }
    if (response.status === 401) {
        window.location.href = "/admin/login";
        return;
    }
    if (!response.ok) {
        // 실패하면 표를 흐린 채로 두지 않는다. 다음 폴링이 다시 그린다.
        document.getElementById(`${section.prefix}-table-body`).classList.remove("is-loading");
        return;
    }
    const data = await response.json();
    if (requestId !== latestSectionRequest[name]) {
        return;
    }
    const total = data[section.totalKey];
    if (pages[section.pageKey] > total) {
        // 그사이 항목이 줄어 지금 페이지가 없어졌다 — 마지막 페이지로 다시 받는다.
        pages[section.pageKey] = total;
        totalPages[section.pageKey] = total;
        await fetchSection(name);
        return;
    }
    drawSection(name, data[section.rowsKey], total);
}

/**
 * 서버에게 "지금 최신 상태가 어때?"라고 물어보고, 그 답으로 화면을 새로 그린다.
 *
 * fetch()는 브라우저가 서버에 요청을 보내는 표준 기능이다. await는 "이 요청의
 * 응답이 올 때까지 여기서 잠깐 기다렸다가, 응답이 오면 다음 줄로 넘어가라"는 뜻이다.
 */
export async function fetchStatus() {
    // 표마다 각자 다른 페이지를 보고 있을 수 있으므로, 지금 기억해둔 페이지 번호를
    // 매번 쿼리 파라미터로 함께 보낸다(routes/admin/status.py의 _page_param() 참고).
    // 1보다 작은 페이지 번호는 1로 바로잡아 보낸다 — "이전"을 응답 전에 빠르게 연달아 누르면
    // 0, -1, …까지 내려가 화면에 "-4 / 8"처럼 보였다(서버는 1페이지로 처리했다).
    const params = new URLSearchParams();
    for (const section of Object.values(SECTIONS)) {
        if (!(pages[section.pageKey] >= 1)) {
            pages[section.pageKey] = 1;
        }
        params.set(section.param, pages[section.pageKey]);
    }
    const epochAtSend = { ...sectionEpoch };
    const requestId = ++latestStatusRequest;
    const response = await fetch(`/api/status?${params}`);
    if (requestId !== latestStatusRequest) {
        return; // 이 응답을 기다리는 동안 더 새로운 요청이 나갔다
    }

    if (response.status === 401) {
        // 401 = "로그인이 안 되어 있다"는 뜻. 예를 들어 관리자가 다른 탭에서
        // 로그아웃했거나, 세션이 만료된 경우다. 이때는 로그인 화면으로 돌려보낸다.
        window.location.href = "/admin/login";
        return;
    }

    const data = await response.json(); // 서버가 보내준 JSON 응답을 자바스크립트 객체로 변환
    if (requestId !== latestStatusRequest) {
        return;
    }

    // 요청을 보낸 뒤 사용자가 페이지를 넘긴 표는 이 응답으로 그리지 않는다(그 표는 fetchSection이 그린다).
    const freshSections = Object.keys(SECTIONS).filter((name) => sectionEpoch[name] === epochAtSend[name]);

    // 삭제로 인해 항목이 줄어들어 지금 보던 페이지가 더 이상 존재하지 않게 된
    // 경우(예: 마지막 페이지의 마지막 한 줄을 지웠을 때), 전체 페이지 수 안으로
    // 페이지 번호를 되돌리고 즉시 다시 요청한다 — 그대로 두면 "3 / 2"처럼 있을 수
    // 없는 페이지 번호가 보이거나 표가 텅 빈 채로 남는다.
    let needsRefetch = false;
    for (const name of freshSections) {
        const section = SECTIONS[name];
        if (pages[section.pageKey] > data[section.totalKey]) {
            pages[section.pageKey] = data[section.totalKey];
            needsRefetch = true;
        }
    }
    if (needsRefetch) {
        // 기다렸다가 끝내야 폴링(../polling.js)이 "요청은 한 번에 하나"를 지킬 수 있다.
        await fetchStatus();
        return;
    }

    // 현재 관리자의 권한을 먼저 기억해둬야 아래 render 함수들이 버튼 노출을 정할 수 있다.
    permissionState.actions = data.permissions || [];
    renderLockoutCards(data.active_lockouts, data.active_account_lockouts, data.active_admin_account_lockouts || []);
    renderPermanentLocks(data.permanent_locks || []);
    renderRecoveryRequests(data.recovery_requests || []);
    renderIpExemptions(data.ip_exemptions || []);
    renderSignupStatus(data.signup_enabled);
    for (const name of freshSections) {
        const section = SECTIONS[name];
        drawSection(name, data[section.rowsKey], data[section.totalKey]);
    }
    renderAdminUsersTable(data.admin_users);
}
