// ============================================================================
// dashboard/render.js — 서버에서 받은 데이터로 표/카드를 그리는 함수 모음
// 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import { SEVERITY_LABELS, signupState } from "./state.js";
import { escapeHtml, formatTime } from "./utils.js";

/**
 * 지금 잠긴 IP들을 카드 형태로 그린다. 각 카드에는 "즉시 해제" 버튼이 붙는다.
 * @param {Array} lockouts - [{ip_address, locked_at, unlock_at, failure_count}, ...]
 */
export function renderLockoutCards(lockouts) {
    const container = document.getElementById("lockout-list");

    if (lockouts.length === 0) {
        container.innerHTML = '<p class="empty-state">현재 잠긴 IP가 없습니다.</p>';
        return;
    }

    // map()으로 각 잠금 데이터를 카드 HTML 문자열로 바꾼 뒤, join("")으로 전부 이어붙인다.
    // data-ip 속성에 IP를 심어두면, events.js의 이벤트 처리에서 "어느 카드의 버튼이
    // 눌렸는지" 알 수 있다.
    container.innerHTML = lockouts
        .map(
            (lockout) => `
                <div class="lockout-card">
                    <div class="ip">${escapeHtml(lockout.ip_address)}</div>
                    <div>실패 ${lockout.failure_count}회</div>
                    <div>해제 예정: ${formatTime(lockout.unlock_at)}</div>
                    <button data-ip="${escapeHtml(lockout.ip_address)}" class="unlock-btn">즉시 해제</button>
                </div>
            `
        )
        .join("");
}

/**
 * 최근 로그인 시도 표를 채운다.
 * @param {Array} attempts - [{attempted_at, ip_address, username, success}, ...]
 */
export function renderAttemptsTable(attempts) {
    const tbody = document.getElementById("attempts-table-body");
    tbody.innerHTML = attempts
        .map((attempt) => {
            const resultClass = attempt.success ? "success-true" : "success-false";
            const resultText = attempt.success ? "성공" : "실패";
            // attempt.location : 서버(helpers.py의 _attach_locations())가 IP 위치 조회
            // 결과를 이미 문자열로 만들어서 넣어준다 — 여기서는 그대로 꺼내 쓰기만 한다.
            return `
                <tr>
                    <td class="mono">${formatTime(attempt.attempted_at)}</td>
                    <td class="mono">${escapeHtml(attempt.ip_address)}</td>
                    <td>${escapeHtml(attempt.location)}</td>
                    <td>${escapeHtml(attempt.username)}</td>
                    <td class="${resultClass}">${resultText}</td>
                </tr>
            `;
        })
        .join("");
}

/**
 * 관리자 로그인 시도 기록 표를 채운다.
 * @param {Array} log - [{attempted_at, username, ip_address, success}, ...]
 */
export function renderAdminLoginLog(log) {
    const tbody = document.getElementById("admin-log-table-body");
    tbody.innerHTML = log
        .map((entry) => {
            const resultClass = entry.success ? "success-true" : "success-false";
            const resultText = entry.success ? "성공" : "실패";
            return `
                <tr>
                    <td class="mono">${formatTime(entry.attempted_at)}</td>
                    <td>${escapeHtml(entry.username)}</td>
                    <td class="mono">${escapeHtml(entry.ip_address)}</td>
                    <td class="${resultClass}">${resultText}</td>
                </tr>
            `;
        })
        .join("");
}

/**
 * 가입된 회원 목록 표를 채운다. 각 줄에 "삭제" 버튼이 붙는다.
 * @param {Array} users - [{id, username, email, created_at}, ...]
 */
export function renderUsersTable(users) {
    const tbody = document.getElementById("users-table-body");

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">가입된 회원이 없습니다.</td></tr>';
        return;
    }

    // data-user-id / data-username 속성에 값을 심어두면, events.js의 이벤트 처리에서
    // "어느 줄의 삭제 버튼이 눌렸는지"를 알 수 있다(잠금 카드의 data-ip와 같은 방식).
    tbody.innerHTML = users
        .map(
            (user) => `
                <tr>
                    <td class="mono">${formatTime(user.created_at)}</td>
                    <td>${escapeHtml(user.username)}</td>
                    <td>${escapeHtml(user.email)}</td>
                    <td>
                        <button data-user-id="${user.id}" data-username="${escapeHtml(user.username)}" class="delete-user-btn">삭제</button>
                    </td>
                </tr>
            `
        )
        .join("");
}

/**
 * "관리자 계정 관리" 카드를 채운다. renderUsersTable()과 같은 패턴이지만,
 * 이 데이터는 super_admin에게만 응답에 실려온다(routes/admin.py 참고) —
 * data가 undefined면(다른 role로 로그인) 카드 자체를 숨긴다.
 * @param {Array|undefined} adminUsers - [{id, username, role, created_at}, ...] | undefined
 */
export function renderAdminUsersTable(adminUsers) {
    const section = document.getElementById("admin-users-section");

    if (adminUsers === undefined) {
        section.hidden = true;
        return;
    }
    section.hidden = false;

    const tbody = document.getElementById("admin-users-table-body");

    // super_admin 행은 삭제 버튼을 아예 그리지 않는다 — "super_admin은 1명만
    // 둔다"는 정책을 이 화면에서부터 지키게 한다(서버도 routes/admin.py에서
    // 한 번 더 막는다).
    tbody.innerHTML = adminUsers
        .map(
            (adminUser) => `
                <tr>
                    <td class="mono">${formatTime(adminUser.created_at)}</td>
                    <td>${escapeHtml(adminUser.username)}</td>
                    <td>${escapeHtml(adminUser.role)}</td>
                    <td>
                        ${
                            adminUser.role === "super_admin"
                                ? ""
                                : `<button data-admin-id="${adminUser.id}" data-username="${escapeHtml(adminUser.username)}" class="delete-admin-user-btn">삭제</button>`
                        }
                    </td>
                </tr>
            `
        )
        .join("");
}

/**
 * 게시판 관리 — 최근 게시글 표를 채운다. 각 줄에 "삭제" 버튼이 붙는다.
 * @param {Array} posts - [{id, title, author_username, created_at}, ...]
 */
export function renderPostsTable(posts) {
    const tbody = document.getElementById("posts-table-body");

    if (posts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">등록된 게시글이 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = posts
        .map(
            (post) => `
                <tr>
                    <td class="mono">${formatTime(post.created_at)}</td>
                    <td>${escapeHtml(post.title)}</td>
                    <td>${escapeHtml(post.author_username)}</td>
                    <td>
                        <button data-post-id="${post.id}" class="delete-post-btn">삭제</button>
                    </td>
                </tr>
            `
        )
        .join("");
}

/**
 * 게시판 관리 — 최근 댓글 표를 채운다. 각 줄에 "삭제" 버튼이 붙는다.
 * @param {Array} comments - [{id, body, author_username, created_at}, ...]
 */
export function renderCommentsTable(comments) {
    const tbody = document.getElementById("comments-table-body");

    if (comments.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">등록된 댓글이 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = comments
        .map(
            (comment) => `
                <tr>
                    <td class="mono">${formatTime(comment.created_at)}</td>
                    <td>${escapeHtml(comment.body)}</td>
                    <td>${escapeHtml(comment.author_username)}</td>
                    <td>
                        <button data-comment-id="${comment.id}" class="delete-comment-btn">삭제</button>
                    </td>
                </tr>
            `
        )
        .join("");
}

/**
 * 보안 이벤트(위험등급 통합) 표를 채운다. 각 줄에 등급 배지와, 미해결 HIGH/MEDIUM
 * 이벤트에는 "처리 완료" 버튼이 붙는다. CRITICAL(IP 잠금)은 잠금이 풀리면 자동으로
 * 처리되므로 버튼 대신 안내 문구만 보여준다(soar.py의 resolve_security_events_for_ip 참고).
 * @param {Array} events - [{id, event_type, severity, ip_address, path, count, action, detected_at, resolved_at}, ...]
 */
export function renderSecurityEventsTable(events) {
    const tbody = document.getElementById("security-events-table-body");

    if (events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-state">보안 이벤트가 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = events
        .map((event) => {
            const severityClass = `severity-${event.severity.toLowerCase()}`;
            const severityLabel = SEVERITY_LABELS[event.severity] || event.severity;

            let statusCell;
            if (event.resolved_at) {
                statusCell = `<span class="success-true">처리 완료</span>`;
            } else if (event.severity === "CRITICAL") {
                statusCell = `<span class="empty-state">자동 해제 대기</span>`;
            } else {
                statusCell = `<button data-event-id="${event.id}" class="resolve-event-btn">처리 완료</button>`;
            }

            return `
                <tr>
                    <td class="mono">${formatTime(event.detected_at)}</td>
                    <td><span class="severity-badge ${severityClass}">${severityLabel}</span></td>
                    <td>${escapeHtml(event.event_type)}</td>
                    <td class="mono">${escapeHtml(event.ip_address)}</td>
                    <td>${escapeHtml(event.path || "-")}</td>
                    <td>${event.count}</td>
                    <td>${escapeHtml(event.action)}</td>
                    <td>${statusCell}</td>
                </tr>
            `;
        })
        .join("");
}

/**
 * 회원가입 On/Off 현재 상태를 문구와 버튼에 반영한다.
 * @param {boolean} enabled
 */
export function renderSignupStatus(enabled) {
    signupState.enabled = enabled; // 토글 버튼을 눌렀을 때 "반대로 바꿔라"고 계산하려면 현재 값을 기억해둬야 한다
    const statusEl = document.getElementById("signup-status");
    const buttonEl = document.getElementById("signup-toggle-btn");

    statusEl.textContent = enabled ? "허용 중" : "중단됨";
    buttonEl.textContent = enabled ? "회원가입 끄기" : "회원가입 켜기";
}
