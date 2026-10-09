// ============================================================================
// dashboard/render/tables.js — 일반 표(로그인 시도·관리자 로그인 기록·회원·관리자 계정·게시글·댓글)와 회원가입 상태
// 원래 render.js 한 파일(556줄)이었는데 화면 영역별로 나눴다. 다른 파일은 예전처럼
// "./render.js"에서 가져다 쓴다(render.js가 재내보내기). 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import { signupState } from "../state.js";
import { escapeHtml, formatTime } from "../utils.js";

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
            // attempt.location : 서버(helpers/request_utils.py의 _attach_locations())가 IP 위치 조회
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

// 회원 이메일 인증 상태 배지(guide40). 반송(UNDELIVERABLE)만 위험 색으로 강조한다.
const EMAIL_STATUS_BADGES = {
    VERIFIED: '<span class="lock-badge lock-badge--warn">인증됨</span>',
    UNDELIVERABLE: '<span class="lock-badge">반송</span>',
};

/**
 * 가입된 회원 목록 표를 채운다. 각 줄에 이메일 인증 상태 배지와 "삭제" 버튼이 붙는다.
 * @param {Array} users - [{id, username, email, email_status, created_at}, ...]
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
                    <td>${escapeHtml(user.email)} ${
                        EMAIL_STATUS_BADGES[user.email_status] || '<span class="lock-badge lock-badge--warn">미인증</span>'
                    }</td>
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
 * 이 데이터는 super_admin에게만 응답에 실려온다(routes/admin/status.py 참고) —
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
    // 둔다"는 정책을 이 화면에서부터 지키게 한다(서버도 routes/admin/manage.py에서
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
