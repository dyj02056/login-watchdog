// ============================================================================
// dashboard/render.js — 서버에서 받은 데이터로 표/카드를 그리는 함수 모음
// 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import { SEVERITY_LABELS, hasPermission, signupState } from "./state.js";
import { escapeHtml, formatTime } from "./utils.js";

/**
 * 지금 잠긴 IP와 계정들을 카드 형태로 그린다. 각 카드에는 "즉시 해제" 버튼이 붙는다.
 * @param {Array} lockouts - [{ip_address, locked_at, unlock_at, failure_count}, ...]
 * @param {Array} accountLockouts - [{username, locked_at, unlock_at, failure_count}, ...]
 * @param {Array} adminAccountLockouts - 관리자 계정 잠금(guide38), accountLockouts와 같은 모양
 */
export function renderLockoutCards(lockouts, accountLockouts = [], adminAccountLockouts = []) {
    const container = document.getElementById("lockout-list");

    // 영구 잠금은 이 카드 목록이 아니라 아래 "영구 잠금" 표에서 다룬다 — 영구 행에는
    // "즉시 해제" 버튼이 통하지 않아서(서버가 409로 막는다) 아예 그리지 않는다(guide33).
    lockouts = lockouts.filter((lockout) => lockout.lock_type !== "PERMANENT");
    accountLockouts = accountLockouts.filter((lockout) => lockout.lock_type !== "PERMANENT");

    if (lockouts.length === 0 && accountLockouts.length === 0 && adminAccountLockouts.length === 0) {
        container.innerHTML = '<p class="empty-state">현재 잠긴 IP/계정이 없습니다.</p>';
        return;
    }

    // map()으로 각 잠금 데이터를 카드 HTML 문자열로 바꾼 뒤, join("")으로 전부 이어붙인다.
    // data-ip / data-username 속성에 대상을 심어두면, events.js의 이벤트 처리에서
    // "어느 카드의 버튼이 눌렸는지" 알 수 있다.
    const ipCards = lockouts.map(
        (lockout) => `
            <div class="lockout-card">
                <div class="lockout-type">IP 잠금</div>
                <div class="ip">${escapeHtml(lockout.ip_address)}</div>
                <div>실패 ${lockout.failure_count}회</div>
                <div>해제 예정: ${formatTime(lockout.unlock_at)}</div>
                <button data-ip="${escapeHtml(lockout.ip_address)}" class="unlock-btn">즉시 해제</button>
            </div>
        `
    );
    const accountCards = accountLockouts.map(
        (lockout) => `
            <div class="lockout-card">
                <div class="lockout-type">계정 잠금</div>
                <div class="ip">${escapeHtml(lockout.username)}</div>
                <div>실패 ${lockout.failure_count}회</div>
                <div>해제 예정: ${formatTime(lockout.unlock_at)}</div>
                <button data-username="${escapeHtml(lockout.username)}" class="unlock-account-btn">즉시 해제</button>
            </div>
        `
    );
    // 관리자 계정 잠금(guide38)은 해제 권한(unlock_admin_account)이 super_admin에게만 있어서,
    // 권한이 없으면 버튼 대신 안내만 보여준다(실제 검사는 서버가 따로 한다).
    const adminAccountCards = adminAccountLockouts.map(
        (lockout) => `
            <div class="lockout-card">
                <div class="lockout-type">관리자 계정 잠금</div>
                <div class="ip">${escapeHtml(lockout.username)}</div>
                <div>실패 ${lockout.failure_count}회</div>
                <div>해제 예정: ${formatTime(lockout.unlock_at)}</div>
                ${
                    hasPermission("unlock_admin_account")
                        ? `<button data-username="${escapeHtml(lockout.username)}" class="unlock-admin-account-btn">즉시 해제</button>`
                        : '<div class="empty-state">해제는 super_admin만 가능</div>'
                }
            </div>
        `
    );
    container.innerHTML = [...ipCards, ...accountCards, ...adminAccountCards].join("");
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
// 회원 이메일 인증 상태 배지(guide40). 반송(UNDELIVERABLE)만 위험 색으로 강조한다.
const EMAIL_STATUS_BADGES = {
    VERIFIED: '<span class="lock-badge lock-badge--warn">인증됨</span>',
    UNDELIVERABLE: '<span class="lock-badge">반송</span>',
};

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
 * "계정" 칸은 계정 단위 이벤트(분산 브루트포스로 인한 계정 잠금 등)에만 값이 있다 —
 * 그 외 IP 단위 이벤트는 username이 비어 있어 "-"로 표시한다. 계정 잠금은 5분 뒤
 * 풀리면 "현재 잠긴 IP / 계정" 카드에서 사라지므로, 잠금이 풀린 뒤에도 어느 계정이
 * 공격받았는지 남아 있는 곳은 이 칸뿐이다.
 * @param {Array} events - [{id, event_type, severity, ip_address, username, path, count, action, detected_at, resolved_at}, ...]
 */
export function renderSecurityEventsTable(events) {
    const tbody = document.getElementById("security-events-table-body");

    if (events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state">보안 이벤트가 없습니다.</td></tr>';
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
                    <td>${escapeHtml(event.username || "-")}</td>
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
 * 연관 사건(SIEM 상관분석) 표를 채운다. 같은 IP가 짧은 시간 안에 서로 다른
 * event_type을 2개 이상 남겼을 때만 여기 나타난다(correlate.py 참고) — 단발성
 * 보안 이벤트는 위 "보안 이벤트" 표에만 남고 여기에는 묶이지 않는다.
 * 사건은 IP 잠금 해제와 별개로, 관리자가 "해결" 버튼을 눌러야만 CLOSED(해결됨)가
 * 된다(db/incidents.py의 resolve_incident 참고). 상태는 세 가지다 — OPEN(진행 중),
 * IDLE(마지막 이벤트로부터 오래 조용해서 새 사건이 따로 열렸지만 아직 미해결),
 * CLOSED(해결됨, 누가 언제 해결했는지 함께 표시).
 * @param {Array} incidents - [{id, ip_address, event_types, severity_max, status, first_event_at, last_event_at, resolved_at, resolved_by}, ...]
 */
export function renderSecurityIncidentsTable(incidents) {
    const tbody = document.getElementById("security-incidents-table-body");

    if (incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">연관된 사건이 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = incidents
        .map((incident) => {
            const severityClass = `severity-${incident.severity_max.toLowerCase()}`;
            const severityLabel = SEVERITY_LABELS[incident.severity_max] || incident.severity_max;
            const eventTypes = incident.event_types.map((type) => escapeHtml(type)).join(", ");

            let statusClass;
            let statusLabel;
            let actionCell;
            if (incident.status === "CLOSED") {
                statusClass = "success-true";
                statusLabel = "해결됨";
                // 예전에 잠금 해제로 자동 종료된 사건은 해결자/시각 기록이 없다.
                actionCell = incident.resolved_by
                    ? `<span class="mono">${escapeHtml(incident.resolved_by)} · ${formatTime(incident.resolved_at)}</span>`
                    : "-";
            } else {
                statusClass = incident.status === "IDLE" ? "status-idle" : "success-false";
                statusLabel = incident.status === "IDLE" ? "활동 없음" : "진행 중";
                actionCell = `<button data-incident-id="${incident.id}" class="resolve-incident-btn">해결</button>`;
            }

            return `
                <tr>
                    <td class="mono">${formatTime(incident.first_event_at)}</td>
                    <td class="mono">${formatTime(incident.last_event_at)}</td>
                    <td><span class="severity-badge ${severityClass}">${severityLabel}</span></td>
                    <td>${eventTypes}</td>
                    <td class="mono">${escapeHtml(incident.ip_address)}</td>
                    <td class="${statusClass}">${statusLabel}</td>
                    <td>${actionCell}</td>
                </tr>
            `;
        })
        .join("");
}

// 유형 코드(soar.py의 event_type과 동일한 문자열) → 화면에 보여줄 한글 라벨.
// soar.py의 _EARLY_WARNING_LABELS와 같은 매핑을 자바스크립트 쪽에도 둔다 —
// 서버가 라벨 문자열까지 내려주지 않고 event_type 코드만 보내므로(다른
// 표들의 event_type 칸도 코드 그대로 보여주는 것과 같은 방식), 이 표만
// 예외적으로 한글로 바꿔서 보여준다(AI 판단 근거와 나란히 놓였을 때 코드
// 문자열보다 읽기 편하다).
const EARLY_WARNING_LABELS = {
    BRUTE_FORCE: "로그인 브루트포스(IP)",
    DISTRIBUTED_BRUTE_FORCE: "계정 단위 분산 브루트포스",
    SIGNUP_RATE_LIMIT: "회원가입 남용",
    WEB_SCANNING: "Web Scanning",
    UNAUTHORIZED_ACCESS: "Unauthorized Access",
    PAGE_ACCESS: "반복 페이지 접근",
    API_MACRO_PATTERN: "매크로/봇 패턴",
    SIEM_HIGH_INCIDENT: "SIEM HIGH 사건 → 영구 잠금",
};

/**
 * "AI 조기 경보" 표를 채운다 (Track A, guide31). 아직 임계값을 넘지 않은
 * 상태에서 LLM이 위험하다고 판단해 등록한 PENDING 요청만 여기 나타난다 —
 * 관리자가 승인하면 그 유형이 원래 임계값을 넘었을 때 하던 조치가 실행되고,
 * 반려하면 아무 일도 일어나지 않는다(soar.py의 execute_approved_request()/
 * reject_pending_request() 참고).
 * @param {Array} requests - [{request_id, event_type, target_kind, target_value,
 *   count, threshold, llm_reason, requested_at}, ...]
 */
export function renderAccessRequestsTable(requests) {
    const tbody = document.getElementById("access-requests-table-body");

    if (requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">대기 중인 AI 조기 경보가 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = requests
        .map((req) => {
            const label = EARLY_WARNING_LABELS[req.event_type] || req.event_type;
            return `
                <tr>
                    <td class="mono">${formatTime(req.requested_at)}</td>
                    <td>${escapeHtml(label)}</td>
                    <td class="mono">${escapeHtml(req.target_value)}</td>
                    <td>${req.count} / ${req.threshold}</td>
                    <td>${escapeHtml(req.llm_reason)}</td>
                    <td>
                        <button data-request-id="${req.request_id}" class="approve-request-btn">승인</button>
                        <button data-request-id="${req.request_id}" class="reject-request-btn">반려</button>
                    </td>
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


// ============================================================================
// 영구 잠금 + 이메일 복구 (guide33 / guide34-a)
// ============================================================================

const PERMANENT_REASON_LABELS = {
    REPEAT_OFFENDER: "반복 위반",
    SIEM_CRITICAL: "SIEM CRITICAL 사건",
    SIEM_HIGH: "SIEM HIGH 사건",
    NETWORK_IDS: "네트워크 침입 탐지",
    ADMIN_MANUAL: "관리자 수동 승격",
};

const RECOVERABLE_LABELS = {
    SELF: "이메일 인증으로 해제",
    EXEMPTION: "이메일 인증 시 본인 기기 예외",
    ADMIN_ONLY: "관리자만 해제",
};

const RECOVERY_STATUS_LABELS = {
    PENDING: "진행 중",
    VERIFIED: "완료",
    EXPIRED: "만료",
    REVOKED: "취소됨",
};

function formatDateTime(isoString) {
    return isoString ? new Date(isoString).toLocaleString("ko-KR") : "-";
}

/**
 * "영구 잠금" 표를 채운다. 각 줄에는 "영구" 배지가 붙고(unlock_at이 없어 시간 계산이 불가능하므로
 * 해제 예정 시각 대신 배지로 표시한다), "영구 해제" 버튼은 release_permanent_lock 권한이
 * 있는 관리자(super_admin)에게만 보인다. 권한이 없으면 버튼 대신 안내 문구만 보인다.
 * 수동 승격 폼도 promote_permanent_lock 권한이 있을 때만 보인다.
 * @param {Array} locks - [{kind, target, permanent_reason, recoverable, promoted_at, email_status}, ...]
 */
export function renderPermanentLocks(locks) {
    document.getElementById("permanent-lock-promote-form").hidden = !hasPermission("promote_permanent_lock");

    const tbody = document.getElementById("permanent-locks-table-body");
    if (locks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">영구 잠금된 IP/계정이 없습니다.</td></tr>';
        return;
    }

    const canRelease = hasPermission("release_permanent_lock");
    tbody.innerHTML = locks
        .map((lock) => {
            const kindLabel = lock.kind === "ip" ? "IP" : "계정";
            const undeliverable =
                lock.email_status === "UNDELIVERABLE"
                    ? '<span class="lock-badge lock-badge--warn" title="메일 서버가 수신자를 거부해 이메일 인증을 쓸 수 없습니다">이메일 확인 불가</span>'
                    : "";
            const action = canRelease
                ? `<button data-kind="${escapeHtml(lock.kind)}" data-target="${escapeHtml(lock.target)}" class="release-permanent-btn">영구 해제</button>`
                : '<span class="permission-note" title="영구 잠금 해제는 super_admin만 할 수 있습니다">super_admin 전용</span>';
            return `
                <tr>
                    <td><span class="lock-badge">영구</span>${kindLabel}</td>
                    <td class="mono">${escapeHtml(lock.target)}</td>
                    <td>${escapeHtml(PERMANENT_REASON_LABELS[lock.permanent_reason] || lock.permanent_reason || "-")}</td>
                    <td>${escapeHtml(RECOVERABLE_LABELS[lock.recoverable] || lock.recoverable || "-")} ${undeliverable}</td>
                    <td class="mono">${formatDateTime(lock.promoted_at || lock.locked_at)}</td>
                    <td>${action}</td>
                </tr>
            `;
        })
        .join("");
}

/**
 * "복구 요청" 표를 채운다. 진행 중(PENDING)인 요청에는 "취소" 버튼이 붙는다
 * (revoke_recovery_request 권한이 있는 관리자에게만).
 * @param {Array} requests - [{id, username, target_kind, target_value, requested_ip, status, created_at}, ...]
 */
export function renderRecoveryRequests(requests) {
    const tbody = document.getElementById("recovery-requests-table-body");
    if (requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">복구 요청이 없습니다.</td></tr>';
        return;
    }

    const canRevoke = hasPermission("revoke_recovery_request");
    tbody.innerHTML = requests
        .map((req) => {
            const kindLabel = req.target_kind === "ip" ? "IP" : "계정";
            const action =
                req.status === "PENDING" && canRevoke
                    ? `<button data-id="${req.id}" class="revoke-recovery-btn">취소</button>`
                    : "-";
            return `
                <tr>
                    <td class="mono">${formatDateTime(req.created_at)}</td>
                    <td>${escapeHtml(req.username || "-")}</td>
                    <td>${kindLabel} ${escapeHtml(req.target_value)}</td>
                    <td class="mono">${escapeHtml(req.requested_ip)}</td>
                    <td>${escapeHtml(RECOVERY_STATUS_LABELS[req.status] || req.status)}</td>
                    <td>${action}</td>
                </tr>
            `;
        })
        .join("");
}

/**
 * "IP 예외" 표를 채운다. "회수" 버튼은 revoke_ip_exemption 권한이 있는 관리자에게만 보인다.
 * @param {Array} exemptions - [{id, ip_address, username, granted_at, expires_at}, ...]
 */
export function renderIpExemptions(exemptions) {
    const tbody = document.getElementById("ip-exemptions-table-body");
    if (exemptions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">발급된 IP 예외가 없습니다.</td></tr>';
        return;
    }

    const canRevoke = hasPermission("revoke_ip_exemption");
    tbody.innerHTML = exemptions
        .map((item) => {
            const action = canRevoke ? `<button data-id="${item.id}" class="revoke-exemption-btn">회수</button>` : "-";
            return `
                <tr>
                    <td class="mono">${formatDateTime(item.granted_at)}</td>
                    <td class="mono">${escapeHtml(item.ip_address)}</td>
                    <td>${escapeHtml(item.username || "-")}</td>
                    <td class="mono">${formatDateTime(item.expires_at)}</td>
                    <td>${action}</td>
                </tr>
            `;
        })
        .join("");
}
