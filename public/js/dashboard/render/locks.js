// ============================================================================
// dashboard/render/locks.js — 잠금 카드, 영구 잠금·복구 요청·IP 예외 표
// 원래 render.js 한 파일(556줄)이었는데 화면 영역별로 나눴다. 다른 파일은 예전처럼
// "./render.js"에서 가져다 쓴다(render.js가 재내보내기). 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import { hasPermission } from "../state.js";
import { escapeHtml, formatTime, formatDateTime } from "../utils.js";

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
