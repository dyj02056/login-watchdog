// ============================================================================
// dashboard/api.js — 서버와 fetch()로 주고받는 함수 모음
// (상태 조회 폴링 + 잠금 해제/회원 삭제/게시글·댓글 삭제/보안 이벤트 처리/
//  회원가입 토글 등 서버 상태를 바꾸는 요청)
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
import { csrfToken, pages, permissionState, signupState } from "./state.js";
import { askNote, renderPagination } from "./utils.js";

/**
 * 서버에게 "지금 최신 상태가 어때?"라고 물어보고, 그 답으로 화면을 새로 그린다.
 *
 * fetch()는 브라우저가 서버에 요청을 보내는 표준 기능이다. await는 "이 요청의
 * 응답이 올 때까지 여기서 잠깐 기다렸다가, 응답이 오면 다음 줄로 넘어가라"는 뜻이다.
 */
export async function fetchStatus() {
    // 표마다 각자 다른 페이지를 보고 있을 수 있으므로, 지금 기억해둔 페이지 번호를
    // 매번 쿼리 파라미터로 함께 보낸다(routes/admin.py의 _page_param() 참고).
    const params = new URLSearchParams({
        attempts_page: pages.attempts,
        users_page: pages.users,
        posts_page: pages.posts,
        comments_page: pages.comments,
        admin_log_page: pages.adminLog,
        security_events_page: pages.securityEvents,
        security_incidents_page: pages.securityIncidents,
        access_requests_page: pages.accessRequests,
    });
    const response = await fetch(`/api/status?${params}`);

    if (response.status === 401) {
        // 401 = "로그인이 안 되어 있다"는 뜻. 예를 들어 관리자가 다른 탭에서
        // 로그아웃했거나, 세션이 만료된 경우다. 이때는 로그인 화면으로 돌려보낸다.
        window.location.href = "/admin/login";
        return;
    }

    const data = await response.json(); // 서버가 보내준 JSON 응답을 자바스크립트 객체로 변환

    // 삭제로 인해 항목이 줄어들어 지금 보던 페이지가 더 이상 존재하지 않게 된
    // 경우(예: 마지막 페이지의 마지막 한 줄을 지웠을 때), 전체 페이지 수 안으로
    // 페이지 번호를 되돌리고 즉시 다시 요청한다 — 그대로 두면 "3 / 2"처럼 있을 수
    // 없는 페이지 번호가 보이거나 표가 텅 빈 채로 남는다.
    let needsRefetch = false;
    if (pages.attempts > data.attempts_total_pages) { pages.attempts = data.attempts_total_pages; needsRefetch = true; }
    if (pages.users > data.users_total_pages) { pages.users = data.users_total_pages; needsRefetch = true; }
    if (pages.posts > data.posts_total_pages) { pages.posts = data.posts_total_pages; needsRefetch = true; }
    if (pages.comments > data.comments_total_pages) { pages.comments = data.comments_total_pages; needsRefetch = true; }
    if (pages.adminLog > data.admin_log_total_pages) { pages.adminLog = data.admin_log_total_pages; needsRefetch = true; }
    if (pages.securityEvents > data.security_events_total_pages) { pages.securityEvents = data.security_events_total_pages; needsRefetch = true; }
    if (pages.securityIncidents > data.security_incidents_total_pages) { pages.securityIncidents = data.security_incidents_total_pages; needsRefetch = true; }
    if (pages.accessRequests > data.access_requests_total_pages) { pages.accessRequests = data.access_requests_total_pages; needsRefetch = true; }
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
    renderAttemptsTable(data.recent_attempts);
    renderPagination("attempts-pagination", pages.attempts, data.attempts_total_pages);
    renderAdminLoginLog(data.admin_login_log);
    renderPagination("admin-log-pagination", pages.adminLog, data.admin_log_total_pages);
    renderUsersTable(data.users);
    renderPagination("users-pagination", pages.users, data.users_total_pages);
    renderSignupStatus(data.signup_enabled);
    renderPostsTable(data.recent_posts);
    renderPagination("posts-pagination", pages.posts, data.posts_total_pages);
    renderCommentsTable(data.recent_comments);
    renderPagination("comments-pagination", pages.comments, data.comments_total_pages);
    renderSecurityEventsTable(data.security_events);
    renderPagination("security-events-pagination", pages.securityEvents, data.security_events_total_pages);
    renderSecurityIncidentsTable(data.security_incidents);
    renderPagination("security-incidents-pagination", pages.securityIncidents, data.security_incidents_total_pages);
    renderAccessRequestsTable(data.access_requests);
    renderPagination("access-requests-pagination", pages.accessRequests, data.access_requests_total_pages);
    renderAdminUsersTable(data.admin_users);
}

/**
 * 관리자가 "즉시 해제" 버튼을 눌렀을 때, 그 IP를 서버에 풀어달라고 요청한다.
 * @param {string} ip
 */
export async function unlockIp(ip) {
    await fetch("/api/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        // 브라우저는 같은 사이트로 요청을 보낼 때 로그인 세션 쿠키를 자동으로 함께
        // 보내주므로, 여기서 관리자 토큰 같은 걸 따로 넣지 않아도 서버가 "로그인된
        // 관리자의 요청"임을 알 수 있다(helpers.py의 login_required가 세션 쿠키로 확인).
        // 다만 세션 쿠키만으로는 "이 요청이 진짜 이 화면에서 왔는지"까지는 보장하지
        // 못하므로(CSRF), X-CSRFToken 헤더로 이 화면이 서버에게 받은 토큰을 함께 보낸다.
        body: JSON.stringify({ ip: ip }),
    });
    // 해제 요청이 끝나면 화면을 바로 한 번 더 갱신해서, 다음 폴링 주기를
    // 기다리지 않고도 즉시 카드가 사라지는 걸 볼 수 있게 한다.
    fetchStatus();
}

/**
 * 관리자가 잠긴 계정 카드의 "즉시 해제" 버튼을 눌렀을 때, 그 계정을 서버에 풀어달라고
 * 요청한다. unlockIp()와 동일한 fetch + CSRF 패턴을 쓴다.
 * @param {string} username
 */
export async function unlockAccount(username) {
    await fetch("/api/unlock-account", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ username: username }),
    });
    fetchStatus();
}

/**
 * 잠긴 관리자 계정 카드의 "즉시 해제" 버튼(guide38, super_admin 전용)을 눌렀을 때 그 관리자
 * 계정의 잠금을 풀어달라고 요청한다. unlockAccount()와 같은 패턴이다.
 * @param {string} username
 */
export async function unlockAdminAccount(username) {
    await fetch("/api/unlock-admin-account", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ username: username }),
    });
    fetchStatus();
}

/**
 * 관리자가 보안 이벤트 표의 "처리 완료" 버튼을 눌렀을 때, 그 이벤트를 해결됨으로
 * 표시해달라고 서버에 요청한다. unlockIp()와 동일한 fetch + CSRF 패턴을 쓴다.
 * @param {string} eventId
 */
export async function resolveEvent(eventId) {
    await fetch("/api/security-events/resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ event_id: Number(eventId) }),
    });
    fetchStatus();
}

/**
 * 관리자가 연관 사건 표의 "해결" 버튼을 눌렀을 때, 확인을 한 번 거친 뒤 그 사건을
 * 해결됨(CLOSED)으로 표시해달라고 서버에 요청한다. 해결한 사건은 다시 열 수 없어서
 * (IP 잠금 해제와는 별개의 "검토 끝" 판단이므로) confirm()으로 실수를 막는다.
 * @param {string} incidentId
 */
export async function resolveIncident(incidentId) {
    if (!confirm("이 사건을 해결됨으로 표시할까요? 해결한 사건은 되돌릴 수 없습니다.")) {
        return;
    }
    await fetch("/api/security-incidents/resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ incident_id: Number(incidentId) }),
    });
    fetchStatus();
}

/**
 * 관리자가 회원 목록의 "삭제" 버튼을 눌렀을 때, 확인을 한 번 거친 뒤 삭제를 요청한다.
 * @param {string} userId
 * @param {string} username
 */
export async function deleteUser(userId, username) {
    // confirm()은 브라우저가 기본으로 제공하는 "확인/취소" 팝업이다. 회원 삭제는
    // 되돌릴 수 없는 작업이라, 실수로 버튼을 잘못 눌렀을 때를 대비한 최소한의
    // 안전장치를 넣어뒀다. 사용자가 "취소"를 누르면 confirm()이 false를 돌려주고,
    // 그러면 아래 요청은 아예 보내지 않는다.
    const confirmed = confirm(`"${username}" 회원을 정말 삭제할까요? 이 작업은 되돌릴 수 없습니다.`);
    if (!confirmed) {
        return;
    }

    await fetch("/api/users/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ user_id: Number(userId) }),
    });
    fetchStatus();
}

/**
 * 관리자가 게시판 관리 표의 "삭제" 버튼을 눌렀을 때, 확인 후 글을 삭제 요청한다.
 * @param {string} postId
 */
export async function deletePost(postId) {
    const confirmed = confirm("이 게시글을 정말 삭제할까요? 댓글도 함께 삭제됩니다.");
    if (!confirmed) {
        return;
    }

    await fetch("/api/board/posts/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ post_id: Number(postId) }),
    });
    fetchStatus();
}

/**
 * 관리자가 게시판 관리 표의 "삭제" 버튼을 눌렀을 때, 확인 후 댓글을 삭제 요청한다.
 * @param {string} commentId
 */
export async function deleteComment(commentId) {
    const confirmed = confirm("이 댓글을 정말 삭제할까요?");
    if (!confirmed) {
        return;
    }

    await fetch("/api/board/comments/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ comment_id: Number(commentId) }),
    });
    fetchStatus();
}

/**
 * "관리자 계정 관리" 카드의 생성 폼이 제출됐을 때 호출된다. 다른 삭제류 함수와
 * 달리, 실패(아이디 중복·형식 오류 등)를 화면에 알려줘야 한다 — 그래서 여기만
 * response.ok를 확인하고 실패 시 서버가 보낸 error 메시지를 alert()로 보여준다
 * (이 화면의 나머지 fetch()들은 성공을 전제로 조용히 fetchStatus()만 다시 부른다).
 * @param {string} username
 * @param {string} password
 * @param {string} role
 * @returns {Promise<boolean>} 생성 성공 여부 — events.js가 성공했을 때만 폼을 비운다.
 */
export async function createAdminUser(username, password, role) {
    const response = await fetch("/api/admin-users/create", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ username: username, password: password, role: role }),
    });
    const data = await response.json();
    if (!response.ok) {
        alert(data.error || "관리자 계정 생성에 실패했습니다.");
        return false;
    }
    fetchStatus();
    return true;
}

/**
 * 관리자 계정 관리 표의 "삭제" 버튼을 눌렀을 때, 확인 후 계정을 삭제 요청한다.
 * deleteUser()와 동일한 패턴 — super_admin 행에는 이 버튼 자체가 그려지지
 * 않으므로(render.js), 여기서 추가로 role을 확인할 필요는 없다.
 * @param {string} adminId
 * @param {string} username
 */
export async function deleteAdminUser(adminId, username) {
    const confirmed = confirm(`관리자 계정 "${username}"을(를) 정말 삭제할까요? 이 작업은 되돌릴 수 없습니다.`);
    if (!confirmed) {
        return;
    }

    await fetch("/api/admin-users/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ admin_id: Number(adminId) }),
    });
    fetchStatus();
}

/**
 * 관리자가 "AI 조기 경보" 표의 "승인" 버튼을 눌렀을 때, 그 요청이 원래 하던
 * 조치를 지금 실행해달라고 서버에 요청한다 (Track A, guide31). enforce_lockout
 * 등 되돌리기 어려운 조치로 이어질 수 있으므로 unlockIp()와 달리 확인 팝업을 거친다.
 * @param {string} requestId
 */
export async function approveAccessRequest(requestId) {
    const confirmed = confirm("이 요청을 승인할까요? AI가 판단한 조치가 즉시 실행됩니다.");
    if (!confirmed) {
        return;
    }

    await fetch("/api/access-requests/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ request_id: Number(requestId) }),
    });
    fetchStatus();
}

/**
 * "AI 조기 경보" 표의 "반려" 버튼을 눌렀을 때, 아무 조치 없이 요청을 기각해달라고
 * 서버에 요청한다. 되돌릴 수 없는 조치가 아니므로(오히려 "아무것도 안 함"에
 * 가깝다) 승인과 달리 확인 팝업 없이 바로 처리한다.
 * @param {string} requestId
 */
export async function rejectAccessRequest(requestId) {
    await fetch("/api/access-requests/reject", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ request_id: Number(requestId) }),
    });
    fetchStatus();
}

/**
 * 회원가입 토글 버튼을 눌렀을 때, 현재 상태의 반대값으로 바꿔달라고 서버에 요청한다.
 */
export async function toggleSignup() {
    await fetch("/api/settings/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ enabled: !signupState.enabled }),
    });
    fetchStatus();
}


/**
 * 영구 잠금 카드의 "영구 해제" 버튼 — 사유 입력 모달을 거친 뒤 서버에 해제를 요청한다
 * (super_admin 전용, release_permanent_lock). 사유 없이는 요청 자체를 보내지 않는다.
 * 실패(권한 없음/대상 없음)는 서버가 보낸 오류 문구를 alert로 보여준다.
 * @param {string} kind - "ip" 또는 "account"
 * @param {string} target - IP 주소 또는 아이디
 */
export async function releasePermanentLock(kind, target) {
    const kindLabel = kind === "ip" ? "IP" : "계정";
    const note = await askNote(`${kindLabel} "${target}"의 영구 잠금을 해제합니다. 해제 사유를 입력하세요.`);
    if (note === null) {
        return;
    }
    const response = await fetch("/api/permanent-locks/release", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ target_kind: kind, target_value: target, note: note }),
    });
    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        alert(data.error || "영구 해제에 실패했습니다.");
    }
    fetchStatus();
}

/**
 * "영구 잠금 걸기" 폼 제출 — 관리자가 IP/계정을 직접 영구 잠금한다(promote_permanent_lock).
 * @returns {Promise<boolean>} 성공 여부 — events.js가 성공했을 때만 폼을 비운다.
 */
export async function promotePermanentLock(kind, target, reason) {
    const confirmed = confirm(`${kind === "ip" ? "IP" : "계정"} "${target}"을(를) 영구 잠금할까요? 관리자만 풀 수 있게 됩니다.`);
    if (!confirmed) {
        return false;
    }
    const response = await fetch("/api/permanent-locks/promote", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ target_kind: kind, target_value: target, reason: reason }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        alert(data.error || "영구 잠금에 실패했습니다.");
        return false;
    }
    fetchStatus();
    return true;
}

/** IP 예외의 "회수" 버튼 — 확인 후 그 예외를 즉시 무효로 만든다. */
export async function revokeIpExemption(exemptionId) {
    if (!confirm("이 IP 예외를 회수할까요? 해당 사용자는 다시 이메일 인증을 해야 합니다.")) {
        return;
    }
    const response = await fetch("/api/ip-exemptions/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ id: Number(exemptionId) }),
    });
    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        alert(data.error || "예외 회수에 실패했습니다.");
    }
    fetchStatus();
}

/** 복구 요청의 "취소" 버튼 — 진행 중인 복구 링크/코드를 즉시 무효로 만든다. */
export async function revokeRecoveryRequest(requestId) {
    if (!confirm("이 복구 요청을 취소할까요? 이미 발송된 메일의 링크와 코드는 더 이상 쓸 수 없게 됩니다.")) {
        return;
    }
    const response = await fetch("/api/recovery-requests/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ id: Number(requestId) }),
    });
    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        alert(data.error || "복구 요청 취소에 실패했습니다.");
    }
    fetchStatus();
}
