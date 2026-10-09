// ============================================================================
// dashboard/events.js — 버튼 클릭 등 화면 이벤트를 actions.js/api.js 함수와 연결한다.
// import되는 순간 아래 addEventListener 호출들이 즉시 실행된다(부수효과 모듈).
// 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import {
    approveAccessRequest,
    createAdminUser,
    deleteAdminUser,
    deleteComment,
    deletePost,
    deleteUser,
    promotePermanentLock,
    rejectAccessRequest,
    releasePermanentLock,
    resolveEvent,
    resolveIncident,
    revokeIpExemption,
    revokeRecoveryRequest,
    toggleSignup,
    unlockAccount,
    unlockAdminAccount,
    unlockIp,
} from "./actions.js";
import { goToPage } from "./api.js";
import { pages } from "./state.js";
import { runAction } from "./utils.js";

// "즉시 해제" 버튼은 render/locks.js의 renderLockoutCards()가 매번 새로 만들어내므로,
// 버튼 각각에 이벤트를 미리 걸어둘 수 없다. 대신 항상 존재하는 container
// (lockout-list)에 이벤트를 걸어두고, "클릭된 곳이 unlock-btn 버튼이 맞는지"를
// 그때그때 확인하는 방식을 쓴다 — 이걸 "이벤트 위임(event delegation)"이라고 부른다.
document.getElementById("lockout-list").addEventListener("click", (event) => {
    if (event.target.classList.contains("unlock-btn")) {
        const ip = event.target.getAttribute("data-ip");
        runAction(event.target, (button) => unlockIp(ip, button));
    } else if (event.target.classList.contains("unlock-account-btn")) {
        const username = event.target.getAttribute("data-username");
        runAction(event.target, (button) => unlockAccount(username, button));
    } else if (event.target.classList.contains("unlock-admin-account-btn")) {
        const username = event.target.getAttribute("data-username");
        runAction(event.target, (button) => unlockAdminAccount(username, button));
    }
});

// 회원 목록의 "삭제" 버튼도 위와 똑같은 이벤트 위임 방식을 쓴다.
document.getElementById("users-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-user-btn")) {
        const userId = event.target.getAttribute("data-user-id");
        const username = event.target.getAttribute("data-username");
        runAction(event.target, (button) => deleteUser(userId, username, button));
    }
});

// 회원가입 토글 버튼은 화면에 딱 하나뿐이라 이벤트 위임 없이 바로 걸어도 된다.
document.getElementById("signup-toggle-btn").addEventListener("click", (event) => {
    runAction(event.currentTarget, (button) => toggleSignup(button));
});

// 게시판 관리 표의 "삭제" 버튼도 회원 목록과 동일한 이벤트 위임 방식을 쓴다.
document.getElementById("posts-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-post-btn")) {
        const postId = event.target.getAttribute("data-post-id");
        runAction(event.target, (button) => deletePost(postId, button));
    }
});

document.getElementById("comments-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-comment-btn")) {
        const commentId = event.target.getAttribute("data-comment-id");
        runAction(event.target, (button) => deleteComment(commentId, button));
    }
});

// "관리자 계정 관리" 표의 "삭제" 버튼도 회원 목록과 동일한 이벤트 위임 방식을 쓴다.
// 이 <tbody>는 항상 DOM에 존재한다(카드 자체는 render/tables.js가 hidden 속성으로만
// 숨기고 제거하지는 않으므로) — viewer/security_admin 로그인 시에도 이 리스너를
// 걸어도 안전하다.
document.getElementById("admin-users-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-admin-user-btn")) {
        const adminId = event.target.getAttribute("data-admin-id");
        const username = event.target.getAttribute("data-username");
        runAction(event.target, (button) => deleteAdminUser(adminId, username, button));
    }
});

// "관리자 계정 관리" 생성 폼 — 다른 버튼들과 달리 <form> submit 이벤트라 페이지
// 새로고침을 막는 preventDefault()가 필요하다. 성공했을 때만 입력칸을 비운다
// (실패하면 사용자가 방금 입력한 값을 다시 볼 수 있어야 고치기 편하다).
document.getElementById("admin-user-create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const usernameInput = document.getElementById("admin-user-username");
    const passwordInput = document.getElementById("admin-user-password");
    const roleSelect = document.getElementById("admin-user-role");

    const succeeded = await runAction(event.submitter, (button) =>
        createAdminUser(usernameInput.value, passwordInput.value, roleSelect.value, button)
    );
    if (succeeded) {
        usernameInput.value = "";
        passwordInput.value = "";
    }
});

// 보안 이벤트 표의 "처리 완료" 버튼도 위와 동일한 이벤트 위임 방식을 쓴다.
document.getElementById("security-events-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("resolve-event-btn")) {
        const eventId = event.target.getAttribute("data-event-id");
        runAction(event.target, (button) => resolveEvent(eventId, button));
    }
});

// 연관 사건 표의 "해결" 버튼도 위와 동일한 이벤트 위임 방식을 쓴다.
document.getElementById("security-incidents-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("resolve-incident-btn")) {
        const incidentId = event.target.getAttribute("data-incident-id");
        runAction(event.target, (button) => resolveIncident(incidentId, button));
    }
});

// "AI 조기 경보" 표의 "승인"/"반려" 버튼도 위와 동일한 이벤트 위임 방식을 쓴다
// (Track A, guide31).
document.getElementById("access-requests-table-body").addEventListener("click", (event) => {
    const requestId = event.target.getAttribute("data-request-id");
    if (event.target.classList.contains("approve-request-btn")) {
        runAction(event.target, (button) => approveAccessRequest(requestId, button));
    } else if (event.target.classList.contains("reject-request-btn")) {
        runAction(event.target, (button) => rejectAccessRequest(requestId, button));
    }
});

// 영구 잠금 + 이메일 복구 카드(guide33/34-a)의 버튼들도 위와 같은 이벤트 위임 방식을 쓴다.
document.getElementById("permanent-locks-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("release-permanent-btn")) {
        const kind = event.target.getAttribute("data-kind");
        const target = event.target.getAttribute("data-target");
        runAction(event.target, (button) => releasePermanentLock(kind, target, button));
    }
});

document.getElementById("ip-exemptions-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("revoke-exemption-btn")) {
        const id = event.target.getAttribute("data-id");
        runAction(event.target, (button) => revokeIpExemption(id, button));
    }
});

document.getElementById("recovery-requests-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("revoke-recovery-btn")) {
        const id = event.target.getAttribute("data-id");
        runAction(event.target, (button) => revokeRecoveryRequest(id, button));
    }
});

// 수동 영구 승격 폼 — 성공했을 때만 입력칸을 비운다(실패하면 입력값을 고쳐 다시 보낼 수 있게).
document.getElementById("permanent-lock-promote-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const kindSelect = document.getElementById("permanent-lock-kind");
    const targetInput = document.getElementById("permanent-lock-target");
    const reasonInput = document.getElementById("permanent-lock-reason");

    const succeeded = await runAction(event.submitter, (button) =>
        promotePermanentLock(kindSelect.value, targetInput.value.trim(), reasonInput.value.trim(), button)
    );
    if (succeeded) {
        targetInput.value = "";
        reasonInput.value = "";
    }
});

// 페이지네이션 버튼도 renderLockoutCards()의 unlock-btn과 같은 이벤트 위임 방식을 쓴다 —
// utils.js의 renderPagination()이 매번 버튼을 새로 만들어내기 때문이다.
// 누른 순간 번호를 새로 그리고 표를 흐리게 한 뒤 그 표만 요청한다(api.js의 goToPage, guide46).
// 응답 전에 연달아 눌러도 번호는 1과 마지막 페이지 사이에서만 움직인다.
function bindPagination(containerId, sectionName, getPage) {
    document.getElementById(containerId).addEventListener("click", (event) => {
        const direction = event.target.getAttribute("data-direction");
        if (direction === "prev") {
            goToPage(sectionName, getPage() - 1);
        } else if (direction === "next") {
            goToPage(sectionName, getPage() + 1);
        }
    });
}

bindPagination("attempts-pagination", "attempts", () => pages.attempts);
bindPagination("users-pagination", "users", () => pages.users);
bindPagination("posts-pagination", "posts", () => pages.posts);
bindPagination("comments-pagination", "comments", () => pages.comments);
bindPagination("admin-log-pagination", "admin_log", () => pages.adminLog);
bindPagination("security-events-pagination", "security_events", () => pages.securityEvents);
bindPagination("security-incidents-pagination", "security_incidents", () => pages.securityIncidents);
bindPagination("access-requests-pagination", "access_requests", () => pages.accessRequests);
