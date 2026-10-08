// ============================================================================
// dashboard/events.js — 버튼 클릭 등 화면 이벤트를 api.js 함수와 연결한다.
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
    fetchStatus,
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
} from "./api.js";
import { pages } from "./state.js";

// "즉시 해제" 버튼은 render.js의 renderLockoutCards()가 매번 새로 만들어내므로,
// 버튼 각각에 이벤트를 미리 걸어둘 수 없다. 대신 항상 존재하는 container
// (lockout-list)에 이벤트를 걸어두고, "클릭된 곳이 unlock-btn 버튼이 맞는지"를
// 그때그때 확인하는 방식을 쓴다 — 이걸 "이벤트 위임(event delegation)"이라고 부른다.
document.getElementById("lockout-list").addEventListener("click", (event) => {
    if (event.target.classList.contains("unlock-btn")) {
        const ip = event.target.getAttribute("data-ip");
        unlockIp(ip);
    } else if (event.target.classList.contains("unlock-account-btn")) {
        const username = event.target.getAttribute("data-username");
        unlockAccount(username);
    } else if (event.target.classList.contains("unlock-admin-account-btn")) {
        const username = event.target.getAttribute("data-username");
        unlockAdminAccount(username);
    }
});

// 회원 목록의 "삭제" 버튼도 위와 똑같은 이벤트 위임 방식을 쓴다.
document.getElementById("users-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-user-btn")) {
        const userId = event.target.getAttribute("data-user-id");
        const username = event.target.getAttribute("data-username");
        deleteUser(userId, username);
    }
});

// 회원가입 토글 버튼은 화면에 딱 하나뿐이라 이벤트 위임 없이 바로 걸어도 된다.
document.getElementById("signup-toggle-btn").addEventListener("click", toggleSignup);

// 게시판 관리 표의 "삭제" 버튼도 회원 목록과 동일한 이벤트 위임 방식을 쓴다.
document.getElementById("posts-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-post-btn")) {
        const postId = event.target.getAttribute("data-post-id");
        deletePost(postId);
    }
});

document.getElementById("comments-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-comment-btn")) {
        const commentId = event.target.getAttribute("data-comment-id");
        deleteComment(commentId);
    }
});

// "관리자 계정 관리" 표의 "삭제" 버튼도 회원 목록과 동일한 이벤트 위임 방식을 쓴다.
// 이 <tbody>는 항상 DOM에 존재한다(카드 자체는 render.js가 hidden 속성으로만
// 숨기고 제거하지는 않으므로) — viewer/security_admin 로그인 시에도 이 리스너를
// 걸어도 안전하다.
document.getElementById("admin-users-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("delete-admin-user-btn")) {
        const adminId = event.target.getAttribute("data-admin-id");
        const username = event.target.getAttribute("data-username");
        deleteAdminUser(adminId, username);
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

    const succeeded = await createAdminUser(usernameInput.value, passwordInput.value, roleSelect.value);
    if (succeeded) {
        usernameInput.value = "";
        passwordInput.value = "";
    }
});

// 보안 이벤트 표의 "처리 완료" 버튼도 위와 동일한 이벤트 위임 방식을 쓴다.
document.getElementById("security-events-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("resolve-event-btn")) {
        const eventId = event.target.getAttribute("data-event-id");
        resolveEvent(eventId);
    }
});

// 연관 사건 표의 "해결" 버튼도 위와 동일한 이벤트 위임 방식을 쓴다.
document.getElementById("security-incidents-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("resolve-incident-btn")) {
        const incidentId = event.target.getAttribute("data-incident-id");
        resolveIncident(incidentId);
    }
});

// "AI 조기 경보" 표의 "승인"/"반려" 버튼도 위와 동일한 이벤트 위임 방식을 쓴다
// (Track A, guide31).
document.getElementById("access-requests-table-body").addEventListener("click", (event) => {
    const requestId = event.target.getAttribute("data-request-id");
    if (event.target.classList.contains("approve-request-btn")) {
        approveAccessRequest(requestId);
    } else if (event.target.classList.contains("reject-request-btn")) {
        rejectAccessRequest(requestId);
    }
});

// 영구 잠금 + 이메일 복구 카드(guide33/34-a)의 버튼들도 위와 같은 이벤트 위임 방식을 쓴다.
document.getElementById("permanent-locks-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("release-permanent-btn")) {
        releasePermanentLock(
            event.target.getAttribute("data-kind"),
            event.target.getAttribute("data-target")
        );
    }
});

document.getElementById("ip-exemptions-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("revoke-exemption-btn")) {
        revokeIpExemption(event.target.getAttribute("data-id"));
    }
});

document.getElementById("recovery-requests-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("revoke-recovery-btn")) {
        revokeRecoveryRequest(event.target.getAttribute("data-id"));
    }
});

// 수동 영구 승격 폼 — 성공했을 때만 입력칸을 비운다(실패하면 입력값을 고쳐 다시 보낼 수 있게).
document.getElementById("permanent-lock-promote-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const kindSelect = document.getElementById("permanent-lock-kind");
    const targetInput = document.getElementById("permanent-lock-target");
    const reasonInput = document.getElementById("permanent-lock-reason");

    const succeeded = await promotePermanentLock(kindSelect.value, targetInput.value.trim(), reasonInput.value.trim());
    if (succeeded) {
        targetInput.value = "";
        reasonInput.value = "";
    }
});

// 회원/게시글/댓글 페이지네이션 버튼도 renderLockoutCards()의 unlock-btn과 같은
// 이벤트 위임 방식을 쓴다 — utils.js의 renderPagination()이 매번 버튼을 새로
// 만들어내기 때문이다.
function bindPagination(containerId, getPage, setPage) {
    document.getElementById(containerId).addEventListener("click", (event) => {
        const direction = event.target.getAttribute("data-direction");
        if (direction === "prev") {
            setPage(getPage() - 1);
            fetchStatus();
        } else if (direction === "next") {
            setPage(getPage() + 1);
            fetchStatus();
        }
    });
}

bindPagination("attempts-pagination", () => pages.attempts, (page) => { pages.attempts = page; });
bindPagination("users-pagination", () => pages.users, (page) => { pages.users = page; });
bindPagination("posts-pagination", () => pages.posts, (page) => { pages.posts = page; });
bindPagination("comments-pagination", () => pages.comments, (page) => { pages.comments = page; });
bindPagination("admin-log-pagination", () => pages.adminLog, (page) => { pages.adminLog = page; });
bindPagination("security-events-pagination", () => pages.securityEvents, (page) => { pages.securityEvents = page; });
bindPagination("security-incidents-pagination", () => pages.securityIncidents, (page) => { pages.securityIncidents = page; });
bindPagination("access-requests-pagination", () => pages.accessRequests, (page) => { pages.accessRequests = page; });
