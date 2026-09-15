// ============================================================================
// dashboard/events.js — 버튼 클릭 등 화면 이벤트를 api.js 함수와 연결한다.
// import되는 순간 아래 addEventListener 호출들이 즉시 실행된다(부수효과 모듈).
// 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import { deleteComment, deletePost, deleteUser, fetchStatus, resolveEvent, toggleSignup, unlockIp } from "./api.js";
import { pages } from "./state.js";

// "즉시 해제" 버튼은 render.js의 renderLockoutCards()가 매번 새로 만들어내므로,
// 버튼 각각에 이벤트를 미리 걸어둘 수 없다. 대신 항상 존재하는 container
// (lockout-list)에 이벤트를 걸어두고, "클릭된 곳이 unlock-btn 버튼이 맞는지"를
// 그때그때 확인하는 방식을 쓴다 — 이걸 "이벤트 위임(event delegation)"이라고 부른다.
document.getElementById("lockout-list").addEventListener("click", (event) => {
    if (event.target.classList.contains("unlock-btn")) {
        const ip = event.target.getAttribute("data-ip");
        unlockIp(ip);
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

// 보안 이벤트 표의 "처리 완료" 버튼도 위와 동일한 이벤트 위임 방식을 쓴다.
document.getElementById("security-events-table-body").addEventListener("click", (event) => {
    if (event.target.classList.contains("resolve-event-btn")) {
        const eventId = event.target.getAttribute("data-event-id");
        resolveEvent(eventId);
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
