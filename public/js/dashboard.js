// ============================================================================
// dashboard.js — 대시보드 화면을 살아있게 만드는 자바스크립트
//
// 이 파일이 하는 일은 크게 3가지다.
// 1) 주기적으로(config.py의 ADMIN_DASHBOARD_POLL_MS, 기본 10초마다) 서버의
//    /api/status에 "지금 상태 알려줘"라고 물어본다.
//    (원래는 2.5초였으나, Supabase 무료 쿼터 점검 결과 대시보드를 오래 켜두면
//    한 달 쿼터를 금방 소진할 수 있다는 걸 확인하고 10초로 늘렸다 — 8단계 이후
//    "쿼터 점검" 단계 참고)
// 2) 받아온 데이터로 화면의 표/카드를 다시 그린다.
// 3) "즉시 해제" 버튼을 누르면 /api/unlock에 "이 IP 좀 풀어줘"라고 요청을 보낸다.
//
// HTML(dashboard.html)은 표의 "틀"만 가지고 있고, 실제 알맹이(데이터)는 전부
// 이 파일이 채워넣는다 — 이런 방식을 "화면을 자바스크립트로 동적으로 그린다"고 한다.
// ============================================================================

// 회원가입 토글 버튼을 누르면 "지금 상태의 반대"로 바꿔야 하는데, 그러려면
// "지금 상태가 뭔지"를 어딘가 기억해둬야 한다. renderSignupStatus()가 매번
// 이 변수를 최신 값으로 갱신해둔다.
let currentSignupEnabled = true;

// 회원/게시글/댓글 관리 표가 지금 몇 페이지를 보고 있는지 기억해둔다. board_list.html의
// URL 쿼리 파라미터(?page=)와 같은 역할이지만, 이 화면은 서버 렌더링이 아니라 매번
// fetch()로 다시 그리는 방식이라 URL 대신 자바스크립트 변수로 상태를 들고 있는다.
let usersPage = 1;
let postsPage = 1;
let commentsPage = 1;

// admin_dashboard.html의 <meta name="csrf-token"> 태그에서 서버가 발급한 CSRF
// 토큰 값을 읽어온다. 아래 unlockIp/deleteUser/toggleSignup이 fetch()로 서버
// 상태를 바꾸는 POST 요청을 보낼 때마다 이 값을 X-CSRFToken 헤더에 실어 보내야,
// 서버의 CSRFProtect가 "이 요청이 정말 이 화면에서 나왔다"고 확인해줄 수 있다
// (CSRF 방어, app.py의 CSRFProtect 설명 참고).
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

// 폴링 주기(밀리초)도 CSRF 토큰과 같은 방식으로, config.py(ADMIN_DASHBOARD_POLL_MS)
// 값을 admin_dashboard.html의 meta 태그에서 읽어온다 — 이 파일에 숫자를 직접
// 적어두지 않는다.
const pollIntervalMs = Number(document.querySelector('meta[name="poll-interval-ms"]').content);

// escapeHtml(): 사용자가 입력한 값(아이디, 이메일 등)을 innerHTML로 화면에 꽂아넣기
// 전에 반드시 거쳐야 하는 관문이다.
//
// 왜 필요한가: 회원가입 화면의 아이디/이메일 입력창에는 원래 글자 제한이 없었다.
// 그래서 누군가 아이디를 `<img src=x onerror="fetch('/api/users/delete',...)">`
// 같은 문자열로 등록하면, 그 값이 대시보드 표에 그대로 삽입되는 순간 브라우저가
// 그걸 "진짜 HTML 태그"로 해석해서 실행해버린다 — 이게 바로 "Stored XSS"다.
// 관리자가 대시보드를 열람하는 순간 관리자의 로그인 세션으로 임의의 API가
// 호출될 수 있어서(IP 잠금 해제, 회원 삭제 등) 위험하다.
//
// 해결 방법: <, >, &, ", ' 같이 HTML에서 특별한 의미를 갖는 글자를 각각의
// "문자 이름"(HTML 엔티티)으로 바꿔치기한다. 그러면 브라우저는 이 값을 더 이상
// 태그로 해석하지 않고, 그냥 눈에 보이는 글자 그대로("<img..." 라는 텍스트)
// 표시한다. 표 안에 넣을 값은 예외 없이 전부 이 함수를 거치도록 한다.
function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

/**
 * 서버에게 "지금 최신 상태가 어때?"라고 물어보고, 그 답으로 화면을 새로 그린다.
 *
 * fetch()는 브라우저가 서버에 요청을 보내는 표준 기능이다. await는 "이 요청의
 * 응답이 올 때까지 여기서 잠깐 기다렸다가, 응답이 오면 다음 줄로 넘어가라"는 뜻이다.
 */
async function fetchStatus() {
    // 회원/게시글/댓글 표는 각자 다른 페이지를 보고 있을 수 있으므로, 지금 기억해둔
    // 페이지 번호를 매번 쿼리 파라미터로 함께 보낸다(app.py의 _page_param() 참고).
    const params = new URLSearchParams({
        users_page: usersPage,
        posts_page: postsPage,
        comments_page: commentsPage,
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
    if (usersPage > data.users_total_pages) { usersPage = data.users_total_pages; needsRefetch = true; }
    if (postsPage > data.posts_total_pages) { postsPage = data.posts_total_pages; needsRefetch = true; }
    if (commentsPage > data.comments_total_pages) { commentsPage = data.comments_total_pages; needsRefetch = true; }
    if (needsRefetch) {
        fetchStatus();
        return;
    }

    renderLockoutCards(data.active_lockouts);
    renderAttemptsTable(data.recent_attempts);
    renderAdminLoginLog(data.admin_login_log);
    renderUsersTable(data.users);
    renderPagination("users-pagination", usersPage, data.users_total_pages);
    renderSignupStatus(data.signup_enabled);
    renderPostsTable(data.recent_posts);
    renderPagination("posts-pagination", postsPage, data.posts_total_pages);
    renderCommentsTable(data.recent_comments);
    renderPagination("comments-pagination", commentsPage, data.comments_total_pages);
}

/**
 * board_list.html의 "← 이전 | N / 총페이지 | 다음 →" 페이지 이동 줄을 그대로
 * 흉내내서 표 하나의 페이지네이션 영역(containerId)을 채운다.
 * @param {string} containerId - "users-pagination" 같은 <nav id> 값
 * @param {number} page - 지금 보고 있는 페이지 번호
 * @param {number} totalPages - 전체 페이지 수
 */
function renderPagination(containerId, page, totalPages) {
    const container = document.getElementById(containerId);
    if (totalPages <= 1) {
        // 페이지가 1개뿐이면 이동할 곳이 없으므로 버튼 자체를 안 보여준다.
        container.innerHTML = "";
        return;
    }
    const prev = page > 1
        ? `<button type="button" class="admin-pagination-btn" data-direction="prev">← 이전</button>`
        : `<span class="admin-pagination-disabled">← 이전</span>`;
    const next = page < totalPages
        ? `<button type="button" class="admin-pagination-btn" data-direction="next">다음 →</button>`
        : `<span class="admin-pagination-disabled">다음 →</span>`;
    container.innerHTML = `${prev}<span class="admin-pagination-current">${page} / ${totalPages}</span>${next}`;
}

/**
 * 지금 잠긴 IP들을 카드 형태로 그린다. 각 카드에는 "즉시 해제" 버튼이 붙는다.
 * @param {Array} lockouts - [{ip_address, locked_at, unlock_at, failure_count}, ...]
 */
function renderLockoutCards(lockouts) {
    const container = document.getElementById("lockout-list");

    if (lockouts.length === 0) {
        container.innerHTML = '<p class="empty-state">현재 잠긴 IP가 없습니다.</p>';
        return;
    }

    // map()으로 각 잠금 데이터를 카드 HTML 문자열로 바꾼 뒤, join("")으로 전부 이어붙인다.
    // data-ip 속성에 IP를 심어두면, 아래 이벤트 처리에서 "어느 카드의 버튼이 눌렸는지" 알 수 있다.
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
function renderAttemptsTable(attempts) {
    const tbody = document.getElementById("attempts-table-body");
    tbody.innerHTML = attempts
        .map((attempt) => {
            const resultClass = attempt.success ? "success-true" : "success-false";
            const resultText = attempt.success ? "성공" : "실패";
            // attempt.location : 서버(app.py의 _attach_locations())가 IP 위치 조회
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
function renderAdminLoginLog(log) {
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
function renderUsersTable(users) {
    const tbody = document.getElementById("users-table-body");

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">가입된 회원이 없습니다.</td></tr>';
        return;
    }

    // data-user-id / data-username 속성에 값을 심어두면, 아래 이벤트 처리에서
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
 * 게시판 관리 — 최근 게시글 표를 채운다. 각 줄에 "삭제" 버튼이 붙는다.
 * @param {Array} posts - [{id, title, author_username, created_at}, ...]
 */
function renderPostsTable(posts) {
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
function renderCommentsTable(comments) {
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
 * 관리자가 게시판 관리 표의 "삭제" 버튼을 눌렀을 때, 확인 후 글을 삭제 요청한다.
 * @param {string} postId
 */
async function deletePost(postId) {
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
async function deleteComment(commentId) {
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
 * 회원가입 On/Off 현재 상태를 문구와 버튼에 반영한다.
 * @param {boolean} enabled
 */
function renderSignupStatus(enabled) {
    currentSignupEnabled = enabled; // 토글 버튼을 눌렀을 때 "반대로 바꿔라"고 계산하려면 현재 값을 기억해둬야 한다
    const statusEl = document.getElementById("signup-status");
    const buttonEl = document.getElementById("signup-toggle-btn");

    statusEl.textContent = enabled ? "허용 중" : "중단됨";
    buttonEl.textContent = enabled ? "회원가입 끄기" : "회원가입 켜기";
}

/**
 * 관리자가 "즉시 해제" 버튼을 눌렀을 때, 그 IP를 서버에 풀어달라고 요청한다.
 * @param {string} ip
 */
async function unlockIp(ip) {
    await fetch("/api/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        // 브라우저는 같은 사이트로 요청을 보낼 때 로그인 세션 쿠키를 자동으로 함께
        // 보내주므로, 여기서 관리자 토큰 같은 걸 따로 넣지 않아도 서버가 "로그인된
        // 관리자의 요청"임을 알 수 있다(app.py의 login_required가 세션 쿠키로 확인).
        // 다만 세션 쿠키만으로는 "이 요청이 진짜 이 화면에서 왔는지"까지는 보장하지
        // 못하므로(CSRF), X-CSRFToken 헤더로 이 화면이 서버에게 받은 토큰을 함께 보낸다.
        body: JSON.stringify({ ip: ip }),
    });
    // 해제 요청이 끝나면 화면을 바로 한 번 더 갱신해서, 다음 폴링 주기를
    // 기다리지 않고도 즉시 카드가 사라지는 걸 볼 수 있게 한다.
    fetchStatus();
}

/**
 * 관리자가 회원 목록의 "삭제" 버튼을 눌렀을 때, 확인을 한 번 거친 뒤 삭제를 요청한다.
 * @param {string} userId
 * @param {string} username
 */
async function deleteUser(userId, username) {
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
 * 회원가입 토글 버튼을 눌렀을 때, 현재 상태의 반대값으로 바꿔달라고 서버에 요청한다.
 */
async function toggleSignup() {
    await fetch("/api/settings/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ enabled: !currentSignupEnabled }),
    });
    fetchStatus();
}

/**
 * 서버가 보내주는 "2026-09-02T13:00:00+00:00" 같은 시각 문자열을,
 * 사람이 보기 편한 "오후 10:00:00" 같은 형태로 바꿔준다.
 */
function formatTime(isoString) {
    return new Date(isoString).toLocaleTimeString("ko-KR");
}

// "즉시 해제" 버튼은 renderLockoutCards()가 매번 새로 만들어내므로, 버튼 각각에
// 이벤트를 미리 걸어둘 수 없다. 대신 항상 존재하는 container(lockout-list)에
// 이벤트를 걸어두고, "클릭된 곳이 unlock-btn 버튼이 맞는지"를 그때그때 확인하는
// 방식을 쓴다 — 이걸 "이벤트 위임(event delegation)"이라고 부른다.
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

// 회원/게시글/댓글 페이지네이션 버튼도 renderLockoutCards()의 unlock-btn과 같은
// 이벤트 위임 방식을 쓴다 — renderPagination()이 매번 버튼을 새로 만들어내기 때문이다.
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

bindPagination("users-pagination", () => usersPage, (page) => { usersPage = page; });
bindPagination("posts-pagination", () => postsPage, (page) => { postsPage = page; });
bindPagination("comments-pagination", () => commentsPage, (page) => { commentsPage = page; });

fetchStatus(); // 화면이 열리자마자 한 번 즉시 데이터를 가져온다.
setInterval(fetchStatus, pollIntervalMs); // 이후로는 pollIntervalMs마다 계속 반복해서 최신 상태로 갱신한다.
