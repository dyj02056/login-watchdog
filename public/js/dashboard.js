// ============================================================================
// dashboard.js — 대시보드 화면을 살아있게 만드는 자바스크립트
//
// 이 파일이 하는 일은 크게 3가지다.
// 1) 주기적으로(10초마다) 서버의 /api/status에 "지금 상태 알려줘"라고 물어본다.
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

/**
 * 서버에게 "지금 최신 상태가 어때?"라고 물어보고, 그 답으로 화면을 새로 그린다.
 *
 * fetch()는 브라우저가 서버에 요청을 보내는 표준 기능이다. await는 "이 요청의
 * 응답이 올 때까지 여기서 잠깐 기다렸다가, 응답이 오면 다음 줄로 넘어가라"는 뜻이다.
 */
async function fetchStatus() {
    const response = await fetch("/api/status");

    if (response.status === 401) {
        // 401 = "로그인이 안 되어 있다"는 뜻. 예를 들어 관리자가 다른 탭에서
        // 로그아웃했거나, 세션이 만료된 경우다. 이때는 로그인 화면으로 돌려보낸다.
        window.location.href = "/admin/login";
        return;
    }

    const data = await response.json(); // 서버가 보내준 JSON 응답을 자바스크립트 객체로 변환
    renderLockoutCards(data.active_lockouts);
    renderAttemptsTable(data.recent_attempts);
    renderAdminLoginLog(data.admin_login_log);
    renderUsersTable(data.users);
    renderSignupStatus(data.signup_enabled);
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
                    <div class="ip">${lockout.ip_address}</div>
                    <div>실패 ${lockout.failure_count}회</div>
                    <div>해제 예정: ${formatTime(lockout.unlock_at)}</div>
                    <button data-ip="${lockout.ip_address}" class="unlock-btn">즉시 해제</button>
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
            return `
                <tr>
                    <td>${formatTime(attempt.attempted_at)}</td>
                    <td>${attempt.ip_address}</td>
                    <td>${attempt.username}</td>
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
                    <td>${formatTime(entry.attempted_at)}</td>
                    <td>${entry.username}</td>
                    <td>${entry.ip_address}</td>
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
                    <td>${formatTime(user.created_at)}</td>
                    <td>${user.username}</td>
                    <td>${user.email}</td>
                    <td>
                        <button data-user-id="${user.id}" data-username="${user.username}" class="delete-user-btn">삭제</button>
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
        headers: { "Content-Type": "application/json" },
        // 브라우저는 같은 사이트로 요청을 보낼 때 로그인 세션 쿠키를 자동으로 함께
        // 보내주므로, 여기서 관리자 토큰 같은 걸 따로 넣지 않아도 서버가 "로그인된
        // 관리자의 요청"임을 알 수 있다(app.py의 login_required가 세션 쿠키로 확인).
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
        headers: { "Content-Type": "application/json" },
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
        headers: { "Content-Type": "application/json" },
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

fetchStatus(); // 화면이 열리자마자 한 번 즉시 데이터를 가져온다.
setInterval(fetchStatus, 10000); // 이후로는 10초마다 계속 반복해서 최신 상태로 갱신한다.
