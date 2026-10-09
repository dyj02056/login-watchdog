// ============================================================================
// dashboard/utils.js — 대시보드 전용 범용 헬퍼(escapeHtml, formatTime, formatDateTime, renderPagination,
// markBusy/runAction, askNote)
// 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

/**
 * escapeHtml(): 사용자가 입력한 값(아이디, 이메일 등)을 innerHTML로 화면에 꽂아넣기
 * 전에 반드시 거쳐야 하는 관문이다.
 *
 * 왜 필요한가: 회원가입 화면의 아이디/이메일 입력창에는 원래 글자 제한이 없었다.
 * 그래서 누군가 아이디를 `<img src=x onerror="fetch('/api/users/delete',...)">`
 * 같은 문자열로 등록하면, 그 값이 대시보드 표에 그대로 삽입되는 순간 브라우저가
 * 그걸 "진짜 HTML 태그"로 해석해서 실행해버린다 — 이게 바로 "Stored XSS"다.
 * 관리자가 대시보드를 열람하는 순간 관리자의 로그인 세션으로 임의의 API가
 * 호출될 수 있어서(IP 잠금 해제, 회원 삭제 등) 위험하다.
 *
 * 해결 방법: <, >, &, ", ' 같이 HTML에서 특별한 의미를 갖는 글자를 각각의
 * "문자 이름"(HTML 엔티티)으로 바꿔치기한다. 그러면 브라우저는 이 값을 더 이상
 * 태그로 해석하지 않고, 그냥 눈에 보이는 글자 그대로("<img..." 라는 텍스트)
 * 표시한다. 표 안에 넣을 값은 예외 없이 전부 이 함수를 거치도록 한다.
 */
export function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

/**
 * 서버가 보내주는 "2026-09-02T13:00:00+00:00" 같은 시각 문자열을,
 * 사람이 보기 편한 "오후 10:00:00" 같은 형태로 바꿔준다.
 */
export function formatTime(isoString) {
    return new Date(isoString).toLocaleTimeString("ko-KR");
}

/** 날짜까지 포함한 시각(영구 잠금·복구 요청 표용). 값이 없으면 "-". */
export function formatDateTime(isoString) {
    return isoString ? new Date(isoString).toLocaleString("ko-KR") : "-";
}

/**
 * board_list.html의 "← 이전 | N / 총페이지 | 다음 →" 페이지 이동 줄을 그대로
 * 흉내내서 표 하나의 페이지네이션 영역(containerId)을 채운다.
 * @param {string} containerId - "users-pagination" 같은 <nav id> 값
 * @param {number} page - 지금 보고 있는 페이지 번호
 * @param {number} totalPages - 전체 페이지 수
 */
export function renderPagination(containerId, page, totalPages, { loading = false } = {}) {
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
    // 페이지 버튼을 누른 순간(응답 전) 번호를 먼저 바꿔 그릴 때 "불러오는 중"을 붙인다(guide46).
    const status = loading ? `<span class="admin-pagination-loading">불러오는 중…</span>` : "";
    container.innerHTML = `${prev}<span class="admin-pagination-current">${page} / ${totalPages}</span>${next}${status}`;
}

const BUSY_LABEL = "처리 중…";

/**
 * 처리 버튼을 "처리 중…"으로 바꾸고 다시 누를 수 없게 한다(guide46). 요청을 실제로 보내기 직전에
 * 부른다(actions.js의 sendAction) — 확인 팝업을 취소했을 때 버튼이 바뀌어 보이지 않게.
 * @param {HTMLElement|null|undefined} button
 */
export function markBusy(button) {
    if (!button || button.dataset.busyLabel !== undefined) {
        return;
    }
    button.dataset.busyLabel = button.textContent;
    button.disabled = true;
    button.textContent = BUSY_LABEL;
}

/**
 * 버튼이 일으킨 처리(action)를 실행하고, 끝나면(성공·실패·취소 모두) 버튼을 원래대로 돌린다.
 * 이미 처리 중인 버튼이면 아무것도 하지 않는다(더블 클릭으로 같은 요청이 두 번 나가지 않게).
 * 처리 뒤 화면이 다시 그려져 버튼이 새로 만들어졌다면 옛 버튼은 화면에 없으니 그대로 둔다.
 * @param {HTMLElement|null|undefined} button
 * @param {(button: HTMLElement|null|undefined) => Promise<unknown>} action
 */
export async function runAction(button, action) {
    if (button && (button.disabled || button.dataset.busyLabel !== undefined)) {
        return undefined;
    }
    try {
        return await action(button);
    } finally {
        if (button && button.dataset.busyLabel !== undefined) {
            // 회원가입 토글처럼 다시 그려지지 않는 버튼은 그사이 새 글자가 들어갔을 수 있다 —
            // 아직 "처리 중…"일 때만 원래 글자로 되돌린다.
            if (button.textContent === BUSY_LABEL) {
                button.textContent = button.dataset.busyLabel;
            }
            delete button.dataset.busyLabel;
            button.disabled = false;
        }
    }
}

/**
 * 사유 입력 모달(#note-dialog)을 열고, 사용자가 입력한 사유를 돌려준다. 취소하면 null.
 * 사유가 비어 있으면(공백만 있어도) 닫히지 않고 오류 문구를 보여준다 — "영구 해제"처럼
 * 누가 언제 왜 했는지가 반드시 남아야 하는 조치에서 쓴다(서버도 note 누락을 400으로 막는다).
 * @param {string} message - 모달 상단에 보여줄 안내 문구
 * @returns {Promise<string|null>}
 */
export function askNote(message) {
    const dialog = document.getElementById("note-dialog");
    const form = document.getElementById("note-dialog-form");
    const input = document.getElementById("note-dialog-input");
    const error = document.getElementById("note-dialog-error");
    const cancelButton = document.getElementById("note-dialog-cancel");

    document.getElementById("note-dialog-message").textContent = message;
    input.value = "";
    error.hidden = true;

    return new Promise((resolve) => {
        function cleanup(result) {
            form.removeEventListener("submit", onSubmit);
            cancelButton.removeEventListener("click", onCancel);
            dialog.removeEventListener("cancel", onCancel);
            dialog.close();
            resolve(result);
        }
        function onSubmit(event) {
            event.preventDefault();
            const note = input.value.trim();
            if (!note) {
                error.hidden = false;
                input.focus();
                return;
            }
            cleanup(note);
        }
        function onCancel(event) {
            event.preventDefault();
            cleanup(null);
        }
        form.addEventListener("submit", onSubmit);
        cancelButton.addEventListener("click", onCancel);
        dialog.addEventListener("cancel", onCancel); // Esc 키
        dialog.showModal();
        input.focus();
    });
}
