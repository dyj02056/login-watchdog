// ============================================================================
// dashboard/utils.js — 대시보드 전용 범용 헬퍼(escapeHtml, formatTime, renderPagination)
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

/**
 * board_list.html의 "← 이전 | N / 총페이지 | 다음 →" 페이지 이동 줄을 그대로
 * 흉내내서 표 하나의 페이지네이션 영역(containerId)을 채운다.
 * @param {string} containerId - "users-pagination" 같은 <nav id> 값
 * @param {number} page - 지금 보고 있는 페이지 번호
 * @param {number} totalPages - 전체 페이지 수
 */
export function renderPagination(containerId, page, totalPages) {
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
