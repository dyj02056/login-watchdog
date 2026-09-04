// ============================================================================
// board.js — 게시글 상세 화면(board_detail.html) 전용. "새로운 댓글이
// 추가되었습니다" 배너를 가볍게 폴링으로 띄워주는 역할만 한다.
//
// 관리자 대시보드(dashboard.js)는 표 전체를 자바스크립트로 다시 그리지만,
// 이 화면은 기본적으로 서버가 완성된 HTML을 내려주는 SSR 방식이다(결정 #6).
// 여기서 폴링하는 건 "댓글이 새로 달렸는지" 신호 하나뿐이고, 배너를 누르면
// 페이지를 통째로 새로고침해서 최신 댓글까지 포함된 SSR 화면을 다시 받는다 —
// 부분 갱신(diff 렌더링) 없이 가장 단순한 방식을 택했다.
// ============================================================================

const boardDetailEl = document.getElementById("board-detail");
const boardPostId = boardDetailEl.getAttribute("data-post-id");
// 폴링 주기는 config.py(BOARD_COMMENT_POLL_MS)에서 app.py가 계산해 넘겨준 값을
// 화면의 data 속성에서 그대로 읽는다 — 이 파일에 숫자를 직접 적어두지 않는다.
const boardPollIntervalMs = Number(boardDetailEl.getAttribute("data-poll-interval-ms"));

// 페이지가 처음 그려진 시점의 댓글 개수/최신 시각을 "기준값"으로 기억해둔다.
// 이후 폴링 결과가 이 값과 달라지면 배너를 띄운다.
//
// data-latest-at은 댓글이 하나도 없을 때 빈 문자열("")로 내려오는데, API 응답의
// latest_at은 같은 "댓글 없음" 상태를 JSON null로 표현한다(db.get_latest_comment_info
// 참고) — 이 둘을 그대로 비교하면 타입이 달라(null !== "") 댓글이 하나도 안
// 달렸는데도 첫 폴링부터 배너가 잘못 뜬다. 그래서 API 쪽 값도 || ""로 정규화해서
// 항상 문자열끼리 비교한다.
let knownCommentCount = Number(boardDetailEl.getAttribute("data-comment-count"));
let knownLatestAt = boardDetailEl.getAttribute("data-latest-at") || "";

/**
 * /api/board/<id>/comments/latest를 호출해 최신 댓글 개수/시각을 확인하고,
 * 기준값과 다르면 배너를 보여준다.
 */
async function checkForNewComments() {
    const response = await fetch(`/api/board/${boardPostId}/comments/latest`);
    if (!response.ok) {
        // 401(세션 만료) 등은 조용히 무시한다 — 이 배너는 부가 기능이라
        // 실패했다고 화면 전체가 멈추면 안 된다(alert.py의 "부가 기능 실패가
        // 핵심 기능을 막으면 안 된다" 원칙과 동일).
        return;
    }
    const data = await response.json();
    const latestAt = data.latest_at || "";

    if (data.count !== knownCommentCount || latestAt !== knownLatestAt) {
        document.getElementById("new-comment-banner").hidden = false;
    }
}

document.getElementById("new-comment-refresh").addEventListener("click", () => {
    window.location.reload();
});

setInterval(checkForNewComments, boardPollIntervalMs);
