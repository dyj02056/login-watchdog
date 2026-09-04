import os

FAILURE_THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", 5))
DETECTION_WINDOW_SECONDS = int(os.environ.get("DETECTION_WINDOW_SECONDS", 60))
LOCKOUT_DURATION_SECONDS = int(os.environ.get("LOCKOUT_DURATION_SECONDS", 300))
TRUST_FORWARDED_FOR = os.environ.get("TRUST_FORWARDED_FOR", "false").lower() == "true"

# 회원가입(/signup) 요청 빈도 제한 — 같은 IP가 DETECTION_WINDOW_SECONDS(기본 60초) 안에
# 이 횟수 이상 가입을 시도하면(성공/실패 무관) 추가 요청을 거부한다. 로그인 브루트포스
# 탐지(FAILURE_THRESHOLD)와 별개로, 계정 대량 생성(테이블 flooding) 남용을 막기 위한 값.
SIGNUP_RATE_LIMIT = int(os.environ.get("SIGNUP_RATE_LIMIT", 5))

# 게시판(/board) 한 페이지에 보여줄 글 개수 (docs/board-comment/plan_board.md 결정 #9).
BOARD_PAGE_SIZE = int(os.environ.get("BOARD_PAGE_SIZE", 10))

# 게시글/댓글 작성 빈도 제한 — SIGNUP_RATE_LIMIT과 동일한 개념(성공/실패 무관,
# DETECTION_WINDOW_SECONDS 안에 이 횟수 이상이면 거부). 댓글은 글보다 자주
# 작성되는 게 자연스러워 기본값을 더 넉넉하게 잡았다 (결정 #7).
POST_RATE_LIMIT = int(os.environ.get("POST_RATE_LIMIT", 5))
COMMENT_RATE_LIMIT = int(os.environ.get("COMMENT_RATE_LIMIT", 10))

# 클라이언트(브라우저)가 서버 상태를 다시 확인하는 폴링 주기(밀리초). 보안 경계가
# 아니라 UX 튜닝값이다 — 이 숫자를 안다고 해서 할 수 있는 게 늘어나지 않는다
# (실제 남용 방지는 위 *_RATE_LIMIT과 로그인 데코레이터가 서버 쪽에서 담당).
# 그동안 board.js/dashboard.js 각 파일에 숫자로 흩어져 있던 걸 다른 상수들처럼
# 한 곳에 모았다.
BOARD_COMMENT_POLL_MS = int(os.environ.get("BOARD_COMMENT_POLL_MS", 5000))
ADMIN_DASHBOARD_POLL_MS = int(os.environ.get("ADMIN_DASHBOARD_POLL_MS", 10000))
