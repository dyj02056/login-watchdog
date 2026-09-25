import os
import re

# 아이디/비밀번호 형식 규칙. 원래 routes/auth.py 안에만 있었는데, Track B
# guide26 이후 관리자 계정 생성(scripts/create_admin.py, 대시보드 "관리자 계정
# 관리")도 같은 규칙을 써야 해서 여러 곳에서 참조하는 값들과 같은 원칙으로
# config.py 한 곳에 모았다.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MIN_PASSWORD_LENGTH = 8

FAILURE_THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", 5))
DETECTION_WINDOW_SECONDS = int(os.environ.get("DETECTION_WINDOW_SECONDS", 60))
LOCKOUT_DURATION_SECONDS = int(os.environ.get("LOCKOUT_DURATION_SECONDS", 300))
TRUST_FORWARDED_FOR = os.environ.get("TRUST_FORWARDED_FOR", "false").lower() == "true"

# 계정(아이디) 단위 실패 횟수 임계값 — FAILURE_THRESHOLD(IP 단위)와 별개로 둔다.
# 공격자가 여러 IP로 나눠서(봇넷/프록시 로테이션) 같은 계정만 노리면 IP당 실패
# 횟수는 임계값을 넘지 않아 탐지를 피해갈 수 있다. 이 값은 "어느 IP에서 왔든
# 이 계정이 총 몇 번 실패당했는가"를 기준으로 삼아 그 빈틈을 메운다. IP 임계값
# (5)보다 높게 잡은 이유: 정상 사용자가 여러 기기/브라우저에서 비밀번호를
# 몇 번 틀리는 정도로는 계정 전체가 잠기지 않게 여유를 주기 위해서다.
ACCOUNT_FAILURE_THRESHOLD = int(os.environ.get("ACCOUNT_FAILURE_THRESHOLD", 8))

# 회원가입(/signup) 요청 빈도 제한 — 같은 IP가 DETECTION_WINDOW_SECONDS(기본 60초) 안에
# 이 횟수 이상 가입을 시도하면(성공/실패 무관) 추가 요청을 거부한다. 로그인 브루트포스
# 탐지(FAILURE_THRESHOLD)와 별개로, 계정 대량 생성(테이블 flooding) 남용을 막기 위한 값.
SIGNUP_RATE_LIMIT = int(os.environ.get("SIGNUP_RATE_LIMIT", 5))

# 게시판(/board) 한 페이지에 보여줄 글 개수 (docs/board-comment/plan_board.md 결정 #9).
BOARD_PAGE_SIZE = int(os.environ.get("BOARD_PAGE_SIZE", 10))

# 관리자 대시보드(/admin/dashboard)의 회원/게시글/댓글 관리 표 한 페이지에 보여줄
# 행 개수. 예전에는 "최근 N개만" 방식(list_users(limit=100) 등)으로 고정해뒀는데,
# 그 이상 쌓이면 오래된 항목이 화면에서 아예 사라져버리는 문제가 있었다.
# BOARD_PAGE_SIZE와 별도 값으로 둔 이유: 회원용 게시판(카드형 목록)과 관리자용
# 표(data-table)는 한 화면에 자연스럽게 들어가는 줄 수가 달라서다.
ADMIN_PAGE_SIZE = int(os.environ.get("ADMIN_PAGE_SIZE", 10))

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
ADMIN_DASHBOARD_POLL_MS = int(os.environ.get("ADMIN_DASHBOARD_POLL_MS", 5000))

# Web Scanning(존재하지 않는 경로 반복 요청) 탐지 임계값 — 같은 IP가
# DETECTION_WINDOW_SECONDS(기본 60초) 안에 이 횟수를 "초과"해서 404를 유발하면
# 관리자에게 Slack 알림을 보낸다. is_suspicious()와 같은 "초과" 기준을 쓰는 이유는
# 정상 방문자도 깨진 링크 몇 개는 우연히 밟을 수 있어서, 로그인 실패 판정과
# 마찬가지로 약간의 여유를 준다 (attack_response_state.md 구현 대상 #1).
WEB_SCANNING_ALERT_THRESHOLD = int(os.environ.get("WEB_SCANNING_ALERT_THRESHOLD", 10))

# Unauthorized Access(로그인 세션 없이 관리자 API를 반복 호출) 탐지 임계값 —
# WEB_SCANNING_ALERT_THRESHOLD와 같은 이유(정상 사용자도 세션 만료 직후 대시보드가
# 자동으로 몇 번 더 요청을 보낼 수 있음)로 "초과"부터 의심한다
# (attack_response_state.md 구현 대상 #2).
UNAUTHORIZED_ACCESS_ALERT_THRESHOLD = int(os.environ.get("UNAUTHORIZED_ACCESS_ALERT_THRESHOLD", 10))

# 반복 페이지 접근(같은 IP가 같은 GET 경로를 짧은 시간에 반복 요청) 탐지 임계값.
# board.js/dashboard.js처럼 이 프로젝트 자체가 만든 자동 폴링 API는 애초에
# 카운트 대상에서 제외하므로(app.py의 _PAGE_ACCESS_EXCLUDED_ENDPOINTS 참고),
# 이 값은 "사람이 직접, 혹은 스크립트가 같은 페이지를 반복 새로고침하는" 상황만
# 대상으로 한다 — 정상적인 수동 새로고침보다는 넉넉하게 잡는다
# (attack_response_state.md 구현 대상 #4).
PAGE_ACCESS_ALERT_THRESHOLD = int(os.environ.get("PAGE_ACCESS_ALERT_THRESHOLD", 20))

# 전역 HTTP 플러딩(대량 요청 도배) 방어 — 위의 *_RATE_LIMIT들은 로그인/가입/글쓰기
# 등 "특정 폼 제출"에만 걸려있고, 일반 GET 페이지는 아무리 요청이 쏟아져도 다
# 받아준다. 이 값은 같은 IP가 1분 안에 "전체 요청 종류를 합쳐서" 몇 번까지
# 허용할지를 정한다 — Flask-Limiter의 전역 기본 한도로 쓰인다(app.py 참고).
# 폴링 API(_PAGE_ACCESS_EXCLUDED_ENDPOINTS)는 정상적으로도 이 한도를 넘길 만큼
# 자주 호출되므로 이 제한에서 제외한다.
GLOBAL_RATE_LIMIT_PER_MINUTE = int(os.environ.get("GLOBAL_RATE_LIMIT_PER_MINUTE", 120))
