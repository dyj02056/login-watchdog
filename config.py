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

# 관리자 계정 단위 실패 임계값과 집계 창(guide38) — /admin/login은 IP 단위 잠금만 있어서
# IP를 나눠 쓰는 분산 브루트포스에 무방비였다. 회원(60초 창)보다 긴 15분 창으로 세서
# 분당 몇 회씩 천천히 시도하는 공격도 잡는다. 관리자는 몇 명뿐이라 오탐 여지가 작다.
# 잠금 시간은 회원과 같은 LOCKOUT_DURATION_SECONDS(5분)이고, 영구 승격은 하지 않는다
# (관리자를 영구히 못 들어오게 만드는 것 자체가 서비스 거부가 되기 때문).
ADMIN_ACCOUNT_FAILURE_THRESHOLD = int(os.environ.get("ADMIN_ACCOUNT_FAILURE_THRESHOLD", 8))
ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS = int(os.environ.get("ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS", 900))

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
# 대시보드 상태 조회(/api/status)가 "만료된 잠금 정리"를 다시 하기까지의 최소 간격(초, guide46).
# 매 갱신마다 정리하면 DB 왕복 한 단계가 늘 더해진다. 실제 차단 해제는 /login 요청마다 따로
# 정리하므로 영향이 없고, 대시보드에 만료된 잠금이 이 시간만큼 더 보일 수 있을 뿐이다. 0이면 매번.
ADMIN_STATUS_RELEASE_INTERVAL_SECONDS = int(os.environ.get("ADMIN_STATUS_RELEASE_INTERVAL_SECONDS", 15))

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

# SIEM 상관분석(Track C guide27) 시간 창 — 같은 IP가 이 시간(분) 안에 서로 다른
# event_type을 2개 이상 남기면 security_incidents로 묶는다. DETECTION_WINDOW_SECONDS
# (60초)보다 훨씬 넉넉하게 잡은 이유: 개별 임계값 판정은 "지금 이 순간의 폭주"를
# 잡는 것이지만, 상관분석은 "정찰(웹 스캐닝) → 공격(브루트포스)"처럼 여러 단계에
# 걸친 공격 흐름을 잡아야 해서 더 넓은 시간대를 봐야 한다.
INCIDENT_CORRELATION_WINDOW_MINUTES = int(os.environ.get("INCIDENT_CORRELATION_WINDOW_MINUTES", 5))

# 열린 사건에 새 이벤트를 "병합"할 수 있는 최대 공백 시간(분) — 마지막 이벤트로부터
# 이 시간이 지나면 옛 사건은 IDLE(활동 없음)로 옮기고 새 사건을 연다. 30분으로 잡은
# 이유: 상관 창(5분)·IP 잠금 시간(5분)보다 충분히 길어야 잠금이 풀린 뒤 공격자가
# 재시도하는 정도의 공백에서 한 공격이 사건 여러 개(+에스컬레이션 알림 반복)로
# 쪼개지지 않고, 반대로 너무 길면 무관한 활동(공유 IP 등)이 한 사건에 섞이고 이미
# escalated 된 옛 사건이 새 공격의 알림을 삼켜버린다. 상관 창보다 작게 설정되면
# 의미가 없으므로 상관 창 값으로 끌어올린다.
INCIDENT_MERGE_IDLE_MINUTES = max(
    int(os.environ.get("INCIDENT_MERGE_IDLE_MINUTES", 30)),
    INCIDENT_CORRELATION_WINDOW_MINUTES,
)

# SOAR 플레이북 고도화(Track C guide28) 에스컬레이션 기준 — 사건(security_incidents)에
# 묶인 서로 다른 event_type이 이 개수 이상이면서 severity_max가 CRITICAL이면,
# correlate.py가 "복합 공격 발생" 에스컬레이션 알림을 별도로 보낸다. 상관분석 자체의
# 기준(2개 이상)보다 한 단계 더 높게 잡은 이유: 2종류만 겹쳐도 사건으로는 묶어서
# 대시보드에 보여주지만, 그 정도로 관리자에게 "추가로" 긴급 알림까지 보낼 필요는
# 없고 정말 여러 단계에 걸친 공격(3종류 이상)일 때만 알림 피로 없이 강조한다.
INCIDENT_ESCALATION_MIN_EVENT_TYPES = int(os.environ.get("INCIDENT_ESCALATION_MIN_EVENT_TYPES", 3))

# 매크로/봇 탐지(Track C guide29) — 같은 IP가 DETECTION_WINDOW_SECONDS(60초) 안에
# 서로 다른 /api/* 경로를 이 개수를 "초과"해서 호출하면 의심한다. is_suspicious()
# 등과 같은 "초과" 기준을 쓰는 이유는 정상 사용자도 화면을 넘나들며 API 몇 개는
# 우연히 부를 수 있어서, 로그인 실패 판정과 마찬가지로 약간의 여유를 준다 —
# 사람이 몇 초 안에 6개 넘는 서로 다른 API를 손으로 누르긴 어렵지만, 스크립트는 쉽다.
MACRO_DISTINCT_API_THRESHOLD = int(os.environ.get("MACRO_DISTINCT_API_THRESHOLD", 5))

# LLM 조기 경보(Track A, guide31) — 임계값을 "아직 못 넘었지만 코앞"인 구간
# (threshold - EARLY_WARNING_BAND ~ threshold - 1)에서만 Groq에게 "지켜볼
# 필요가 있는지" 판단을 맡긴다. 이미 임계값을 넘긴 경우는 규칙이 이미 확정
# 판단을 내린 상태이므로 이 구간에 해당하지 않는다 — soar.py의
# consider_early_warning() 호출부(routes/auth.py, app.py, helpers.py) 참고.
# 폭을 너무 넓게 잡으면(예: 4) 정상 사용자의 사소한 실수까지 AI 호출 대상이 되어
# 비용/지연이 늘고, 너무 좁게 잡으면(0) 규칙을 살짝 피해 가는 패턴을 놓친다.
EARLY_WARNING_BAND = int(os.environ.get("EARLY_WARNING_BAND", 2))

# 전역 HTTP 플러딩(대량 요청 도배) 방어 — 위의 *_RATE_LIMIT들은 로그인/가입/글쓰기
# 등 "특정 폼 제출"에만 걸려있고, 일반 GET 페이지는 아무리 요청이 쏟아져도 다
# 받아준다. 이 값은 같은 IP가 1분 안에 "전체 요청 종류를 합쳐서" 몇 번까지
# 허용할지를 정한다 — Flask-Limiter의 전역 기본 한도로 쓰인다(app.py 참고).
# 폴링 API(_PAGE_ACCESS_EXCLUDED_ENDPOINTS)는 정상적으로도 이 한도를 넘길 만큼
# 자주 호출되므로 이 제한에서 제외한다.
GLOBAL_RATE_LIMIT_PER_MINUTE = int(os.environ.get("GLOBAL_RATE_LIMIT_PER_MINUTE", 120))

# 관리자 세션 최대 수명(시간, guide37) — 로그인 시각부터 센다. 지나면 다음 요청에서 다시
# 로그인해야 한다. 대시보드가 5초마다 폴링해서 "활동 없음"이 생기지 않으므로 절대 수명만 둔다.
ADMIN_SESSION_MAX_HOURS = int(os.environ.get("ADMIN_SESSION_MAX_HOURS", 8))

# ============================================================================
# 영구 잠금 + 이메일 인증 복구 (guide33 / guide34-a)
# 배경: docs/beginner-guide/guide33_permanent_lock.md, guide34a_email_recovery.md
# ============================================================================

# FLASK_ENV=production(Vercel 배포)일 때만 운영 모드로 본다 — 로컬에서는 보통 이 값이
# 비어 있으므로 "production이 아니면 개발 환경"으로 취급한다. 운영 모드에서는
# 메일 console 백엔드(토큰을 터미널에 그대로 출력)를 막는다(mailer.py 참고).
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"


def _csv_set(raw: str) -> frozenset[str]:
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


# IP 영구 잠금 승격 기준 — "최근 PERMANENT_LOCK_STRIKE_WINDOW_DAYS일 안에 N번째 잠금"이면
# 같은 행을 TEMPORARY에서 PERMANENT로 올린다. 창(window)이 없으면 1년 전 잠금 한 번이
# 평생 누적되어 정상 사용자가 다음 실수 한 번에 영구 잠금되므로 기간을 반드시 둔다.
PERMANENT_LOCK_STRIKE_COUNT = int(os.environ.get("PERMANENT_LOCK_STRIKE_COUNT", 2))
# 계정(아이디) 영구 잠금 기준 횟수 — 공격자가 피해자 계정을 노려 일부러 영구 잠금을 일으킬
# 수 있어서 IP와 따로 조절할 수 있게 분리했다(필요하면 3 이상으로 올린다).
PERMANENT_LOCK_ACCOUNT_STRIKE_COUNT = int(os.environ.get("PERMANENT_LOCK_ACCOUNT_STRIKE_COUNT", 2))
PERMANENT_LOCK_STRIKE_WINDOW_DAYS = int(os.environ.get("PERMANENT_LOCK_STRIKE_WINDOW_DAYS", 30))

# HIGH 사건(security_incidents.severity_max == HIGH)을 자동으로 영구 잠금할지, 관리자
# 승인 대기(access_requests, PERMANENT_LOCK_IP)로 돌릴지. HIGH에는 가입·글·댓글 도배
# 같은 비교적 가벼운 사건도 섞여 있어 기본은 승인 대기(false)다.
PERMANENT_LOCK_AUTO_ON_HIGH = os.environ.get("PERMANENT_LOCK_AUTO_ON_HIGH", "false").lower() == "true"

# 영구 잠금 이벤트(PERMANENT_LOCK)가 사건에 병합된 직후 그 사건을 자동으로 CLOSED 처리할지.
# 기본 false — guide32의 원칙("접속 차단을 거두는 것과 관리자가 검토를 마쳤다는 판단은
# 별개")대로 사건은 관리자가 직접 "해결"을 눌러야 닫힌다. true면 resolved_by에
# "system:permanent_lock"이 기록된다.
PERMANENT_LOCK_AUTO_CLOSE_INCIDENT = (
    os.environ.get("PERMANENT_LOCK_AUTO_CLOSE_INCIDENT", "false").lower() == "true"
)

# 절대 영구 잠그지 않을 IP(관리자 PC, Docker 게이트웨이 등). 자기 자신을 잠그는 "자충수"
# 방지용이다(soar.notify_unauthorized_access 주석과 같은 이유).
# IPv6를 몇 비트 대역 단위로 세고 잠글지(guide42). 보통 가정·회선 하나가 /64를 받는다 — 통신사가
# /56·/48을 주는 환경이면 값을 줄인다. 1~128 밖의 값은 64로 취급한다(ip_utils.py).
IPV6_PREFIX_LENGTH = int(os.environ.get("IPV6_PREFIX_LENGTH", 64))
PERMANENT_LOCK_IP_ALLOWLIST = _csv_set(os.environ.get("PERMANENT_LOCK_IP_ALLOWLIST", "127.0.0.1,::1"))

# 이메일 복구 정책
RECOVERY_TOKEN_TTL_MINUTES = int(os.environ.get("RECOVERY_TOKEN_TTL_MINUTES", 15))
RECOVERY_MAX_PER_USER_PER_DAY = int(os.environ.get("RECOVERY_MAX_PER_USER_PER_DAY", 3))
RECOVERY_MAX_PER_IP_PER_HOUR = int(os.environ.get("RECOVERY_MAX_PER_IP_PER_HOUR", 5))
RECOVERY_COOLDOWN_SECONDS = int(os.environ.get("RECOVERY_COOLDOWN_SECONDS", 60))
RECOVERY_MAX_CODE_ATTEMPTS = int(os.environ.get("RECOVERY_MAX_CODE_ATTEMPTS", 5))
# /recovery/verify 제출(POST)의 IP당 분당 한도 — 코드 시도 횟수 제한(RECOVERY_MAX_CODE_ATTEMPTS)
# 앞단의 2차 방어선. 전역 한도와 같은 인메모리 저장소라 서버리스에서는 인스턴스마다 따로 센다.
RECOVERY_VERIFY_RATE_LIMIT_PER_MINUTE = int(os.environ.get("RECOVERY_VERIFY_RATE_LIMIT_PER_MINUTE", 10))
# 복구 요청(POST /recovery/request)의 IP당 분당 한도(guide43) — 이 요청은 응답마다 고정 시간
# (RECOVERY_MIN_RESPONSE_SECONDS)만큼 함수를 붙잡으므로, IP 하나가 함수를 묶어 둘 수 있는 횟수를
# 줄인다. 한도를 넘기면 기다림 없이 바로 429 — IP 기준이라 계정 존재 여부와 무관하다.
RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE = int(os.environ.get("RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE", 5))
RECOVERY_PROBATION_HOURS = int(os.environ.get("RECOVERY_PROBATION_HOURS", 24))
# 복구 요청 응답에 걸리는 "고정" 시간(초) — 메일을 실제로 보낸 경우(DB 조회 여러 번 + SMTP)와
# 아무것도 안 한 경우(없는 아이디 등)의 응답 시간 차이로 계정 존재 여부가 새지 않게, 처리가
# 끝나도 이 시간이 될 때까지 기다렸다가 항상 같은 시점에 응답한다. 처음에는 추정으로 8초를
# 잡았고, guide43에서 운영(Vercel) 실측(메일 발송 3.04초, 메일 없음 0.6~1.5초)에 여유를 더해
# 5초로 줄였다 — 이 시간 동안 서버리스 함수가 묶이므로 짧을수록 좋다. 처리가 이 시간을 넘기면
# 그만큼 응답이 늦어져 시간 차이가 드러나므로, `[timing] ... overrun` 로그가 보이면 늘린다.
# 0이면 기다림 없이 그 자리에서 처리한다(테스트용).
RECOVERY_MIN_RESPONSE_SECONDS = float(os.environ.get("RECOVERY_MIN_RESPONSE_SECONDS", 5.0))
# 복구 처리를 응답과 별개의 백그라운드 스레드로 돌릴지. 기본 false — Vercel 같은 서버리스는
# 응답을 보내는 순간 함수를 멈춰서 백그라운드 스레드의 메일 발송이 끝나기 전에 끊길 수 있으므로,
# 기본은 "요청 안에서 메일 발송까지 끝낸 뒤 응답"한다. 상시 실행 서버(로컬/gunicorn)에서만 true.
RECOVERY_BACKGROUND_WORK = os.environ.get("RECOVERY_BACKGROUND_WORK", "false").lower() == "true"
IP_EXEMPTION_DAYS = int(os.environ.get("IP_EXEMPTION_DAYS", 30))
# 예외로 통과한 사용자가 이 횟수만큼 연달아 로그인에 실패하면 예외를 회수한다.
IP_EXEMPTION_MAX_FAILURES = int(os.environ.get("IP_EXEMPTION_MAX_FAILURES", 3))

# 이메일 인증·이메일 변경 확인 링크(guide40) — 유효 시간과, 회원·용도별 재발송 간격/하루 한도.
# 한도는 메일 폭탄(남의 주소로 확인 메일을 계속 보내게 하는 것)을 막기 위한 값이다.
EMAIL_TOKEN_TTL_MINUTES = int(os.environ.get("EMAIL_TOKEN_TTL_MINUTES", 15))
EMAIL_TOKEN_COOLDOWN_SECONDS = int(os.environ.get("EMAIL_TOKEN_COOLDOWN_SECONDS", 60))
EMAIL_TOKEN_MAX_PER_DAY = int(os.environ.get("EMAIL_TOKEN_MAX_PER_DAY", 5))
# 비밀번호 재설정(guide41) — 회원당 하루 한도, IP당 시간당 한도, 요청·재설정 제출의 IP당 분당 한도.
# 재설정 메일은 "계정을 되찾는 메일"이라 영구 잠금 복구(RECOVERY_MAX_PER_USER_PER_DAY=3)와 같은 수준으로 잡았다.
PASSWORD_RESET_MAX_PER_DAY = int(os.environ.get("PASSWORD_RESET_MAX_PER_DAY", 3))
PASSWORD_RESET_MAX_PER_IP_PER_HOUR = int(os.environ.get("PASSWORD_RESET_MAX_PER_IP_PER_HOUR", 5))
PASSWORD_RESET_RATE_LIMIT_PER_MINUTE = int(os.environ.get("PASSWORD_RESET_RATE_LIMIT_PER_MINUTE", 10))
# 링크 확인 제출(POST /email/confirm)의 IP당 분당 한도 — /recovery/verify와 같은 2차 방어선.
EMAIL_CONFIRM_RATE_LIMIT_PER_MINUTE = int(os.environ.get("EMAIL_CONFIRM_RATE_LIMIT_PER_MINUTE", 10))

# 복구 요청 기기를 구분하는 쿠키(lw_dev) — 30일 유지.
DEVICE_COOKIE_NAME = "lw_dev"
DEVICE_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 3600

# 메일 발송. MAIL_BACKEND=console은 개발 전용(운영에서는 거부), smtp는 Mailpit/Gmail/Brevo 등.
MAIL_BACKEND = os.environ.get("MAIL_BACKEND", "console").lower()
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "true").lower() == "true"
# 포트 465처럼 처음부터 TLS로 접속하는 서버용(Gmail은 587+STARTTLS 또는 465+SSL 둘 다 지원).
# true면 SMTP_STARTTLS는 무시된다.
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").lower() == "true"
# 응답 고정 시간(RECOVERY_MIN_RESPONSE_SECONDS)보다 짧게 둔다 — 소켓 작업 하나당 적용되는
# 값이라 접속·로그인·전송이 모두 느려도 최악의 경우 이 값의 몇 배까지 걸릴 수 있다.
SMTP_TIMEOUT_SECONDS = int(os.environ.get("SMTP_TIMEOUT_SECONDS", 6))
# 같은 원인(설정/인증/연결)의 "메일 발송 실패" Slack 알림을 다시 보내기까지의 최소 간격(초).
MAIL_FAILURE_ALERT_COOLDOWN_SECONDS = int(os.environ.get("MAIL_FAILURE_ALERT_COOLDOWN_SECONDS", 3600))
MAIL_FROM = os.environ.get("MAIL_FROM", "login-watchdog@localhost")
# 복구 링크의 기준 주소 — Host 헤더(공격자가 조작 가능)가 아니라 이 값으로만 링크를 만든다.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
