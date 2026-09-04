import os

FAILURE_THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", 5))
DETECTION_WINDOW_SECONDS = int(os.environ.get("DETECTION_WINDOW_SECONDS", 60))
LOCKOUT_DURATION_SECONDS = int(os.environ.get("LOCKOUT_DURATION_SECONDS", 300))
TRUST_FORWARDED_FOR = os.environ.get("TRUST_FORWARDED_FOR", "false").lower() == "true"

# 회원가입(/signup) 요청 빈도 제한 — 같은 IP가 DETECTION_WINDOW_SECONDS(기본 60초) 안에
# 이 횟수 이상 가입을 시도하면(성공/실패 무관) 추가 요청을 거부한다. 로그인 브루트포스
# 탐지(FAILURE_THRESHOLD)와 별개로, 계정 대량 생성(테이블 flooding) 남용을 막기 위한 값.
SIGNUP_RATE_LIMIT = int(os.environ.get("SIGNUP_RATE_LIMIT", 5))
