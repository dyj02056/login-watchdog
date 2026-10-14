# ============================================================================
# routes/internal/ — Track D 내부 API(/api/internal/*): 센서·차단 프로그램 전용 창구
#
# 브라우저가 아니라 같은 Docker 단지 안의 프로그램(shipper, fw-agent)만 부르는 주소들이다.
# 사람의 세션 쿠키 대신 요청마다 서명(HMAC, 계약서 K3)을 붙여 보내므로 CSRF 검사에서 빼고
# (app.py의 csrf.exempt), 관찰 훅·전역 요청 한도에서도 뺀다(helpers/hooks.py의
# PAGE_ACCESS_EXCLUDED_ENDPOINTS).
#
# 상위 계획서는 이 창구를 routes/internal.py 한 파일로 두었지만, 역할 B와 C가 같은 파일을
# 동시에 고치면 머지 충돌이 나므로 방마다 주인을 정해 파일을 나눴다(team-plan 00 차이표 1번):
#   _hmac.py     — 서명 검증 공용 함수 (B, B0-1)
#   ingest.py    — POST /net-events: 센서 경보 접수 (B, B1-1)
#   blocks.py    — GET /blocks, POST /blocks/ack: 차단 목록·반영 확인 (C, C1-2)
#   heartbeat.py — POST /heartbeat: 장비 생존 신호 (C, C1-2)
#
# 이 파일은 Track D 뼈대 PR(I0-1)이 만들고 이후에는 아무도 고치지 않는다.
# 하위 모듈 import는 internal_bp를 만든 "뒤"에 해야 한다(routes/admin/__init__.py와 같은 방식).
# ============================================================================

from flask import Blueprint

internal_bp = Blueprint("internal", __name__, url_prefix="/api/internal")

from routes.internal import blocks, heartbeat, ingest  # noqa: E402,F401
