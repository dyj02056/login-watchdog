# ============================================================================
# helpers/ — routes/*.py(블루프린트) 전체가 공유하는 문지기·공용 함수
#
# 원래 app.py 안에 있던 함수들 중, admin/board/member 블루프린트 라우트가
# 공통으로 가져다 쓰는 것들만 helpers.py로 옮겼다. app.py 자체(에러 핸들러,
# before_request, index 라우트)도 그대로 이 패키지를 가져다 쓴다.
#
# 그 helpers.py 한 파일(314줄)에 성격이 다른 함수가 섞여 있어서 기능 묶음별로 나눴다(2026-10-09):
#   request_utils.py — get_request_ip, 허니팟(is_bot_submission), 위치 붙이기, 아이디 가리기, 메일 링크 주소
#   device.py        — hash_secret, 기기 쿠키(lw_dev)
#   auth.py          — 관리자/회원 세션, login_required / require_permission / member_login_required
#   timing.py        — run_with_fixed_response_time (원래 routes/recovery.py에 있던 것)
#   hooks.py         — 모든 요청에 걸리는 훅(보안 헤더, 404 기록, 반복 접근·매크로 관찰) — 원래 app.py에 있던 것.
#                      app.py가 `from helpers.hooks import register_request_hooks`로 직접 가져다 쓴다(재내보내기 안 함).
#
# 이 파일은 위 모듈의 함수를 그대로 다시 내보내기만 한다 — 그래서 routes/*.py, app.py,
# 테스트는 예전처럼 `from helpers import get_request_ip` / `helpers.hash_secret(...)`로 쓴다.
#
# docs/refactor/2026-09-15-file-split.md — app.py에서 helpers.py를 처음 떼어낸 작업.
# docs/refactor/2026-10-09-module-plan.md — helpers.py를 이 패키지로 나눈 작업.
# ============================================================================

from helpers.auth import (
    ADMIN_SESSION_KEYS,
    _load_current_admin,
    _reject_admin_request,
    clear_admin_session,
    clear_member_session,
    login_required,
    member_login_required,
    require_permission,
    start_admin_session,
)
from helpers.device import get_device_hash, hash_secret, new_device_token, set_device_cookie
from helpers.request_utils import (
    HONEYPOT_FIELD_NAME,
    _attach_locations,
    get_request_ip,
    is_bot_submission,
    mask_username,
    public_base_url,
)
from helpers.timing import report_internal_error, run_with_fixed_response_time
