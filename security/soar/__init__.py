# ============================================================================
# security/soar/ — "집행관" 역할: 판정 결과를 실제 조치(잠금 / 알림 / 해제)로 실행한다
#
# SOAR = Security Orchestration, Automation and Response
#        (보안 이상 징후를 자동으로 판단해 대응 조치까지 실행한다는 뜻의 보안 업계 용어)
#
# security/detector.py가 "수상하다"고 판단만 해주면, 이 파일이 그 판단을 받아서
# 실제로 db를 통해 잠금을 기록하고, notify/alert.py를 통해 Slack 알림을 보낸다.
# "누가 이 조치를 실행할 권한이 있는가"(예: 관리자 로그인 여부)는 이 파일이
# 신경 쓰지 않는다 — 그건 라우트의 문지기(helpers/auth.py)가 확인해야 할 몫이다.
#
# 원래 루트의 soar.py 한 파일(497줄)이었는데, 기능 묶음별로 나눴다(2026-10-09):
#   _events.py        — _record_event (이벤트 기록 + 상관분석 훅, 아래 모듈들이 공유)
#   lockouts.py       — enforce_* (잠금 집행), try_release_expired_*, manual_release_* (해제)
#   observe.py        — notify_* (잠그지 않고 알림 + 기록만), record_rejection (HIGH 거부 기록)
#   early_warning.py  — consider_early_warning (LLM 조기 경보), 관리자 승인/반려
#
# 이 파일은 위 모듈의 함수를 그대로 다시 내보내기만 한다 — 그래서 호출부와 테스트는
# 예전처럼 `soar.enforce_lockout(...)`, `monkeypatch.setattr(soar, "enforce_lockout", ...)`로 쓴다.
# 하위 모듈끼리 서로의 함수를 부를 때는 반드시 `soar.xxx()`처럼 패키지 속성으로 부른다
# (db/ 패키지와 같은 이유 — docs/refactor/2026-09-15-file-split.md "까다로웠던 부분" 참고).
# ============================================================================

from security.soar._events import _record_event
from security.soar.early_warning import (
    _run_pending_action,
    consider_early_warning,
    execute_approved_request,
    reject_pending_request,
)
from security.soar.lockouts import (
    enforce_account_lockout,
    enforce_admin_account_lockout,
    enforce_lockout,
    manual_release,
    manual_release_account,
    manual_release_admin_account,
    try_release_expired_account_lockouts,
    try_release_expired_admin_account_lockouts,
    try_release_expired_lockouts,
)
from security.soar.observe import (
    notify_bot_detected,
    notify_macro_pattern,
    notify_page_access,
    notify_unauthorized_access,
    notify_web_scanning,
    record_rejection,
)
