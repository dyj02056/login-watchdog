# ============================================================================
# db/__init__.py — 데이터베이스(Supabase)와 대화하는 유일한 창구
#
# 이 프로그램의 다른 파일(security/detector.py, security/soar/, app.py 등)은 데이터베이스에
# 직접 말을 걸지 않고, 항상 이 db 패키지의 함수를 통해서만 데이터를 읽고 씁니다.
# 그래야 "데이터를 어떻게 저장/조회하는지"에 대한 규칙이 한 곳에만 있어서
# 관리하기 쉬워집니다.
#
# 원래는 db.py 파일 하나(1,030줄)에 모든 함수가 들어있었다. 표 16개를 다루는
# 함수가 전부 한 파일에 있다 보니 원하는 함수를 찾기 어려워져서, 표 묶음(도메인)
# 단위로 아래처럼 나눴다:
#   _client.py         — Supabase 연결, 공용 시각 헬퍼
#   attempts.py         — login_attempts (로그인 시도 기록)
#   lockouts.py         — lockouts (IP 잠금 현재 상태)
#   account_lockouts.py — account_lockouts (회원 계정 단위 잠금, 분산 브루트포스 대응)
#   admin.py            — admin_users, admin_login_log (관리자 계정/로그인 기록)
#   admin_lockouts.py   — admin_account_lockouts (관리자 계정 단위 잠금, guide38)
#   roles.py            — roles, permissions (RBAC 역할별 허용 액션, Track B guide26)
#   users.py            — users (회원 계정)
#   settings.py         — app_settings, signup_attempts (설정값, 가입 빈도 제한)
#   geoip_cache.py       — ip_locations (IP 위치 조회 캐시)
#   board.py            — posts, comments, post_attempts, comment_attempts (게시판)
#   access_logs.py      — not_found/unauthorized/page_access_attempts (요청 로그)
#   security_events.py  — security_events (위험등급 이벤트)
#   incidents.py         — security_incidents (SIEM 상관분석, Track C guide27)
#   api_access_log.py    — api_access_log (매크로/봇 탐지, Track C guide29)
#   access_requests.py   — access_requests (AI 조기 경보 등 관리자 승인 대기, Track A guide31)
#   lock_history.py      — lock_history (잠금 이력 append-only, guide33 영구 잠금)
#   recovery.py          — recovery_requests, users.email_status (이메일 복구, guide34-a)
#   ip_exemptions.py     — ip_lock_exemptions (IP 영구 잠금 본인 기기 예외, guide34-a)
#   email_tokens.py      — email_tokens (이메일 인증·변경 확인·비밀번호 재설정 링크, guide40)
#
# 이 파일은 위 각 모듈의 함수를 그대로 다시 내보내기(re-export)만 한다 — 그래서
# app.py, routes/, security/, services/, scripts/*.py나 테스트 코드는 예전처럼
# `import db` 후 `db.log_attempt(...)`, `db.create_lockout(...)`처럼 그대로 쓰면 된다.
# 어느 파일이 실제로 그 함수를 담고 있는지는 몰라도 되고, 호출부 코드는 이 분리
# 작업 때문에 단 한 줄도 바뀌지 않았다.
#
# docs/refactor/2026-09-15-file-split.md — 이 분리 작업의 배경과 계획 문서.
# ============================================================================

from ._client import _now_iso, get_client
from .access_logs import (
    count_recent_not_found_attempts,
    count_recent_page_access_attempts,
    count_recent_unauthorized_attempts,
    log_not_found_attempt,
    log_page_access_attempt,
    log_unauthorized_attempt,
)
from .access_requests import (
    count_recent_requests_for_target,
    decide_request,
    get_pending_request,
    get_request,
    insert_pending_request,
    list_pending_requests,
)
from .account_lockouts import (
    create_account_lockout,
    get_account_lockout_row,
    get_active_account_lockout,
    list_active_account_lockouts,
    list_expired_active_account_lockouts,
    promote_account_lockout_permanent,
    release_account_lockout,
    release_permanent_account_lockout,
    set_account_lockout_recoverable,
    set_account_probation,
)
from .admin import (
    count_recent_admin_failures,
    count_recent_distinct_admin_usernames,
    create_admin_user,
    delete_admin_user,
    ensure_bootstrap_admin,
    get_admin_by_id,
    get_admin_id_by_username,
    get_admin_role_by_id,
    list_admin_login_log,
    list_admin_users,
    log_admin_attempt,
    verify_admin_credentials,
)
from .admin_lockouts import (
    count_recent_admin_failures_by_username,
    count_recent_distinct_admin_ips_by_username,
    create_admin_account_lockout,
    get_active_admin_account_lockout,
    list_active_admin_account_lockouts,
    list_expired_active_admin_account_lockouts,
    release_admin_account_lockout,
)
from .api_access_log import count_recent_distinct_api_paths, log_api_access
from .attempts import (
    count_recent_distinct_ips_by_username,
    count_recent_distinct_usernames,
    count_recent_failures,
    count_recent_failures_by_username,
    list_attempts_between,
    list_attempts_by_username,
    list_attempts_since,
    list_recent_attempts,
    log_attempt,
)
from .board import (
    count_recent_comment_attempts,
    count_recent_post_attempts,
    create_comment,
    create_post,
    delete_comment,
    delete_post,
    get_comment,
    get_latest_comment_info,
    get_post,
    list_comments_admin,
    list_comments_by_post,
    list_posts,
    log_comment_attempt,
    log_post_attempt,
    update_post,
)
from .email_tokens import (
    consume_email_token,
    count_email_tokens_by_ip,
    create_email_token,
    get_email_token_activity,
    get_pending_email_token,
    get_pending_email_token_for_user,
    revoke_email_token,
)
from .geoip_cache import get_cached_ip_locations, save_ip_location
from .incidents import (
    close_incident_system,
    get_open_incident,
    get_recent_distinct_event_types,
    list_security_incidents,
    mark_incident_escalated,
    mark_incident_idle,
    record_incident,
    resolve_incident,
)
from .lock_history import count_lock_history, insert_lock_history, mark_lock_released
from .lockouts import (
    create_lockout,
    get_active_lockout,
    get_lockout_row,
    list_active_lockouts,
    list_expired_active_lockouts,
    list_lockouts_between,
    list_lockouts_since,
    promote_lockout_permanent,
    release_lockout,
    release_permanent_lockout,
)
from .ip_exemptions import (
    get_active_ip_exemption,
    insert_ip_exemption,
    list_active_ip_exemptions,
    revoke_ip_exemption,
)
from .recovery import (
    consume_recovery_request,
    count_recovery_requests_by_ip,
    count_recovery_requests_by_user,
    create_recovery_request,
    expire_old_recovery_requests,
    get_email_statuses,
    get_latest_pending_recovery_for_username,
    get_latest_recovery_request_time,
    get_pending_recovery_by_token_hash,
    get_recovery_activity,
    list_recent_recovery_requests,
    reserve_recovery_code_attempt,
    revoke_recovery_request,
    set_user_email_status,
)
from .roles import has_permission, list_role_permissions
from .security_events import (
    ADMIN_ACCOUNT_LOCK_EVENT_TYPE,
    count_security_events,
    delete_all_security_events,
    delete_resolved_security_events,
    delete_security_event,
    get_unresolved_security_event,
    insert_security_event,
    insert_security_event_or_bump,
    list_resolved_critical_events_since,
    list_security_events,
    resolve_security_event,
    resolve_security_events_for_ip,
    resolve_security_events_for_username,
    update_security_event_count,
)
from .settings import (
    count_recent_signup_attempts,
    get_signup_enabled,
    log_signup_attempt,
    set_signup_enabled,
)
from .users import (
    change_user_email,
    create_user,
    delete_user,
    get_user_by_id,
    get_user_by_username,
    get_user_session_version,
    is_email_taken,
    list_users,
    mark_user_email_verified,
    update_user_name,
    update_user_password,
    verify_user_credentials,
)

__all__ = [
    "ADMIN_ACCOUNT_LOCK_EVENT_TYPE",
    "get_client",
    "ensure_bootstrap_admin",
    "verify_admin_credentials",
    "get_admin_by_id",
    "count_recent_admin_failures_by_username",
    "count_recent_distinct_admin_ips_by_username",
    "create_admin_account_lockout",
    "get_active_admin_account_lockout",
    "list_active_admin_account_lockouts",
    "list_expired_active_admin_account_lockouts",
    "release_admin_account_lockout",
    "get_admin_id_by_username",
    "has_permission",
    "list_admin_users",
    "get_admin_role_by_id",
    "create_admin_user",
    "delete_admin_user",
    "count_recent_admin_failures",
    "count_recent_distinct_admin_usernames",
    "log_admin_attempt",
    "list_admin_login_log",
    "log_attempt",
    "count_recent_failures",
    "count_recent_distinct_usernames",
    "count_recent_failures_by_username",
    "count_recent_distinct_ips_by_username",
    "list_recent_attempts",
    "list_attempts_since",
    "list_attempts_between",
    "list_attempts_by_username",
    "create_lockout",
    "get_active_lockout",
    "release_lockout",
    "list_active_lockouts",
    "list_expired_active_lockouts",
    "list_lockouts_since",
    "list_lockouts_between",
    "create_account_lockout",
    "get_active_account_lockout",
    "release_account_lockout",
    "list_active_account_lockouts",
    "list_expired_active_account_lockouts",
    "get_user_by_username",
    "get_user_by_id",
    "create_user",
    "verify_user_credentials",
    "update_user_name",
    "is_email_taken",
    "change_user_email",
    "mark_user_email_verified",
    "create_email_token",
    "get_pending_email_token",
    "get_pending_email_token_for_user",
    "consume_email_token",
    "count_email_tokens_by_ip",
    "revoke_email_token",
    "get_email_token_activity",
    "list_users",
    "delete_user",
    "get_signup_enabled",
    "set_signup_enabled",
    "log_signup_attempt",
    "count_recent_signup_attempts",
    "get_cached_ip_locations",
    "save_ip_location",
    "create_post",
    "get_post",
    "list_posts",
    "update_post",
    "delete_post",
    "create_comment",
    "get_comment",
    "list_comments_by_post",
    "delete_comment",
    "get_latest_comment_info",
    "list_comments_admin",
    "log_post_attempt",
    "count_recent_post_attempts",
    "log_comment_attempt",
    "count_recent_comment_attempts",
    "log_not_found_attempt",
    "count_recent_not_found_attempts",
    "log_unauthorized_attempt",
    "count_recent_unauthorized_attempts",
    "log_page_access_attempt",
    "count_recent_page_access_attempts",
    "insert_security_event",
    "list_security_events",
    "resolve_security_event",
    "resolve_security_events_for_ip",
    "get_unresolved_security_event",
    "update_security_event_count",
    "insert_security_event_or_bump",
    "resolve_security_events_for_username",
    "count_security_events",
    "delete_security_event",
    "delete_resolved_security_events",
    "delete_all_security_events",
    "get_recent_distinct_event_types",
    "get_open_incident",
    "record_incident",
    "resolve_incident",
    "mark_incident_idle",
    "list_security_incidents",
    "mark_incident_escalated",
    "log_api_access",
    "count_recent_distinct_api_paths",
    "list_resolved_critical_events_since",
    "get_pending_request",
    "insert_pending_request",
    "list_pending_requests",
    "get_request",
    "decide_request",
    "count_recent_requests_for_target",
    # 영구 잠금 + 이메일 복구 (guide33 / guide34-a)
    "get_lockout_row",
    "promote_lockout_permanent",
    "release_permanent_lockout",
    "get_account_lockout_row",
    "promote_account_lockout_permanent",
    "release_permanent_account_lockout",
    "set_account_lockout_recoverable",
    "set_account_probation",
    "insert_lock_history",
    "count_lock_history",
    "mark_lock_released",
    "close_incident_system",
    "list_role_permissions",
    "create_recovery_request",
    "get_pending_recovery_by_token_hash",
    "get_latest_pending_recovery_for_username",
    "consume_recovery_request",
    "reserve_recovery_code_attempt",
    "revoke_recovery_request",
    "expire_old_recovery_requests",
    "count_recovery_requests_by_ip",
    "count_recovery_requests_by_user",
    "get_latest_recovery_request_time",
    "get_recovery_activity",
    "list_recent_recovery_requests",
    "insert_ip_exemption",
    "get_active_ip_exemption",
    "revoke_ip_exemption",
    "list_active_ip_exemptions",
    "set_user_email_status",
    "get_email_statuses",
    # 비밀번호 변경 + 세션 무효화 (guide35)
    "get_user_session_version",
    "update_user_password",
]
