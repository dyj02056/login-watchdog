# ============================================================================
# db/__init__.py — 데이터베이스(Supabase)와 대화하는 유일한 창구
#
# 이 프로그램의 다른 파일(detector.py, soar.py, app.py 등)은 데이터베이스에
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
#   admin.py            — admin_users, admin_login_log (관리자 계정/로그인 기록)
#   users.py            — users (회원 계정)
#   settings.py         — app_settings, signup_attempts (설정값, 가입 빈도 제한)
#   geoip_cache.py       — ip_locations (IP 위치 조회 캐시)
#   board.py            — posts, comments, post_attempts, comment_attempts (게시판)
#   security_events.py  — not_found/unauthorized/page_access_attempts, security_events
#
# 이 파일은 위 각 모듈의 함수를 그대로 다시 내보내기(re-export)만 한다 — 그래서
# app.py/detector.py/soar.py/scripts/*.py나 테스트 코드는 예전처럼
# `import db` 후 `db.log_attempt(...)`, `db.create_lockout(...)`처럼 그대로 쓰면 된다.
# 어느 파일이 실제로 그 함수를 담고 있는지는 몰라도 되고, 호출부 코드는 이 분리
# 작업 때문에 단 한 줄도 바뀌지 않았다.
#
# docs/refactor/2026-09-15-file-split.md — 이 분리 작업의 배경과 계획 문서.
# ============================================================================

from ._client import _now_iso, get_client
from .account_lockouts import (
    create_account_lockout,
    get_active_account_lockout,
    list_active_account_lockouts,
    list_expired_active_account_lockouts,
    release_account_lockout,
)
from .admin import (
    count_recent_admin_failures,
    count_recent_distinct_admin_usernames,
    create_admin_user,
    delete_admin_user,
    ensure_bootstrap_admin,
    get_admin_role,
    get_admin_role_by_id,
    list_admin_login_log,
    list_admin_users,
    log_admin_attempt,
    verify_admin_credentials,
)
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
from .geoip_cache import get_cached_ip_locations, save_ip_location
from .roles import has_permission
from .lockouts import (
    create_lockout,
    get_active_lockout,
    list_active_lockouts,
    list_expired_active_lockouts,
    list_lockouts_between,
    list_lockouts_since,
    release_lockout,
)
from .security_events import (
    count_recent_not_found_attempts,
    count_recent_page_access_attempts,
    count_recent_unauthorized_attempts,
    count_security_events,
    delete_all_security_events,
    delete_resolved_security_events,
    delete_security_event,
    get_unresolved_security_event,
    insert_security_event,
    insert_security_event_or_bump,
    list_security_events,
    log_not_found_attempt,
    log_page_access_attempt,
    log_unauthorized_attempt,
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
    create_user,
    delete_user,
    get_user_by_id,
    get_user_by_username,
    list_users,
    update_user_profile,
    verify_user_credentials,
)

__all__ = [
    "get_client",
    "ensure_bootstrap_admin",
    "verify_admin_credentials",
    "get_admin_role",
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
    "update_user_profile",
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
]
