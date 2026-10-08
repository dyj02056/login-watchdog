# ============================================================================
# test_log_retention.py — 로그 자동 정리(guide44) SQL이 스키마와 맞는지 확인한다
#
# 정리 함수는 Supabase 안(pg_cron)에서만 돌아서 이 테스트들(가짜 DB)로는 실행해 볼 수 없다.
# SQL 자체는 실제 Postgres(PGlite)에 schema.sql을 올려 검증했고, 여기서는 앞으로 바뀔 수 있는
# 부분만 지킨다.
#   - 정리 대상 표·날짜 칸이 schema.sql에 실제로 있는지(이름이 틀리면 매일 밤 조용히 실패한다)
#   - schema.sql의 모든 표가 "정리한다" 또는 "지우지 않는다" 중 하나로 분류돼 있는지
#     (새 기록 표를 만들고 정리 대상에 넣는 것을 잊지 않게)
#   - 마이그레이션 파일과 schema.sql의 내용이 같은지
# ============================================================================

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = (ROOT / "docs" / "schema.sql").read_text(encoding="utf-8")
MIGRATION = (ROOT / "docs" / "migrations" / "guide44_log_retention.sql").read_text(encoding="utf-8")

# 정리 대상: 표 → 요약 날짜로 쓰는 칸
CLEANED = {
    "page_access_attempts": "attempted_at",
    "not_found_attempts": "attempted_at",
    "unauthorized_attempts": "attempted_at",
    "signup_attempts": "attempted_at",
    "post_attempts": "attempted_at",
    "comment_attempts": "attempted_at",
    "api_access_log": "requested_at",
    "login_attempts": "attempted_at",
    "admin_login_log": "attempted_at",
    "security_events": "detected_at",
    "security_incidents": "first_event_at",
    "access_requests": "requested_at",
    "email_tokens": "created_at",
    "recovery_requests": "created_at",
    "ip_locations": "looked_up_at",
}

# 현재 상태·감사 기록이라 지우지 않는 표
KEPT = {
    "users", "admin_users", "lockouts", "account_lockouts", "admin_account_lockouts",
    "lock_history", "ip_lock_exemptions", "posts", "comments", "app_settings",
    "roles", "permissions", "log_daily_summary",
}


def _tables_in_schema() -> set[str]:
    return set(re.findall(r"^create table (?:if not exists )?(\w+)", SCHEMA, re.MULTILINE))


def _columns_of(table: str) -> set[str]:
    """create table 본문의 칸 + 나중에 alter table ... add column으로 추가된 칸."""
    body = re.search(rf"^create table (?:if not exists )?{table} \((.*?)^\);", SCHEMA, re.MULTILINE | re.DOTALL)
    assert body, f"schema.sql에 {table} 표가 없다"
    columns = set(re.findall(r"^\s+(\w+)\s", body.group(1), re.MULTILINE))
    columns |= set(re.findall(rf"alter table {table} add column (?:if not exists )?(\w+)", SCHEMA))
    return columns


def test_every_table_is_either_cleaned_or_explicitly_kept():
    tables = _tables_in_schema()
    assert tables == set(CLEANED) | KEPT, (
        f"분류되지 않은 표: {tables - set(CLEANED) - KEPT}, 없어진 표: {(set(CLEANED) | KEPT) - tables}"
    )


def test_cleaned_tables_and_their_time_columns_exist():
    for table, time_column in CLEANED.items():
        assert time_column in _columns_of(table), f"{table}.{time_column}"


def test_migration_cleans_exactly_the_listed_tables():
    called = set(re.findall(r"_cleanup_log_table\('(\w+)', '(\w+)'", MIGRATION))
    looped = set()
    for array in re.findall(r"foreach t in array array\[(.*?)\]", MIGRATION, re.DOTALL):
        looped |= set(re.findall(r"'(\w+)'", array))
    # foreach 반복문 안의 표는 모두 _cleanup_log_table(t, 'attempted_at', ...)으로 부른다
    assert re.findall(r"_cleanup_log_table\(t, '(\w+)'", MIGRATION) == ["attempted_at", "attempted_at"]

    cleaned = {table for table, _ in called} | looped
    assert cleaned == set(CLEANED)
    for table, column in called:
        assert CLEANED[table] == column, table
    for table in looped:
        assert CLEANED[table] == "attempted_at", table


def test_columns_used_in_conditions_exist():
    # 조건·종류 식에 쓰인 칸들 — 이름이 틀리면 그 표만이 아니라 정리 전체가 멈춘다
    used = {
        "security_events": {"resolved_at", "event_type"},
        "security_incidents": {"status", "resolved_at", "last_event_at", "severity_max"},
        "access_requests": {"status", "decided_at", "event_type"},
        "email_tokens": {"status", "expires_at", "purpose"},
        "recovery_requests": {"status", "expires_at", "target_kind"},
        "login_attempts": {"success"},
        "admin_login_log": {"success"},
        "api_access_log": {"method"},
    }
    for table, columns in used.items():
        assert columns <= _columns_of(table), f"{table}: {columns - _columns_of(table)}"


def test_pending_and_unresolved_rows_are_never_targets():
    assert "resolved_at is not null" in MIGRATION                       # 처리 전 이벤트는 남긴다
    assert "status = ''CLOSED''" in MIGRATION                           # 진행 중인 사건은 남긴다
    assert MIGRATION.count("status <> ''PENDING''") == 3                # 승인 요청·메일 링크 2종


def test_functions_are_not_callable_with_site_keys():
    assert re.search(r"revoke all on function cleanup_old_logs\(boolean\) from public, anon, authenticated", MIGRATION)
    assert re.search(r"revoke all on function _cleanup_log_table\(.*?\)\s+from public, anon, authenticated", MIGRATION)


def test_schema_sql_contains_the_migration():
    assert MIGRATION.strip() in SCHEMA
