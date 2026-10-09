# ============================================================================
# test_daily_log_summary.py — 매일 어제 하루치를 요약하는 방식(guide47) SQL이 스키마와 맞는지 확인한다
#
# 요약·정리 함수는 Supabase 안(pg_cron)에서만 돌아서 이 테스트들로는 실행해 볼 수 없다. SQL 자체는
# 실제 Postgres(PGlite)에 schema.sql을 올려 검증했다(시간대 경계, 상위 5개 + 그 외, 다시 요약해도
# 같은 결과, 밀린 날 채우기, 요약 전 원본 보호, 권한). 여기서는 앞으로 바뀔 수 있는 부분을 지킨다.
# ============================================================================

import re
from pathlib import Path

from tests.test_log_retention import CLEANED, SCHEMA, _columns_of

ROOT = Path(__file__).resolve().parent.parent
MIGRATION = (ROOT / "docs" / "migrations" / "guide47_daily_log_summary.sql").read_text(encoding="utf-8")

# 요약 대상: 표 → (날짜 칸, 종류 식에 쓰는 칸, IP 칸, 주소 칸, 로그인 기록 여부)
SUMMARIZED = {
    "login_attempts": ("attempted_at", {"success"}, "ip_address", None, True),
    "admin_login_log": ("attempted_at", {"success"}, "ip_address", None, True),
    "page_access_attempts": ("attempted_at", set(), "ip_address", "path", False),
    "not_found_attempts": ("attempted_at", set(), "ip_address", "path", False),
    "unauthorized_attempts": ("attempted_at", set(), "ip_address", "path", False),
    "signup_attempts": ("attempted_at", set(), "ip_address", None, False),
    "post_attempts": ("attempted_at", set(), "ip_address", None, False),
    "comment_attempts": ("attempted_at", set(), "ip_address", None, False),
    "api_access_log": ("requested_at", {"method"}, "ip_address", "path", False),
    "security_events": ("detected_at", {"event_type"}, "ip_address", "path", False),
    "security_incidents": ("first_event_at", {"severity_max"}, "ip_address", None, False),
    "access_requests": ("requested_at", {"event_type"}, None, None, False),
    "email_tokens": ("created_at", {"purpose"}, None, None, False),
    "recovery_requests": ("created_at", {"target_kind"}, None, None, False),
}


def test_every_cleaned_log_table_is_summarized_before_it_is_deleted():
    # 위치 캐시(ip_locations)만 요약 없이 지운다 — 기록이 아니라 조회 결과 저장소라서.
    assert set(SUMMARIZED) == set(CLEANED) - {"ip_locations"}


def test_summary_calls_match_the_listed_tables_and_columns():
    calls = re.findall(r"_summarize_log_source\(p_day, '(\w+)', '(\w+)'", MIGRATION)
    looped = {}
    for array, time_col in re.findall(
        r"foreach t in array array\[(.*?)\] loop.*?_summarize_log_source\(p_day, t, '(\w+)'", MIGRATION, re.DOTALL
    ):
        for table in re.findall(r"'(\w+)'", array):
            looped[table] = time_col
    called = dict(calls) | looped
    assert set(called) == set(SUMMARIZED)
    for table, time_col in called.items():
        assert SUMMARIZED[table][0] == time_col, table


def test_every_column_used_by_the_summary_exists():
    for table, (time_col, category_cols, ip_col, path_col, is_login) in SUMMARIZED.items():
        needed = {time_col} | category_cols | {c for c in (ip_col, path_col) if c}
        if is_login:
            needed |= {"username", "success", "ip_address"}   # 실패한 아이디 수, 나라(ip_locations와 연결)
        assert needed <= _columns_of(table), f"{table}: {needed - _columns_of(table)}"
    assert {"ip_address", "country"} <= _columns_of("ip_locations")


def test_only_counts_are_kept_never_ips_or_usernames():
    # 요약표 칸은 날짜·시간대·표·종류·항목·값·건수뿐이다.
    # (_columns_of는 "primary key (…)", "check (…)" 줄의 첫 단어도 칸으로 읽으므로 뺀다)
    assert _columns_of("log_daily_summary") - {"primary", "check"} == {"day", "source", "category", "count", "hour"}
    assert _columns_of("log_daily_breakdown") - {"primary", "check"} == {"day", "source", "dimension", "value", "count"}
    # 하루 상세의 값으로 들어가는 것은 주소·나라 이름뿐 — IP·아이디는 count(distinct …)로 숫자만.
    assert "count(distinct username)" in MIGRATION
    assert "count(distinct %I)" in MIGRATION
    assert not re.search(r"'distinct_ips', \w+", MIGRATION)


def test_country_and_username_counts_are_only_for_login_tables():
    # 위치는 로그인 기록의 IP만 조회해 두므로, 다른 기록의 나라는 대부분 "알 수 없음"이 된다.
    login_tables = {t for t, spec in SUMMARIZED.items() if spec[4]}
    assert login_tables == {"login_attempts", "admin_login_log"}
    assert len(re.findall(r", true\);", MIGRATION)) == 1               # p_login=true는 로그인 2종의 반복문 하나
    login_block = MIGRATION[MIGRATION.index("  if p_login then"):MIGRATION.index("  return n;")]
    for dimension in ("'failed_usernames', ''", "'country', coalesce"):
        assert MIGRATION.count(dimension) == 1 and dimension in login_block


def test_rows_are_never_deleted_before_they_are_summarized():
    assert "safe_until := case when last_day is null then '-infinity'::timestamptz" in MIGRATION
    for name in ("raw_cutoff", "login_cutoff", "done_cutoff", "token_cutoff"):
        assert re.search(rf"{name} *:= least\(now\(\) - interval '\d+ days', safe_until\)", MIGRATION), name


def test_daily_job_summarizes_then_deletes():
    body = MIGRATION[MIGRATION.index("create or replace function run_daily_log_maintenance()"):]
    assert body.index("perform summarize_pending_log_days();") < body.index("perform cleanup_old_logs(false);")
    assert "select cron.unschedule(jobid) from cron.job where jobname = 'cleanup-old-logs';" in MIGRATION
    assert "'daily-log-maintenance'" in MIGRATION and "'0 18 * * *'" in MIGRATION


def test_functions_are_not_callable_with_site_keys():
    functions = re.findall(r"create or replace function (\w+)\(", MIGRATION)
    for name in functions:
        assert re.search(rf"revoke all on function {name}\(.*?\) from public, anon, authenticated;", MIGRATION), name


def test_schema_sql_contains_the_migration():
    assert MIGRATION.strip() in SCHEMA
