"""guide53의 보존 조건과 guide47의 기존 정리 동작을 SQL 문자열로 확인한다."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = (ROOT / "docs/migrations/guide53_track_d_retention.sql").read_text(encoding="utf-8")
SCHEMA = (ROOT / "docs/schema.sql").read_text(encoding="utf-8")
GUIDE47 = (ROOT / "docs/migrations/guide47_daily_log_summary.sql").read_text(encoding="utf-8")


def _function(sql: str) -> str:
    match = re.search(
        r"create or replace function cleanup_old_logs\(dry_run boolean default false\).*?^\$\$;",
        sql,
        re.MULTILINE | re.DOTALL,
    )
    assert match, "cleanup_old_logs 정의가 없다"
    return match.group()


def _cleanup_call(table: str) -> str:
    match = re.search(
        rf"log_table := '{table}';\s*deleted_rows := _delete_old_log_rows\('{table}',\s*"
        r"'((?:[^']|'')*)',\s*(.*?), dry_run\);\s*return next;",
        _function(MIGRATION),
    )
    assert match, f"{table} 삭제 호출이 없다"
    return match.group(1), match.group(2)


def test_guide47_cleanup_body_is_preserved():
    old = _function(GUIDE47)
    new = _function(MIGRATION)
    assert new.startswith(old[: old.rfind("end;\n$$;")])
    assert new.endswith("end;\n$$;")


def test_track_d_retention_periods_and_columns():
    assert _cleanup_call("network_events") == ("observed_at < $1", "now() - interval '7 days'")
    assert _cleanup_call("playbook_runs") == ("ran_at < $1", "now() - interval '90 days'")
    condition, cutoff = _cleanup_call("network_blocks")
    assert cutoff == "now() - interval '30 days'"
    assert condition == (
        "(status = ''REMOVED'' and coalesce(removed_at, requested_at) < $1) "
        "or (status = ''FAILED'' and requested_at < $1)"
    )
    assert all(status not in condition for status in ("PENDING_APPLY", "APPLIED", "PENDING_REMOVE"))


def test_dry_run_and_access_controls_remain():
    assert "returns table (log_table text, deleted_rows bigint)" in _function(MIGRATION)
    assert "revoke all on function cleanup_old_logs(boolean) from public, anon, authenticated;" in MIGRATION
    assert "create table" not in MIGRATION.lower()
    assert "alter table" not in MIGRATION.lower()
    assert "cron.schedule" not in MIGRATION.lower()


def test_schema_contains_guide53():
    assert "-- Track D 보존 (guide53)" in SCHEMA
    assert MIGRATION.strip() in SCHEMA
