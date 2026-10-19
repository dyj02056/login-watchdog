"""guide52 SQL의 핵심 멱등 조건과 스키마 반영 누락을 문자열 수준에서 검출한다."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent
MIGRATION = (ROOT / "docs" / "migrations" / "guide52_track_d.sql").read_text(encoding="utf-8")
SCHEMA = (ROOT / "docs" / "schema.sql").read_text(encoding="utf-8")
TABLES = {
    "network_events",
    "network_blocks",
    "agent_heartbeats",
    "notification_cooldowns",
    "playbook_runs",
}




def test_track_d_tables_are_created_idempotently():
    for table in TABLES:
        assert f"create table if not exists {table}" in MIGRATION


def test_track_d_indexes_and_columns_use_if_not_exists():
    assert "create index " not in MIGRATION.replace("create index if not exists", "")
    assert "add column " not in MIGRATION.replace("add column if not exists", "")


def test_existing_incidents_are_backfilled():
    assert "update security_incidents set app_severity_max = severity_max where app_severity_max is null;" in MIGRATION


def test_schema_contains_the_track_d_migration():
    # schema 구역은 제목만 다르고 실제 SQL 본문은 마이그레이션과 같아야 한다.
    sql_body = MIGRATION[MIGRATION.index("create table if not exists network_events"):]
    assert sql_body.strip() in SCHEMA
