"""샘플 로그 도구(scripts/demo/)의 순수 부품과 Supabase 적재·삭제 로직을 점검한다(진짜 DB 없이 메모리 DB로)."""

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "scripts" / "demo"
sys.path.insert(0, str(DEMO))

import demo_data as dd  # noqa: E402
import load_demo_to_supabase as loader  # noqa: E402
from memory_supabase import MemoryClient  # noqa: E402


def test_ip_pool_picks_unique_ips_inside_country_prefixes():
    pool = dd.IpPool(random.Random(1))
    ips = [pool.pick("Germany") for _ in range(50)]
    assert len(set(ips)) == 50
    assert all(ip.startswith("87.150.") for ip in ips)
    assert {pool.country_of[ip] for ip in ips} == {"Germany"}


def test_pick_mixed_uses_different_countries_and_never_south_korea():
    pool = dd.IpPool(random.Random(2))
    ips = pool.pick_mixed(6)
    countries = {pool.country_of[ip] for ip in ips}
    assert len(countries) == 6
    assert "South Korea" not in countries


def test_location_rows_cover_every_picked_ip():
    pool = dd.IpPool(random.Random(3))
    ips = [pool.pick() for _ in range(10)]
    rows = pool.location_rows("2026-10-09T00:00:00+00:00")
    assert {r["ip_address"] for r in rows} == set(ips)
    assert all(r["country"] and r["city"] and r["lookup_failed"] is False for r in rows)


def test_shift_dump_to_now_moves_times_and_days():
    generated = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    dump = {
        "generated_at": generated.isoformat(),
        "tables": {
            "security_events": [{"detected_at": generated.isoformat(), "resolved_at": None, "count": 3}],
            "log_daily_summary": [{"day": "2026-09-30", "hour": 3, "count": 5}],
        },
    }
    now = generated + timedelta(days=4)
    dd.shift_dump_to_now(dump, now)
    assert dump["tables"]["security_events"][0]["detected_at"] == now.isoformat()
    assert dump["tables"]["security_events"][0]["resolved_at"] is None
    assert dump["tables"]["log_daily_summary"][0]["day"] == "2026-10-04"


def test_memory_client_fills_only_real_columns_and_request_id():
    client = MemoryClient()
    client.table("users").insert({"username": "a", "email": "a@example.com", "password_hash": "x"}).execute()
    row = client.table("users").select("*").execute().data[0]
    assert row["email_status"] == "UNKNOWN" and "created_at" in row
    assert "detected_at" not in row and "attempted_at" not in row  # 이 표에 없는 시각 칸은 만들지 않는다
    client.table("access_requests").insert({"event_type": "BRUTE_FORCE"}).execute()
    request = client.table("access_requests").select("*").execute().data[0]
    assert request["request_id"] == 1 and request["status"] == "PENDING"


def test_memory_client_emulates_user_join_and_head_count():
    client = MemoryClient()
    client.table("users").insert({"username": "kim", "email": "k@example.com", "password_hash": "x"}).execute()
    client.table("recovery_requests").insert({"user_id": 1, "status": "PENDING"}).execute()
    row = client.table("recovery_requests").select("id, users(username)").execute().data[0]
    assert row["users"] == {"username": "kim"}
    assert client.table("users").select("*", count="exact", head=True).execute().count == 1


def _dump():
    now = datetime(2026, 10, 9, tzinfo=timezone.utc).isoformat()
    return {
        "generated_at": now,
        "tables": {
            "users": [{"id": 7, "username": "kim", "email": "kim@example.com", "password_hash": "real-hash", "created_at": now}],
            "posts": [{"id": 3, "author_username": "kim", "title": "t", "body": "b", "created_at": now, "updated_at": now}],
            "comments": [{"id": 9, "post_id": 3, "author_username": "kim", "body": "c", "created_at": now}],
            "security_incidents": [{"id": 4, "ip_address": "1.2.3.4", "event_types": ["A"], "severity_max": "HIGH", "status": "OPEN",
                                    "first_event_at": now, "last_event_at": now}],
            "lock_history": [{"id": 1, "target_kind": "ip", "target_value": "1.2.3.4", "lock_type": "TEMPORARY",
                              "trigger_reason": "THRESHOLD", "incident_id": 4, "locked_at": now}],
            "access_requests": [{"request_id": 5, "event_type": "BRUTE_FORCE", "status": "APPROVED", "decided_by_admin_id": 1}],
            "lockouts": [{"ip_address": "1.2.3.4", "locked_at": now, "unlock_at": now, "failure_count": 6, "active": True}],
            "admin_users": [{"id": 1, "username": "demo-admin", "password_hash": "h"}],
        },
    }


def test_load_remaps_foreign_keys_disables_passwords_and_purges(monkeypatch, tmp_path):
    client = MemoryClient()
    monkeypatch.setattr(loader, "MANIFEST", tmp_path / "manifest.json")
    monkeypatch.setenv("SUPABASE_URL", "https://example-project.supabase.co")
    # 이미 운영 데이터가 있다고 가정: 번호가 겹치지 않아야 하고, 지울 때도 건드리면 안 된다
    client.table("users").insert({"username": "real_user", "email": "r@example.com", "password_hash": "keep"}).execute()
    client.table("posts").insert({"author_username": "real_user", "title": "x", "body": "y"}).execute()

    prepared, notes = loader.prepare(_dump(), client, [t for t in loader.ORDER if t not in loader.SKIP_TABLES])
    assert "admin_users" not in prepared and prepared["users"][0]["password_hash"] == loader.DISABLED_HASH
    loader.apply_load(client, _dump(), prepared)

    users = {u["username"]: u for u in client.table("users").select("*").execute().data}
    assert users["kim"]["id"] == 2 and users["kim"]["password_hash"] == loader.DISABLED_HASH
    assert client.table("comments").select("*").execute().data[0]["post_id"] == 2          # 새 글 번호로 이어졌다
    assert client.table("lock_history").select("*").execute().data[0]["incident_id"] == 1  # 새 사건 번호로 이어졌다
    assert client.table("access_requests").select("*").execute().data[0]["decided_by_admin_id"] is None

    loader.purge(client)
    assert [u["username"] for u in client.table("users").select("*").execute().data] == ["real_user"]
    assert len(client.table("posts").select("*").execute().data) == 1
    assert client.table("lockouts").select("*").execute().data == []
    assert not (tmp_path / "manifest.json").exists()


def test_load_stops_when_a_member_already_exists():
    client = MemoryClient()
    client.table("users").insert({"username": "kim", "email": "other@example.com", "password_hash": "keep"}).execute()
    with pytest.raises(SystemExit):
        loader.prepare(_dump(), client, ["users"])
    assert len(client.table("users").select("*").execute().data) == 1
