# ============================================================================
# tests/track_d/test_c_netblock.py — L4 차단/해제 요청(request_block, request_unblock) 단위 테스트
# ============================================================================

from datetime import datetime, timezone
import pytest

import config
from security import netblock


def test_request_block_rejects_allowlisted_ip(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: True)
    assert netblock.request_block("127.0.0.1", "NET_FLOOD", "SPOOFABLE") is False


def test_request_block_rejects_ipv6(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    assert netblock.request_block("2001:db8::1", "NET_FLOOD", "SPOOFABLE") is False


def test_request_block_rejects_subnet_mask(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    assert netblock.request_block("192.168.1.0/24", "NET_FLOOD", "SPOOFABLE") is False


def test_request_block_spoofable_default_ttl(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)

    mock_db = {}
    monkeypatch.setattr("db.get_network_block", lambda ip: mock_db.get(ip), raising=False)
    
    inserted_rows = []
    def fake_insert(row):
        mock_db[row["ip_address"]] = row
        inserted_rows.append(row)
        return True

    monkeypatch.setattr("db.insert_network_block", fake_insert, raising=False)
    monkeypatch.setattr("db.count_recent_net_blocked_events", lambda ip, since_iso: 0, raising=False)

    res = netblock.request_block("10.0.0.1", "NET_FLOOD", "SPOOFABLE")
    assert res is True
    assert len(inserted_rows) == 1
    row = inserted_rows[0]
    assert row["status"] == "PENDING_APPLY"
    assert row["expires_at"] is not None


def test_request_block_spoofable_exponential_backoff(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)

    # 과거 1회 차단 이력 -> TTL 2배 (7200s)
    monkeypatch.setattr("db.get_network_block", lambda ip: None, raising=False)
    inserted_rows = []
    monkeypatch.setattr("db.insert_network_block", lambda row: inserted_rows.append(row) or True, raising=False)
    monkeypatch.setattr("db.count_recent_net_blocked_events", lambda ip, since_iso: 1, raising=False)

    netblock.request_block("10.0.0.2", "NET_FLOOD", "SPOOFABLE")
    assert len(inserted_rows) == 1
    exp_dt1 = datetime.fromisoformat(inserted_rows[0]["expires_at"])

    # 과거 3회 차단 이력 -> 계산치 28800s이나 MAX_TTL(21600s) 상한 적용
    inserted_rows.clear()
    monkeypatch.setattr("db.count_recent_net_blocked_events", lambda ip, since_iso: 3, raising=False)

    netblock.request_block("10.0.0.3", "NET_FLOOD", "SPOOFABLE")
    assert len(inserted_rows) == 1
    exp_dt2 = datetime.fromisoformat(inserted_rows[0]["expires_at"])
    
    # 21600초 근처인지 검증
    req_at = datetime.fromisoformat(inserted_rows[0]["requested_at"])
    diff = (exp_dt2 - req_at).total_seconds()
    assert abs(diff - config.NET_BLOCK_MAX_TTL_SECONDS) < 5


def test_request_block_connected_permanent(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    monkeypatch.setattr("db.get_network_block", lambda ip: None, raising=False)
    inserted_rows = []
    monkeypatch.setattr("db.insert_network_block", lambda row: inserted_rows.append(row) or True, raising=False)

    res = netblock.request_block("10.0.0.4", "KILL_CHAIN", "CONNECTED")
    assert res is True
    assert inserted_rows[0]["expires_at"] is None


def test_request_block_idempotent_if_not_stronger(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)

    existing = {
        "ip_address": "10.0.0.5",
        "status": "APPLIED",
        "reason": "NET_FLOOD",
        "evidence": "CONNECTED",
        "expires_at": None,
    }
    monkeypatch.setattr("db.get_network_block", lambda ip: existing, raising=False)

    # 이미 영구 차단인 상태에서 만료 시간이 지정된 약한 요청 시도 -> False
    res = netblock.request_block("10.0.0.5", "NET_FLOOD", "SPOOFABLE", ttl_seconds=3600)
    assert res is False


def test_request_block_updates_when_stronger(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)

    existing = {
        "ip_address": "10.0.0.6",
        "status": "APPLIED",
        "reason": "NET_FLOOD",
        "evidence": "SPOOFABLE",
        "expires_at": "2026-10-19T10:00:00+00:00",
    }
    monkeypatch.setattr("db.get_network_block", lambda ip: existing, raising=False)

    updated = []
    def fake_update(ip, from_statuses, fields):
        updated.append(fields)
        return True

    monkeypatch.setattr("db.update_network_block_if_status", fake_update, raising=False)

    # 더 늦게 만료되는 영구 요청(CONNECTED)으로 갱신
    res = netblock.request_block("10.0.0.6", "KILL_CHAIN", "CONNECTED")
    assert res is True
    assert len(updated) == 1
    assert updated[0]["status"] == "PENDING_APPLY"
    assert updated[0]["evidence"] == "CONNECTED"


def test_request_block_reuses_removed_row(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)

    existing = {
        "ip_address": "10.0.0.7",
        "status": "REMOVED",
        "reason": "NET_FLOOD",
        "evidence": "SPOOFABLE",
        "expires_at": "2026-10-19T00:00:00+00:00",
    }
    monkeypatch.setattr("db.get_network_block", lambda ip: existing, raising=False)

    updated = []
    monkeypatch.setattr("db.update_network_block_if_status", lambda ip, st, f: updated.append(f) or True, raising=False)

    res = netblock.request_block("10.0.0.7", "ADMIN_MANUAL", "CONNECTED")
    assert res is True
    assert len(updated) == 1
    assert updated[0]["status"] == "PENDING_APPLY"


def test_request_unblock_success_and_failure(monkeypatch):
    monkeypatch.setattr("db.update_network_block_if_status", lambda ip, st, f: True if ip == "10.0.0.8" else False, raising=False)

    assert netblock.request_unblock("10.0.0.8", "admin:alice") is True
    assert netblock.request_unblock("10.0.0.9", "admin:alice") is False
    assert netblock.request_unblock("invalid_ip", "admin:alice") is False


# ---------------------------------------------------------------------------
# 보강: 시각 표기 차이·잘못된 TTL·알 수 없는 상태
# ---------------------------------------------------------------------------

def _fix_now(monkeypatch, iso):
    """netblock의 '지금' 시각을 고정한다(만료 비교를 결정적으로 만들기 위해)."""
    fixed = datetime.fromisoformat(iso)
    monkeypatch.setattr(netblock, "_now_utc", lambda: fixed)


def test_request_block_compares_expiry_as_time_not_string(monkeypatch):
    """기존 만료가 더 늦은데 표기(시간대) 때문에 문자열로는 더 일러 보이는 경우, 갱신하지 않는다."""
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    _fix_now(monkeypatch, "2026-10-19T10:00:00+00:00")
    existing = {
        "ip_address": "10.0.1.1",
        "status": "APPLIED",
        "evidence": "SPOOFABLE",
        # 11:30 UTC를 -05:00 표기로 적은 값. 문자열로는 "T06:30"이라 새 만료("T11:00")보다 작아 보인다.
        "expires_at": "2026-10-19T06:30:00-05:00",
    }
    monkeypatch.setattr("db.get_network_block", lambda ip: existing, raising=False)
    updated = []
    monkeypatch.setattr("db.update_network_block_if_status", lambda ip, st, f: updated.append(f) or True, raising=False)

    # 새 만료 = 10:00 + 3600초 = 11:00 UTC → 실제로는 기존(11:30 UTC)보다 이르므로 더 약한 요청이다.
    res = netblock.request_block("10.0.1.1", "NET_FLOOD", "SPOOFABLE", ttl_seconds=3600)
    assert res is False
    assert updated == []


def test_request_block_unparsable_existing_expiry_is_replaced(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    existing = {"ip_address": "10.0.1.2", "status": "APPLIED", "evidence": "SPOOFABLE", "expires_at": "broken"}
    monkeypatch.setattr("db.get_network_block", lambda ip: existing, raising=False)
    updated = []
    monkeypatch.setattr("db.update_network_block_if_status", lambda ip, st, f: updated.append((st, f)) or True, raising=False)

    assert netblock.request_block("10.0.1.2", "NET_FLOOD", "SPOOFABLE", ttl_seconds=600) is True
    assert updated[0][0] == ["APPLIED"]


def test_request_block_rejects_zero_and_non_int_ttl(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    assert netblock.request_block("10.0.1.3", "NET_FLOOD", "SPOOFABLE", ttl_seconds=0) is False
    assert netblock.request_block("10.0.1.3", "NET_FLOOD", "SPOOFABLE", ttl_seconds="3600") is False
    assert netblock.request_block("10.0.1.3", "NET_FLOOD", "SPOOFABLE", ttl_seconds=True) is False


def test_request_block_rejects_unknown_reason_and_evidence(monkeypatch):
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    assert netblock.request_block("10.0.1.4", "SOMETHING", "SPOOFABLE") is False
    assert netblock.request_block("10.0.1.4", "NET_FLOOD", "MAYBE") is False


def test_request_block_retries_read_after_insert_conflict(monkeypatch):
    """동시 요청으로 insert가 실패하면 다시 읽어 일반 규칙(더 강할 때만 갱신)으로 처리한다."""
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    reads = iter([None, {"ip_address": "10.0.1.5", "status": "PENDING_APPLY", "evidence": "CONNECTED", "expires_at": None}])
    monkeypatch.setattr("db.get_network_block", lambda ip: next(reads), raising=False)
    monkeypatch.setattr("db.insert_network_block", lambda row: False, raising=False)
    monkeypatch.setattr("db.count_recent_net_blocked_events", lambda ip, since_iso: 0, raising=False)

    # 다른 요청이 먼저 영구 차단을 넣었으므로 TTL 요청은 더 약하다 → False
    assert netblock.request_block("10.0.1.5", "NET_FLOOD", "SPOOFABLE") is False


def test_request_block_spoofable_never_permanent_even_when_existing_connected(monkeypatch):
    """SPOOFABLE + ttl None 요청은 새 행으로 들어갈 때 expires_at이 항상 있다(영구 금지)."""
    monkeypatch.setattr("security.lockdown.is_ip_allowlisted", lambda ip: False)
    monkeypatch.setattr("db.get_network_block", lambda ip: None, raising=False)
    rows = []
    monkeypatch.setattr("db.insert_network_block", lambda row: rows.append(row) or True, raising=False)
    monkeypatch.setattr("db.count_recent_net_blocked_events", lambda ip, since_iso: 10, raising=False)

    assert netblock.request_block("10.0.1.6", "NET_FLOOD", "SPOOFABLE") is True
    assert rows[0]["expires_at"] is not None
