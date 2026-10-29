"""TTL 차단이 끝난 뒤에도 공격이 이어지면 같은 사건 안에서 다시 차단을 요청하는지 검증한다.

센서는 iptables보다 앞(AF_PACKET)에서 패킷을 보므로 차단 중에도 경보가 계속 들어오고, 사건의
last_event_at이 계속 갱신돼 IDLE이 되지 않는다. 그래서 "이미 실행한 규칙" 분기에서도 TTL이 끝난
차단은 다시 걸어야 한다. 관리자가 직접 푼 차단과 영구 차단 규칙(CR-01)은 다시 막지 않는다.
DB·플레이북은 모두 가짜로 바꿔 실제 DB에 접속하지 않는다.
"""

from datetime import datetime, timedelta, timezone

import db
from security import correlate, playbooks


IP = "172.28.12.103"
# 가짜로 바꾸기 전의 진짜 플레이북 실행기 — 마지막 테스트가 request_block까지 끝까지 돌려 본다.
_real_run = playbooks.run


def _iso(minutes_from_now):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes_from_now)).isoformat()


def _install(monkeypatch, block_row, matched_rules=("NET-01",)):
    """열린 사건(IDLE 아님, 규칙 이미 기록)과 network_blocks 행 하나를 가짜로 둔다."""
    state = {"runs": []}
    incident = {
        "id": 41, "event_types": ["NET_BLOCKED", "NET_SYN_FLOOD"], "severity_max": "CRITICAL",
        "app_severity_max": None, "matched_rules": list(matched_rules), "escalated": False,
        "last_event_at": _iso(-1),
    }
    monkeypatch.setattr(db, "get_open_incident", lambda ip: incident)
    monkeypatch.setattr(db, "get_network_block", lambda ip: block_row, raising=False)
    # 첫 실행의 차단 단계는 성공(OK)으로 남아 있다 — 실패 단계 재실행 경로로는 다시 돌지 않는 상황.
    monkeypatch.setattr(
        db, "list_playbook_runs",
        lambda trigger_ref: [{"step": "block_l4_ttl", "status": "OK"}, {"step": "notify_slack", "status": "OK"}],
        raising=False,
    )
    monkeypatch.setattr(
        db, "list_recent_security_events_for_correlation", lambda ip, minutes: [], raising=False
    )

    def fake_run(name, trigger_ref, ctx, only_steps=None):
        state["runs"].append((name, trigger_ref, only_steps))
        return []

    monkeypatch.setattr(playbooks, "run", fake_run)
    return state


def test_reblocks_when_ttl_block_expired_and_removed(monkeypatch):
    # 지연 만료가 REMOVED로 바꾼 행: removed_at이 expires_at 이후다.
    row = {"ip_address": IP, "status": "REMOVED", "expires_at": _iso(-10), "removed_at": _iso(-9)}
    state = _install(monkeypatch, row)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert state["runs"] == [("NET_FLOOD_TTL", "incident:41:NET-01", ["block_l4_ttl"])]


def test_reblocks_when_active_row_is_past_expiry(monkeypatch):
    # 다음 경보가 fw-agent 폴링보다 먼저 오면 행은 아직 APPLIED다. 커널은 이미 풀었으므로 다시 막되,
    # 지연 만료와 똑같이 먼저 REMOVED로 바꾸고 NET_BLOCKED를 해결해야 TTL 2배가 이어진다(10/29 실측).
    row = {"ip_address": IP, "status": "APPLIED", "expires_at": _iso(-1), "removed_at": None, "version": 4}
    state = _install(monkeypatch, row)
    updates, resolved = [], []
    monkeypatch.setattr(
        db, "update_network_block_if_status",
        lambda ip, statuses, fields, expected_version=None:
            updates.append((statuses, fields["status"], expected_version)) or True,
        raising=False,
    )
    monkeypatch.setattr(db, "resolve_net_blocked_events", resolved.append, raising=False)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert updates == [(["APPLIED"], "REMOVED", 4)]
    assert resolved == [IP]
    assert state["runs"] == [("NET_FLOOD_TTL", "incident:41:NET-01", ["block_l4_ttl"])]


def test_active_expired_row_changed_concurrently_is_not_reblocked(monkeypatch):
    # 정리하려는 순간 다른 요청이 이미 다시 막았으면(PENDING_APPLY) 또 요청하지 않는다.
    rows = iter([
        {"ip_address": IP, "status": "APPLIED", "expires_at": _iso(-1), "removed_at": None, "version": 4},
        {"ip_address": IP, "status": "PENDING_APPLY", "expires_at": _iso(2), "removed_at": None, "version": 5},
    ])
    state = _install(monkeypatch, None)
    monkeypatch.setattr(db, "get_network_block", lambda ip: next(rows), raising=False)
    monkeypatch.setattr(
        db, "update_network_block_if_status",
        lambda ip, statuses, fields, expected_version=None: False, raising=False,
    )
    monkeypatch.setattr(db, "resolve_net_blocked_events", lambda ip: None, raising=False)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert state["runs"] == []


def test_active_expired_row_already_expired_by_poll_is_reblocked(monkeypatch):
    # 정리하려는 순간 지연 만료(GET /blocks)가 먼저 REMOVED로 바꿨다면 그쪽이 NET_BLOCKED를 해결했으니 그대로 다시 막는다.
    rows = iter([
        {"ip_address": IP, "status": "APPLIED", "expires_at": _iso(-1), "removed_at": None, "version": 4},
        {"ip_address": IP, "status": "REMOVED", "expires_at": _iso(-1), "removed_at": _iso(0), "version": 4},
    ])
    state = _install(monkeypatch, None)
    monkeypatch.setattr(db, "get_network_block", lambda ip: next(rows), raising=False)
    monkeypatch.setattr(
        db, "update_network_block_if_status",
        lambda ip, statuses, fields, expected_version=None: False, raising=False,
    )

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert state["runs"] == [("NET_FLOOD_TTL", "incident:41:NET-01", ["block_l4_ttl"])]


def test_does_not_reblock_while_block_is_active(monkeypatch):
    row = {"ip_address": IP, "status": "APPLIED", "expires_at": _iso(30), "removed_at": None}
    state = _install(monkeypatch, row)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert state["runs"] == []


def test_does_not_reblock_after_admin_release(monkeypatch):
    # 관리자가 만료 전에 푼 차단(removed_at < expires_at)은 관리자 판단을 존중해 다시 막지 않는다.
    row = {"ip_address": IP, "status": "REMOVED", "expires_at": _iso(30), "removed_at": _iso(-2)}
    state = _install(monkeypatch, row)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert state["runs"] == []


def test_does_not_reblock_when_no_block_row(monkeypatch):
    # 행이 없으면 처음부터 차단이 거절된 IP(허용 목록 등)일 수 있어, 경보마다 같은 거절을 반복하지 않는다.
    state = _install(monkeypatch, None)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert state["runs"] == []


def test_does_not_reblock_when_block_lookup_fails(monkeypatch):
    state = _install(monkeypatch, None)

    def broken(ip):
        raise RuntimeError("db down")

    monkeypatch.setattr(db, "get_network_block", broken, raising=False)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert state["runs"] == []


def test_kill_chain_rule_is_not_reblocked(monkeypatch):
    # CR-01은 영구 차단 규칙이라 TTL로 끝나지 않는다. 풀렸다면 관리자가 푼 것이다.
    row = {"ip_address": IP, "status": "REMOVED", "expires_at": _iso(-10), "removed_at": _iso(-9)}
    state = _install(monkeypatch, row, matched_rules=("CR-01",))
    monkeypatch.setattr(
        correlate, "_match_cross_layer_rule",
        lambda ip, event_type, rule: [{"event_type": "NET_PORT_SCAN", "severity": "MEDIUM"}]
        if rule["id"] == "CR-01" else [],
    )

    correlate.check_cross_layer(IP, "BRUTE_FORCE")

    assert state["runs"] == []


def test_reblock_doubles_ttl_through_request_block(monkeypatch):
    # 다시 막을 때 request_block이 실제 적용 횟수(NET_BLOCKED)만큼 TTL을 2배로 늘리는지 끝까지 확인한다.
    import config
    from security import lockdown

    row = {"ip_address": IP, "status": "REMOVED", "expires_at": _iso(-10), "removed_at": _iso(-9),
           "evidence": "SPOOFABLE", "version": 3}
    _install(monkeypatch, row)
    monkeypatch.setattr(playbooks, "run", _real_run)
    updates = []
    monkeypatch.setattr(lockdown, "is_ip_allowlisted", lambda ip: False)
    monkeypatch.setattr(db, "count_recent_net_blocked_events", lambda ip, since: 1, raising=False)
    monkeypatch.setattr(
        db, "update_network_block_if_status",
        lambda ip, statuses, fields, expected_version=None: updates.append(fields) or True,
        raising=False,
    )
    monkeypatch.setattr(db, "insert_playbook_run", lambda *args: None, raising=False)
    monkeypatch.setattr(config, "NET_BLOCK_DEFAULT_TTL_SECONDS", 3600)
    monkeypatch.setattr(config, "NET_BLOCK_MAX_TTL_SECONDS", 21600)

    correlate.check_cross_layer(IP, "NET_SYN_FLOOD")

    assert len(updates) == 1
    expires = datetime.fromisoformat(updates[0]["expires_at"])
    remaining = (expires - datetime.now(timezone.utc)).total_seconds()
    assert 7100 < remaining <= 7200  # 3600 × 2^1
