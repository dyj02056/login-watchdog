"""가짜 REST 저장소로 NET 승격·중복 처리·한정 해결과 APP 호환성을 검증한다."""

import json
from types import SimpleNamespace

import pytest
from postgrest.exceptions import APIError

import config
import db
from db import incidents, network_events
from security import correlate, net_ingest
from security.soar._events import _record_event


IP = "172.28.13.103"
SECRET = "test-ingest-secret"
EXPECTED = [
    ("SYN_FLOOD", "NET_SYN_FLOOD", "HIGH"),
    ("PORT_SCAN", "NET_PORT_SCAN", "MEDIUM"),
    ("SCANNER_UA", "NET_SCANNER_UA", "MEDIUM"),
    ("WEB_ATTACK", "NET_WEB_ATTACK", "HIGH"),
    ("LOGIN_BURST", "NET_LOGIN_BURST", "MEDIUM"),
]
_REAL_CORRELATE = correlate.check_and_correlate


class FakeDB:
    """HIGH 유니크 제약과 조건 필터를 적용해 삽입과 갱신 결과를 확인한다."""

    def __init__(self):
        self.tables = {"security_events": [], "network_events": []}
        self.queries = []
        self.insert_error = None

    def table(self, name):
        query = FakeQuery(self, name)
        self.queries.append(query)
        return query


class FakeQuery:
    def __init__(self, client, table):
        self.client, self.table = client, table
        self.operation = "select"
        self.values = None
        self.filters = []
        self.maximum = None

    def select(self, columns):
        return self

    def insert(self, values):
        self.operation, self.values = "insert", values
        return self

    def update(self, values):
        self.operation, self.values = "update", values
        return self

    def eq(self, column, value):
        self.filters.append(("eq", column, value))
        return self

    def lt(self, column, value):
        self.filters.append(("lt", column, value))
        return self

    def is_(self, column, value):
        assert value == "null"
        self.filters.append(("is", column, None))
        return self

    def limit(self, maximum):
        self.maximum = maximum
        return self

    def execute(self):
        table = self.client.tables[self.table]
        if self.operation == "insert":
            if self.client.insert_error is not None:
                raise self.client.insert_error
            row = self.values.copy()
            conflict = False
            if self.table == "security_events":
                row.setdefault("source", "APP")
                row.setdefault("layer", None)
                row.setdefault("resolved_at", None)
                conflict = row["severity"] == "HIGH" and any(
                    old["ip_address"] == row["ip_address"] and old["event_type"] == row["event_type"]
                    and old["severity"] == "HIGH" and old["resolved_at"] is None for old in table
                )
            elif self.table == "network_events":
                conflict = any(old["event_id"] == row["event_id"] for old in table)
            if conflict:
                raise APIError({"code": "23505", "message": "test-unique-conflict"})
            row.setdefault("id", len(table) + 1)
            table.append(row)
            return SimpleNamespace(data=[row.copy()])

        rows = list(table)
        for operation, column, value in self.filters:
            if operation == "eq":
                rows = [row for row in rows if row[column] == value]
            elif operation == "is":
                rows = [row for row in rows if row[column] is None]
            else:
                rows = [row for row in rows if row[column] < value]
        if self.operation == "update":
            for row in rows:
                row.update(self.values)
        if self.maximum is not None:
            rows = rows[:self.maximum]
        return SimpleNamespace(data=[row.copy() for row in rows])


@pytest.fixture
def stored(monkeypatch):
    fake = FakeDB()
    correlations = []
    monkeypatch.setattr(db, "get_client", lambda: fake)
    monkeypatch.setattr(config, "NET_INGEST_SECRET", SECRET)
    monkeypatch.setattr(config, "NET_INGEST_MAX_BODY_BYTES", 16384)
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *args, **kwargs: correlations.append((args, kwargs)))
    return SimpleNamespace(db=fake, events=fake.tables["security_events"],
                           network=fake.tables["network_events"], correlations=correlations)


@pytest.fixture
def row():
    return {
        "event_id": "a" * 64, "sensor": "suricata", "layer": "L4", "src_ip": IP,
        "dst_port": 8080, "proto": "TCP", "category": "SYN_FLOOD", "signature_id": 9000001,
        "signature": "LW test network alert", "sensor_severity": 1, "packet_count": 143,
        "window_start": "2026-10-20T03:12:00Z", "observed_at": "2026-10-20T03:12:44.120Z",
    }


@pytest.mark.parametrize("category,event_type,severity", EXPECTED)
@pytest.mark.parametrize("layer", ["L3", "L4", "L7"])
def test_category_mapping_and_metadata(stored, row, category, event_type, severity, layer):
    row.update(category=category, layer=layer)
    assert net_ingest.promote(row) is True
    assert len(stored.events) == 1
    event = stored.events[0]
    assert (event["event_type"], event["severity"], event["source"], event["layer"]) == (
        event_type, severity, "NET", layer,
    )
    assert (event["ip_address"], event["path"], event["count"], event["action"]) == (
        IP, None, 143, "NET_ALERT",
    )
    assert stored.correlations == [((IP, event_type, severity), {"source": "NET"})]


def test_other_is_not_promoted(stored, row):
    row["category"] = "OTHER"
    assert net_ingest.promote(row) is False
    assert stored.events == stored.correlations == []


@pytest.mark.parametrize("category,event_type,severity", EXPECTED)
def test_high_uses_bump_and_medium_uses_common_record(monkeypatch, row, category, event_type, severity):
    calls = []
    row["category"] = category
    monkeypatch.setattr(db, "insert_security_event_or_bump", lambda *a, **k: calls.append(("bump", a, k)))
    monkeypatch.setattr(net_ingest, "_record_event", lambda *a, **k: calls.append(("record", a, k)))
    monkeypatch.setattr(correlate, "check_and_correlate", lambda *a, **k: calls.append(("correlate", a, k)))
    assert net_ingest.promote(row) is True
    assert calls[0] == (
        "bump" if severity == "HIGH" else "record",
        (event_type, severity, IP, None, 143, "NET_ALERT"), {"source": "NET", "layer": "L4"},
    )
    if severity == "HIGH":
        assert calls[1:] == [("correlate", (IP, event_type, severity), {"source": "NET"})]
    else:
        assert len(calls) == 1


def test_high_conflict_bumps_existing_event(stored, row):
    assert net_ingest.promote(row) is True
    row["event_id"] = "b" * 64
    assert net_ingest.promote(row) is True
    assert len(stored.events) == 1
    assert stored.events[0]["count"] == 144
    assert stored.events[0]["source"] == "NET"
    assert stored.events[0]["layer"] == "L4"
    assert len(stored.correlations) == 2


def test_record_net_blocked_is_idempotent_and_does_not_correlate(stored):
    net_ingest.record_net_blocked(IP, "NET_FLOOD")
    net_ingest.record_net_blocked(IP, "KILL_CHAIN")
    assert len(stored.events) == 1
    event = stored.events[0]
    assert (event["event_type"], event["severity"], event["source"], event["layer"], event["action"]) == (
        "NET_BLOCKED", "CRITICAL", "NET", "L4", "L4_BLOCKED",
    )
    assert event["path"] is None and event["count"] == 1
    assert "reason" not in event
    assert stored.correlations == []


def test_resolve_only_unresolved_net_blocked_for_this_ip(stored):
    net_ingest.record_net_blocked(IP, "NET_FLOOD")
    net_ingest.record_net_blocked("172.28.13.104", "NET_FLOOD")
    stored.events.extend([
        {**stored.events[0], "id": 3, "event_type": "NET_SYN_FLOOD"},
        {**stored.events[0], "id": 4, "resolved_at": "2026-10-19T00:00:00Z"},
    ])
    net_ingest.resolve_net_blocked(IP)
    assert stored.events[0]["resolved_at"] is not None
    assert stored.events[1]["resolved_at"] is None
    assert stored.events[2]["resolved_at"] is None
    assert stored.events[3]["resolved_at"] == "2026-10-19T00:00:00Z"
    resolved_at = stored.events[0]["resolved_at"]
    net_ingest.resolve_net_blocked(IP)
    assert stored.events[0]["resolved_at"] == resolved_at
    net_ingest.record_net_blocked(IP, "NET_FLOOD")
    assert len(stored.events) == 5
    assert stored.correlations == []


@pytest.mark.parametrize("source,layer", [("APP", None), ("NET", "L7")])
def test_record_event_preserves_username_and_source(stored, source, layer):
    _record_event("TEST_EVENT", "MEDIUM", IP, None, 2, "TEST_ACTION",
                  username="test-user", source=source, layer=layer)
    event = stored.events[0]
    assert (event["username"], event["source"], event["layer"]) == ("test-user", source, layer)
    assert stored.correlations == [((IP, "TEST_EVENT", "MEDIUM"), {} if source == "APP" else {"source": source})]


def test_correlate_forwards_net_source(monkeypatch):
    calls = []
    monkeypatch.setattr(db, "get_recent_distinct_event_types", lambda *a: ["NET_SYN_FLOOD", "NET_PORT_SCAN"])
    incident = {"id": 1, "severity_max": "HIGH", "escalated": True, "event_types": []}
    monkeypatch.setattr(db, "record_incident", lambda *a, **k: calls.append((a, k)) or incident)
    # [B2-1 보완] 이 테스트는 사건 기록에 source가 넘어가는지만 본다. B2-1 이후 NET_SYN_FLOOD는
    # NET-01 교차 규칙도 깨워 record_incident를 한 번 더 부르므로, 그 경로는 test_b_cross_layer가 본다.
    monkeypatch.setattr(correlate, "check_cross_layer", lambda ip, event_type: None)
    _REAL_CORRELATE(IP, "NET_SYN_FLOOD", "HIGH", source="NET")
    assert calls == [((IP, ["NET_SYN_FLOOD", "NET_PORT_SCAN"], "HIGH"), {"source": "NET"})]


def test_record_incident_accepts_net_source_without_changing_existing_logic(monkeypatch):
    calls = []
    monkeypatch.setattr(incidents, "get_open_incident", lambda ip: None)
    monkeypatch.setattr(incidents, "_insert_incident", lambda *a: calls.append(a) or 7)
    assert incidents.record_incident(IP, ["NET_SYN_FLOOD", "NET_PORT_SCAN"], "HIGH", source="NET") == {
        "id": 7, "event_types": ["NET_SYN_FLOOD", "NET_PORT_SCAN"], "severity_max": "HIGH", "escalated": False,
        "app_severity_max": None, "matched_rules": [],
    }
    assert calls == [(IP, ["NET_SYN_FLOOD", "NET_PORT_SCAN"], "HIGH")]


@pytest.mark.parametrize("code", ["23514", "08006"])
def test_db_errors_are_not_treated_as_success(stored, row, code):
    stored.db.insert_error = APIError({"code": code, "message": "test-db-error"})
    with pytest.raises(APIError):
        net_ingest.promote(row)
    assert stored.events == stored.correlations == []


def _post(client, signed_headers, row):
    body = json.dumps(row).encode()
    return client.post("/api/internal/net-events", data=body, content_type="application/json",
                       headers=signed_headers("shipper", SECRET, body))


@pytest.mark.parametrize("category,event_type,severity", EXPECTED)
def test_stored_is_promoted_then_duplicate_is_not(client, signed_headers, stored, row,
                                                monkeypatch, category, event_type, severity):
    row["category"] = category
    called = []
    real_promote = net_ingest.promote

    def promote(event):
        called.append(event.copy())
        return real_promote(event)

    monkeypatch.setattr(net_ingest, "promote", promote)
    response = _post(client, signed_headers, row)
    assert response.status_code == 200
    assert response.get_json() == {"status": "stored", "promoted": True}
    assert stored.network[0]["promoted"] is True
    assert stored.events[0]["event_type"] == event_type
    row["packet_count"] = 200
    response = _post(client, signed_headers, row)
    assert response.status_code == 200
    assert response.get_json() == {"status": "updated", "promoted": False}
    assert len(called) == len(stored.events) == len(stored.correlations) == 1
    assert stored.network[0]["packet_count"] == 200
    assert stored.network[0]["promoted"] is True


def test_stored_other_is_not_marked_promoted(client, signed_headers, stored, row):
    row["category"] = "OTHER"
    response = _post(client, signed_headers, row)
    assert response.status_code == 200
    assert response.get_json() == {"status": "stored", "promoted": False}
    assert stored.events == stored.correlations == []
    assert stored.network[0]["promoted"] is False


def test_promotion_failure_is_not_marked_success(client, signed_headers, stored, row, monkeypatch):
    def fail(row):
        raise RuntimeError("test-promotion-error")

    monkeypatch.setattr(net_ingest, "promote", fail)
    with pytest.raises(RuntimeError, match="test-promotion-error"):
        _post(client, signed_headers, row)
    assert stored.network[0]["promoted"] is False


def test_promoted_mark_is_limited_to_matching_event(stored, row):
    stored.network.extend([{**row, "promoted": False}, {**row, "event_id": "b" * 64, "promoted": False}])
    network_events.mark_network_event_promoted(row["event_id"])
    network_events.mark_network_event_promoted(row["event_id"])
    assert [event["promoted"] for event in stored.network] == [True, False]


@pytest.mark.parametrize("category,event_type,severity", EXPECTED)
def test_retry_after_promotion_failure_promotes_once(client, signed_headers, stored, row,
                                                    monkeypatch, category, event_type, severity):
    # [B1-1 보완] 저장 직후 승격이 끊긴 경보는 shipper 재전송 때 승격을 마저 한다.
    row["category"] = category
    real_promote = net_ingest.promote

    def fail(event):
        raise RuntimeError("test-promotion-error")

    monkeypatch.setattr(net_ingest, "promote", fail)
    with pytest.raises(RuntimeError, match="test-promotion-error"):
        _post(client, signed_headers, row)
    assert stored.network[0]["promoted"] is False

    monkeypatch.setattr(net_ingest, "promote", real_promote)
    response = _post(client, signed_headers, row)
    assert response.get_json() == {"status": "updated", "promoted": True}
    assert stored.network[0]["promoted"] is True
    assert [event["event_type"] for event in stored.events] == [event_type]

    # 승격을 마친 뒤의 재전송은 다시 올리지 않는다.
    response = _post(client, signed_headers, row)
    assert response.get_json() == {"status": "updated", "promoted": False}
    assert len(stored.events) == 1


def test_retry_of_other_category_does_not_check_promotion(client, signed_headers, stored, row, monkeypatch):
    # [B1-1 보완] OTHER는 승격 대상이 아니므로 재전송 때 승격 여부를 조회하지 않는다.
    row["category"] = "OTHER"
    _post(client, signed_headers, row)

    def unexpected(event_id):
        raise AssertionError("OTHER 재전송에서 승격 여부를 조회하면 안 된다")

    monkeypatch.setattr(db, "is_network_event_unpromoted", unexpected)
    response = _post(client, signed_headers, row)
    assert response.get_json() == {"status": "updated", "promoted": False}
    assert stored.events == []


def test_is_network_event_unpromoted(stored, row):
    # [B1-1 보완] 행이 없으면 False, promoted 값에 따라 True/False.
    assert network_events.is_network_event_unpromoted(row["event_id"]) is False
    stored.network.append({**row, "promoted": False})
    assert network_events.is_network_event_unpromoted(row["event_id"]) is True
    stored.network[0]["promoted"] = True
    assert network_events.is_network_event_unpromoted(row["event_id"]) is False


def test_new_db_functions_are_exported():
    for name in ("mark_network_event_promoted", "resolve_net_blocked_events", "is_network_event_unpromoted"):
        assert name in network_events.__all__
        assert name in db.__all__
        assert getattr(db, name) is getattr(network_events, name)
