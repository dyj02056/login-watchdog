"""가짜 DB와 서명된 요청으로 K4의 저장 경계 및 K10의 조회 범위를 검증한다."""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest
from postgrest.exceptions import APIError

import config
import db
from db import network_events
from routes.internal import ingest


URL = "/api/internal/net-events"
SECRET = "test-ingest-secret"
REQUIRED = ("event_id", "sensor", "layer", "src_ip", "category", "signature_id",
            "signature", "packet_count", "window_start", "observed_at")


@pytest.fixture
def event():
    return {
        "event_id": "a" * 64,
        "sensor": "suricata",
        "layer": "L4",
        "src_ip": "172.28.13.103",
        "dst_port": 8080,
        "proto": "TCP",
        "category": "SYN_FLOOD",
        "signature_id": 9000001,
        "signature": "LW SYN flood suspected",
        "sensor_severity": 1,
        "packet_count": 143,
        "window_start": "2026-10-20T03:12:00Z",
        "observed_at": "2026-10-20T03:12:44.120Z",
    }


@pytest.fixture
def storage(monkeypatch):
    inserted, bumped = [], []
    monkeypatch.setattr(config, "NET_INGEST_SECRET", SECRET)
    monkeypatch.setattr(config, "NET_AGENT_SECRET", "test-agent-secret")
    monkeypatch.setattr(config, "NET_INGEST_MAX_BODY_BYTES", 16384)

    def insert(row):
        inserted.append(row)
        return True

    def bump(event_id, packet_count, last_seen_at):
        bumped.append((event_id, packet_count, last_seen_at))

    monkeypatch.setattr(db, "insert_network_event", insert, raising=False)
    monkeypatch.setattr(db, "bump_network_event", bump, raising=False)
    return SimpleNamespace(inserted=inserted, bumped=bumped)


def _post(client, signed_headers, event, sender="shipper", key=SECRET):
    body = json.dumps(event).encode()
    return client.post(URL, data=body, content_type="application/json",
                       headers=signed_headers(sender, key, body))


def test_stored(client, signed_headers, event, storage):
    response = _post(client, signed_headers, event)
    assert response.status_code == 200
    assert response.get_json() == {"status": "stored", "promoted": False}
    assert storage.inserted == [{**event, "last_seen_at": event["observed_at"], "promoted": False}]
    assert storage.bumped == []


def test_duplicate_is_updated(client, signed_headers, event, storage, monkeypatch):
    def insert(row):
        storage.inserted.append(row)
        return len(storage.inserted) == 1

    monkeypatch.setattr(db, "insert_network_event", insert)
    assert _post(client, signed_headers, event).get_json()["status"] == "stored"
    event["packet_count"] = 200
    response = _post(client, signed_headers, event)
    assert response.status_code == 200
    assert response.get_json() == {"status": "updated", "promoted": False}
    assert storage.bumped == [(event["event_id"], 200, event["observed_at"])]


@pytest.mark.parametrize("sender,key", [("fw-agent", "test-agent-secret"), ("shipper", "test-agent-secret")])
def test_agent_credentials_are_rejected(client, signed_headers, event, storage, sender, key):
    response = _post(client, signed_headers, event, sender, key)
    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}
    assert storage.inserted == storage.bumped == []


def test_unsigned_request_is_rejected_before_json(client, storage):
    response = client.post(URL, data=b"not-json", content_type="application/json")
    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}
    assert storage.inserted == storage.bumped == []


def test_large_body_is_rejected_before_signature(client, storage):
    response = client.post(URL, data=b"x" * 16385)
    assert response.status_code == 413
    assert response.get_json() == {"error": "too_large"}
    assert storage.inserted == storage.bumped == []


def test_exact_body_limit_is_accepted(client, signed_headers, event, storage, monkeypatch):
    monkeypatch.setattr(config, "NET_INGEST_MAX_BODY_BYTES", len(json.dumps(event).encode()))
    assert _post(client, signed_headers, event).status_code == 200


@pytest.mark.parametrize("body", [b"[]", b"null", b"1", b'"text"', b"{broken", b""])
def test_invalid_json_body(client, signed_headers, storage, body):
    response = client.post(URL, data=body, content_type="application/json",
                           headers=signed_headers("shipper", SECRET, body))
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid", "field": "body"}
    assert storage.inserted == storage.bumped == []


@pytest.mark.parametrize("field,value", [
    ("event_id", "A" * 64), ("event_id", "a" * 63), ("event_id", "a" * 64 + "\n"),
    ("sensor", "other"), ("sensor", []), ("layer", "L2"), ("layer", {}),
    ("src_ip", "bad-ip"), ("src_ip", "172.28.13.0/24"), ("src_ip", 123),
    ("dst_port", -1), ("dst_port", 65536), ("dst_port", True), ("dst_port", 80.0),
    ("proto", "tcp"), ("proto", []), ("category", "BAD"), ("category", {}),
    ("signature_id", 0), ("signature_id", True), ("signature_id", "1"),
    ("signature", ""), ("signature", "x" * 201), ("signature", 1),
    ("sensor_severity", 0), ("sensor_severity", 4), ("sensor_severity", False),
    ("packet_count", 0), ("packet_count", 10000001), ("packet_count", True),
    ("packet_count", 1.1), ("packet_count", "143"),
    ("window_start", "2026-10-20"), ("window_start", "2026-10-20Z"),
    ("window_start", "2026-02-30T00:00:00Z"),
    ("observed_at", "2026-10-20T03:12:44+00:00"),
    ("observed_at", "2026-10-20T03:12:44"), ("observed_at", "bad-timeZ"),
    ("observed_at", 123), ("observed_at", "2026-10-20T25:00:00Z"),
])
def test_invalid_field(client, signed_headers, event, storage, field, value):
    event[field] = value
    response = _post(client, signed_headers, event)
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid", "field": field}
    assert storage.inserted == storage.bumped == []


@pytest.mark.parametrize("field", REQUIRED)
@pytest.mark.parametrize("missing", [False, True])
def test_required_field(client, signed_headers, event, storage, field, missing):
    if missing:
        del event[field]
    else:
        event[field] = None
    response = _post(client, signed_headers, event)
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid", "field": field}
    assert storage.inserted == storage.bumped == []


@pytest.mark.parametrize("remove", [False, True])
def test_optional_fields(client, signed_headers, event, storage, remove):
    for field in ("dst_port", "proto", "sensor_severity"):
        if remove:
            del event[field]
        else:
            event[field] = None
    assert _post(client, signed_headers, event).status_code == 200
    assert all(storage.inserted[0][field] is None for field in ("dst_port", "proto", "sensor_severity"))


@pytest.mark.parametrize("raw,expected", [
    ("::ffff:203.0.113.10", "203.0.113.10"),
    ("2001:db8:1:2:abcd::5", "2001:db8:1:2::/64"),
])
def test_ip_is_normalized(client, signed_headers, event, storage, monkeypatch, raw, expected):
    monkeypatch.setattr(config, "IPV6_PREFIX_LENGTH", 64)
    event["src_ip"] = raw
    assert _post(client, signed_headers, event).status_code == 200
    assert storage.inserted[0]["src_ip"] == expected


def test_server_fields_are_not_trusted(client, signed_headers, event, storage):
    event.update(id=123, promoted=True, received_at="bad-time", last_seen_at="bad-time", extra="ignored")
    assert _post(client, signed_headers, event).status_code == 200
    row = storage.inserted[0]
    assert row["promoted"] is False
    assert row["last_seen_at"] == event["observed_at"]
    assert {"id", "received_at", "extra"}.isdisjoint(row)


@pytest.mark.parametrize("sender,expected", [(None, "unknown"), ("", "unknown"),
                                          ("shipper", "shipper"), ("fw-agent", "fw-agent")])
def test_rate_limit_key(flask_app, sender, expected):
    headers = {} if sender is None else {"X-LW-Sender": sender}
    with flask_app.test_request_context(URL, headers=headers):
        assert ingest.rate_limit_key() == f"net-ingest:{expected}"


def test_rate_limits_are_separate_by_sender(client, storage):
    for _ in range(config.NET_INGEST_RATE_LIMIT_PER_MINUTE):
        assert client.post(URL, headers={"X-LW-Sender": "shipper"}).status_code == 401
    response = client.post(URL, headers={"X-LW-Sender": "shipper"})
    assert response.status_code == 429
    assert response.get_json() == {"error": "rate_limited"}
    assert client.post(URL, headers={"X-LW-Sender": "fw-agent"}).status_code == 401


class FakeClient:
    """조건부 UPDATE와 페이지 경계를 실제 행에 적용해 감소·누락을 검출한다."""

    def __init__(self, rows=(), error=None):
        self.rows = [row.copy() for row in rows]
        self.error = error
        self.queries = []

    def table(self, name):
        assert name == "network_events"
        query = FakeQuery(self)
        self.queries.append(query)
        return query


class FakeQuery:
    def __init__(self, client):
        self.client = client
        self.operation = "select"
        self.values = None
        self.columns = "*"
        self.filters = []
        self.orders = []
        self.bounds = None
        self.maximum = None

    def insert(self, values):
        self.operation, self.values = "insert", values
        return self

    def update(self, values):
        self.operation, self.values = "update", values
        return self

    def select(self, columns):
        self.columns = columns
        return self

    def eq(self, column, value):
        self.filters.append(("eq", column, value))
        return self

    def lt(self, column, value):
        self.filters.append(("lt", column, value))
        return self

    def gte(self, column, value):
        self.filters.append(("gte", column, value))
        return self

    def order(self, column, desc=False):
        self.orders.append((column, desc))
        return self

    def range(self, start, end):
        self.bounds = (start, end)
        return self

    def limit(self, maximum):
        self.maximum = maximum
        return self

    def execute(self):
        if self.client.error:
            raise self.client.error
        if self.operation == "insert":
            self.client.rows.append(self.values.copy())
            return SimpleNamespace(data=[self.values.copy()])
        rows = self.client.rows[:]
        for operator, column, value in self.filters:
            def matches(row):
                actual, target = row[column], value
                if column.endswith("_at"):
                    actual, target = datetime.fromisoformat(actual), datetime.fromisoformat(target)
                return {"eq": actual == target, "lt": actual < target, "gte": actual >= target}[operator]
            rows = [row for row in rows if matches(row)]
        if self.operation == "update":
            for row in rows:
                row.update(self.values)
        else:
            for column, desc in reversed(self.orders):
                rows.sort(key=lambda row: row[column], reverse=desc)
            if self.bounds is not None:
                start, end = self.bounds
                rows = rows[start:end + 1]
            if self.maximum is not None:
                rows = rows[:self.maximum]
            if self.columns != "*":
                rows = [{column: row[column] for column in self.columns.split(",")} for row in rows]
        return SimpleNamespace(data=rows)


def test_insert_network_event(monkeypatch, event):
    fake = FakeClient()
    monkeypatch.setattr(db, "get_client", lambda: fake)
    assert network_events.insert_network_event(event) is True
    assert fake.rows == [event]


@pytest.mark.parametrize("code", ["23505", "23514", "08006"])
def test_insert_handles_only_unique_violation(monkeypatch, event, code):
    error = APIError({"code": code, "message": "test-db-error", "details": None, "hint": None})
    monkeypatch.setattr(db, "get_client", lambda: FakeClient(error=error))
    if code == "23505":
        assert network_events.insert_network_event(event) is False
    else:
        with pytest.raises(APIError):
            network_events.insert_network_event(event)


def test_bump_never_decreases_count_or_last_seen(monkeypatch, event):
    initial = {**event, "last_seen_at": event["observed_at"], "promoted": True}
    fake = FakeClient([initial, {**initial, "event_id": "b" * 64}])
    monkeypatch.setattr(db, "get_client", lambda: fake)
    network_events.bump_network_event(event["event_id"], 200, "2026-10-20T03:13:00Z")
    network_events.bump_network_event(event["event_id"], 10, "2026-10-20T03:12:00Z")
    assert fake.rows[0]["packet_count"] == 200
    assert fake.rows[0]["last_seen_at"] == "2026-10-20T03:13:00Z"
    network_events.bump_network_event(event["event_id"], 200, "2026-10-20T03:14:00Z")
    assert fake.rows[0] == {**initial, "packet_count": 200, "last_seen_at": "2026-10-20T03:14:00Z"}
    assert fake.rows[1] == {**initial, "event_id": "b" * 64}
    assert ("lt", "packet_count", 200) in fake.queries[0].filters


def test_recent_events_projection_order_and_limit(monkeypatch, event):
    fake = FakeClient([{**event, "id": index, "promoted": False} for index in range(60)])
    monkeypatch.setattr(db, "get_client", lambda: fake)
    rows = network_events.list_recent_network_events()
    assert len(rows) == 50
    assert rows[0]["id"] == 59
    assert set(rows[0]) == {"id", "observed_at", "src_ip", "layer", "category", "signature", "packet_count", "promoted"}
    assert fake.queries[0].orders[0] == ("observed_at", True)
    assert len(network_events.list_recent_network_events(limit=3)) == 3


def test_category_count_spans_pages_and_filters_date(monkeypatch):
    rows = [
        {"id": index, "observed_at": "2026-10-20T00:00:00Z", "category": "SYN_FLOOD", "layer": "L4"}
        for index in range(1001)
    ]
    rows.extend([
        {"id": 2000, "observed_at": "2026-10-20T00:00:00Z", "category": "SYN_FLOOD", "layer": "L3"},
        {"id": 2001, "observed_at": "2026-10-20T00:00:00Z", "category": "PORT_SCAN", "layer": "L4"},
        {"id": 2002, "observed_at": "2026-10-19T00:00:00Z", "category": "OTHER", "layer": "L7"},
    ])
    fake = FakeClient(rows)
    monkeypatch.setattr(db, "get_client", lambda: fake)
    assert network_events.count_network_events_by_category("2026-10-20T00:00:00Z") == [
        {"category": "SYN_FLOOD", "layer": "L4", "count": 1001},
        {"category": "PORT_SCAN", "layer": "L4", "count": 1},
        {"category": "SYN_FLOOD", "layer": "L3", "count": 1},
    ]
    assert [query.bounds for query in fake.queries] == [(0, 999), (1000, 1999)]


def test_category_count_is_capped_at_twenty_thousand(monkeypatch):
    fake = FakeClient([
        {"id": index, "observed_at": "2026-10-20T00:00:00Z", "category": "OTHER", "layer": "L4"}
        for index in range(20001)
    ])
    monkeypatch.setattr(db, "get_client", lambda: fake)
    assert network_events.count_network_events_by_category("2026-10-20T00:00:00Z") == [
        {"category": "OTHER", "layer": "L4", "count": 20000}
    ]
    assert len(fake.queries) == 20
    assert fake.queries[-1].bounds == (19000, 19999)


def test_empty_category_count(monkeypatch):
    monkeypatch.setattr(db, "get_client", lambda: FakeClient())
    assert network_events.count_network_events_by_category("2026-10-20T00:00:00Z") == []
