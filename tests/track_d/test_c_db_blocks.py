# ============================================================================
# tests/track_d/test_c_db_blocks.py — DB 함수(network_blocks, agent_heartbeats) 단위 테스트
# ============================================================================

import pytest
from postgrest.exceptions import APIError

import db


class DummyResponse:
    def __init__(self, data=None, count=None):
        self.data = data if data is not None else []
        self.count = count


class FakeQueryBuilder:
    def __init__(self, table_name, state=None):
        self.table_name = table_name
        self.state = state if state is not None else {}
        self.state["table"] = table_name

    def select(self, *args, **kwargs):
        self.state["select"] = args
        self.state["select_kwargs"] = kwargs
        return self

    def insert(self, row):
        self.state["insert"] = row
        return self

    def update(self, fields):
        self.state["update"] = fields
        return self

    def upsert(self, row, **kwargs):
        self.state["upsert"] = row
        self.state["upsert_kwargs"] = kwargs
        return self

    def eq(self, column, value):
        self.state.setdefault("eq", []).append((column, value))
        return self

    def in_(self, column, values):
        self.state.setdefault("in", []).append((column, values))
        return self

    def gte(self, column, value):
        self.state.setdefault("gte", []).append((column, value))
        return self

    def lte(self, column, value):
        self.state.setdefault("lte", []).append((column, value))
        return self

    def lt(self, column, value):
        self.state.setdefault("lt", []).append((column, value))
        return self

    def not_(self):
        return self

    def is_(self, column, value):
        self.state.setdefault("is", []).append((column, value))
        return self

    def or_(self, query):
        self.state["or"] = query
        return self

    def order(self, column, desc=False):
        self.state["order"] = (column, desc)
        return self

    def limit(self, count):
        self.state["limit"] = count
        return self

    def execute(self):
        if self.state.get("raise_api_error"):
            err = APIError({"message": "duplicate key value violates unique constraint", "code": "23505"})
            err.code = "23505"
            raise err
        return DummyResponse(
            data=self.state.get("return_data", []),
            count=self.state.get("return_count", 0),
        )


class FakeSupabaseClient:
    def __init__(self):
        self.builders = []

    def table(self, table_name):
        builder = FakeQueryBuilder(table_name)
        self.builders.append(builder)
        return builder


def test_get_network_block(monkeypatch):
    client = FakeSupabaseClient()
    monkeypatch.setattr(db, "get_client", lambda: client)

    client.table = lambda name: FakeQueryBuilder(name, {"return_data": [{"ip_address": "10.0.0.1", "status": "APPLIED"}]})
    res = db.get_network_block("10.0.0.1")
    assert res == {"ip_address": "10.0.0.1", "status": "APPLIED"}


def test_insert_network_block_duplicate_key(monkeypatch):
    client = FakeSupabaseClient()
    monkeypatch.setattr(db, "get_client", lambda: client)

    def fake_table(name):
        builder = FakeQueryBuilder(name)
        builder.state["raise_api_error"] = True
        return builder

    monkeypatch.setattr(client, "table", fake_table)
    assert db.insert_network_block({"ip_address": "10.0.0.1"}) is False


def test_update_network_block_if_status(monkeypatch):
    client = FakeSupabaseClient()
    monkeypatch.setattr(db, "get_client", lambda: client)

    def fake_table(name):
        return FakeQueryBuilder(name, {"return_data": [{"ip_address": "10.0.0.1"}]})

    monkeypatch.setattr(client, "table", fake_table)
    res = db.update_network_block_if_status("10.0.0.1", ["PENDING_APPLY"], {"status": "APPLIED"})
    assert res is True


def test_upsert_agent_heartbeat(monkeypatch):
    builders = []

    def fake_table(name):
        builder = FakeQueryBuilder(name)
        builders.append(builder)
        return builder

    monkeypatch.setattr(db, "get_client", lambda: type("Client", (), {"table": fake_table})())

    db.upsert_agent_heartbeat("fw-agent", "node-1", {"status": "ok"})
    assert len(builders) == 1
    assert builders[0].table_name == "agent_heartbeats"
    assert builders[0].state["upsert"]["agent"] == "fw-agent"


def test_try_acquire_cooldown(monkeypatch):
    # 1. update 성공 시 True
    def fake_table_update_success(name):
        return FakeQueryBuilder(name, {"return_data": [{"key": "test_key"}]})

    monkeypatch.setattr(db, "get_client", lambda: type("Client", (), {"table": fake_table_update_success})())
    assert db.try_acquire_cooldown("test_key", 60) is True

    # 2. update 실패 후 insert 23505 충돌 시 False
    def fake_table_insert_duplicate(name):
        builder = FakeQueryBuilder(name, {"return_data": []})
        original_insert = builder.insert
        def mock_insert(row):
            builder.state["raise_api_error"] = True
            return original_insert(row)
        builder.insert = mock_insert
        return builder

    monkeypatch.setattr(db, "get_client", lambda: type("Client", (), {"table": fake_table_insert_duplicate})())
    assert db.try_acquire_cooldown("test_key", 60) is False