"""메모리에 사는 가짜 Supabase — 시뮬레이션 점검용 서버가 진짜 DB 대신 쓴다.

db 패키지가 쓰는 PostgREST 쿼리 체인(.table().select().eq()....execute())을 흉내 내서, 표(table)를
파이썬 리스트로 들고 있다. demo_server.py의 가짜 클라이언트는 항상 빈 결과를 돌려주지만, 이쪽은
insert한 행을 실제로 기억하고 where 조건으로 걸러서 센다 — 그래야 "5번 틀리면 잠금" 같은 탐지가
진짜처럼 작동한다. 진짜 Supabase·Slack·메일에는 아무것도 보내지 않는다.

지원하는 연산은 db 패키지가 실제로 쓰는 것만이다: select(count) / insert / update / delete / upsert,
eq·neq·gt·gte·lt·lte·is_·in_·or_·not_, order·limit·range.
"""

import itertools
import threading
from datetime import datetime, timezone

# 진짜 DB가 default now()로 채워주는 시각 칸 — 표마다 실제로 있는 칸만 채운다(없는 칸까지 채우면 진짜 DB에 넣을 때 오류가 난다).
_AUTO_TIME_COLUMNS = {
    "login_attempts": ("attempted_at",), "signup_attempts": ("attempted_at",), "not_found_attempts": ("attempted_at",),
    "unauthorized_attempts": ("attempted_at",), "page_access_attempts": ("attempted_at",), "admin_login_log": ("attempted_at",),
    "post_attempts": ("attempted_at",), "comment_attempts": ("attempted_at",), "api_access_log": ("requested_at",),
    "users": ("created_at",), "admin_users": ("created_at",), "posts": ("created_at", "updated_at"), "comments": ("created_at",),
    "security_events": ("detected_at",), "access_requests": ("requested_at",), "lockouts": ("locked_at",),
    "account_lockouts": ("locked_at",), "admin_account_lockouts": ("locked_at",), "lock_history": ("locked_at",),
    "recovery_requests": ("created_at",), "email_tokens": ("created_at",), "ip_lock_exemptions": ("granted_at",),
    "ip_locations": ("looked_up_at",), "security_incidents": (),
}
_ALL_TIME_COLUMNS = (
    "attempted_at", "created_at", "detected_at", "logged_at", "accessed_at", "locked_at", "requested_at",
)


# 기본키 칸 이름이 id가 아닌 표 (진짜 DB에서 identity로 채워지는 칸)
_PRIMARY_KEY = {"access_requests": "request_id"}


# 진짜 DB가 default로 채워주는 칸 (insert 때 값이 없으면 이 값을 넣는다)
_TABLE_DEFAULTS = {
    "users": {"name": "", "email_status": "UNKNOWN", "email_status_checked_at": None, "session_version": 0},
    "admin_users": {"role": "security_admin"},
    "security_events": {"path": None, "username": None, "resolved_at": None},
    "lockouts": {"lock_type": "TEMPORARY", "recoverable": "EXEMPTION", "active": True, "permanent_reason": None, "promoted_at": None},
    "account_lockouts": {"lock_type": "TEMPORARY", "recoverable": "SELF", "active": True, "permanent_reason": None,
                         "promoted_at": None, "probation_until": None},
    "admin_account_lockouts": {"active": True},
    "lock_history": {"source_event_type": None, "incident_id": None, "trigger_note": None, "released_at": None,
                     "released_by": None, "release_note": None},
    "security_incidents": {"status": "OPEN", "escalated": False, "resolved_at": None, "resolved_by": None},
    "access_requests": {"status": "PENDING", "path": None, "context_count": None, "context_ip": None,
                        "decided_by_admin_id": None, "decided_at": None},
}


class Result:
    def __init__(self, data, count=None):
        self.data = data
        self.count = count


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _as_datetime(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _norm(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return None
    return str(value)


def _compare(row_value, op, target):
    """한 칸의 값을 조건과 비교한다. 날짜 문자열은 시각으로 바꿔서 비교한다."""
    if op in ("eq", "neq"):
        same = _norm(row_value) == _norm(target)
        return same if op == "eq" else not same
    if op == "is":
        want_null = str(target).lower() == "null"
        return (row_value is None) == want_null
    if row_value is None:
        return False
    left, right = _as_datetime(row_value), _as_datetime(target)
    if left is None or right is None:
        try:
            left, right = float(row_value), float(target)
        except (TypeError, ValueError):
            left, right = str(row_value), str(target)
    return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[op]


class _Store:
    """표 이름 → 행 목록. 모든 쿼리가 같은 저장소를 본다."""

    def __init__(self):
        self.lock = threading.RLock()
        self.tables = {}
        self._ids = {}

    def rows(self, name):
        return self.tables.setdefault(name, [])

    def next_id(self, name):
        counter = self._ids.setdefault(name, itertools.count(1))
        return next(counter)

    def reset(self, keep=()):
        with self.lock:
            for name in list(self.tables):
                if name not in keep:
                    self.tables[name].clear()


class _Not:
    def __init__(self, query):
        self._query = query

    def is_(self, column, value):
        self._query._filters.append((column, "is", value, True))
        return self._query


class Query:
    def __init__(self, store, name):
        self._store = store
        self._name = name
        self._action = "select"
        self._payload = None
        self._on_conflict = None
        self._count = False
        self._columns = "*"
        self._filters = []   # (column, op, value, negate) 또는 ("__or__", None, [조건...], False)
        self._order = None
        self._limit = None
        self._range = None

    # --- 동작 선택 ---
    def select(self, _columns="*", count=None, **_kwargs):  # head=True 같은 옵션은 무시한다(개수만 세는 호출도 그대로 동작)
        self._action = "select"
        self._columns = _columns
        self._count = bool(count)
        return self

    def insert(self, payload):
        self._action, self._payload = "insert", payload
        return self

    def update(self, payload):
        self._action, self._payload = "update", payload
        return self

    def delete(self):
        self._action = "delete"
        return self

    def upsert(self, payload, on_conflict=None):
        self._action, self._payload, self._on_conflict = "upsert", payload, on_conflict
        return self

    # --- 조건 ---
    def _add(self, column, op, value):
        self._filters.append((column, op, value, False))
        return self

    def eq(self, column, value): return self._add(column, "eq", value)
    def neq(self, column, value): return self._add(column, "neq", value)
    def gt(self, column, value): return self._add(column, "gt", value)
    def gte(self, column, value): return self._add(column, "gte", value)
    def lt(self, column, value): return self._add(column, "lt", value)
    def lte(self, column, value): return self._add(column, "lte", value)
    def is_(self, column, value): return self._add(column, "is", value)

    def in_(self, column, values):
        self._filters.append((column, "in", list(values), False))
        return self

    def or_(self, expression):
        conditions = []
        for part in expression.split(","):
            column, op, value = part.split(".", 2)
            conditions.append((column, op, value))
        self._filters.append(("__or__", None, conditions, False))
        return self

    @property
    def not_(self):
        return _Not(self)

    # --- 정렬·범위 ---
    def order(self, column, desc=False, **_kwargs):
        self._order = (column, desc)
        return self

    def limit(self, count):
        self._limit = count
        return self

    def range(self, start, end):
        self._range = (start, end)
        return self

    # --- 실행 ---
    def _matches(self, row):
        for column, op, value, negate in self._filters:
            if column == "__or__":
                ok = any(_compare(row.get(c), o, v) for c, o, v in value)
            elif op == "in":
                ok = _norm(row.get(column)) in {_norm(v) for v in value}
            else:
                ok = _compare(row.get(column), op, value)
            if ok == negate:
                return False
        return True

    def execute(self):
        store = self._store
        with store.lock:
            rows = store.rows(self._name)
            if self._action == "insert":
                return Result([self._insert(row) for row in self._as_list()])
            if self._action == "upsert":
                return Result([self._upsert(row) for row in self._as_list()])
            matched = [row for row in rows if self._matches(row)]
            if self._action == "update":
                for row in matched:
                    row.update(self._payload)
                return Result([dict(row) for row in matched])
            if self._action == "delete":
                for row in matched:
                    rows.remove(row)
                return Result([dict(row) for row in matched])
            return self._select(matched)

    def _as_list(self):
        return self._payload if isinstance(self._payload, list) else [self._payload]

    def _fill_defaults(self, row):
        row = dict(row)
        for column, value in _TABLE_DEFAULTS.get(self._name, {}).items():
            row.setdefault(column, value)
        key = _PRIMARY_KEY.get(self._name, "id")
        if key not in row:
            row[key] = self._store.next_id(self._name)
        for column in _AUTO_TIME_COLUMNS.get(self._name, _ALL_TIME_COLUMNS):
            row.setdefault(column, _now_iso())
        return row

    def _insert(self, row):
        row = self._fill_defaults(row)
        self._store.rows(self._name).append(row)
        return dict(row)

    def _upsert(self, row):
        key = self._on_conflict
        if key:
            for existing in self._store.rows(self._name):
                if existing.get(key) == row.get(key):
                    existing.update(row)
                    return dict(existing)
        return self._insert(row)

    def _select(self, matched):
        if self._order:
            column, desc = self._order
            matched = sorted(
                matched,
                key=lambda row: (row.get(column) is not None, _as_datetime(row.get(column)) or row.get(column) or 0),
                reverse=bool(desc),
            )
        total = len(matched)
        if self._range:
            matched = matched[self._range[0]:self._range[1] + 1]
        if self._limit is not None:
            matched = matched[:self._limit]
        rows = [dict(row) for row in matched]
        if "users(username)" in str(self._columns):   # PostgREST의 연결 조회: user_id → users.username
            names = {user["id"]: user["username"] for user in self._store.rows("users")}
            for row in rows:
                row["users"] = {"username": names.get(row.get("user_id"))}
        return Result(rows, count=total if self._count else None)


class MemoryClient:
    def __init__(self):
        self.store = _Store()

    def table(self, name):
        return Query(self.store, name)
