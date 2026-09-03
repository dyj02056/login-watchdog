# ============================================================================
# test_db.py — db.py의 verify_admin_credentials()가 비밀번호를 정확히
# 구분해내는지 확인하는 단위 테스트
#
# 이 함수는 내부에서 Supabase에 접속(get_client())해야 하는데, 테스트에서는
# 진짜로 접속하고 싶지 않다. 그래서 "Supabase 클라이언트인 척하는 가짜 객체
# (FakeSupabaseClient)"를 만들어서 db.get_client()가 그 가짜 객체를 돌려주도록
# 바꿔치기한다. 진짜 db.py 코드(verify_admin_credentials 자체)는 손대지 않고
# 그대로 실행시키면서, 그 코드가 딛고 서는 "바닥(Supabase 연결)"만 가짜로
# 깔아주는 방식이다.
# ============================================================================

from werkzeug.security import generate_password_hash

import db


class _FakeQuery:
    """db.py가 .table().select().eq().limit().execute() 순서로 체이닝(연쇄 호출)하는
    Supabase 문법을 흉내내는 가짜 객체. 어떤 메서드를 불러도 그냥 자기 자신을
    돌려주다가(체이닝을 이어가기 위해), execute()에서만 미리 정해둔 결과를 내놓는다.

    calls 리스트에 어떤 메서드가 어떤 값으로 호출됐는지 순서대로 기록해둔다 —
    "delete_user가 정말 delete()를 불렀는지" 같은 걸 확인하고 싶을 때 쓴다.
    """

    def __init__(self, rows, calls=None):
        self._rows = rows
        self.calls = calls if calls is not None else []

    def table(self, *args, **kwargs):
        self.calls.append(("table", args, kwargs))
        return self

    def select(self, *args, **kwargs):
        self.calls.append(("select", args, kwargs))
        return self

    def eq(self, *args, **kwargs):
        self.calls.append(("eq", args, kwargs))
        return self

    def neq(self, *args, **kwargs):
        self.calls.append(("neq", args, kwargs))
        return self

    def gte(self, *args, **kwargs):
        self.calls.append(("gte", args, kwargs))
        return self

    def limit(self, *args, **kwargs):
        return self

    def order(self, *args, **kwargs):
        return self

    def delete(self, *args, **kwargs):
        self.calls.append(("delete", args, kwargs))
        return self

    def update(self, *args, **kwargs):
        self.calls.append(("update", args, kwargs))
        return self

    def upsert(self, *args, **kwargs):
        self.calls.append(("upsert", args, kwargs))
        return self

    def in_(self, *args, **kwargs):
        self.calls.append(("in_", args, kwargs))
        return self

    def execute(self):
        return _FakeResult(self._rows)


class _FakeResult:
    def __init__(self, data):
        self.data = data


def test_verify_admin_credentials_true_for_correct_password(monkeypatch):
    stored_hash = generate_password_hash("correct-horse-battery-staple")
    fake_client = _FakeQuery(rows=[{"password_hash": stored_hash}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.verify_admin_credentials("soung1009", "correct-horse-battery-staple")

    assert result is True


def test_verify_admin_credentials_false_for_wrong_password(monkeypatch):
    stored_hash = generate_password_hash("correct-horse-battery-staple")
    fake_client = _FakeQuery(rows=[{"password_hash": stored_hash}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.verify_admin_credentials("soung1009", "wrong-password")

    assert result is False


def test_verify_admin_credentials_false_when_username_not_found(monkeypatch):
    # 아이디로 조회했는데 결과 행이 하나도 없는 상황(가입한 적 없는 아이디)을 흉내낸다.
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.verify_admin_credentials("no_such_admin", "anything")

    assert result is False


def test_list_users_returns_rows_from_client(monkeypatch):
    rows = [
        {"id": 2, "username": "bbb", "email": "bbb@example.com", "created_at": "2026-09-02T00:00:00Z"},
        {"id": 1, "username": "aaa", "email": "aaa@example.com", "created_at": "2026-09-01T00:00:00Z"},
    ]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.list_users()

    # list_users는 정렬 자체를 하지 않는다(Supabase 쪽에 정렬을 맡긴다) — 그래서
    # 여기서는 "가짜 클라이언트가 준 데이터를 그대로 전달하는지"만 확인한다.
    assert result == rows


def test_delete_user_true_when_row_was_deleted(monkeypatch):
    # Supabase는 삭제된 행 자체를 응답으로 돌려준다 — 행이 1개 있으면 "진짜 지워졌다"는 뜻.
    fake_client = _FakeQuery(rows=[{"id": 5}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.delete_user(5)

    assert result is True
    assert ("delete", (), {}) in fake_client.calls


def test_delete_user_false_when_id_not_found(monkeypatch):
    # 삭제 대상 id가 애초에 없었다면 Supabase는 빈 목록을 돌려준다.
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.delete_user(999)

    assert result is False


def test_get_signup_enabled_reflects_stored_value(monkeypatch):
    fake_client = _FakeQuery(rows=[{"signup_enabled": False}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_signup_enabled() is False


def test_get_signup_enabled_defaults_true_when_no_settings_row(monkeypatch):
    # app_settings에 아직 행이 하나도 없는(설치 직후 등) 예외 상황을 흉내낸다.
    # 회원가입을 "막힌 상태"로 기본값을 잡으면 설정 실수로 아무도 가입 못 하는
    # 사고가 날 수 있으므로, 안전한 기본값은 "허용"이어야 한다.
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_signup_enabled() is True


def test_set_signup_enabled_calls_update_with_new_value(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.set_signup_enabled(False)

    assert ("update", ({"signup_enabled": False},), {}) in fake_client.calls


def test_get_user_by_id_returns_row(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 7, "username": "hyun", "name": "", "email": "hyun@example.com"}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_user_by_id(7)

    assert result["username"] == "hyun"


def test_get_user_by_id_none_when_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_user_by_id(999) is None


def test_update_user_profile_true_when_email_not_taken(monkeypatch):
    # 이메일 중복 검사 쿼리가 빈 목록을 돌려주는 상황 = "다른 사람은 안 쓰고 있다"
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.update_user_profile(3, "새 이름", "new@example.com")

    assert result is True
    assert ("update", ({"name": "새 이름", "email": "new@example.com"},), {}) in fake_client.calls


def test_update_user_profile_false_when_email_taken_by_someone_else(monkeypatch):
    # 이메일 중복 검사 쿼리가 "다른 사람의" 행을 하나라도 돌려주면 실패해야 한다
    fake_client = _FakeQuery(rows=[{"id": 99}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.update_user_profile(3, "새 이름", "taken@example.com")

    assert result is False
    # 중복이 확인된 즉시 되돌아가야 하므로, update()는 아예 호출되면 안 된다.
    assert not any(call[0] == "update" for call in fake_client.calls)


def test_list_attempts_by_username_filters_by_username(monkeypatch):
    rows = [{"username": "hyun", "ip_address": "1.2.3.4", "success": True}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.list_attempts_by_username("hyun")

    assert result == rows
    assert ("eq", ("username", "hyun"), {}) in fake_client.calls


def test_list_attempts_since_filters_by_time_window(monkeypatch):
    rows = [{"ip_address": "1.2.3.4", "username": "hyun", "success": False}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.list_attempts_since(24)

    assert result == rows
    assert ("table", ("login_attempts",), {}) in fake_client.calls


def test_list_lockouts_since_filters_by_time_window(monkeypatch):
    rows = [{"ip_address": "9.9.9.9", "failure_count": 6}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.list_lockouts_since(24)

    assert result == rows
    assert ("table", ("lockouts",), {}) in fake_client.calls


def test_get_cached_ip_locations_returns_empty_dict_for_empty_input(monkeypatch):
    # IP 목록이 아예 비어있으면 Supabase에 물어볼 필요조차 없다 — 쿼리를 안 보내고
    # 바로 빈 딕셔너리를 돌려줘야 한다.
    fake_client = _FakeQuery(rows=[{"ip_address": "1.2.3.4"}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_cached_ip_locations([])

    assert result == {}
    assert fake_client.calls == []  # table()조차 호출되지 않아야 한다


def test_get_cached_ip_locations_indexes_by_ip(monkeypatch):
    rows = [
        {"ip_address": "1.1.1.1", "country": "Australia"},
        {"ip_address": "8.8.8.8", "country": "United States"},
    ]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_cached_ip_locations(["1.1.1.1", "8.8.8.8"])

    assert result == {"1.1.1.1": rows[0], "8.8.8.8": rows[1]}
    assert ("in_", ("ip_address", ["1.1.1.1", "8.8.8.8"]), {}) in fake_client.calls


def test_save_ip_location_upserts_row(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.save_ip_location("9.9.9.9", "South Korea", "Seoul", "Seoul", False)

    expected = {
        "ip_address": "9.9.9.9",
        "country": "South Korea",
        "region_name": "Seoul",
        "city": "Seoul",
        "lookup_failed": False,
    }
    assert ("upsert", (expected,), {}) in fake_client.calls
