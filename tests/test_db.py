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
