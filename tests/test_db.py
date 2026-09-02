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
    """

    def __init__(self, rows):
        self._rows = rows

    def table(self, *args, **kwargs):
        return self

    def select(self, *args, **kwargs):
        return self

    def eq(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
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
