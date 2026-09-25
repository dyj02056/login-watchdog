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

import pytest
from postgrest.exceptions import APIError
from werkzeug.security import generate_password_hash

import db


class _FakeQuery:
    """db.py가 .table().select().eq().limit().execute() 순서로 체이닝(연쇄 호출)하는
    Supabase 문법을 흉내내는 가짜 객체. 어떤 메서드를 불러도 그냥 자기 자신을
    돌려주다가(체이닝을 이어가기 위해), execute()에서만 미리 정해둔 결과를 내놓는다.

    calls 리스트에 어떤 메서드가 어떤 값으로 호출됐는지 순서대로 기록해둔다 —
    "delete_user가 정말 delete()를 불렀는지" 같은 걸 확인하고 싶을 때 쓴다.

    count : select(..., count="exact") 뒤에 res.count로 읽히는 값을 흉내낼 때만
    넘겨준다(기본 None → res.count or 0 패턴에서 0으로 처리됨).

    raise_error : insert_security_event_or_bump()의 "삽입이 DB 제약에 걸려 실패하는"
    경로를 흉내낼 때만 넘겨준다. execute()가 처음 한 번만 이 예외를 던지고(진짜
    Supabase도 실패한 요청 자체는 재시도하지 않으므로), 그 다음부터는 평소처럼
    rows/count를 돌려준다 — 실패 이후 db.py가 이어서 하는 조회/갱신 호출은
    정상적으로 응답받아야 하기 때문이다.
    """

    def __init__(self, rows, calls=None, count=None, raise_error=None):
        self._rows = rows
        self.calls = calls if calls is not None else []
        self._count = count
        self._raise_error = raise_error

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

    def is_(self, *args, **kwargs):
        self.calls.append(("is_", args, kwargs))
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

    def range(self, *args, **kwargs):
        self.calls.append(("range", args, kwargs))
        return self

    def insert(self, *args, **kwargs):
        self.calls.append(("insert", args, kwargs))
        return self

    def execute(self):
        if self._raise_error is not None:
            error, self._raise_error = self._raise_error, None
            raise error
        return _FakeResult(self._rows, self._count)


class _FakeResult:
    def __init__(self, data, count=None):
        self.data = data
        self.count = count


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


def test_verify_admin_credentials_hashes_even_when_username_not_found(monkeypatch):
    # test_verify_user_credentials_hashes_even_when_username_not_found와 동일한
    # 목적의 관리자 로그인 버전 (L7 공격 보강 계획 Tier 3).
    from db import admin as admin_module

    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    calls = []
    original_check = admin_module.check_password_hash

    def spy_check_password_hash(pwhash, password):
        calls.append((pwhash, password))
        return original_check(pwhash, password)

    monkeypatch.setattr(admin_module, "check_password_hash", spy_check_password_hash)

    db.verify_admin_credentials("no_such_admin", "anything")

    assert len(calls) == 1
    assert calls[0][0] == admin_module._DUMMY_PASSWORD_HASH


def test_get_admin_role_returns_stored_role(monkeypatch):
    fake_client = _FakeQuery(rows=[{"role": "super_admin"}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_admin_role("sktmaster123")

    assert result == "super_admin"


def test_get_admin_role_none_when_username_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_admin_role("no_such_admin")

    assert result is None


def test_has_permission_true_when_row_exists(monkeypatch):
    fake_client = _FakeQuery(rows=[{"role": "security_admin"}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.has_permission("security_admin", "unlock_ip")

    assert result is True


def test_has_permission_false_when_no_matching_row(monkeypatch):
    # security_viewer는 permissions 표에 아무 행도 없으므로(guide26 시드 데이터),
    # 어떤 action을 물어봐도 항상 False여야 한다.
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.has_permission("security_viewer", "unlock_ip")

    assert result is False


def test_list_admin_users_returns_rows_from_client(monkeypatch):
    rows = [
        {"id": 1, "username": "sktmaster123", "role": "super_admin", "created_at": "2026-01-01T00:00:00Z"},
        {"id": 2, "username": "sktviewer123", "role": "security_viewer", "created_at": "2026-01-02T00:00:00Z"},
    ]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.list_admin_users()

    assert result == rows


def test_get_admin_role_by_id_returns_stored_role(monkeypatch):
    fake_client = _FakeQuery(rows=[{"role": "security_admin"}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_admin_role_by_id(2)

    assert result == "security_admin"


def test_get_admin_role_by_id_none_when_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_admin_role_by_id(999)

    assert result is None


def test_create_admin_user_true_when_username_available(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.create_admin_user("sktviewer123", "TestViewer2026!", "security_viewer")

    assert result is True
    insert_calls = [call for call in fake_client.calls if call[0] == "insert"]
    assert len(insert_calls) == 1
    inserted_row = insert_calls[0][1][0]
    assert inserted_row["username"] == "sktviewer123"
    assert inserted_row["role"] == "security_viewer"
    assert inserted_row["password_hash"] != "TestViewer2026!"  # 평문이 아니라 해시로 저장됨


def test_create_admin_user_false_when_username_taken(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.create_admin_user("sktviewer123", "TestViewer2026!", "security_viewer")

    assert result is False
    assert not any(call[0] == "insert" for call in fake_client.calls)


def test_delete_admin_user_true_when_row_was_deleted(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 2}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.delete_admin_user(2)

    assert result is True
    assert ("delete", (), {}) in fake_client.calls


def test_delete_admin_user_false_when_id_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.delete_admin_user(999)

    assert result is False


def test_count_recent_distinct_usernames_dedupes_rows(monkeypatch):
    # 같은 아이디("hyun")로 두 번, 다른 아이디("guest")로 한 번 실패한 상황을 흉내낸다.
    # 행은 3개지만 서로 다른 아이디는 2개여야 한다 — Brute Force(1개)와
    # Password Spraying(2개 이상)을 구분하려면 이 dedup이 정확해야 한다.
    rows = [{"username": "hyun"}, {"username": "hyun"}, {"username": "guest"}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.count_recent_distinct_usernames("1.2.3.4")

    assert result == 2


def test_verify_user_credentials_true_for_correct_password(monkeypatch):
    stored_hash = generate_password_hash("correct-horse-battery-staple")
    fake_client = _FakeQuery(rows=[{"password_hash": stored_hash}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.verify_user_credentials("hyun", "correct-horse-battery-staple")

    assert result is True


def test_verify_user_credentials_false_for_wrong_password(monkeypatch):
    stored_hash = generate_password_hash("correct-horse-battery-staple")
    fake_client = _FakeQuery(rows=[{"password_hash": stored_hash}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.verify_user_credentials("hyun", "wrong-password")

    assert result is False


def test_verify_user_credentials_false_when_username_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.verify_user_credentials("no_such_user", "anything")

    assert result is False


def test_verify_user_credentials_hashes_even_when_username_not_found(monkeypatch):
    # 타이밍 사이드채널 방지 확인 (L7 공격 보강 계획 Tier 3) — 아이디가 없을
    # 때도 check_password_hash가 실제로 호출돼야 한다. 예전 코드는 아이디가
    # 없으면 이 호출 자체를 건너뛰어서, "즉시 반환"과 "해시 비교 후 반환"
    # 사이에 응답 시간 차이가 생겼다.
    from db import users as users_module

    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    calls = []
    original_check = users_module.check_password_hash

    def spy_check_password_hash(pwhash, password):
        calls.append((pwhash, password))
        return original_check(pwhash, password)

    monkeypatch.setattr(users_module, "check_password_hash", spy_check_password_hash)

    db.verify_user_credentials("no_such_user", "anything")

    assert len(calls) == 1
    assert calls[0][0] == users_module._DUMMY_PASSWORD_HASH


def test_count_recent_distinct_ips_by_username_dedupes_rows(monkeypatch):
    # 같은 IP("1.1.1.1")에서 두 번, 다른 IP("2.2.2.2")에서 한 번 실패한 상황을
    # 흉내낸다. 행은 3개지만 서로 다른 IP는 2개여야 한다 — 분산 브루트포스
    # (여러 IP가 한 계정을 노림) 판단이 정확하려면 이 dedup이 정확해야 한다.
    rows = [{"ip_address": "1.1.1.1"}, {"ip_address": "1.1.1.1"}, {"ip_address": "2.2.2.2"}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.count_recent_distinct_ips_by_username("victim")

    assert result == 2


def test_count_recent_distinct_admin_usernames_dedupes_rows(monkeypatch):
    rows = [{"username": "admin1"}, {"username": "admin2"}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.count_recent_distinct_admin_usernames("1.2.3.4")

    assert result == 2


def test_log_not_found_attempt_inserts_ip_and_path(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.log_not_found_attempt("1.2.3.4", "/wp-admin")

    assert ("insert", ({"ip_address": "1.2.3.4", "path": "/wp-admin"},), {}) in fake_client.calls


def test_count_recent_not_found_attempts_returns_count(monkeypatch):
    fake_client = _FakeQuery(rows=[], count=11)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.count_recent_not_found_attempts("1.2.3.4")

    assert result == 11


def test_log_unauthorized_attempt_inserts_ip_and_path(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.log_unauthorized_attempt("1.2.3.4", "/api/status")

    assert ("insert", ({"ip_address": "1.2.3.4", "path": "/api/status"},), {}) in fake_client.calls


def test_count_recent_unauthorized_attempts_returns_count(monkeypatch):
    fake_client = _FakeQuery(rows=[], count=11)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.count_recent_unauthorized_attempts("1.2.3.4")

    assert result == 11


def test_log_page_access_attempt_inserts_ip_and_path(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.log_page_access_attempt("1.2.3.4", "/board")

    assert ("insert", ({"ip_address": "1.2.3.4", "path": "/board"},), {}) in fake_client.calls


def test_count_recent_page_access_attempts_returns_count(monkeypatch):
    fake_client = _FakeQuery(rows=[], count=21)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.count_recent_page_access_attempts("1.2.3.4", "/board")

    assert result == 21


def test_list_users_returns_rows_and_count_from_client(monkeypatch):
    rows = [
        {"id": 2, "username": "bbb", "email": "bbb@example.com", "created_at": "2026-09-02T00:00:00Z"},
        {"id": 1, "username": "aaa", "email": "aaa@example.com", "created_at": "2026-09-01T00:00:00Z"},
    ]
    fake_client = _FakeQuery(rows=rows, count=17)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result, total = db.list_users()

    # list_users는 정렬 자체를 하지 않는다(Supabase 쪽에 정렬을 맡긴다) — 그래서
    # 여기서는 "가짜 클라이언트가 준 데이터를 그대로 전달하는지"만 확인한다.
    assert result == rows
    assert total == 17


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


# ============================================================================
# 게시판/댓글 함수 테스트 (docs/board-comment/plan_board.md 참고)
# ============================================================================

def test_create_post_returns_inserted_row(monkeypatch):
    inserted_row = {"id": 1, "author_username": "hyun", "title": "제목", "body": "내용"}
    fake_client = _FakeQuery(rows=[inserted_row])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.create_post("hyun", "제목", "내용")

    assert result == inserted_row
    assert (
        "insert",
        ({"author_username": "hyun", "title": "제목", "body": "내용"},),
        {},
    ) in fake_client.calls


def test_get_post_none_when_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_post(999) is None


def test_list_posts_uses_range_for_pagination(monkeypatch):
    rows = [{"id": 1, "title": "글1"}]
    fake_client = _FakeQuery(rows=rows, count=42)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result, total = db.list_posts(page=2, page_size=10)

    assert result == rows
    assert total == 42
    # 2페이지, 페이지당 10개 → 11~20번째(0-index 10~19) 행을 요청해야 한다.
    assert ("range", (10, 19), {}) in fake_client.calls


def test_list_posts_total_is_zero_when_count_missing(monkeypatch):
    fake_client = _FakeQuery(rows=[], count=None)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    _, total = db.list_posts(page=1, page_size=10)

    assert total == 0


def test_delete_post_true_when_row_was_deleted(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 3}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.delete_post(3) is True


def test_delete_post_false_when_id_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.delete_post(999) is False


def test_get_comment_none_when_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_comment(999) is None


def test_create_comment_inserts_expected_row(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.create_comment(1, "hyun", "댓글 내용")

    assert (
        "insert",
        ({"post_id": 1, "author_username": "hyun", "body": "댓글 내용"},),
        {},
    ) in fake_client.calls


def test_list_comments_by_post_filters_by_post_id(monkeypatch):
    rows = [{"id": 1, "post_id": 5, "body": "댓글"}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.list_comments_by_post(5)

    assert result == rows
    assert ("eq", ("post_id", 5), {}) in fake_client.calls


def test_delete_comment_true_when_row_was_deleted(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 7}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.delete_comment(7) is True


# ============================================================================
# security_events 표 관련 함수 — 위험등급 통합 (security-risk-response-summary.md 5절)
# ============================================================================

def test_insert_security_event_inserts_expected_row(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.insert_security_event("WEB_SCANNING", "MEDIUM", "9.9.9.9", "/no-such-page", 11, "ALERTED")

    assert (
        "insert",
        (
            {
                "event_type": "WEB_SCANNING",
                "severity": "MEDIUM",
                "ip_address": "9.9.9.9",
                "path": "/no-such-page",
                "count": 11,
                "action": "ALERTED",
                "username": None,
            },
        ),
        {},
    ) in fake_client.calls


def test_list_security_events_returns_rows_and_count_from_client(monkeypatch):
    rows = [
        {"id": 2, "event_type": "WEB_SCANNING", "severity": "MEDIUM"},
        {"id": 1, "event_type": "BRUTE_FORCE", "severity": "CRITICAL"},
    ]
    fake_client = _FakeQuery(rows=rows, count=9)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result, total = db.list_security_events()

    assert result == rows
    assert total == 9


def test_resolve_security_event_true_when_row_was_updated(monkeypatch):
    # 아직 미해결(resolved_at이 비어있음)이었던 이벤트만 실제로 업데이트되므로,
    # Supabase가 업데이트된 행을 돌려주면 "진짜 처리됐다"는 뜻이다.
    fake_client = _FakeQuery(rows=[{"id": 5, "resolved_at": "2026-09-09T00:00:00Z"}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.resolve_security_event(5) is True
    assert ("is_", ("resolved_at", "null"), {}) in fake_client.calls


def test_resolve_security_event_false_when_already_resolved(monkeypatch):
    # 이미 처리된 이벤트는 is_("resolved_at", "null") 조건에 안 걸려 아무 행도
    # 업데이트되지 않는다 — 같은 버튼을 두 번 눌러도 안전해야 한다.
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.resolve_security_event(5) is False


def test_resolve_security_event_excludes_critical_severity(monkeypatch):
    # CRITICAL은 이 함수로 처리되면 안 된다 — 잠금이 아직 안 풀렸는데 이벤트만
    # "처리 완료"로 표시되는 상태를 막기 위해 severity 조건을 쿼리에 건다.
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.resolve_security_event(5)

    assert ("neq", ("severity", "CRITICAL"), {}) in fake_client.calls


def test_resolve_security_events_for_ip_filters_by_ip_and_critical_severity(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.resolve_security_events_for_ip("9.9.9.9")

    assert ("eq", ("ip_address", "9.9.9.9"), {}) in fake_client.calls
    assert ("eq", ("severity", "CRITICAL"), {}) in fake_client.calls


def test_get_unresolved_security_event_returns_row_when_exists(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1, "count": 5}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_unresolved_security_event("9.9.9.9", "SIGNUP_RATE_LIMIT") == {"id": 1, "count": 5}


def test_get_unresolved_security_event_returns_none_when_no_row(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_unresolved_security_event("9.9.9.9", "SIGNUP_RATE_LIMIT") is None


def test_update_security_event_count_updates_expected_row(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 7, "count": 6}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.update_security_event_count(7, 6)

    assert ("update", ({"count": 6},), {}) in fake_client.calls
    assert ("eq", ("id", 7), {}) in fake_client.calls


def test_insert_security_event_or_bump_inserts_when_no_conflict(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.insert_security_event_or_bump("SIGNUP_RATE_LIMIT", "HIGH", "9.9.9.9", "/signup", 5, "REJECTED")

    assert (
        "insert",
        (
            {
                "event_type": "SIGNUP_RATE_LIMIT",
                "severity": "HIGH",
                "ip_address": "9.9.9.9",
                "path": "/signup",
                "count": 5,
                "action": "REJECTED",
                "username": None,
            },
        ),
        {},
    ) in fake_client.calls


def test_insert_security_event_or_bump_falls_back_to_increment_on_conflict(monkeypatch):
    # 삽입이 idx_security_events_high_open_incident 유니크 인덱스에 걸려 실패하면
    # (동시 요청이 실제로 겹친 드문 경우), 새로 만드는 대신 이미 삽입된 행을 찾아
    # count만 올려야 한다.
    conflict = APIError({"code": "23505", "message": "duplicate key value violates unique constraint"})
    fake_client = _FakeQuery(rows=[{"id": 7, "count": 5}], raise_error=conflict)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.insert_security_event_or_bump("SIGNUP_RATE_LIMIT", "HIGH", "9.9.9.9", "/signup", 5, "REJECTED")

    assert (
        "insert",
        (
            {
                "event_type": "SIGNUP_RATE_LIMIT",
                "severity": "HIGH",
                "ip_address": "9.9.9.9",
                "path": "/signup",
                "count": 5,
                "action": "REJECTED",
                "username": None,
            },
        ),
        {},
    ) in fake_client.calls
    assert ("update", ({"count": 6},), {}) in fake_client.calls


def test_insert_security_event_or_bump_reraises_non_conflict_errors(monkeypatch):
    other_error = APIError({"code": "42501", "message": "permission denied"})
    fake_client = _FakeQuery(rows=[], raise_error=other_error)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    with pytest.raises(APIError):
        db.insert_security_event_or_bump("SIGNUP_RATE_LIMIT", "HIGH", "9.9.9.9", "/signup", 5, "REJECTED")


def test_delete_comment_false_when_id_not_found(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.delete_comment(999) is False


def test_get_latest_comment_info_with_comments(monkeypatch):
    rows = [{"id": 9, "created_at": "2026-09-04T12:00:00+00:00"}]
    fake_client = _FakeQuery(rows=rows, count=3)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_latest_comment_info(1)

    assert result == {"count": 3, "latest_at": "2026-09-04T12:00:00+00:00"}


def test_get_latest_comment_info_with_no_comments(monkeypatch):
    fake_client = _FakeQuery(rows=[], count=0)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_latest_comment_info(1)

    assert result == {"count": 0, "latest_at": None}


# ============================================================================
# security_incidents 표 관련 함수 (Track C guide27, SIEM 상관분석)
# ============================================================================

def test_list_security_incidents_returns_rows_and_count_from_client(monkeypatch):
    # list_security_events()와 동일한 페이지네이션 방식 — 관리자 대시보드의
    # "연관 사건" 표에 쓰인다.
    rows = [
        {"id": 2, "ip_address": "9.9.9.9", "event_types": ["BRUTE_FORCE", "WEB_SCANNING"], "status": "OPEN"},
        {"id": 1, "ip_address": "1.1.1.1", "event_types": ["UNAUTHORIZED_ACCESS", "WEB_SCANNING"], "status": "CLOSED"},
    ]
    fake_client = _FakeQuery(rows=rows, count=5)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result, total = db.list_security_incidents()

    assert result == rows
    assert total == 5


def test_get_recent_distinct_event_types_returns_sorted_unique_types(monkeypatch):
    rows = [{"event_type": "WEB_SCANNING"}, {"event_type": "BRUTE_FORCE"}, {"event_type": "WEB_SCANNING"}]
    fake_client = _FakeQuery(rows=rows)
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_recent_distinct_event_types("9.9.9.9", 5)

    assert result == ["BRUTE_FORCE", "WEB_SCANNING"]


def test_get_open_incident_returns_row_when_exists(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1, "event_types": ["BRUTE_FORCE"], "severity_max": "CRITICAL"}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = db.get_open_incident("9.9.9.9")

    assert result == {"id": 1, "event_types": ["BRUTE_FORCE"], "severity_max": "CRITICAL"}


def test_get_open_incident_returns_none_when_no_open_incident(monkeypatch):
    fake_client = _FakeQuery(rows=[])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    assert db.get_open_incident("9.9.9.9") is None


def test_close_open_incident_for_ip_filters_by_ip_and_open_status(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 1}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.close_open_incident_for_ip("9.9.9.9")

    assert ("eq", ("ip_address", "9.9.9.9"), {}) in fake_client.calls
    assert ("eq", ("status", "OPEN"), {}) in fake_client.calls
    assert ("update", ({"status": "CLOSED"},), {}) in fake_client.calls


def test_record_incident_inserts_new_incident_when_none_open(monkeypatch):
    from db import incidents as incidents_module

    # record_incident()는 db/incidents.py 안에서 get_open_incident을 이름으로
    # 직접 부르므로(같은 모듈 안), db.get_open_incident이 아니라
    # incidents_module.get_open_incident을 바꿔치기해야 실제로 적용된다.
    monkeypatch.setattr(incidents_module, "get_open_incident", lambda ip: None)
    calls = []

    def fake_insert_incident(ip, event_types, severity_max):
        calls.append((ip, event_types, severity_max))
        return 99

    monkeypatch.setattr(incidents_module, "_insert_incident", fake_insert_incident)
    monkeypatch.setattr(
        incidents_module,
        "_update_incident",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("열린 사건이 없는데 _update_incident가 호출되면 안 된다")
        ),
    )

    result = db.record_incident("9.9.9.9", ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")

    assert calls == [("9.9.9.9", ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")]
    # 새로 연 사건이므로 escalated는 항상 False에서 시작해야 한다(Track C guide28).
    assert result == {
        "id": 99,
        "event_types": ["BRUTE_FORCE", "WEB_SCANNING"],
        "severity_max": "CRITICAL",
        "escalated": False,
    }


def test_record_incident_merges_into_existing_open_incident(monkeypatch):
    from db import incidents as incidents_module

    existing = {"id": 5, "event_types": ["BRUTE_FORCE"], "severity_max": "MEDIUM", "escalated": False}
    monkeypatch.setattr(incidents_module, "get_open_incident", lambda ip: existing)
    monkeypatch.setattr(
        incidents_module,
        "_insert_incident",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("이미 열린 사건이 있는데 _insert_incident가 호출되면 안 된다")
        ),
    )
    calls = []
    monkeypatch.setattr(
        incidents_module,
        "_update_incident",
        lambda incident_id, event_types, severity_max: calls.append((incident_id, event_types, severity_max)),
    )

    # 새로 들어온 이벤트는 WEB_SCANNING/CRITICAL — 기존 사건(BRUTE_FORCE만, MEDIUM)과
    # 병합되면 event_types는 합집합, severity_max는 더 높은 쪽(CRITICAL)이어야 한다.
    result = db.record_incident("9.9.9.9", ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")

    assert calls == [(5, ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")]
    assert result == {
        "id": 5,
        "event_types": ["BRUTE_FORCE", "WEB_SCANNING"],
        "severity_max": "CRITICAL",
        "escalated": False,
    }


def test_record_incident_falls_back_to_merge_on_unique_violation(monkeypatch):
    # get_open_incident()로 확인했을 땐 없었지만(None), 그 확인과 삽입 사이의
    # 아주 짧은 틈에 동시 요청이 겹쳐 실제로는 이미 삽입돼 있던 경우(경쟁 조건)를
    # 흉내낸다 — 두 번째 get_open_incident() 호출에서는 그 사건을 찾아야 한다.
    from db import incidents as incidents_module

    lookups = [None, {"id": 9, "event_types": ["WEB_SCANNING"], "severity_max": "MEDIUM", "escalated": False}]
    monkeypatch.setattr(incidents_module, "get_open_incident", lambda ip: lookups.pop(0))

    conflict = APIError({"code": "23505", "message": "duplicate key value violates unique constraint"})

    def raising_insert(ip, event_types, severity_max):
        raise conflict

    monkeypatch.setattr(incidents_module, "_insert_incident", raising_insert)
    calls = []
    monkeypatch.setattr(
        incidents_module,
        "_update_incident",
        lambda incident_id, event_types, severity_max: calls.append((incident_id, event_types, severity_max)),
    )

    result = db.record_incident("9.9.9.9", ["BRUTE_FORCE"], "CRITICAL")

    assert calls == [(9, ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")]
    assert result == {
        "id": 9,
        "event_types": ["BRUTE_FORCE", "WEB_SCANNING"],
        "severity_max": "CRITICAL",
        "escalated": False,
    }


def test_record_incident_reraises_non_conflict_errors(monkeypatch):
    from db import incidents as incidents_module

    monkeypatch.setattr(incidents_module, "get_open_incident", lambda ip: None)
    other_error = APIError({"code": "42501", "message": "permission denied"})

    def raising_insert(ip, event_types, severity_max):
        raise other_error

    monkeypatch.setattr(incidents_module, "_insert_incident", raising_insert)

    with pytest.raises(APIError):
        db.record_incident("9.9.9.9", ["BRUTE_FORCE"], "CRITICAL")


def test_insert_incident_returns_new_row_id_from_client(monkeypatch):
    from db import incidents as incidents_module

    fake_client = _FakeQuery(rows=[{"id": 17}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    result = incidents_module._insert_incident("9.9.9.9", ["BRUTE_FORCE", "WEB_SCANNING"], "CRITICAL")

    assert result == 17
    inserted = next(call for call in fake_client.calls if call[0] == "insert")
    assert inserted[1][0]["escalated"] is False
    assert inserted[1][0]["status"] == "OPEN"


def test_mark_incident_escalated_updates_expected_row(monkeypatch):
    fake_client = _FakeQuery(rows=[{"id": 42, "escalated": True}])
    monkeypatch.setattr(db, "get_client", lambda: fake_client)

    db.mark_incident_escalated(42)

    assert ("update", ({"escalated": True},), {}) in fake_client.calls
    assert ("eq", ("id", 42), {}) in fake_client.calls
