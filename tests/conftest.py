# ============================================================================
# conftest.py — pytest가 테스트를 실행하기 전에 자동으로 읽어들이는 "공용 준비물" 파일
#
# app.py는 모듈 맨 위에서(import되는 순간) 아래 두 가지 일을 실제로 저지른다.
# 1) os.environ["SECRET_KEY"] 같은 필수 환경변수를 즉시 읽는다 — 없으면 KeyError로
#    죽는다.
# 2) db.ensure_bootstrap_admin()을 호출해서 진짜 Supabase에 접속을 시도한다.
#
# 테스트(그리고 CI)는 진짜 Supabase 자격 증명이 없어도 항상 통과해야 하므로,
# 여기서 "app.py를 import하기 전에" 가짜 환경변수를 채워넣고 ensure_bootstrap_admin을
# 아무 일도 안 하는 함수로 바꿔치기해둔다. 이 파일의 fixture를 쓰는 테스트만 이
# 준비된 상태에서 app 모듈을 (다시) import하게 된다.
# ============================================================================

import sys

import pytest


@pytest.fixture
def flask_app(monkeypatch):
    """CSRF 보호가 켜진 채로(운영과 동일한 조건) 테스트용 Flask 앱 인스턴스를 만들어준다."""
    monkeypatch.setenv("SECRET_KEY", "test-only-secret-key")
    monkeypatch.setenv("ADMIN_USERNAME", "test-admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("SUPABASE_URL", "http://supabase.invalid")
    monkeypatch.setenv("SUPABASE_KEY", "test-supabase-key")

    import db
    import detector
    monkeypatch.setattr(db, "ensure_bootstrap_admin", lambda: None)

    # track_page_access()(21단계, attack_response_state.md 구현 대상 #4)는 GET으로
    # 렌더링되는 거의 모든 페이지에서 매번 실행되는 before_request 훅이라, 이걸
    # 기본으로 막아두지 않으면 이 파일과 무관한 기존 테스트 수십 개가 전부 진짜
    # Supabase로 네트워크 요청을 시도하게 된다. 그래서 다른 fixture들과 달리
    # "이 훅과 관련된 걸 테스트하는 몇 개"만 각자 필요한 값으로 다시
    # monkeypatch하고, 나머지 테스트는 이 기본값(수상하지 않음)으로 그냥 통과한다.
    monkeypatch.setattr(db, "log_page_access_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_page_access_suspicious", lambda ip, path: (False, 1, False))

    # track_api_access()(Track C guide29, 매크로/봇 탐지)도 /api/*로 가는 거의
    # 모든 요청마다 실행되는 before_request 훅이라, 위 track_page_access()와
    # 같은 이유로 기본값을 막아둔다 — 이걸 막아두지 않으면 /api/status 등을
    # 호출하는 기존 테스트 수십 개가 전부 진짜 Supabase로 요청을 시도하게 된다.
    monkeypatch.setattr(db, "log_api_access", lambda ip, path, method: None)
    monkeypatch.setattr(detector, "is_macro_pattern_suspicious", lambda ip: (False, 1, False))

    # 관리자 문지기(guide37)가 요청마다 세션의 admin_id로 계정을 조회한다. 기본값은 "세션의
    # 아이디 그대로인 security_admin 계정이 있다"로 둔다 — role이 중요한 테스트는
    # tests/admin_session.py의 stub_admin_role()로, 삭제된 계정을 흉내낼 테스트는
    # get_admin_by_id를 직접 바꿔치기한다.
    from tests.admin_session import stub_admin_role
    stub_admin_role(monkeypatch, "security_admin")

    # 관리자 계정 단위 잠금(guide38)이 /admin/login과 /api/status에 새로 끼워 넣은 조회 —
    # 기본값은 "잠긴 관리자 계정 없음, 실패 0회"로 둔다. 이 기능을 테스트하는 곳만 다시 바꾼다.
    monkeypatch.setattr(db, "list_expired_active_admin_account_lockouts", lambda: [])
    monkeypatch.setattr(db, "list_active_admin_account_lockouts", lambda: [])
    monkeypatch.setattr(db, "get_active_admin_account_lockout", lambda username: None)
    monkeypatch.setattr(db, "count_recent_admin_failures_by_username", lambda username: 0)

    # 이전 테스트가 이미 app을 import해둔 상태일 수 있으므로, sys.modules에서
    # 지워서 위의 monkeypatch가 적용된 새 환경으로 app.py가 다시 실행되게 한다.
    sys.modules.pop("app", None)
    import app as app_module

    app_module.app.config.update(TESTING=True)
    yield app_module.app

    sys.modules.pop("app", None)


@pytest.fixture
def client(flask_app):
    """flask_app의 테스트 클라이언트. 실제 서버를 띄우지 않고도 라우트에 요청을 보내볼 수 있다."""
    return flask_app.test_client()


# ============================================================================
# 영구 잠금(guide33)이 기존 코드 경로에 새로 끼워 넣은 DB 호출을 막아두는 공용 준비물
#
# soar.enforce_lockout() 등이 이제 잠금 이력(lock_history)을 남기고, 로그인/가입/관리자
# API가 영구 잠금 상태를 한 번 더 확인한다. 영구 잠금과 무관한 기존 테스트가 이 새 호출
# 때문에 진짜 Supabase로 네트워크 요청을 시도하지 않도록, 기본값(영구 잠금 없음)으로
# 막아둔다. 영구 잠금/복구 자체를 테스트하는 파일은 모듈 맨 위에
# `pytestmark = pytest.mark.real_lockdown`을 달아서 이 기본값을 끄고 자기가 필요한 것만
# monkeypatch한다.
# ============================================================================

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_lockdown: 영구 잠금 기본 stub(autouse)을 끄고 실제 함수를 테스트한다"
    )


@pytest.fixture(autouse=True)
def _stub_permanent_lock_defaults(request, monkeypatch):
    if request.node.get_closest_marker("real_lockdown"):
        return

    import db
    import detector
    import lockdown

    monkeypatch.setattr(db, "insert_lock_history", lambda *a, **k: None)
    monkeypatch.setattr(db, "count_lock_history", lambda *a, **k: 0)
    monkeypatch.setattr(db, "get_account_lockout_row", lambda username: None)
    # is_locked()를 True로 흉내낸 기존 테스트가 "임시 잠금"으로 취급되게 한다.
    monkeypatch.setattr(detector, "get_ip_lock_state", lambda ip: detector.LOCK_STATE_TEMPORARY)
    monkeypatch.setattr(detector, "get_account_lock_state", lambda username: detector.LOCK_STATE_TEMPORARY)
    monkeypatch.setattr(lockdown, "consider_incident_promotion", lambda ip, incident: None)
    monkeypatch.setattr(lockdown, "close_incident_if_configured", lambda incident: None)
    monkeypatch.setattr(lockdown, "is_permanent_ip", lambda ip: False)
    monkeypatch.setattr(lockdown, "is_permanent_account", lambda username: False)
    # /api/status가 새로 조회하는 영구 잠금·복구 카드용 데이터
    monkeypatch.setattr(db, "list_recent_recovery_requests", lambda limit=20: [])
    monkeypatch.setattr(db, "list_active_ip_exemptions", lambda limit=20: [])
    monkeypatch.setattr(db, "list_role_permissions", lambda role: [])
    monkeypatch.setattr(db, "get_email_statuses", lambda usernames: {})
    # 회원 화면 문지기(member_login_required)의 세션 세대 번호 확인(guide35) — 기존 회원 화면
    # 테스트는 세대 번호를 모르므로 "변경 없음(0)"으로 둔다.
    monkeypatch.setattr(db, "get_user_session_version", lambda user_id: 0)
