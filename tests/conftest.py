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
    monkeypatch.setattr(detector, "is_page_access_suspicious", lambda ip, path: (False, 1))

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
