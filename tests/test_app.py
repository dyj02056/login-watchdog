# ============================================================================
# test_app.py — Flask 테스트 클라이언트로 실제 라우트(/login, /admin/*, /api/*)를
# 검증하는 통합 테스트
#
# 지금까지의 테스트(test_detector.py, test_db.py 등)는 함수 하나하나를 따로
# 떼어내 검증하는 "단위 테스트"였다. guide08_testing.md도 "진짜 서버 없이
# 코드만 자동으로 검증"으로 범위를 단위 테스트에 의도적으로 한정해뒀었다.
#
# 하지만 단위 테스트만으로는 "라우트 등록이 맞는지", "login_required 문지기가
# 실제로 막아주는지", "CSRF 토큰 없이 폼을 제출하면 정말 거부되는지" 같은
# 부품들이 "조립됐을 때"의 동작은 확인할 수 없다 — 부품 하나하나가 멀쩡해도
# 조립이 잘못되면(예: 데코레이터를 빼먹음) 개별 테스트는 여전히 통과하기
# 때문이다. Flask의 test_client()는 진짜 네트워크 서버를 띄우지 않고도 이
# "조립된 상태"를 검증할 수 있게 해준다.
#
# db/detector/soar/geoip 쪽 실제 Supabase 접속은 conftest.py의 flask_app
# fixture가 이미 막아뒀고(가짜 환경변수 + ensure_bootstrap_admin 무력화),
# 각 테스트는 그 테스트가 실제로 거치는 함수만 monkeypatch로 가짜 응답을
# 채워넣는다 — 나머지 함수가 호출되면 진짜 Supabase로 네트워크 요청이 나가
# 테스트가 느려지거나 실패하므로, "이 테스트에 필요한 것만" 최소한으로 막는다.
# ============================================================================

import detector
import soar
import geoip
import db


def get_csrf_token(client, path: str) -> str:
    """`path`(GET)가 돌려주는 HTML에서 hidden csrf_token input의 값을 뽑아온다.

    CSRF가 켜진 상태로 폼 제출을 테스트하려면, 먼저 화면을 한 번 GET으로 받아와
    서버가 그 순간 발급한 진짜 토큰 값을 알아내야 한다(문자열을 아무거나 지어내면
    당연히 검증에 실패한다) — 브라우저가 폼을 로드했다가 제출하는 흐름과 동일하다.
    admin_dashboard.html처럼 hidden input 대신 <meta name="csrf-token"> 태그로
    토큰을 내려주는 화면도 있으므로, 둘 다 찾아본다.
    """
    response = client.get(path)
    html = response.get_data(as_text=True)
    for marker in ('name="csrf_token" value="', 'name="csrf-token" content="'):
        if marker in html:
            start = html.index(marker) + len(marker)
            end = html.index('"', start)
            return html[start:end]
    raise AssertionError(f"{path} 응답에서 csrf 토큰을 찾지 못했습니다")


# ============================================================================
# /login — 감시 대상 로그인 화면
# ============================================================================

def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "csrf_token" in response.get_data(as_text=True)


def test_login_success_creates_session_and_redirects(client, monkeypatch):
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(db, "verify_user_credentials", lambda username, password: True)
    monkeypatch.setattr(db, "log_attempt", lambda ip, username, success: None)
    monkeypatch.setattr(
        db, "get_user_by_username", lambda username: {"id": 1, "username": username}
    )

    token = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={"username": "hyun", "password": "correct-password", "csrf_token": token},
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/dashboard"
    with client.session_transaction() as sess:
        assert sess["username"] == "hyun"
        assert sess["user_id"] == 1


def test_login_locked_ip_short_circuits_before_checking_credentials(client, monkeypatch):
    # 잠긴 IP라면 verify_user_credentials가 아예 호출되면 안 된다 — 호출되면
    # 이 테스트가 그 자리에서 바로 실패하도록 monkeypatch로 "함정"을 심어둔다.
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("잠긴 IP인데 verify_user_credentials가 호출되었다")

    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(db, "verify_user_credentials", _fail_if_called)

    token = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={"username": "hyun", "password": "whatever", "csrf_token": token},
    )

    assert "잠긴 계정입니다" in response.get_data(as_text=True)


def test_login_failure_over_threshold_triggers_lockout(client, monkeypatch):
    enforce_lockout_calls = []

    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(db, "verify_user_credentials", lambda username, password: False)
    monkeypatch.setattr(db, "log_attempt", lambda ip, username, success: None)
    monkeypatch.setattr(detector, "is_suspicious", lambda ip: (True, 6))
    monkeypatch.setattr(
        soar, "enforce_lockout", lambda ip, failure_count: enforce_lockout_calls.append((ip, failure_count))
    )

    token = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={"username": "hyun", "password": "wrong", "csrf_token": token},
    )

    assert len(enforce_lockout_calls) == 1
    assert "잠긴 계정입니다" in response.get_data(as_text=True)


def test_login_post_without_csrf_token_is_rejected(client, monkeypatch):
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)

    response = client.post("/login", data={"username": "hyun", "password": "whatever"})

    assert response.status_code == 400


# ============================================================================
# /admin/login — 관리자 로그인 브루트포스 방어 (18단계 보안 점검 보완)
# — /login과 똑같은 구조의 테스트를 관리자 경로에도 그대로 재현해서, 두 경로가
#   실제로 같은 수준의 방어를 받는지 확인한다.
# ============================================================================

def test_admin_login_locked_ip_short_circuits_before_checking_credentials(client, monkeypatch):
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("잠긴 IP인데 verify_admin_credentials가 호출되었다")

    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: True)
    monkeypatch.setattr(db, "verify_admin_credentials", _fail_if_called)

    token = get_csrf_token(client, "/admin/login")
    response = client.post(
        "/admin/login",
        data={"username": "test-admin", "password": "whatever", "csrf_token": token},
    )

    assert "잠긴 계정입니다" in response.get_data(as_text=True)


def test_admin_login_failure_over_threshold_triggers_lockout(client, monkeypatch):
    enforce_lockout_calls = []

    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(db, "verify_admin_credentials", lambda username, password: False)
    monkeypatch.setattr(db, "log_admin_attempt", lambda username, success, ip: None)
    monkeypatch.setattr(detector, "is_admin_suspicious", lambda ip: (True, 6))
    monkeypatch.setattr(
        soar, "enforce_lockout", lambda ip, failure_count: enforce_lockout_calls.append((ip, failure_count))
    )

    token = get_csrf_token(client, "/admin/login")
    response = client.post(
        "/admin/login",
        data={"username": "test-admin", "password": "wrong", "csrf_token": token},
    )

    assert len(enforce_lockout_calls) == 1
    assert "잠긴 계정입니다" in response.get_data(as_text=True)


def test_admin_login_success_still_creates_session_when_not_suspicious(client, monkeypatch):
    # 방어 로직을 추가하면서 정상 로그인 흐름을 망가뜨리지 않았는지 확인한다.
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(db, "verify_admin_credentials", lambda username, password: True)
    monkeypatch.setattr(db, "log_admin_attempt", lambda username, success, ip: None)

    token = get_csrf_token(client, "/admin/login")
    response = client.post(
        "/admin/login",
        data={"username": "test-admin", "password": "correct", "csrf_token": token},
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/admin/dashboard"
    with client.session_transaction() as sess:
        assert sess["admin_username"] == "test-admin"


# ============================================================================
# /signup — 회원가입 입력 검증
# ============================================================================

def test_signup_rejects_username_with_html_special_characters(client, monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(detector, "is_signup_rate_limited", lambda ip: False)
    monkeypatch.setattr(db, "log_signup_attempt", lambda ip: None)

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("검증에 실패한 아이디인데 create_user가 호출되었다")

    monkeypatch.setattr(db, "create_user", _fail_if_called)

    token = get_csrf_token(client, "/signup")
    response = client.post(
        "/signup",
        data={
            "username": "<img src=x onerror=alert(1)>",
            "email": "test@example.com",
            "password": "password123",
            "password_confirm": "password123",
            "csrf_token": token,
        },
    )

    assert "아이디는 영문자, 숫자, 밑줄" in response.get_data(as_text=True)


def test_signup_rejects_short_password(client, monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(detector, "is_signup_rate_limited", lambda ip: False)
    monkeypatch.setattr(db, "log_signup_attempt", lambda ip: None)

    token = get_csrf_token(client, "/signup")
    response = client.post(
        "/signup",
        data={
            "username": "hyun_2",
            "email": "test@example.com",
            "password": "short",
            "password_confirm": "short",
            "csrf_token": token,
        },
    )

    assert "8자 이상" in response.get_data(as_text=True)


def test_signup_accepts_valid_input(client, monkeypatch):
    created_with = []
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(detector, "is_signup_rate_limited", lambda ip: False)
    monkeypatch.setattr(db, "log_signup_attempt", lambda ip: None)
    monkeypatch.setattr(
        db,
        "create_user",
        lambda username, email, password: created_with.append((username, email, password)) or True,
    )

    token = get_csrf_token(client, "/signup")
    response = client.post(
        "/signup",
        data={
            "username": "hyun_2",
            "email": "hyun2@example.com",
            "password": "password123",
            "password_confirm": "password123",
            "csrf_token": token,
        },
    )

    assert response.status_code == 302
    assert created_with == [("hyun_2", "hyun2@example.com", "password123")]


def test_signup_rejects_when_rate_limited(client, monkeypatch):
    monkeypatch.setattr(db, "get_signup_enabled", lambda: True)
    monkeypatch.setattr(detector, "is_signup_rate_limited", lambda ip: True)

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("빈도 제한에 걸렸는데 log_signup_attempt가 호출되었다")

    monkeypatch.setattr(db, "log_signup_attempt", _fail_if_called)

    token = get_csrf_token(client, "/signup")
    response = client.post(
        "/signup",
        data={
            "username": "hyun_3",
            "email": "hyun3@example.com",
            "password": "password123",
            "password_confirm": "password123",
            "csrf_token": token,
        },
    )

    assert "너무 많은 가입 시도" in response.get_data(as_text=True)


# ============================================================================
# 관리자 대시보드/API — login_required 문지기 및 API 흐름
# ============================================================================

def test_admin_dashboard_redirects_to_login_when_not_authenticated(client):
    response = client.get("/admin/dashboard")
    assert response.status_code == 302
    assert response.headers["Location"] == "/admin/login"


def test_api_status_returns_401_json_when_not_authenticated(client):
    response = client.get("/api/status")
    assert response.status_code == 401
    assert response.get_json()["error"] == "로그인이 필요합니다."


def test_api_unlock_requires_ip_in_body(client, monkeypatch):
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)

    with client.session_transaction() as sess:
        sess["admin_username"] = "test-admin"

    token = get_csrf_token(client, "/admin/dashboard")
    response = client.post(
        "/api/unlock",
        json={},
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 400


def test_api_unlock_releases_ip_when_authenticated(client, monkeypatch):
    monkeypatch.setattr(soar, "manual_release", lambda ip: ip == "1.2.3.4")

    with client.session_transaction() as sess:
        sess["admin_username"] = "test-admin"

    token = get_csrf_token(client, "/admin/dashboard")
    response = client.post(
        "/api/unlock",
        json={"ip": "1.2.3.4"},
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 200
    assert response.get_json() == {"success": True}


def test_api_unlock_without_csrf_header_is_rejected(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["admin_username"] = "test-admin"

    response = client.post("/api/unlock", json={"ip": "1.2.3.4"})

    assert response.status_code == 400
