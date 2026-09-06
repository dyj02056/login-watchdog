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
    # 서로 다른 아이디 3개로 실패했다고 흉내내서(Password Spraying 시나리오),
    # 그 값이 enforce_lockout까지 그대로 전달되는지 확인한다.
    monkeypatch.setattr(detector, "count_distinct_usernames", lambda ip: 3)
    monkeypatch.setattr(
        soar,
        "enforce_lockout",
        lambda ip, failure_count, distinct_usernames: enforce_lockout_calls.append(
            (ip, failure_count, distinct_usernames)
        ),
    )

    token = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={"username": "hyun", "password": "wrong", "csrf_token": token},
    )

    assert enforce_lockout_calls[0][1:] == (6, 3)
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
    monkeypatch.setattr(detector, "count_distinct_admin_usernames", lambda ip: 1)
    monkeypatch.setattr(
        soar,
        "enforce_lockout",
        lambda ip, failure_count, distinct_usernames: enforce_lockout_calls.append(
            (ip, failure_count, distinct_usernames)
        ),
    )

    token = get_csrf_token(client, "/admin/login")
    response = client.post(
        "/admin/login",
        data={"username": "test-admin", "password": "wrong", "csrf_token": token},
    )

    assert enforce_lockout_calls[0][1:] == (6, 1)
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


def test_api_status_returns_401_json_when_not_authenticated(client, monkeypatch):
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 1))

    response = client.get("/api/status")
    assert response.status_code == 401
    assert response.get_json()["error"] == "로그인이 필요합니다."


# ============================================================================
# login_required의 401 분기 — Unauthorized Access(세션 없이 관리자 API 반복
# 호출) 탐지 (21단계, attack_response_state.md 구현 대상 #2)
# ============================================================================

def test_unauthorized_api_access_logs_attempt(client, monkeypatch):
    logged = []
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: logged.append((ip, path)))
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 1))

    client.get("/api/status")

    assert logged == [("127.0.0.1", "/api/status")]


def test_unauthorized_api_access_alerts_exactly_when_crossing_threshold(client, monkeypatch):
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (True, 11))
    notify_calls = []
    monkeypatch.setattr(
        soar, "notify_unauthorized_access", lambda ip, count, path: notify_calls.append((ip, count, path))
    )

    client.get("/api/status")

    assert notify_calls == [("127.0.0.1", 11, "/api/status")]


def test_unauthorized_api_access_does_not_alert_again_after_threshold_crossing(client, monkeypatch):
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (True, 15))

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("임계값을 이미 넘긴 뒤인데 notify_unauthorized_access가 또 호출되었다")

    monkeypatch.setattr(soar, "notify_unauthorized_access", _fail_if_called)

    response = client.get("/api/status")

    assert response.status_code == 401


def test_unauthorized_api_access_does_not_alert_below_threshold(client, monkeypatch):
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 3))

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("아직 임계값 미만인데 notify_unauthorized_access가 호출되었다")

    monkeypatch.setattr(soar, "notify_unauthorized_access", _fail_if_called)

    response = client.get("/api/status")

    assert response.status_code == 401


# ============================================================================
# track_page_access() — 반복 페이지 접근 탐지
# (21단계, attack_response_state.md 구현 대상 #4)
# ============================================================================

def test_page_access_logs_get_request_to_real_page(client, monkeypatch):
    logged = []
    monkeypatch.setattr(db, "log_page_access_attempt", lambda ip, path: logged.append((ip, path)))
    monkeypatch.setattr(detector, "is_page_access_suspicious", lambda ip, path: (False, 1))

    client.get("/login")

    assert logged == [("127.0.0.1", "/login")]


def test_page_access_alerts_exactly_when_crossing_threshold(client, monkeypatch):
    monkeypatch.setattr(db, "log_page_access_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_page_access_suspicious", lambda ip, path: (True, 21))  # threshold(20) + 1
    notify_calls = []
    monkeypatch.setattr(
        soar, "notify_page_access", lambda ip, count, path: notify_calls.append((ip, count, path))
    )

    client.get("/login")

    assert notify_calls == [("127.0.0.1", 21, "/login")]


def test_page_access_does_not_alert_again_after_threshold_crossing(client, monkeypatch):
    monkeypatch.setattr(db, "log_page_access_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_page_access_suspicious", lambda ip, path: (True, 25))

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("임계값을 이미 넘긴 뒤인데 notify_page_access가 또 호출되었다")

    monkeypatch.setattr(soar, "notify_page_access", _fail_if_called)

    response = client.get("/login")

    assert response.status_code == 200


def test_page_access_does_not_alert_below_threshold(client, monkeypatch):
    monkeypatch.setattr(db, "log_page_access_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_page_access_suspicious", lambda ip, path: (False, 3))

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("아직 임계값 미만인데 notify_page_access가 호출되었다")

    monkeypatch.setattr(soar, "notify_page_access", _fail_if_called)

    response = client.get("/login")

    assert response.status_code == 200


def test_page_access_ignores_static_files(client, monkeypatch):
    # 정적 파일(endpoint="static")은 폴링 API와 마찬가지로 관찰 대상에서 빠져야 한다.
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("정적 파일 요청인데 log_page_access_attempt가 호출되었다")

    monkeypatch.setattr(db, "log_page_access_attempt", _fail_if_called)

    client.get("/css/auth.css")  # public/css/auth.css — static_url_path=""로 서빙됨


def test_page_access_ignores_polling_endpoints(client, monkeypatch):
    # /api/status(대시보드 자동 폴링)는 로그인 세션이 있어도 없어도 관찰 대상에서 빠져야 한다.
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("자동 폴링 API인데 log_page_access_attempt가 호출되었다")

    monkeypatch.setattr(db, "log_page_access_attempt", _fail_if_called)
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 1))

    client.get("/api/status")


def test_page_access_ignores_nonexistent_paths(client, monkeypatch):
    # 존재하지 않는 경로(request.url_rule is None)는 not_found_attempts가 따로
    # 기록하므로, track_page_access()에서 중복으로 기록하면 안 된다.
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("존재하지 않는 경로인데 log_page_access_attempt가 호출되었다")

    monkeypatch.setattr(db, "log_page_access_attempt", _fail_if_called)
    monkeypatch.setattr(db, "log_not_found_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_web_scanning", lambda ip: (False, 1))

    client.get("/no-such-page")


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


# ============================================================================
# /board — 게시판 (docs/board-comment/plan_board.md 참고)
# — 전부 member_login_required로 보호되므로(회원 전용, 결정 #1), 대부분의
#   테스트는 먼저 세션에 username/user_id를 심어 "로그인한 회원"을 흉내낸다.
# ============================================================================

def _login_as_member(client, username="hyun", user_id=1):
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["user_id"] = user_id


def test_board_list_redirects_to_login_when_not_authenticated(client):
    response = client.get("/board")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_board_new_redirects_to_login_when_not_authenticated(client):
    response = client.get("/board/new")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_board_new_submit_creates_post_and_redirects(client, monkeypatch):
    _login_as_member(client)
    monkeypatch.setattr(detector, "is_post_rate_limited", lambda ip: False)
    monkeypatch.setattr(db, "log_post_attempt", lambda ip: None)
    monkeypatch.setattr(
        db, "create_post", lambda author, title, body: {"id": 42, "author_username": author}
    )

    token = get_csrf_token(client, "/board/new")
    response = client.post(
        "/board/new",
        data={"title": "제목", "body": "내용", "csrf_token": token},
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/board/42"


def test_board_new_submit_rejects_when_rate_limited(client, monkeypatch):
    _login_as_member(client)
    monkeypatch.setattr(detector, "is_post_rate_limited", lambda ip: True)

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("빈도 제한에 걸렸는데 create_post가 호출되었다")

    monkeypatch.setattr(db, "create_post", _fail_if_called)

    token = get_csrf_token(client, "/board/new")
    response = client.post(
        "/board/new",
        data={"title": "제목", "body": "내용", "csrf_token": token},
    )

    assert "너무 많은 게시글 작성 시도" in response.get_data(as_text=True)


def test_board_new_submit_without_csrf_token_is_rejected(client, monkeypatch):
    _login_as_member(client)
    monkeypatch.setattr(detector, "is_post_rate_limited", lambda ip: False)

    response = client.post("/board/new", data={"title": "제목", "body": "내용"})

    assert response.status_code == 400


def test_board_new_submit_rejects_empty_title(client, monkeypatch):
    _login_as_member(client)
    monkeypatch.setattr(detector, "is_post_rate_limited", lambda ip: False)
    monkeypatch.setattr(db, "log_post_attempt", lambda ip: None)

    token = get_csrf_token(client, "/board/new")
    response = client.post(
        "/board/new",
        data={"title": "", "body": "내용", "csrf_token": token},
    )

    assert "제목과 내용을 모두 입력해주세요" in response.get_data(as_text=True)


def test_board_edit_submit_rejects_when_rate_limited(client, monkeypatch):
    _login_as_member(client, username="hyun")
    post = {
        "id": 1,
        "author_username": "hyun",
        "title": "제목",
        "body": "내용",
        "created_at": "2026-09-04T12:00:00+00:00",
    }
    monkeypatch.setattr(db, "get_post", lambda post_id: post)
    monkeypatch.setattr(detector, "is_post_rate_limited", lambda ip: True)

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("빈도 제한에 걸렸는데 update_post가 호출되었다")

    monkeypatch.setattr(db, "update_post", _fail_if_called)

    token = get_csrf_token(client, "/board/1/edit")
    response = client.post(
        "/board/1/edit",
        data={"title": "새 제목", "body": "새 내용", "csrf_token": token},
    )

    assert "너무 많은 게시글 작성 시도" in response.get_data(as_text=True)


def test_board_edit_submit_updates_post_and_redirects(client, monkeypatch):
    _login_as_member(client, username="hyun")
    post = {
        "id": 1,
        "author_username": "hyun",
        "title": "제목",
        "body": "내용",
        "created_at": "2026-09-04T12:00:00+00:00",
    }
    monkeypatch.setattr(db, "get_post", lambda post_id: post)
    monkeypatch.setattr(detector, "is_post_rate_limited", lambda ip: False)
    monkeypatch.setattr(db, "log_post_attempt", lambda ip: None)
    monkeypatch.setattr(db, "update_post", lambda post_id, title, body: None)

    token = get_csrf_token(client, "/board/1/edit")
    response = client.post(
        "/board/1/edit",
        data={"title": "새 제목", "body": "새 내용", "csrf_token": token},
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/board/1"


def test_board_detail_shows_post_and_comments(client, monkeypatch):
    _login_as_member(client)
    monkeypatch.setattr(
        db,
        "get_post",
        lambda post_id: {
            "id": post_id,
            "author_username": "hyun",
            "title": "제목입니다",
            "body": "내용입니다",
            "created_at": "2026-09-04T12:00:00+00:00",
        },
    )
    monkeypatch.setattr(db, "list_comments_by_post", lambda post_id: [])

    response = client.get("/board/1")

    assert response.status_code == 200
    assert "제목입니다" in response.get_data(as_text=True)


def test_board_detail_redirects_when_post_not_found(client, monkeypatch):
    _login_as_member(client)
    monkeypatch.setattr(db, "get_post", lambda post_id: None)

    response = client.get("/board/999")

    assert response.status_code == 302
    assert response.headers["Location"] == "/board"


def test_board_delete_rejected_when_not_owner(client, monkeypatch):
    _login_as_member(client, username="hyun")
    monkeypatch.setattr(
        db,
        "get_post",
        lambda post_id: {
            "id": post_id,
            "author_username": "other_user",
            "title": "제목",
            "body": "내용",
            "created_at": "2026-09-04T12:00:00+00:00",
        },
    )
    monkeypatch.setattr(db, "list_comments_by_post", lambda post_id: [])

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("본인 글이 아닌데 delete_post가 호출되었다")

    monkeypatch.setattr(db, "delete_post", _fail_if_called)

    token = get_csrf_token(client, "/board/1")
    # flash 메시지는 redirect 대상 화면이 렌더링될 때 비로소 보이므로,
    # follow_redirects=True로 최종 화면까지 따라가서 확인한다.
    response = client.post("/board/1/delete", data={"csrf_token": token}, follow_redirects=True)

    assert "본인이 작성한 글만 삭제할 수 있습니다" in response.get_data(as_text=True)


def test_board_delete_allowed_when_owner(client, monkeypatch):
    _login_as_member(client, username="hyun")
    monkeypatch.setattr(
        db,
        "get_post",
        lambda post_id: {
            "id": post_id,
            "author_username": "hyun",
            "title": "제목",
            "body": "내용",
            "created_at": "2026-09-04T12:00:00+00:00",
        },
    )
    monkeypatch.setattr(db, "list_comments_by_post", lambda post_id: [])
    deleted_ids = []
    monkeypatch.setattr(db, "delete_post", lambda post_id: deleted_ids.append(post_id) or True)

    token = get_csrf_token(client, "/board/1")
    response = client.post("/board/1/delete", data={"csrf_token": token})

    assert response.status_code == 302
    assert response.headers["Location"] == "/board"
    assert deleted_ids == [1]


def test_board_comment_submit_creates_comment(client, monkeypatch):
    _login_as_member(client, username="hyun")
    monkeypatch.setattr(
        db,
        "get_post",
        lambda post_id: {
            "id": post_id,
            "author_username": "hyun",
            "title": "제목",
            "body": "내용",
            "created_at": "2026-09-04T12:00:00+00:00",
        },
    )
    monkeypatch.setattr(db, "list_comments_by_post", lambda post_id: [])
    monkeypatch.setattr(detector, "is_comment_rate_limited", lambda ip: False)
    monkeypatch.setattr(db, "log_comment_attempt", lambda ip: None)
    created = []
    monkeypatch.setattr(
        db,
        "create_comment",
        lambda post_id, author, body: created.append((post_id, author, body)),
    )

    token = get_csrf_token(client, "/board/1")
    response = client.post(
        "/board/1/comments", data={"body": "댓글 내용", "csrf_token": token}
    )

    assert response.status_code == 302
    assert created == [(1, "hyun", "댓글 내용")]


def test_board_comment_submit_rejects_when_rate_limited(client, monkeypatch):
    _login_as_member(client, username="hyun")
    monkeypatch.setattr(
        db,
        "get_post",
        lambda post_id: {
            "id": post_id,
            "author_username": "hyun",
            "title": "제목",
            "body": "내용",
            "created_at": "2026-09-04T12:00:00+00:00",
        },
    )
    monkeypatch.setattr(db, "list_comments_by_post", lambda post_id: [])
    monkeypatch.setattr(detector, "is_comment_rate_limited", lambda ip: True)

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("빈도 제한에 걸렸는데 create_comment가 호출되었다")

    monkeypatch.setattr(db, "create_comment", _fail_if_called)

    token = get_csrf_token(client, "/board/1")
    response = client.post(
        "/board/1/comments", data={"body": "댓글 내용", "csrf_token": token}
    )

    assert response.status_code == 302


def test_board_comment_delete_rejected_when_not_owner(client, monkeypatch):
    _login_as_member(client, username="hyun")
    monkeypatch.setattr(
        db,
        "get_post",
        lambda post_id: {
            "id": post_id,
            "author_username": "hyun",
            "title": "제목",
            "body": "내용",
            "created_at": "2026-09-04T12:00:00+00:00",
        },
    )
    monkeypatch.setattr(db, "list_comments_by_post", lambda post_id: [])
    monkeypatch.setattr(
        db,
        "get_comment",
        lambda comment_id: {"id": comment_id, "author_username": "other_user"},
    )

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("본인 댓글이 아닌데 delete_comment가 호출되었다")

    monkeypatch.setattr(db, "delete_comment", _fail_if_called)

    token = get_csrf_token(client, "/board/1")
    response = client.post(
        "/board/1/comments/5/delete", data={"csrf_token": token}, follow_redirects=True
    )

    assert "본인이 작성한 댓글만 삭제할 수 있습니다" in response.get_data(as_text=True)


def test_api_board_comments_latest_requires_login(client):
    # 이 API는 member_login_required로 보호된다 — login_required(관리자용)와
    # 달리 "/api/" 경로 특례가 없어, 미인증 시에도 401 JSON이 아니라 로그인
    # 화면으로 리다이렉트된다(app.py의 member_login_required 정의 참고).
    response = client.get("/api/board/1/comments/latest")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login"


def test_api_board_comments_latest_returns_latest_info(client, monkeypatch):
    _login_as_member(client)
    monkeypatch.setattr(
        db,
        "get_latest_comment_info",
        lambda post_id: {"count": 3, "latest_at": "2026-09-04T12:00:00+00:00"},
    )

    response = client.get("/api/board/1/comments/latest")

    assert response.status_code == 200
    assert response.get_json() == {"count": 3, "latest_at": "2026-09-04T12:00:00+00:00"}


def test_api_board_posts_delete_requires_admin(client, monkeypatch):
    # CSRF 토큰이 없으면 CSRFProtect가 login_required보다 먼저 400으로 막아버려서
    # "인증 부족"을 제대로 검증할 수 없다 — 그래서 유효한 토큰은 실어 보내되
    # (로그인 없이도 발급 가능한 /login 화면에서 얻는다), 관리자 세션만 없는
    # 상태로 요청해 login_required 자체가 막는지 확인한다.
    monkeypatch.setattr(db, "log_unauthorized_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_unauthorized_access_suspicious", lambda ip: (False, 1))

    token = get_csrf_token(client, "/login")
    response = client.post(
        "/api/board/posts/delete",
        json={"post_id": 1},
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 401


def test_api_board_posts_delete_succeeds_for_admin(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["admin_username"] = "test-admin"
    monkeypatch.setattr(db, "delete_post", lambda post_id: post_id == 1)

    token = get_csrf_token(client, "/admin/dashboard")
    response = client.post(
        "/api/board/posts/delete",
        json={"post_id": 1},
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 200


# ============================================================================
# 404 처리 — Web Scanning(존재하지 않는 경로 반복 요청) 탐지
# (21단계, attack_response_state.md 구현 대상 #1)
# ============================================================================

def test_not_found_still_returns_404_and_logs_attempt(client, monkeypatch):
    logged = []
    monkeypatch.setattr(db, "log_not_found_attempt", lambda ip, path: logged.append((ip, path)))
    monkeypatch.setattr(detector, "is_web_scanning", lambda ip: (False, 1))

    response = client.get("/no-such-page")

    assert response.status_code == 404
    assert logged == [("127.0.0.1", "/no-such-page")]


def test_not_found_sends_alert_exactly_when_crossing_threshold(client, monkeypatch):
    monkeypatch.setattr(db, "log_not_found_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_web_scanning", lambda ip: (True, 11))  # threshold(10) + 1
    notify_calls = []
    monkeypatch.setattr(
        soar, "notify_web_scanning", lambda ip, count, path: notify_calls.append((ip, count, path))
    )

    client.get("/wp-admin")

    assert notify_calls == [("127.0.0.1", 11, "/wp-admin")]


def test_not_found_does_not_alert_again_after_threshold_crossing(client, monkeypatch):
    # count가 threshold+1을 이미 지나친(예: 15) 다음 요청에서는 "새로 넘은 순간"이
    # 아니므로 다시 알리지 않는다 — 매 요청마다 알림이 반복되는 걸(알림 피로) 막는다.
    monkeypatch.setattr(db, "log_not_found_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_web_scanning", lambda ip: (True, 15))

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("임계값을 이미 넘긴 뒤인데 notify_web_scanning이 또 호출되었다")

    monkeypatch.setattr(soar, "notify_web_scanning", _fail_if_called)

    response = client.get("/wp-admin")

    assert response.status_code == 404


def test_not_found_does_not_alert_below_threshold(client, monkeypatch):
    monkeypatch.setattr(db, "log_not_found_attempt", lambda ip, path: None)
    monkeypatch.setattr(detector, "is_web_scanning", lambda ip: (False, 3))

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("아직 임계값 미만인데 notify_web_scanning이 호출되었다")

    monkeypatch.setattr(soar, "notify_web_scanning", _fail_if_called)

    response = client.get("/no-such-page")

    assert response.status_code == 404
