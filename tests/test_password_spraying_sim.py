"""실제 서버에 접속하지 않고 시뮬레이터의 요청 안전장치와 실행 흐름을 검증한다."""

import json
import socket
from types import SimpleNamespace

import pytest
import requests

from scripts import password_spraying_sim as sim


def make_response(status=200, body="잘못된 아이디 또는 비밀번호입니다.", **headers):
    """네트워크 없이 Requests의 실제 응답 파싱을 사용할 수 있는 응답을 만든다."""
    response = requests.Response()
    response.status_code = status
    response.url = "http://127.0.0.1:5000/login"
    response.encoding = "utf-8"
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers.update(headers)
    response._content = body.encode("utf-8")
    response._content_consumed = True
    return response


def block_network(*args, **kwargs):
    """네트워크 접근이 없어야 하는 검사에서 DNS나 HTTP가 실행되면 실패한다."""
    pytest.fail("이 테스트에서는 실제 네트워크 요청을 보내면 안 됩니다.")


@pytest.fixture
def fake_server(monkeypatch):
    """하나의 세션이 보낸 GET/POST 순서와 payload를 기록하는 가짜 서버를 만든다."""
    sessions = []
    calls = []
    post_responses = []
    get_responses = []
    session_class = requests.Session

    class RecordingSession(session_class):
        def __init__(self):
            super().__init__()
            sessions.append(self)
            self.get_count = 0
            self.post_count = 0

        def get(self, url, **kwargs):
            self.get_count += 1
            calls.append(("GET", self, url, kwargs))
            self.cookies.set("test_csrf_session", "same-session")
            if get_responses:
                return get_responses.pop(0)
            return make_response(
                body=(
                    '<form><input value="token-%d" type="hidden" '
                    'name="csrf_token"></form>' % self.get_count
                )
            )

        def post(self, url, **kwargs):
            self.post_count += 1
            calls.append(("POST", self, url, kwargs))
            if post_responses:
                response = post_responses.pop(0)
                if isinstance(response, Exception):
                    raise response
                return response
            return make_response()

    monkeypatch.setattr(sim.requests, "Session", RecordingSession)
    monkeypatch.setattr(sim.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(sim.socket, "getaddrinfo", block_network)
    monkeypatch.setattr(session_class, "send", block_network)
    return SimpleNamespace(
        sessions=sessions,
        calls=calls,
        post_responses=post_responses,
        get_responses=get_responses,
    )


@pytest.mark.parametrize("host", ["127.0.0.1", "127.20.30.40", "[::1]"])
def test_loopback_literals_are_allowed_without_dns(monkeypatch, host):
    monkeypatch.setattr(sim.socket, "getaddrinfo", block_network)
    assert sim.is_local_host(f"http://{host}:5000") is True


@pytest.mark.parametrize(
    "host",
    ["localhost.attacker.example", "attacker-localhost.example", "192.168.1.2", "10.0.0.2"],
)
def test_nonloopback_hosts_are_not_implicitly_allowed_or_resolved(monkeypatch, host):
    monkeypatch.setattr(sim.socket, "getaddrinfo", block_network)
    assert sim.is_local_host(f"http://{host}:5000") is False


@pytest.mark.parametrize("ipv4, expected", [("127.0.0.1", True), ("192.168.1.2", False)])
def test_localhost_requires_every_resolved_address_to_be_loopback(monkeypatch, ipv4, expected):
    resolved = []

    def resolve(host, *args, **kwargs):
        resolved.append(host)
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 5000, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ipv4, 5000)),
        ]

    monkeypatch.setattr(sim.socket, "getaddrinfo", resolve)
    assert sim.is_local_host("http://localhost:5000") is expected
    assert resolved == ["localhost"]


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1:5000",
        "http://user:password@127.0.0.1:5000",
        "http://127.0.0.1:5000?key=value",
        "http://127.0.0.1:5000#fragment",
        "http://127.0.0.1:invalid",
        "http://127.0.0.1:5000/path",
        "http://",
    ],
)
def test_malformed_or_credentialed_host_is_rejected(url):
    with pytest.raises(ValueError):
        sim.is_local_host(url)


def test_username_list_strips_whitespace_and_empty_items():
    args = SimpleNamespace(usernames=" a, b,,c,d,e, f, ", username_prefix=None, count=6)
    assert sim.parse_usernames(args) == ["a", "b", "c", "d", "e", "f"]


@pytest.mark.parametrize("names", ["a,b,c,d,e,a", "a,b,c,d,e", "a,a,a,a,a,a"])
def test_duplicate_or_insufficient_usernames_are_rejected(names):
    with pytest.raises(ValueError):
        sim.parse_usernames(SimpleNamespace(usernames=names, username_prefix=None, count=6))


def test_username_prefix_generates_exact_count():
    args = SimpleNamespace(usernames=None, username_prefix="spray_", count=7)
    assert sim.parse_usernames(args) == [f"spray_{index}" for index in range(1, 8)]


def test_dry_run_uses_no_dns_http_or_session_and_masks_password(monkeypatch, capsys):
    monkeypatch.setattr(sim.socket, "getaddrinfo", block_network)
    monkeypatch.setattr(sim.requests, "Session", block_network)
    result = sim.main([
        "--host", "http://localhost:5000", "--dry-run", "--password", "private-test-password"
    ])
    output = capsys.readouterr().out
    assert result == 0
    assert "private-test-password" not in output
    assert "SAME PASSWORD" in output
    assert "SAME SESSION" in output
    assert "spray_user6" in output


def test_six_posts_share_one_session_password_and_fresh_csrf(fake_server, capsys):
    fake_server.post_responses.extend([make_response() for _ in range(5)])
    fake_server.post_responses.append(make_response(body="잠긴 계정입니다."))

    assert sim.main(["--username-prefix", "spray_user", "--count", "6"]) == 0

    assert len(fake_server.sessions) == 1
    session = fake_server.sessions[0]
    assert session.trust_env is False
    assert session.auth is None
    assert "PasswordSpraying-Test" in session.headers["User-Agent"]
    assert "Authorization" not in session.headers
    assert "X-Forwarded-For" not in session.headers
    assert [call[0] for call in fake_server.calls] == ["GET", "POST"] * 6
    posts = [call for call in fake_server.calls if call[0] == "POST"]
    assert [call[3]["data"]["username"] for call in posts] == [
        f"spray_user{index}" for index in range(1, 7)
    ]
    assert {call[3]["data"]["password"] for call in posts} == {sim.DEFAULT_TEST_PASSWORD}
    assert [call[3]["data"]["csrf_token"] for call in posts] == [
        f"token-{index}" for index in range(1, 7)
    ]
    for method, actual_session, url, kwargs in fake_server.calls:
        assert actual_session is session
        assert url == "http://127.0.0.1:5000/login"
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == sim.REQUEST_TIMEOUT
    assert session.cookies.get("test_csrf_session") == "same-session"
    output = capsys.readouterr().out
    assert "THRESHOLD EXCEEDED" in output
    assert "MANUAL CHECK" in output
    assert "PASSWORD_SPRAYING" in output
    assert sim.DEFAULT_TEST_PASSWORD not in output


def test_json_posts_use_json_parameter_and_current_csrf(fake_server):
    assert sim.main(["--json"]) == 0
    posts = [call[3] for call in fake_server.calls if call[0] == "POST"]
    assert len(posts) == 6
    for index, kwargs in enumerate(posts, 1):
        assert "data" not in kwargs
        assert kwargs["json"]["csrf_token"] == f"token-{index}"
        assert kwargs["headers"]["X-CSRFToken"] == f"token-{index}"


def test_missing_csrf_prevents_any_login_post(fake_server, capsys):
    fake_server.get_responses.append(make_response(body="<form></form>"))
    assert sim.main([]) == 1
    assert [call[0] for call in fake_server.calls] == ["GET"]
    assert "--no-csrf" in capsys.readouterr().out


def test_no_csrf_makes_exactly_six_posts_and_no_marker_is_not_failure(fake_server):
    assert sim.main(["--no-csrf"]) == 0
    assert [call[0] for call in fake_server.calls] == ["POST"] * 6
    for call in fake_server.calls:
        assert "csrf_token" not in call[3]["data"]


@pytest.mark.parametrize(
    "response",
    [
        make_response(302, "", Location="/admin/dashboard"),
        make_response(200, "로그인 성공"),
    ],
)
def test_possible_login_success_stops_before_next_username(fake_server, capsys, response):
    fake_server.post_responses.append(response)
    assert sim.main(["--no-csrf"]) == 1
    assert len(fake_server.calls) == 1
    assert "POSSIBLE LOGIN SUCCESS" in capsys.readouterr().out


@pytest.mark.parametrize(
    "response",
    [make_response(423, "잠긴 계정"), make_response(429, "Too Many Requests"), make_response(500, "error")],
)
def test_early_lock_or_server_error_fails_and_stops(fake_server, response):
    fake_server.post_responses.append(response)
    assert sim.main(["--no-csrf"]) == 1
    assert len(fake_server.calls) == 1


@pytest.mark.parametrize("error", [requests.ConnectionError(), requests.Timeout()])
def test_transport_errors_return_failure_without_traceback(fake_server, capsys, error):
    fake_server.post_responses.append(error)
    assert sim.main(["--no-csrf"]) == 1
    assert len(fake_server.calls) == 1
    output = capsys.readouterr().out
    assert "[FAIL]" in output
    assert "Traceback" not in output


def test_user_interrupt_returns_130(fake_server, monkeypatch, capsys):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(sim, "send_login_attempt", interrupt)
    assert sim.main(["--no-csrf"]) == 130
    assert "[INTERRUPTED]" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["--count", "5"],
        ["--count", "0"],
        ["--interval", "0.1"],
        ["--interval", "2"],
        ["--host", "http://192.168.1.2:5000"],
        ["--usernames", "a,b,c,d,e,a"],
    ],
)
def test_config_errors_happen_before_session_creation(monkeypatch, argv):
    monkeypatch.setattr(sim.requests, "Session", block_network)
    monkeypatch.setattr(sim.socket, "getaddrinfo", block_network)
    try:
        code = sim.main(argv)
    except SystemExit as error:
        code = error.code
    assert code == 2


def test_response_validation_keeps_detection_indicators_separate():
    result = sim.validate_response(make_response(429, "Too Many Requests"))
    assert result["possible_lock"] is True
    assert result["lock_detected"] is False
    assert result["possible_login_success"] is False
    result = sim.validate_response(make_response(423, ""))
    assert result["lock_detected"] is True


def test_response_preview_is_bounded_and_json_is_parsed():
    response = make_response(401, '{"error":"' + "x" * 1000 + '"}')
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Set-Cookie"] = "session=do-not-print-this-value"
    result = sim.validate_response(response)
    assert result["is_json"] is True
    assert result["status"] == 401
    assert len(result["body_preview"]) <= sim.MAX_RESPONSE_PREVIEW + 3
    assert "do-not-print-this-value" not in str(result)


@pytest.mark.parametrize("payload_mode", ["data", "json"])
def test_json_echo_of_quoted_password_is_redacted(payload_mode):
    """일반 message 필드에 재출력된 비밀번호도 JSON 이스케이프와 무관하게 가린다."""
    password = 'private-"quoted"-\\password'
    payload = {"username": "spray_user1", "password": password}
    prepared = requests.Request(
        "POST", "http://127.0.0.1:5000/login", **{payload_mode: payload}
    ).prepare()
    response = make_response(401, json.dumps({"message": password}))
    response.headers["Content-Type"] = "application/json"
    response.request = prepared

    result = sim.validate_response(response)

    assert result["is_json"] is True
    assert password not in result["body_preview"]
    assert json.dumps(password)[1:-1] not in result["body_preview"]


def test_invalid_header_returns_failure_without_leaking_exception(fake_server, capsys):
    """헤더 값이 포함될 수 있는 Requests 예외의 원문과 traceback을 출력하지 않는다."""
    fake_server.post_responses.append(requests.exceptions.InvalidHeader("sensitive-token"))

    assert sim.main(["--no-csrf"]) == 1

    assert len(fake_server.calls) == 1
    output = capsys.readouterr().out
    assert "[FAIL]" in output
    assert "sensitive-token" not in output
    assert "Traceback" not in output
