# ============================================================================
# test_db_client.py — Supabase HTTP 연결 설정 (db/_client.py)
#
# 배포 사이트에서 "Server disconnected"(쉬던 HTTP/2 연결 재사용)로 /login 등이 가끔 500이
# 나던 문제의 수정을 확인한다.
#   - Supabase 클라이언트가 우리가 만든 HTTP/1.1 연결 설정으로 만들어지는가
#   - 조회(GET/HEAD)는 연결 끊김 시 1회만 재시도하는가
#   - 기록·수정(POST/PATCH/DELETE)은 재시도하지 않는가(두 번 기록되는 것 방지)
# ============================================================================

import httpx
import pytest

import db
from db import _client as client_module

URL = "https://example.supabase.co/rest/v1/users"


@pytest.fixture
def fake_send(monkeypatch):
    """실제 네트워크 대신, 미리 정한 결과(예외 또는 응답)를 순서대로 돌려주는 전송 계층."""
    calls = []
    outcomes = []

    def handle_request(self, request):
        calls.append(request.method)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle_request)
    return calls, outcomes


def _transport():
    return client_module._RetryOnDisconnectTransport(http2=False)


def test_get_is_retried_once_after_a_disconnect(fake_send):
    calls, outcomes = fake_send
    outcomes += [httpx.RemoteProtocolError("Server disconnected"), httpx.Response(200)]

    response = _transport().handle_request(httpx.Request("GET", URL))

    assert response.status_code == 200 and calls == ["GET", "GET"]


def test_read_error_on_get_is_also_retried(fake_send):
    calls, outcomes = fake_send
    outcomes += [httpx.ReadError("connection reset"), httpx.Response(200)]

    assert _transport().handle_request(httpx.Request("HEAD", URL)).status_code == 200
    assert calls == ["HEAD", "HEAD"]


def test_get_is_retried_only_once(fake_send):
    calls, outcomes = fake_send
    outcomes += [httpx.RemoteProtocolError("down"), httpx.RemoteProtocolError("still down")]

    with pytest.raises(httpx.RemoteProtocolError):
        _transport().handle_request(httpx.Request("GET", URL))

    assert calls == ["GET", "GET"]


@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE"])
def test_writes_are_never_retried(fake_send, method):
    # 서버에 이미 반영됐는데 응답만 끊긴 경우 두 번 기록될 수 있어서 재시도하지 않는다.
    calls, outcomes = fake_send
    outcomes += [httpx.RemoteProtocolError("Server disconnected"), httpx.Response(201)]

    with pytest.raises(httpx.RemoteProtocolError):
        _transport().handle_request(httpx.Request(method, URL, json={"a": 1}))

    assert calls == [method]


def test_other_errors_are_not_retried(fake_send):
    calls, outcomes = fake_send
    outcomes += [httpx.ReadTimeout("slow"), httpx.Response(200)]

    with pytest.raises(httpx.ReadTimeout):
        _transport().handle_request(httpx.Request("GET", URL))

    assert calls == ["GET"]


def test_http_client_uses_http11_with_short_keepalive_and_connect_retry():
    client = client_module._build_http_client()
    transport = client._transport
    pool = transport._pool

    assert isinstance(transport, client_module._RetryOnDisconnectTransport)
    assert pool._http2 is False and pool._http1 is True  # HTTP/2 연결 재사용을 쓰지 않는다
    assert pool._keepalive_expiry == client_module._KEEPALIVE_EXPIRY_SECONDS
    assert pool._retries == 1  # 접속 단계 실패는 1회 재시도
    client.close()


def test_get_client_passes_our_http_client_to_supabase(monkeypatch):
    seen = {}
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "test-key")
    monkeypatch.setattr(client_module, "_client", None)
    monkeypatch.setattr(
        client_module, "create_client", lambda url, key, options=None: seen.update(url=url, options=options) or "client"
    )

    assert client_module.get_client() == "client"
    assert client_module.get_client() == "client"  # 두 번째 호출은 만들어 둔 연결을 재사용

    http_client = seen["options"].httpx_client
    assert isinstance(http_client, httpx.Client)
    assert isinstance(http_client._transport, client_module._RetryOnDisconnectTransport)
    http_client.close()


def test_real_supabase_client_builds_postgrest_on_top_of_our_http_client(monkeypatch):
    # 실제 supabase 라이브러리로 만들었을 때 postgrest가 우리 연결 설정을 그대로 쓰는지 확인한다
    # (네트워크 요청은 보내지 않는다 — 클라이언트 객체만 만든다).
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv(
        "SUPABASE_KEY",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.c2lnbmF0dXJl",
    )
    monkeypatch.setattr(client_module, "_client", None)

    supabase_client = client_module.get_client()

    assert isinstance(supabase_client.postgrest.session._transport, client_module._RetryOnDisconnectTransport)
    monkeypatch.setattr(client_module, "_client", None)


def test_db_package_still_exposes_get_client():
    assert db.get_client is client_module.get_client
