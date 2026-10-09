# ============================================================================
# db/_client.py — Supabase 연결과 공용 시각 헬퍼
#
# 원래 db.py 최상단에 있던 부분을 그대로 옮겨왔다. db 패키지의 다른 모든
# 모듈(attempts.py, users.py 등)이 이 파일의 get_client()/_now_iso()를 쓴다.
# ============================================================================

import os
from datetime import datetime, timezone

import httpx
from postgrest.constants import DEFAULT_POSTGREST_CLIENT_TIMEOUT
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions

# 프로그램 전체에서 Supabase 연결을 딱 하나만 만들어서 재사용하기 위한 변수.
# 처음엔 비어있다가(None), 처음 필요할 때 한 번만 실제 연결을 만듭니다.
_client: Client | None = None


# ============================================================================
# Supabase로 가는 HTTP 연결 설정 — "Server disconnected" 오류 방지
#
# Supabase 라이브러리(postgrest)는 기본으로 HTTP/2 연결 하나를 계속 재사용한다. Vercel 같은
# 서버리스에서는 함수가 잠시 쉬는 사이 Supabase 쪽이 그 연결을 닫는데, 함수가 다시 깨어나
# 이미 닫힌 연결로 요청을 보내면 httpx.RemoteProtocolError("Server disconnected")로 실패한다
# (배포 사이트에서 /login, /api/status가 가끔 500이 나던 원인 — 다시 요청하면 정상).
# 라이브러리 자체 재시도는 503/520 "응답"에만 동작해서 이런 연결 끊김 "예외"는 막지 못한다.
#
# 그래서 연결 설정을 직접 만들어 넘긴다:
#   1) HTTP/1.1 — 연결을 여러 개 두고, 쉬던 연결을 다시 쓰기 전에 이미 닫혔는지 확인해서
#      닫혔으면 새로 연결한다. 쉬는 연결은 오래 붙잡아 두지 않는다(keepalive_expiry).
#   2) 접속 단계 실패는 1회 재시도(retries=1) — 아직 아무것도 보내지 않은 상태라 안전하다.
#   3) 조회(GET/HEAD)만, 연결이 끊겨 실패하면 1회 재시도 — 기록·수정(POST/PATCH/DELETE)은
#      재시도하지 않는다. 서버에는 이미 반영됐는데 응답만 끊긴 경우 두 번 기록될 수 있어서다
#      (로그인 실패 기록이 두 번 남으면 잠금 횟수가 틀어진다).
# ============================================================================

_RETRYABLE_METHODS = frozenset({"GET", "HEAD"})
# 이미 맺어진 연결이 중간에 끊겼을 때 나는 예외들(접속 자체의 실패는 retries=1이 처리한다).
_DISCONNECT_ERRORS = (httpx.RemoteProtocolError, httpx.ReadError)
# 쉬는 연결을 다시 쓸 수 있는 최대 시간(초). 서버리스에서는 오래된 연결이 닫혀 있을 가능성이 크다.
_KEEPALIVE_EXPIRY_SECONDS = 5.0


class _RetryOnDisconnectTransport(httpx.HTTPTransport):
    """조회 요청이 연결 끊김으로 실패하면 새 연결로 한 번만 다시 보내는 전송 계층."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            return super().handle_request(request)
        except _DISCONNECT_ERRORS:
            if request.method not in _RETRYABLE_METHODS:
                raise
            return super().handle_request(request)


def _build_http_client() -> httpx.Client:
    """Supabase(postgrest)가 쓸 HTTP 연결 설정. 타임아웃은 라이브러리 기본값을 그대로 쓴다."""
    transport = _RetryOnDisconnectTransport(
        http2=False,
        retries=1,
        limits=httpx.Limits(max_keepalive_connections=20, keepalive_expiry=_KEEPALIVE_EXPIRY_SECONDS),
    )
    return httpx.Client(
        transport=transport,
        timeout=DEFAULT_POSTGREST_CLIENT_TIMEOUT,
        follow_redirects=True,
    )


def get_client() -> Client:
    """Supabase(데이터베이스)에 접속하는 연결 객체를 돌려준다.

    이미 한 번 접속해뒀다면 새로 접속하지 않고 기존 연결을 재사용한다
    (전화를 걸 때마다 새로 다이얼하지 않고, 이미 연결된 통화선을 계속 쓰는 것과 비슷함).
    실제 HTTP 연결 방식은 위 _build_http_client() 설명 참고.
    """
    global _client
    if _client is None:
        # .env 파일에 적어둔 주소(URL)와 비밀 열쇠(KEY)를 읽어와서 접속을 시도한다.
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_KEY"]
        _client = create_client(url, key, options=SyncClientOptions(httpx_client=_build_http_client()))
    return _client


def _now_iso() -> str:
    """지금 이 순간의 시각을 데이터베이스가 알아듣는 표준 문자열 형식으로 돌려준다.

    이름 앞의 밑줄(_)은 "이 함수는 db 패키지 안에서만 쓰는 내부용 도구"라는 표시
    (패키지 안의 다른 모듈들은 db._now_iso()로 부른다).
    """
    return datetime.now(timezone.utc).isoformat()
