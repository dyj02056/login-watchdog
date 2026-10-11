# 19단원 — 배포 환경 DB 연결 안정화 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "19-db-connection"
TITLE = "19. 배포 환경 DB 연결 안정화"
SUBTITLE = "서버리스에서 쉬던 DB 연결이 끊겨 생기던 500 오류를, 연결 한 곳만 고쳐서 막은 코드 흐름도"

FILE_ROLES = {
    "db/_client.py": "Supabase 연결을 만들고 재사용하는 파일. db 패키지의 모든 함수가 이 연결을 쓴다.",
    "db/users.py": "회원 표 함수들. 이 단원에서는 'DB 호출 코드는 하나도 안 바뀌었다'는 예시로만 등장한다.",
}

s1 = Scenario("conn", "연결을 만드는 방법",
              "배포 사이트(Vercel)에서 가끔 500 오류가 났습니다. 함수가 잠시 쉬는 사이 Supabase 가 닫은 HTTP/2 연결을 함수가 다시 깨어나 그대로 쓰다가 'Server disconnected' 로 실패한 것입니다. 연결 설정 한 곳만 바꿔 해결했습니다.")
s1.screen("DB 를 처음 쓰는 순간", "어떤 db 함수든 db.get_client() 를 부릅니다. 처음 한 번만 실제 연결을 만들고 이후에는 재사용합니다.",
          fn="db/_client.py:get_client", hl=("global _client", "return _client"),
          calls=[call("db/users.py:get_user_by_username", "예: 회원 조회", "이런 db 함수 155곳이 코드 변경 없이 같은 연결을 씁니다.")])
s1.step("① 연결 설정을 직접 만들어 넘긴다", "라이브러리 기본 연결 대신, 아래 ②~③ 설정을 가진 HTTP 연결을 만들어 Supabase 클라이언트에 넘깁니다.",
        fn="db/_client.py:get_client", hl="_client = create_client(url, key, options=SyncClientOptions(httpx_client=_build_http_client()))",
        calls=[call("db/_client.py:_build_http_client", "HTTP 연결 설정 만들기", "HTTP/1.1 · 쉬는 연결 5초 · 접속 1회 재시도.")])
s1.step("② HTTP/1.1 + 5초 넘게 쉰 연결은 재사용 안 함 + 접속 1회 재시도", "HTTP/1.1 은 연결을 여러 개 두고 쉬던 연결을 다시 쓰기 전에 이미 닫혔는지 확인해, 닫혔으면 새로 맺습니다. 접속 단계 실패는 아직 아무것도 보내지 않은 상태라 1회 재시도해도 안전합니다.",
        fn="db/_client.py:_build_http_client", hl=("transport = _RetryOnDisconnectTransport(", "keepalive_expiry=_KEEPALIVE_EXPIRY_SECONDS"),
        calls=[call(snippet=("db/_client.py", "_RETRYABLE_METHODS =", "_KEEPALIVE_EXPIRY_SECONDS ="), title="재시도·유지 시간 상수", plain="재시도 대상 메서드 · 끊김 예외 종류 · 연결 유지 5초.", label="재시도 상수")])
s1.step("③ 조회(GET/HEAD)만, 끊기면 1회 재시도", "기록·수정(POST/PATCH/DELETE)은 재시도하지 않습니다. 서버에는 이미 반영됐는데 응답만 끊긴 경우 두 번 기록될 수 있기 때문입니다(로그인 실패 기록이 두 번 남으면 잠금 횟수가 틀어집니다).",
        fn="db/_client.py:_RetryOnDisconnectTransport.handle_request", hl=("try:", "return super().handle_request(request)"))

SCENARIOS = [s1.build()]
