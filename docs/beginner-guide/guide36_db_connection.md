# 36단계 — 배포 환경 DB 연결 끊김 해결

[◀ 35단계](guide35_password_change.md) · [전체 목차](beginner-guide.md)

> 배포 사이트에서 `/login`이나 관리자 대시보드(`/api/status`)가 **가끔** 500 오류를 냈습니다. 다시 요청하면 멀쩡했습니다. 이 단계에서는 원인을 찾아 Supabase 연결 방식을 바꿔 해결했습니다. 코드 수정은 `db/_client.py` 한 파일뿐이고, DB를 부르는 155곳의 코드는 그대로입니다.

## 증상과 원인

| 항목 | 내용 |
|---|---|
| 증상 | 가끔 500 오류, 바로 다시 요청하면 정상 |
| Vercel 로그 | `httpx.RemoteProtocolError: Server disconnected` |
| 원인 | Supabase 라이브러리(`postgrest`)는 기본으로 **HTTP/2 연결 하나를 계속 재사용**한다. Vercel 함수는 요청이 없으면 잠시 쉬는데, 그 사이 Supabase 쪽이 연결을 닫는다. 함수가 다시 깨어나 **이미 닫힌 연결로 요청을 보내다** 실패한다 |
| 라이브러리 재시도가 못 막은 이유 | 라이브러리 자체 재시도는 503/520 같은 **응답**에만 동작하고, 연결 끊김 같은 **예외**에는 동작하지 않는다 |

**비유:** 오래 쉬고 있던 전화선이 저쪽에서 끊겼는데, 그걸 모르고 수화기를 들어 바로 말을 시작한 셈입니다.

## 해결 방법

Supabase 클라이언트를 만들 때 연결 설정(`httpx_client`)을 직접 만들어 넘깁니다.

| 방법 | 내용 | 효과 |
|---|---|---|
| HTTP/1.1 연결 | 연결 하나를 계속 쓰는 HTTP/2 대신, 연결을 여러 개 두는 방식 | 쉬던 연결을 다시 쓰기 전에 **이미 닫혔는지 확인**하고, 닫혔으면 새로 연결 |
| 짧은 연결 유지(5초) | 5초 넘게 쉰 연결은 재사용하지 않음 | 닫혔을 가능성이 큰 오래된 연결을 피함 |
| 접속 단계 1회 재시도 | 연결을 맺다가 실패하면 한 번 더 | 아직 아무것도 보내지 않은 상태라 안전 |
| **조회만** 1회 재시도 | 연결이 중간에 끊기면 GET/HEAD 요청만 새 연결로 한 번 더 보냄 | 남는 드문 경우를 처리 |

### 왜 기록·수정은 재시도하지 않나

로그인 실패 기록(INSERT)처럼 서버에 무언가를 남기는 요청은, **서버에는 이미 반영됐는데 응답만 끊긴** 경우가 있습니다. 이때 다시 보내면 같은 기록이 두 번 남습니다. 로그인 실패가 두 번 기록되면 잠금 횟수가 틀어지므로, POST·PATCH·DELETE는 재시도하지 않습니다. 대신 HTTP/1.1로 바꾼 것만으로 대부분 예방됩니다.

## 실제 코드 함께 보기

```python
class _RetryOnDisconnectTransport(httpx.HTTPTransport):
    """조회 요청이 연결 끊김으로 실패하면 새 연결로 한 번만 다시 보내는 전송 계층."""

    def handle_request(self, request):
        try:
            return super().handle_request(request)
        except (httpx.RemoteProtocolError, httpx.ReadError):
            if request.method not in ("GET", "HEAD"):
                raise                      # 기록·수정은 재시도하지 않는다
            return super().handle_request(request)


def _build_http_client():
    transport = _RetryOnDisconnectTransport(
        http2=False,                        # HTTP/1.1
        retries=1,                          # 접속 단계 실패는 1회 재시도
        limits=httpx.Limits(max_keepalive_connections=20, keepalive_expiry=5.0),
    )
    return httpx.Client(transport=transport, timeout=DEFAULT_POSTGREST_CLIENT_TIMEOUT, follow_redirects=True)


_client = create_client(url, key, options=SyncClientOptions(httpx_client=_build_http_client()))
```

`postgrest`는 넘겨받은 연결 설정을 그대로 쓰고, 요청마다 전체 주소와 인증 헤더를 붙이기 때문에 연결 설정만 바꿔도 안전합니다(설치된 `supabase 2.31.0` 소스로 확인).

## 확인한 결과

**자동 테스트** (`tests/test_db_client.py`, 11개)
- 조회는 끊김 뒤 1회만 재시도, 기록·수정은 재시도 안 함, 타임아웃 같은 다른 오류는 재시도 안 함
- HTTP/1.1·5초 유지·접속 재시도 설정이 적용되는지
- 실제 supabase 라이브러리로 만든 클라이언트가 이 설정을 쓰는지

**로컬 (실제 DB)**

| 항목 | 결과 |
|---|---|
| 단일 조회 | 첫 연결 1.07초, 이후 0.19~0.5초 |
| 동시 조회 12개 (대시보드와 비슷) | 0.55초 |
| 8초 쉰 뒤 재조회 | 새 연결로 정상 (0.52초) |

**배포 사이트 (Vercel)**

| | 배포 전 (50분) | 배포 후 (약 24분) |
|---|---|---|
| `/api/status` 오류 | 8건 | 0건 |
| `/login` 오류 | 1건 | 0건 |

배포 후 Supabase 요청 로그가 `HTTP/2 200 OK`에서 `HTTP/1.1 200 OK`로 바뀐 것으로 새 연결 방식이 적용된 것을 확인했습니다. 다만 배포 후 관찰 시간과 요청량이 배포 전보다 적어서, 일정 기간 더 지켜보는 것이 좋습니다(무료 플랜은 로그를 1시간만 보관).

## 알아두세요

- 오래 쉰 뒤 첫 요청은 연결을 새로 맺느라 0.3초 정도 더 걸릴 수 있습니다. 오류 화면보다 낫다고 판단했습니다.
- 기록 요청 도중 연결이 끊기는 드문 경우는 여전히 오류가 날 수 있습니다(두 번 기록되는 것보다 안전).
- 34단계 복구 요청에 넣어 둔 재시도와 Slack 알림은 그대로 남겨 두었습니다. 거의 동작하지 않겠지만, 실패를 알려주는 장치입니다.
- DB 스키마 변경, 환경변수 추가, 화면 변경은 없습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- 수정: [db/_client.py](../../db/_client.py)
- 신규: [tests/test_db_client.py](../../tests/test_db_client.py)
