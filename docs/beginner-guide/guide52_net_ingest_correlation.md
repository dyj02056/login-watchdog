# 52단계 — 경보 수집과 교차 상관분석 (서명 검사)

[◀ 51단계](guide51_network_sensor.md) · [전체 목차](beginner-guide.md) · 53단계 ▶ (작성 예정)

> [51단계](guide51_network_sensor.md)의 정문 CCTV가 본 것을 앱이 받아서 기존 보안 기록과 엮어 "같은 공격 흐름"인지 판단하는 과정을 다룹니다.
> 이 문서는 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 첫 절인 **서명 검사(B0-1)** 까지입니다. 경보 접수 창구·보안 기록·교차 규칙은 다음 절에서 다룹니다.

## 비유 — 형사 사무실의 접수대

앱을 사건을 맡는 **형사**라고 생각하면, CCTV 기록을 들고 오는 배달원(shipper)과 차단 결과를 보고하는 집행관(fw-agent)이 형사 사무실 **접수대**(내부 창구 `/api/internal/*`)로 서류를 냅니다.

형사가 서류를 읽기 전에 접수대가 먼저 확인하는 것이 있습니다. **"이 서류에 우리 편 도장이 찍혀 있나?"** 도장이 없거나 위조됐거나 너무 오래된 서류는 내용을 보지 않고 돌려보냅니다. 이 도장이 HMAC 서명이고, 도장 검사기가 `routes/internal/_hmac.py`의 `verify_request()`입니다.

| 비유 | 실제 |
|---|---|
| 접수대 | 내부 API `/api/internal/*` (브라우저가 아니라 단지 안 프로그램만 씀) |
| 서류 | HTTP 요청 한 번 (본문은 JSON) |
| 도장 | `X-LW-Signature` 헤더 (HMAC-SHA256) |
| 도장 찍은 시각 | `X-LW-Timestamp` 헤더 (유닉스 시각, 초) |
| 누가 냈는지 | `X-LW-Sender` 헤더 (`shipper` 또는 `fw-agent`) |
| 도장(비밀키) 2개 | `NET_INGEST_SECRET`(shipper용), `NET_AGENT_SECRET`(fw-agent용) |

## 왜 서명이 필요한가

내부 창구는 사람의 로그인 세션이 아니라 프로그램이 부릅니다. 그래서 세션 쿠키·CSRF 토큰 대신 **요청마다 서명**을 붙입니다(`app.py`가 내부 창구를 CSRF 검사에서 뺍니다).

서명이 없으면 누구든 "이 IP가 SYN Flood를 했다"는 가짜 경보를 보내 아무 주소나 차단시키거나, "차단했음" 보고를 꾸밀 수 있습니다. 비밀키를 아는 우리 프로그램만 올바른 서명을 만들 수 있으므로, 서명이 맞으면 "진짜 우리 편이 보냈고 내용이 바뀌지 않았다"고 믿을 수 있습니다.

## 도장 만드는 법 (계약서 K3)

```python
def sign(key: str, timestamp: str, body: bytes) -> str:
    return hmac.new(key.encode(), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
```

| 규칙 | 이유 |
|---|---|
| 서명 대상은 `시각 + "." + 본문 바이트` | 시각까지 서명해야 시각만 바꿔 옛 서류를 다시 내는 것을 막습니다 |
| 본문은 **보낸 바이트 그대로** (GET은 빈 바이트) | JSON을 다시 정리(공백·순서)하면 값이 달라지므로 받은 그대로 계산합니다 |
| 결과는 소문자 16진수 | 보내는 쪽과 받는 쪽이 같은 문자열을 비교하게 |

**기준 예시값** — 키 `test-key`, 시각 `1760930000`, 본문 `{"a":1}` →
`2f744cec328f65506df5ad72df7fdd688c7a3cf3c6f90b1e0085849106179de2`

shipper와 fw-agent는 다른 컨테이너에서 돌아서 앱 코드를 import하지 못합니다. 그래서 같은 규칙을 **각자 파일에 따로** 구현했고, 모두 이 기준값을 만드는지 테스트로 확인합니다.

| 구현 | 위치 |
|---|---|
| 앱(받는 쪽) | `routes/internal/_hmac.py`의 `sign()` |
| shipper(보내는 쪽) | `netwatch/shipper/eve_shipper.py`의 `sign_headers()` |
| fw-agent(보내는 쪽) | `netwatch/fw_agent/fw_agent.py`의 `sign_headers()` |
| 테스트 도우미 | `tests/track_d/conftest.py`의 `signed_headers` — 일부러 `_hmac.sign()`을 쓰지 않고 표준 라이브러리로 직접 계산해, 앱 쪽 구현이 계약서와 어긋나면 테스트가 잡게 했습니다 |

## 도장 검사 순서 — `verify_request(allowed_senders)`

위에서부터 확인하고, 하나라도 걸리면 `None`(거절)을 돌려줍니다. 모두 통과하면 보낸이 이름(`"shipper"` 또는 `"fw-agent"`)을 돌려줍니다.

| 순서 | 확인 | 걸리면 로그에 남는 이유 |
|---|---|---|
| 1 | 헤더 3개가 모두 있나 | `missing_header` |
| 2 | 보낸이가 이 창구에 허용된 이름인가 | `disallowed_sender` |
| 3 | 그 보낸이의 키가 비어 있지 않나 | `empty_key` |
| 4 | 시각이 정수인가 | `invalid_timestamp` |
| 5 | 지금과 시각 차이가 `NET_INTERNAL_MAX_SKEW_SECONDS`(60초) 이내인가 | `timestamp_skew` |
| 6 | 내가 계산한 서명과 같은가 (`hmac.compare_digest`) | `signature_mismatch` |

- **창구마다 받는 보낸이가 다릅니다.** 경보 접수(`net-events`)는 shipper만, 차단 목록·결과 보고(`blocks`, `blocks/ack`)는 fw-agent만, 생존 신호(`heartbeat`)는 둘 다.
- **키를 두 개로 나눈 이유:** 한쪽 키가 새도 다른 쪽 권한은 쓸 수 없게 하려는 것입니다. shipper 키로는 차단 결과를 꾸밀 수 없고, fw-agent 키로는 경보를 넣을 수 없습니다.
- **키가 비어 있으면 모두 거절합니다.** Vercel처럼 Track D 값을 넣지 않은 곳에서는 내부 창구가 자동으로 닫힙니다.
- **거절 이유는 로그에만 남기고 응답은 항상 `401 {"error": "unauthorized"}`** 입니다. "시각이 틀렸다", "서명이 틀렸다"를 알려 주면 공격자가 무엇을 고치면 되는지 배웁니다.
- **`compare_digest`를 쓰는 이유:** 일반 `==` 비교는 앞 글자가 다르면 바로 끝나서, 응답 시간 차이로 서명을 한 글자씩 맞혀 볼 수 있습니다. `compare_digest`는 항상 같은 시간이 걸립니다.
- 서명을 계산할 때 본문을 `request.get_data(cache=True)`로 읽습니다. 이렇게 저장해 둬야 뒤에서 창구가 `get_json()`으로 같은 본문을 다시 읽을 수 있습니다.

> **60초 제한이 막는 것과 못 막는 것:** 오래된 서류를 다시 내는 공격(재전송)은 막습니다. 하지만 60초 안에 같은 서류를 다시 내는 것까지 막지는 않습니다. 같은 경보가 두 번 들어와도 새로 저장하지 않는 처리는 경보마다 붙는 번호(`event_id`)로 접수 창구에서 합니다(다음 절).

## 지금 상태

서명 검사기를 쓰는 창구 4개는 2026-10-20 main 기준으로 모두 구현돼 있습니다. 경보 접수(`net-events`, B1-1)는 `network_events` 표에, 차단 창구(`blocks`·`blocks/ack`, C1-2)는 `network_blocks` 표에, 생존 신호(`heartbeat`, C1-2)는 `agent_heartbeats` 표에 씁니다. 네 창구 모두 서명이 없거나 틀리면 내용을 보기 전에 401로 돌려보냅니다. 경보 접수 이후의 흐름(보안 기록 승격·앱 등급 분리)은 다음 절에서 이어 씁니다.

## 직접 확인해 보기

```bash
# 서명 규칙·기준값·거절 이유 테스트
pytest tests/track_d/test_b_hmac.py -q

# 단지를 켠 뒤, 서명 없이 경보 창구를 부르면 401이 나와야 합니다
docker compose up -d
curl -i -X POST http://localhost:8080/api/internal/net-events -H "Content-Type: application/json" -d "{}"

# 앱 로그에서 거절 이유 확인 (missing_header)
docker compose logs app | grep internal_hmac
```

- 로그에는 거절 **이유만** 남고 키나 서명 값은 남지 않습니다.
- 서명 없이 보낸 요청은 401로 끝나므로 Supabase의 어느 표에도 새 행이 생기지 않아야 합니다. 창구별 표(`network_events` 등)는 다음 절에서 다룹니다.

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [routes/internal/_hmac.py](../../routes/internal/_hmac.py), [tests/track_d/test_b_hmac.py](../../tests/track_d/test_b_hmac.py)
- 뼈대(I0-1): [routes/internal/](../../routes/internal/) 창구 파일들, [tests/track_d/conftest.py](../../tests/track_d/conftest.py)의 `signed_headers`
