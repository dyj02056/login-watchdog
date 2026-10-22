# 52단계 — 경보 수집과 교차 상관분석 (서명 검사)

[◀ 51단계](guide51_network_sensor.md) · [전체 목차](beginner-guide.md) · 53단계 ▶ (작성 예정)

> [51단계](guide51_network_sensor.md)의 정문 CCTV가 본 것을 앱이 받아서 기존 보안 기록과 엮어 "같은 공격 흐름"인지 판단하는 과정을 다룹니다.
> 이 문서는 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 **서명 검사(B0-1)** 와 **경보 접수 창구·보안 기록 승격·앱 등급 분리(B1-1~B1-3)** 까지입니다(2026-10-22 main 기준). 교차 규칙(NET-01·CR-01·CR-02)은 다음 절에서 다룹니다.

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

서명 검사기를 쓰는 창구 4개는 2026-10-20 main 기준으로 모두 구현돼 있습니다. 경보 접수(`net-events`, B1-1)는 `network_events` 표에, 차단 창구(`blocks`·`blocks/ack`, C1-2)는 `network_blocks` 표에, 생존 신호(`heartbeat`, C1-2)는 `agent_heartbeats` 표에 씁니다. 네 창구 모두 서명이 없거나 틀리면 내용을 보기 전에 401로 돌려보냅니다. 경보 접수 이후의 흐름은 아래 ② 절에서 이어 씁니다. 차단 창구(`blocks`·`heartbeat`)는 [54단계](guide54_l4_block_agent.md)에서 다룹니다.

## ② 경보 접수 창구 — `POST /api/internal/net-events` (B1-1)

배달원(shipper)이 CCTV 기록 한 건을 서류 한 장(JSON)으로 만들어 냅니다. 접수대는 아래 순서로 확인하고, 처음 걸린 곳에서 돌려보냅니다.

| 순서 | 확인 | 걸리면 |
|---|---|---|
| 1 | 본문 크기가 `NET_INGEST_MAX_BODY_BYTES`(16KB) 이하인가 | `413` |
| 2 | shipper 도장이 맞는가 (`verify_request({"shipper"})`) | `401` |
| 3 | 본문이 JSON 객체인가 | `400 {"field": "body"}` |
| 4 | 칸마다 계약서 K4 규칙을 지키는가 | `400 {"field": "<처음 틀린 칸>"}` |

- **칸 검사(계약서 K4):** `event_id`는 64자 16진수, `sensor`·`layer`·`category`는 정해진 값만, `src_ip`는 실제 IP 주소, 시각은 `Z`로 끝나는 UTC, `packet_count`는 1~1,000만입니다. `True`처럼 정수로 착각되는 값도 거절합니다.
- **정해진 칸만 저장합니다.** 본문에 `id`·`promoted` 같은 서버 관리 칸을 끼워 넣어도 무시합니다. 출발지 주소는 `normalize_ip()`로 정리해서 저장합니다.
- **같은 서류 번호는 새로 저장하지 않습니다.** shipper는 같은 1분 창의 경보를 첫 건·창 끝 갱신·재시도 모두 같은 `event_id`로 보냅니다. 표의 유니크 제약이 두 번째 저장을 막고, 그때는 `packet_count`(더 클 때만)와 `last_seen_at`만 갱신합니다.
- **보낸이별 한도:** 분당 `NET_INGEST_RATE_LIMIT_PER_MINUTE`(600)번입니다. shipper는 단지 안 주소 하나에서 모든 경보를 보내므로 IP가 아니라 보낸이 이름으로 셉니다. 이 창구가 한도에 걸려도 `HTTP_FLOOD`로 기록하지 않습니다. 센서 자신의 전송이 "HTTP 폭주"로 잡혀 상관분석을 더럽히면 안 되기 때문입니다.

| 경우 | 응답 |
|---|---|
| 처음 저장 | `{"status": "stored", "promoted": true/false}` |
| 같은 `event_id` 재전송·갱신 | `{"status": "updated", "promoted": false}` |
| 재전송 중 승격 복구 | `{"status": "updated", "promoted": true}` — 처음 저장 직후 승격이 오류로 끊겼던 경보만 이번에 마저 올립니다 |

저장된 경보는 `network_events` 표에 남고, 관리자 화면용 조회 함수(`list_recent_network_events`, `count_network_events_by_category`)도 이 표를 읽습니다.

## ② 경보를 보안 기록으로 올리기 (B1-2)

`network_events`는 센서가 본 **원본 기록**입니다. 그중 정해진 다섯 종류만 형사가 다루는 **보안 기록**(`security_events`)으로 올립니다(`security/net_ingest.py`의 `promote()`). 모든 경보를 올리면 화면이 잡음으로 덮이기 때문입니다.

| 센서 분류(`category`) | 보안 이벤트 | 등급 | 증거 |
|---|---|---|---|
| `SYN_FLOOD` | `NET_SYN_FLOOD` | HIGH | 위조 가능 |
| `PORT_SCAN` | `NET_PORT_SCAN` | MEDIUM | 위조 가능 |
| `SCANNER_UA` | `NET_SCANNER_UA` | MEDIUM | 연결 완성 |
| `WEB_ATTACK` | `NET_WEB_ATTACK` | HIGH | 연결 완성 |
| `LOGIN_BURST` | `NET_LOGIN_BURST` | MEDIUM | 연결 완성 |
| `OTHER` | 올리지 않음 | — | — |

- **네트워크 경보는 최대 HIGH입니다.** CRITICAL은 "실제로 막았다"는 뜻으로만 씁니다(계획 P3). 그래서 CRITICAL 네트워크 이벤트는 정문 차단이 실제로 걸렸을 때 생기는 `NET_BLOCKED` 하나뿐입니다.
- **출처를 남깁니다.** 올린 행은 `source='NET'`, `layer`(L3·L4·L7), `action='NET_ALERT'`, `count=packet_count`입니다. 앱이 직접 남긴 기록은 `source='APP'`입니다. 이 칸이 다음 절(앱 등급 분리)의 근거가 됩니다.
- **HIGH는 기존 HIGH 이벤트와 같은 길로 올립니다.** 같은 IP·유형의 미해결 HIGH 이벤트가 있으면 새 행 대신 횟수만 올립니다(`insert_security_event_or_bump`). MEDIUM은 기존 `_record_event`로 올립니다. 어느 쪽이든 마지막에 상관분석(`check_and_correlate`)을 부르고, `source`를 끝까지 넘깁니다.
- **원본에 "올렸음" 표시:** 승격이 끝나면 `network_events.promoted`를 true로 바꿉니다. 재전송 때 승격 복구는 이 값이 false인 행만 대상으로 합니다.

**`NET_BLOCKED` 기록·해결 (계약서 K6)** — 집행관 쪽 창구([54단계](guide54_l4_block_agent.md))가 부르는 함수입니다.

| 함수 | 언제 | 하는 일 |
|---|---|---|
| `record_net_blocked(ip, reason)` | fw-agent가 "막았음(APPLIED)"을 보고한 순간 | `NET_BLOCKED`(CRITICAL, `action='L4_BLOCKED'`, `layer='L4'`) 기록. 같은 IP에 해결 안 된 것이 이미 있으면 새로 만들지 않음 |
| `resolve_net_blocked(ip)` | "풀었음(REMOVED)" 보고 또는 TTL 만료 | 그 IP의 미해결 `NET_BLOCKED`**만** 해결 처리(다른 이벤트는 건드리지 않음) |

`reason`(왜 막았나)은 로그·알림용이고 이벤트 칸에는 넣지 않습니다.

## ② 앱 등급 분리 — `app_severity_max` (B1-3)

기존 영구 잠금 판단(T3·T4)은 "사건의 최고 등급이 CRITICAL/HIGH면 그 IP를 영구 잠금"이었습니다. 네트워크 경보가 같은 사건에 섞이면 두 가지 문제가 생깁니다.

| 위험 | 예 | 막는 방법 |
|---|---|---|
| 위조된 경보로 영구 잠금 | 공격자가 남의 주소를 사칭해 SYN Flood(HIGH)를 보내면, 그 주소의 주인이 앱에서 영구 잠금됨 | 판단을 **앱 이벤트 등급만**으로 한다 |
| 일부러 섞어 방어 끄기(V1) | 네트워크 경보를 섞어 판단 기준을 흐리게 만듦 | 앱 등급은 네트워크 경보와 상관없이 따로 유지된다 |

그래서 사건(`security_incidents`)에 등급 칸이 두 개 있습니다.

| 칸 | 올리는 이벤트 | 쓰는 곳 |
|---|---|---|
| `severity_max` | 앱 + 네트워크 전체 | 복합 공격 Slack 알림(기존 그대로) |
| `app_severity_max` | `source='APP'`만 | **영구 잠금 판단(T3·T4)** — `consider_incident_promotion()` |

- `record_incident(..., source=...)`가 두 칸을 함께 관리합니다. 네트워크 경보로 새 사건이 열리면 `app_severity_max`는 비워 두고(NULL), 앱 이벤트가 들어올 때만 올립니다.
- 두 요청이 동시에 와도 앱 등급이 낮아지지 않게, "지금 값이 비었거나 더 낮을 때만" 바꾸는 조건부 UPDATE로 씁니다.
- `consider_incident_promotion()`은 `app_severity_max`만 봅니다. 값이 없으면 전체 등급으로 대신하지 않고 그냥 건너뜁니다. 함수 인자는 바꾸지 않았습니다.
- 마이그레이션(guide52 SQL)이 기존 사건의 `app_severity_max`를 `severity_max`로 채워 두었습니다. 기존 사건은 모두 앱 이벤트뿐이었으므로 판단 결과가 예전과 같습니다.

결과적으로 네트워크 경보만으로는 앱 영구 잠금이 걸리지 않습니다. 네트워크 경보가 강한 조치로 이어지는 길은 **교차 규칙**뿐이고, 그것도 위조 가능한 증거면 짧은 정문 차단(TTL)까지만 갑니다(다음 절).

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
- 서명 없이 보낸 요청은 401로 끝나므로 Supabase의 어느 표에도 새 행이 생기지 않아야 합니다.

**② 절 확인 (B1-1~B1-3)**

```bash
# 접수 창구·승격·NET_BLOCKED·앱 등급 분리 테스트 (실제 DB는 건드리지 않음)
pytest tests/track_d/test_b_ingest.py tests/track_d/test_b_net_ingest.py tests/track_d/test_b_app_severity.py -q
```

단지를 켜고 브라우저로 `/login`을 몇 번 연 뒤(shipper가 경보를 보내도록), Supabase SQL Editor에서 봅니다.

```sql
-- 원본 경보: 승격 대상이면 promoted가 true
select observed_at, src_ip, layer, category, packet_count, promoted
from network_events order by observed_at desc limit 10;

-- 올린 보안 기록: source가 NET
select detected_at, event_type, severity, ip_address, source, layer, count
from security_events where source = 'NET' order by detected_at desc limit 10;

-- 사건의 두 등급: 네트워크 경보만 있는 사건은 app_severity_max가 비어 있어야 한다
select id, ip_address, event_types, severity_max, app_severity_max, status
from security_incidents order by last_event_at desc limit 10;
```

- `OTHER` 경보는 `network_events`에만 있고 `security_events`에는 없어야 합니다.
- `NET_BLOCKED` 기록·해결을 직접 보는 방법은 [54단계 "직접 확인해 보기"](guide54_l4_block_agent.md#직접-확인해-보기)의 수동 차단 SQL입니다.

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [routes/internal/_hmac.py](../../routes/internal/_hmac.py), [tests/track_d/test_b_hmac.py](../../tests/track_d/test_b_hmac.py)
- 뼈대(I0-1): [routes/internal/](../../routes/internal/) 창구 파일들, [tests/track_d/conftest.py](../../tests/track_d/conftest.py)의 `signed_headers`
- B1-1: [routes/internal/ingest.py](../../routes/internal/ingest.py), [db/network_events.py](../../db/network_events.py), [tests/track_d/test_b_ingest.py](../../tests/track_d/test_b_ingest.py)
- B1-2: [security/net_ingest.py](../../security/net_ingest.py), [security/soar/_events.py](../../security/soar/_events.py)(`source`·`layer` 인자), [db/security_events.py](../../db/security_events.py)(선택 인자), [tests/track_d/test_b_net_ingest.py](../../tests/track_d/test_b_net_ingest.py)
- B1-3: [db/incidents.py](../../db/incidents.py)(`app_severity_max`), [security/lockdown.py](../../security/lockdown.py)의 `consider_incident_promotion()`, [tests/track_d/test_b_app_severity.py](../../tests/track_d/test_b_app_severity.py)
