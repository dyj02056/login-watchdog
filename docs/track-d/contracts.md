<!-- 이 파일은 팀 계획 문서 team-plan/02-연동-계약서.md의 저장소 사본이다(Track D 뼈대 PR). 원본이 바뀌면 통합 담당자가 다시 복사한다. 직접 고치지 않는다. -->

# 02. 연동 계약서 — 역할끼리 주고받는 약속

> **버전 v1.0 확정 (2026-10-12) · 10/13 보완(맨 아래 변경 기록)** — 통합 담당자가 현재 저장소 코드·역할별 요청서와 대조해 확정했다. 10/14 계획 확정 회의에서 세 사람의 동의를 받는다. 이후 바뀌는 내용은 맨 아래 변경 기록에 남긴다.
> **이 문서가 기준이다.** 함수 이름·인자·JSON 모양이 이 문서와 다르면 코드가 틀린 것이다.
> 뼈대 PR(I0-1)에서 이 문서를 저장소의 `docs/track-d/contracts.md`로 복사한다. LLM(Codex)은 저장소 사본을 읽는다.
> 바꾸려면 01의 8장 절차를 따른다. 바꾼 내용은 맨 아래 **변경 기록**에 남긴다.

**비전공자용 한 줄 설명:** 세 사람이 각자 부품을 만들어 마지막에 끼워 맞추려면, 미리 "나사 구멍 위치"를 정해 둬야 한다. 이 문서가 그 도면이다.

| 번호 | 무엇 | 만드는 쪽 → 쓰는 쪽 |
|---|---|---|
| K1 | 설정값 이름 (`config.py`, `.env`) | 통합 담당자 → 모두 |
| K2 | Docker 주소표 | A → 모두 |
| K3 | 내부 API 서명(HMAC) 규칙 | B → A·C |
| K4 | 경보 수집 API `POST /api/internal/net-events` | A(보냄) → B(받음) |
| K5 | 보안 이벤트 이름·등급 | B → C·통합(화면) |
| K6 | `NET_BLOCKED` 기록·해결 함수 | B → C |
| K7 | L4 차단 요청 함수 `netblock.*` | C → B |
| K8 | 조치 함수 3개 | C → B |
| K9 | fw-agent 내부 API (`/blocks`, `/blocks/ack`, `/heartbeat`) | C(앱·agent 둘 다) / A(shipper heartbeat) |
| K10 | 화면용 데이터 (`/api/status`, `/api/stats`) | B·C(API) → 통합 담당자(화면) |
| K11 | DB 표·칸 | B(마이그레이션) ← C(초안) |
| K12 | 규칙·플레이북·사유 이름표 | B → C |

---

## K1. 설정값 이름

뼈대 PR이 `config.py` 맨 아래 `# === Track D ===` 구역에 아래 이름을 **기본값과 함께 미리** 만든다. 담당자는 자기 소구역의 값만 조정한다.
읽는 방식은 기존 `config.py`와 같다: `os.environ.get("이름", "기본값")`을 알맞은 형으로 바꾼다.

| 이름 | 기본값 | 소구역 | 뜻 |
|---|---|---|---|
| `NET_INGEST_SECRET` | `""` | B | shipper → 앱 서명 키. 비어 있으면 수집 API가 **모든 요청을 401**로 거부 |
| `NET_INTERNAL_MAX_SKEW_SECONDS` | `60` | B | 서명 타임스탬프 허용 오차(초). 넘으면 401 |
| `NET_INGEST_MAX_BODY_BYTES` | `16384` | B | 수집 요청 본문 최대 크기. 넘으면 413 |
| `NET_INGEST_RATE_LIMIT_PER_MINUTE` | `600` | B | 보낸이(`X-LW-Sender` 헤더)별 분당 수집 요청 한도. 넘으면 429. PC마다 shipper가 하나이므로 사실상 PC별 한도다. 서명 검사 전에 세므로 헤더 값은 이름표로만 쓴다 |
| `NET_CORRELATION_WINDOW_MINUTES` | `15` | B | CR-01·04·06 창 |
| `NET_FLOOD_WINDOW_MINUTES` | `5` | B | CR-02 창 |
| `NET_SUCCESS_LOGIN_LOOKBACK_MINUTES` | `30` | B | CR-03 창 |
| `NET_ROTATION_WINDOW_MINUTES` | `10` | B | CR-05 창 |
| `NET_SUBNET_MIN_IPS` | `3` | B | CR-04 같은 /24 최소 IP 수 |
| `NET_FLOOD_REPEAT_DAYS` | `30` | B | CR-02 반복 판단 기간 |
| `NET_AGENT_SECRET` | `""` | C | fw-agent → 앱 서명 키. 비어 있으면 agent API가 모든 요청을 401로 거부 |
| `TRUSTED_PROXY_IPS` | `""` (쉼표 목록) | C | 이 주소에서 온 요청만 X-Forwarded-For를 믿는다. **비어 있으면 기존 동작 그대로** |
| `NET_EDGE_SUBNET` | `""` | C | 이 PC가 맡는 공격 대역(예 `172.28.13.0/24`). 비어 있으면 필터 없음 |
| `NET_BLOCK_DEFAULT_TTL_SECONDS` | `3600` | C | 위조 가능 증거 L4 차단 기본 1시간 |
| `NET_BLOCK_MAX_TTL_SECONDS` | `21600` | C | 위조 가능 증거 L4 차단 최대 6시간 |
| `NET_BLOCK_REPEAT_DAYS` | `30` | C | TTL 2배 계산에 쓰는 과거 차단 조회 기간 |
| `SUSPICIOUS_LOGIN_MAIL_COOLDOWN_SECONDS` | `3600` | C | 같은 주소로 의심 로그인 경고 메일을 다시 보내기까지의 시간 |
| `FW_AGENT_STALE_SECONDS` | `30` | C | fw-agent가 이 시간 넘게 조용하면 "정지" |
| `SHIPPER_STALE_SECONDS` | `120` | C | shipper가 이 시간 넘게 조용하면 "정지" |
| `AGENT_ALERT_COOLDOWN_SECONDS` | `600` | C | 구성요소 정지 Slack 알림 쿨다운 |
| `LW_NODE_NAME` | `""` | C | 이 앱이 어느 PC의 Track D인지(`A`·`B`·`C`·`demo`). 생존 신호를 PC별로 저장하고 화면에 이 PC 것만 보여 준다. **비어 있으면(Vercel 등) 장비 정지 감시·알림을 하지 않는다** |

**`.env`에만 있고 `config.py`에는 없는 값 (Docker Compose가 읽음, A 소구역)**

| 이름 | 예 | 뜻 |
|---|---|---|
| `LW_EDGE_PREFIX` | `172.28.13` | 사람별 공격 대역 앞 세 자리 (01의 4장 표) |
| `SENSOR_IFACE` | `eth0` | Suricata·Scapy가 감시할 인터페이스 (A0-2에서 확인한 값) |
| `LW_VICTIM_PASSWORD` | (사람마다 다름) | S4·S6에서 공격 상자(attacker-2)가 `victim_<역할>` 계정으로 로그인할 때 쓰는 테스트 계정 비밀번호. A2-1의 로그인 명령과 C3-1이 읽는다. **LLM에 붙여 넣지 않고** 이미지·compose·README에 값을 적지 않는다 |

---

## K2. Docker 주소표 (A가 `docker-compose.yml`로 보장)

| 대상 | 주소 | 비고 |
|---|---|---|
| gateway(nginx) edge 쪽 | `${LW_EDGE_PREFIX}.10` | sensor·l4-detector·fw-agent가 이 네임스페이스를 공유 |
| gateway core 쪽 | `172.29.0.10` (고정) | 앱의 `TRUSTED_PROXY_IPS` 값 |
| attacker-1 / 2 / 3 | `${LW_EDGE_PREFIX}.101` / `.102` / `.103` | `profiles: [attack]` |
| 내 브라우저(호스트) | `${LW_EDGE_PREFIX}.1` | 허용 목록에 넣는다 |
| 앱 내부 주소 | `http://app:5000` | shipper·fw-agent가 사용 |
| 외부 접속 | `http://localhost:8080` | gateway만 포트 공개 |
| Mailpit 화면 | `http://localhost:8025` | |

---

## K3. 내부 API 서명(HMAC) 규칙 — `routes/internal/_hmac.py` (B 소유, B0-1)

**보내는 쪽(shipper·fw-agent)이 붙이는 헤더**

| 헤더 | 값 |
|---|---|
| `X-LW-Sender` | `shipper` 또는 `fw-agent` |
| `X-LW-Timestamp` | 현재 유닉스 시각(초, 정수 문자열). 예: `1760930000` |
| `X-LW-Signature` | `hex(hmac_sha256(key, timestamp + "." + body))` — 소문자 16진수 |

- `body`는 **보낸 바이트 그대로**다. GET 요청은 빈 바이트 `b""`.
- 서명 대상 바이트: `timestamp.encode("ascii") + b"." + body`.
- 키 선택: `X-LW-Sender: shipper` → `NET_INGEST_SECRET`, `fw-agent` → `NET_AGENT_SECRET`.
- 엔드포인트마다 허용하는 보낸이: `net-events` = shipper만, `blocks`·`blocks/ack` = fw-agent만, `heartbeat` = 둘 다.

**앱 쪽 함수**

```python
# routes/internal/_hmac.py
def sign(key: str, timestamp: str, body: bytes) -> str:
    """서명 문자열(hex)을 만든다. 테스트와 보내는 쪽 구현의 기준값."""

def verify_request(allowed_senders: set[str]) -> str | None:
    """현재 flask.request의 서명을 검증한다.
    성공하면 보낸이 이름('shipper' | 'fw-agent'), 실패하면 None.
    실패 조건: 헤더 누락, 허용되지 않은 보낸이, 키가 빈 문자열,
             |now - timestamp| > NET_INTERNAL_MAX_SKEW_SECONDS, 서명 불일치(hmac.compare_digest)."""
```

**실패 응답 (모든 내부 API 공통)**

| 상황 | 응답 |
|---|---|
| 서명·타임스탬프 실패 | `401 {"error": "unauthorized"}` — 이유를 자세히 알려 주지 않는다 |
| 본문 크기 초과 | `413 {"error": "too_large"}` |
| 형식 오류 | `400 {"error": "invalid", "field": "<칸 이름>"}` |
| 한도 초과 | `429 {"error": "rate_limited"}` |

> **shipper·fw-agent는 앱 코드를 import하지 않는다**(다른 컨테이너). 같은 규칙을 각자 파일에 직접 구현하고, B의 `sign()`과 같은 값이 나오는지 테스트로 확인한다. 기준 예시값: key=`test-key`, timestamp=`1760930000`, body=`b'{"a":1}'` → 결과값 **`2f744cec328f65506df5ad72df7fdd688c7a3cf3c6f90b1e0085849106179de2`**. B의 `sign()`(B0-1), A의 shipper(A1-3), C의 fw-agent(C1-3), 뼈대의 `tests/track_d/conftest.py`가 모두 이 값을 만들어야 한다.

---

## K4. 경보 수집 API — `POST /api/internal/net-events`

**요청 본문 (A의 shipper가 만든다)**

```json
{
  "event_id": "9f2c…(64자 16진수)",
  "sensor": "suricata",
  "layer": "L4",
  "src_ip": "172.28.13.103",
  "dst_port": 8080,
  "proto": "TCP",
  "category": "SYN_FLOOD",
  "signature_id": 9000001,
  "signature": "LW SYN flood suspected",
  "sensor_severity": 1,
  "packet_count": 143,
  "window_start": "2026-10-20T03:12:00Z",
  "observed_at": "2026-10-20T03:12:44.120Z"
}
```

**칸별 규칙 (B가 검증, 어기면 400)**

| 칸 | 형 | 필수 | 허용 값 |
|---|---|---|---|
| `event_id` | 문자열 | ✓ | 정규식 `^[0-9a-f]{64}$` |
| `sensor` | 문자열 | ✓ | `suricata`, `scapy` |
| `layer` | 문자열 | ✓ | `L3`, `L4`, `L7` |
| `src_ip` | 문자열 | ✓ | `ipaddress.ip_address()` 통과. 저장 전 `normalize_ip()` |
| `dst_port` | 정수 또는 null | | 0~65535 |
| `proto` | 문자열 또는 null | | `TCP`, `UDP`, `ICMP` |
| `category` | 문자열 | ✓ | `SYN_FLOOD`, `PORT_SCAN`, `SCANNER_UA`, `WEB_ATTACK`, `LOGIN_BURST`, `OTHER` |
| `signature_id` | 정수 | ✓ | 1 이상 |
| `signature` | 문자열 | ✓ | 1~200자 |
| `sensor_severity` | 정수 또는 null | | 1~3 |
| `packet_count` | 정수 | ✓ | 1~10,000,000 |
| `window_start` | 문자열 | ✓ | ISO 8601 UTC, `Z`로 끝남 |
| `observed_at` | 문자열 | ✓ | ISO 8601 UTC, `Z`로 끝남 |

**`event_id`·`window_start` 만드는 법 (A)**

- `window_start` = 경보 시각을 **분 단위로 내림**한 값. 예: `03:12:44.120Z` → `03:12:00Z`. 60초 창은 매 분 정각에 시작한다.
- `event_id` = `sha256(f"{sensor}|{src_ip}|{category}|{signature_id}|{window_start}")`의 hex.
- 같은 창의 첫 전송·창 종료 시 갱신·재시도는 모두 같은 `event_id`다. 갱신 때는 그 창의 누적 `packet_count`를 보낸다.

**`category`·`signature_id` 정하는 법 (A의 shipper)**

| 출처 | 조건 | category | layer | signature_id |
|---|---|---|---|---|
| Suricata | sid `9000001` | `SYN_FLOOD` | L4 | 9000001 |
| Suricata | sid `9000003` | `LOGIN_BURST` | L7 | 9000003 |
| Suricata | sid `9000004` | `SCANNER_UA` | L7 | 9000004 |
| Suricata | 위에 없고 classtype `web-application-attack` | `WEB_ATTACK` | L7 | 원래 sid |
| Suricata | 그 외 alert | `OTHER` | L4 | 원래 sid |
| Scapy | SYN 비율 초과 | `SYN_FLOOD` | L4 | **9100001** |
| Scapy | 서로 다른 포트 수 초과 | `PORT_SCAN` | L4 | **9100002** |

**응답 (B)**

| 경우 | 응답 |
|---|---|
| 처음 저장 | `200 {"status": "stored", "promoted": true/false}` |
| 같은 `event_id` 재전송·갱신 | `200 {"status": "updated", "promoted": false}` — `packet_count`(더 큰 값)·`last_seen_at`만 갱신, 보안 이벤트로 다시 올리지 않음 |

> 재시도 판단(A): `5xx`·연결 실패만 지수 백오프로 재시도한다. `4xx`는 재시도하지 않고 로그만 남긴다.

---

## K5. 보안 이벤트 이름·등급 (B가 기록, 통합 담당자가 화면에 표시)

| category | event_type | 등급 | 증거 | 보안 이벤트로 올림 |
|---|---|---|---|---|
| `SYN_FLOOD` | `NET_SYN_FLOOD` | HIGH | 위조 가능 | ✓ (HIGH는 기존 bump 경로) |
| `PORT_SCAN` | `NET_PORT_SCAN` | MEDIUM | 위조 가능 | ✓ |
| `SCANNER_UA` | `NET_SCANNER_UA` | MEDIUM | 연결 완성 | ✓ |
| `WEB_ATTACK` | `NET_WEB_ATTACK` | HIGH | 연결 완성 | ✓ |
| `LOGIN_BURST` | `NET_LOGIN_BURST` | MEDIUM | 연결 완성 | ✓ |
| `OTHER` | — | — | — | ✕ (`network_events`에만) |
| (L4 차단 실제 적용) | `NET_BLOCKED` | **CRITICAL** | — | K6 함수로만 |

- NET 이벤트의 `security_events.source='NET'`, `layer`는 수집 값 그대로, `path=None`, `count=packet_count`, `action='NET_ALERT'`.
- `NET_BLOCKED`는 `action='L4_BLOCKED'`, `layer='L4'`.
- `_record_event` 새 모양(B1-2):

```python
def _record_event(event_type, severity, ip, path, count, action,
                  username=None, source="APP", layer=None) -> None
```

기존 호출부는 그대로 동작해야 한다(새 인자는 모두 기본값 있음).

---

## K6. `NET_BLOCKED` 기록·해결 — `security/net_ingest.py` (B 소유, B1-2) → C가 호출

```python
# security/net_ingest.py
def record_net_blocked(ip: str, reason: str) -> None:
    """fw-agent가 APPLIED를 보고한 순간 C가 부른다. NET_BLOCKED(CRITICAL)를 기록한다.
    같은 IP에 미해결 NET_BLOCKED가 이미 있으면 새로 만들지 않는다(멱등).
    교차 계층 규칙의 입력으로 쓰지 않는다."""

def resolve_net_blocked(ip: str) -> None:
    """fw-agent가 REMOVED를 보고했거나 TTL이 만료됐을 때 C가 부른다.
    그 IP의 미해결 NET_BLOCKED만 해결 처리한다(다른 이벤트는 건드리지 않음)."""
```

**B1-2가 머지되기 전 C의 임시 방법:** 테스트에서 `monkeypatch.setattr(net_ingest, "record_net_blocked", 가짜)`로 바꿔 끼운다. 코드는 `from security import net_ingest` 후 `net_ingest.record_net_blocked(...)`처럼 **모듈 이름을 거쳐** 부른다.

---

## K7. L4 차단 요청 — `security/netblock.py` (C 소유, C0-2)

```python
def request_block(ip: str, reason: str, evidence: str,
                  ttl_seconds: int | None = None,
                  requested_by: str = "playbook") -> bool:
    """network_blocks에 '막아라'를 기록한다(실제 차단은 fw-agent). 실제로 바뀌었을 때만 True.

    거부(False): 허용 목록 IP(lockdown.is_ip_allowlisted), IP 형식 오류, IPv6,
                 '/'가 들어간 대역, evidence가 'SPOOFABLE'/'CONNECTED'가 아님.
    TTL 계산:
      - evidence='SPOOFABLE': ttl_seconds가 None이면
        NET_BLOCK_DEFAULT_TTL_SECONDS × 2^(최근 NET_BLOCK_REPEAT_DAYS일 이 IP 차단 횟수),
        어떤 경우든 NET_BLOCK_MAX_TTL_SECONDS로 상한. 영구(None) 불가.
      - evidence='CONNECTED': ttl_seconds=None이면 영구(expires_at=NULL).
    멱등: 이미 PENDING_APPLY/APPLIED이고 기존 차단이 같거나 더 강하면(영구이거나 만료가 더 늦음) False.
          더 약하면 강한 쪽으로 갱신하고 PENDING_APPLY로 되돌린 뒤 True.
          REMOVED/FAILED 행은 같은 행을 PENDING_APPLY로 재사용."""

def request_unblock(ip: str, actor: str) -> bool:
    """PENDING_APPLY/APPLIED인 행을 PENDING_REMOVE로 바꾼다. 바뀌었을 때만 True."""
```

- `reason` 값은 K12 표에서 고른다. `requested_by`는 `playbook:<플레이북 이름>`, `admin:<관리자 아이디>`, `script:<스크립트 이름>` 중 하나.
- **플레이북이 부를 때 넘기는 값 (B2-2):**
  - `block_l4_ttl` → `request_block(ip, "NET_FLOOD", evidence="SPOOFABLE", ttl_seconds=None, requested_by="playbook:<플레이북>")`. TTL 계산(기본 × 2^반복, 상한)은 이 함수만 한다. CR-02처럼 연결 완성 증거가 있어도 `SPOOFABLE`로 넘긴다 — `CONNECTED` + `None`은 영구 차단이 되기 때문이다.
  - `block_l4` → `request_block(ip, "KILL_CHAIN", evidence="CONNECTED", ttl_seconds=None, requested_by="playbook:KILL_CHAIN")`. CR-01 영구 L4 전용.
- `netblock.py`는 `db`, `config`, `lockdown.is_ip_allowlisted`만 import한다(순환 import 방지: `lockdown`은 `release()` 안에서 함수 안 import로 `netblock`을 부른다).

**C0-2가 머지되기 전 B의 임시 방법:** 테스트에서 `monkeypatch.setattr(netblock, "request_block", lambda *a, **k: True)`.

---

## K8. 조치 함수 (C 소유, C2-1) → B의 플레이북이 호출

```python
# db/users.py
def bump_session_version(user_id: int) -> bool:
    """users.session_version을 조건부 UPDATE로 1 올린다(비밀번호 변경과 같은 방식).
    경합으로 0행이면 1회 다시 읽어 재시도. 성공하면 True."""

# notify/mailer.py
def send_suspicious_login_notice(to_address: str, ip: str, at_iso: str) -> str:
    """의심 로그인 경고 메일. 반환: mailer.SENT / REFUSED / FAILED / SKIPPED.
    (SKIPPED는 지금 mailer.py에 없는 값이다. C2-1이 SENT·REFUSED·FAILED 옆에 SKIPPED = "SKIPPED"를 추가한다.)
    같은 주소로 SUSPICIOUS_LOGIN_MAIL_COOLDOWN_SECONDS 안에 이미 보냈으면 보내지 않고 SKIPPED.
    쿨다운은 db.try_acquire_cooldown(f"mail:suspicious:{to_address.lower()}", 초)로 판단(여러 스레드·여러 PC 공통)."""

# notify/alert.py
def send_playbook_alert(playbook: str, ip: str, matched_rules: list[str],
                        results: list[dict]) -> None:
    """플레이북 실행 결과를 Slack으로 알린다. results 항목:
    {"step": "block_l4_ttl", "status": "OK" | "FAILED" | "SKIPPED", "error": str | None}.
    실패한 단계가 있으면 메시지 첫 줄에 '⚠ 일부 조치 실패'를 넣는다(V6)."""

# db/agent_heartbeats.py (C)
def try_acquire_cooldown(key: str, seconds: int) -> bool:
    """notification_cooldowns 표로 '지금 보내도 되는지'를 원자적으로 판단한다.
    마지막 전송이 seconds보다 오래됐거나 기록이 없으면 지금 시각으로 기록하고 True."""
```

**플레이북이 넘기는 `ctx` (B가 채움)**

```python
ctx = {
    "ip": "172.28.13.102",
    "incident_id": 12 | None,
    "rule_id": "CR-01",
    "priority": "CRITICAL" | "HIGH",          # 규칙의 알림 우선순위(보안 이벤트 등급과 별개)
    "matched_rules": ["CR-01"],               # 이 사건에 지금까지 맞은 규칙 ID 전부(Slack 알림에 그대로 넘김)
    "evidence": "CONNECTED" | "SPOOFABLE",
    "username": "victim_c" | None,
    "user_id": 7 | None,
    "user_email": "victim@example.com" | None,
}
```

---

## K9. fw-agent·heartbeat 내부 API (C 소유, C1-2)

모든 요청에 K3 서명 헤더를 붙인다.

**① `GET /api/internal/blocks`** (보낸이: fw-agent) — 2초마다

```json
{
  "generated_at": "2026-10-20T03:12:46Z",
  "blocks": [
    {"ip": "172.28.13.103", "status": "PENDING_APPLY",  "ttl_seconds": 3600},
    {"ip": "172.28.13.102", "status": "APPLIED",        "ttl_seconds": null},
    {"ip": "172.28.13.101", "status": "PENDING_REMOVE", "ttl_seconds": null}
  ]
}
```

- "원하는 상태" 전체를 돌려준다: `PENDING_APPLY`, `APPLIED`, `PENDING_REMOVE` 행.
- `ttl_seconds` = 만료까지 **남은** 초(올림). 영구면 `null`. `PENDING_REMOVE`는 `null`.
- **`NET_EDGE_SUBNET`이 설정돼 있으면 그 대역 안의 IP만** 돌려준다.
- 응답하기 전에 **만료된 `APPLIED`/`PENDING_APPLY` 행을 `REMOVED`로 바꾸고** `net_ingest.resolve_net_blocked(ip)`를 부른다(지연 만료 처리).
- agent 동작: `PENDING_APPLY` → `ipset add … timeout <ttl>`(영구면 timeout 없음) 후 ack `APPLIED` / `APPLIED` → 없으면 다시 추가(drift 보정) / `PENDING_REMOVE` → `ipset del` 후 ack `REMOVED`.

**② `POST /api/internal/blocks/ack`** (보낸이: fw-agent)

```json
{"ip": "172.28.13.103", "status": "APPLIED", "error": null}
```

| status | 허용되는 이전 상태 | 바뀌면 앱이 하는 일 |
|---|---|---|
| `APPLIED` | `PENDING_APPLY` | `applied_at` 기록, `net_ingest.record_net_blocked(ip, reason)` |
| `REMOVED` | `PENDING_REMOVE` | `removed_at` 기록, `net_ingest.resolve_net_blocked(ip)` |
| `FAILED` | `PENDING_APPLY`, `PENDING_REMOVE` | `last_error` 기록(최대 500자) |

응답: `200 {"changed": true | false}`. 이전 상태가 맞지 않으면 `changed: false`(오류 아님, 멱등). 대역 밖 IP는 `400 {"error": "invalid", "field": "ip"}`.

**③ `POST /api/internal/heartbeat`** (보낸이: fw-agent 또는 shipper)

```json
{"agent": "fw-agent", "detail": {"poll_failures": 0, "ipset_size": 2}}
{"agent": "shipper", "stalled": false, "detail": {"eve_bytes": 104857, "l4_bytes": 2048, "queue": 0}}
```

- `agent`는 `X-LW-Sender`와 같아야 한다(다르면 400). `detail`은 JSON 객체, 직렬화 2KB 이하.
- 보내는 주기: fw-agent **10초**, shipper **30초**. (정지 판단 기준 30초와 같으면 배지가 깜빡이므로 fw-agent는 10초. 본 계획서 2.6도 10/13에 맞췄다)
- 앱은 받은 신호를 **(agent, `LW_NODE_NAME`)** 한 줄로 저장한다. 세 PC가 같은 DB를 써도 서로 덮어쓰지 않는다. `LW_NODE_NAME`이 비어 있으면 `400 {"error": "invalid", "field": "node"}`.
- `stalled: true`를 받으면 앱이 Slack 알림(구성요소당 `AGENT_ALERT_COOLDOWN_SECONDS` 쿨다운).
- 신호를 받을 때 **상대 장비**(fw-agent ↔ shipper)의 마지막 신호도 확인해, 정지 기준(`FW_AGENT_STALE_SECONDS` / `SHIPPER_STALE_SECONDS`)을 넘었으면 Slack 알림을 보낸다. 쿨다운 키 `slack:stale:<LW_NODE_NAME>:<장비>`는 K10 화면 쪽(C2-3) 정지 알림과 같아서 두 번 가지 않는다. 관리자 화면을 아무도 열지 않아도 정지를 알리기 위해서다. 이 확인이 실패해도 응답은 `200 {"ok": true}`.
- 응답: `200 {"ok": true}`.

---

## K10. 화면용 데이터 (API = C2-3, 화면 = 통합 담당자 I2-1)

**`GET /api/status`에 추가되는 칸**

```json
{
  "network_events": [
    {"id": 1, "observed_at": "…Z", "src_ip": "172.28.13.103", "layer": "L4",
     "category": "SYN_FLOOD", "signature": "LW SYN flood suspected",
     "packet_count": 143, "promoted": true}
  ],
  "network_blocks": [
    {"ip": "172.28.13.103", "reason": "NET_FLOOD", "evidence": "SPOOFABLE",
     "status": "APPLIED", "expires_at": "…Z", "requested_by": "playbook:NET_FLOOD_TTL",
     "applied_at": "…Z", "last_error": null}
  ],
  "agent_status": {
    "fw-agent": {"last_seen_at": "…Z", "stale": false, "detail": {}},
    "shipper":  {"last_seen_at": null,  "stale": true,  "detail": {}}
  }
}
```

- `network_events`: 최근 50건, 최신순. 데이터는 B가 제공하는 `db.list_recent_network_events(limit=50)`. `NET_EDGE_SUBNET`이 설정돼 있으면 그 대역의 `src_ip`만 남긴다(C2-3에서 거름).
- `agent_status`: **이 앱의 `LW_NODE_NAME`** 줄만. `LW_NODE_NAME`이 비어 있으면 빈 객체 `{}`를 돌려준다.
- `network_blocks`: `REMOVED` 제외 전부 + 최근 24시간 `REMOVED`. `db.list_network_blocks_for_dashboard()`(C). `NET_EDGE_SUBNET`이 설정돼 있으면 그 대역의 `ip`만 남긴다(C2-3에서 거름).
- 기존 사건 목록의 각 항목에 `"matched_rules": ["CR-01"]` 추가(B2-1이 칸을 채우고, 화면 표시는 통합 담당자의 선택 작업).

**`GET /api/stats`의 `network_layer`** (지금은 빈 목록)

```json
"network_layer": [
  {"category": "SYN_FLOOD", "layer": "L4", "count": 12},
  {"category": "SCANNER_UA", "layer": "L7", "count": 3}
]
```

최근 `RECENT_DAYS`(7일, `db/stats.py`의 값) 집계. B가 제공하는 `db.count_network_events_by_category(since_iso: str) -> list[dict]`.
이 통계는 `NET_EDGE_SUBNET`으로 거르지 않는다 — 공용 DB 전체(세 PC 합계) 집계다. 발표 날에는 시연 PC만 돌기 때문에 시연 결과만 남는다.

---

## K11. DB 표·칸 — `docs/migrations/guide52_track_d.sql` (B0-2)

본 계획서 2.3 ⑥의 SQL에 아래를 **더한다**.

> 쿨다운 표와 PC별 생존 신호 표는 10/13에 본 계획서 2.3 ⑥에도 같은 정의로 반영했다. guide52에는 한 번만 만든다.

| 추가 | 내용 | 이유 |
|---|---|---|
| 기존 사건 값 채우기 | `update security_incidents set app_severity_max = severity_max where app_severity_max is null;` | 기존 사건은 모두 앱 이벤트뿐이다. `consider_incident_promotion()`이 새 칸만 읽어도 기존 사건 판단이 바뀌지 않음 |
| 쿨다운 표 (C 소유) | `create table notification_cooldowns (key text primary key, last_sent_at timestamptz not null);` | 메일·Slack 쿨다운을 여러 스레드·여러 PC(같은 DB)·Vercel 인스턴스가 함께 지키도록 |
| 생존 신호 표 변경 (C 소유) | 본 계획서 DDL 대신: `create table agent_heartbeats (agent text not null check (agent in ('fw-agent','shipper')), node text not null, last_seen_at timestamptz not null, detail jsonb, primary key (agent, node));` | 세 PC가 같은 DB를 쓰므로 PC(`LW_NODE_NAME`)별로 저장 |
| 권한 추가 | `permissions_action_check`에 `'release_network_block'` 추가, `unlock_ip`를 가진 역할에 같은 권한 insert | (선택) L4 해제 버튼. 나중에 마이그레이션을 다시 만들지 않도록 미리 넣는다 |
| `access_requests` 확장 | 본 계획서대로 `NET_REPEAT_FLOOD`·`NET_SUBNET_ATTACK` / `BLOCK_L4_PERMANENT`·`BLOCK_SUBNET` / `subnet` 허용 | CR-02 반복, CR-04 |
| 사건 상태 | `security_incidents.status` 제약은 현재 DB 기준을 확인하고 건드리지 않는다 | 추가만(01의 D2) |

- 모든 문장은 **여러 번 실행해도 안전**하게 쓴다: `create table if not exists`, `add column if not exists`, `drop constraint if exists` 후 `add constraint`, `on conflict do nothing`.
- 파일 맨 위 주석에 "실행 순서·되돌리는 방법(rollback SQL)"을 적는다.
- 같은 내용을 `docs/schema.sql`에도 반영한다.

---

## K12. 이름표 (B 정의, 모두 같은 철자 사용)

**교차 계층 규칙과 플레이북**

| 규칙 ID | 플레이북 | 단계 (`ACTIONS` 이름) |
|---|---|---|
| `NET-01` | `NET_FLOOD_TTL` | `block_l4_ttl`, `notify_slack` |
| `CR-01` | `KILL_CHAIN` | `lock_ip_permanent`, `block_l4`, `notify_slack`, `llm_postmortem` |
| `CR-02` | `NET_FLOOD` | `block_l4_ttl`, `notify_slack` (+반복 시 `require_approval`) |
| `CR-03` | `SUSPICIOUS_SUCCESS_LOGIN` | `invalidate_sessions`, `notify_owner_email`, `notify_slack` |
| `CR-04` | `SUBNET_REVIEW` | `require_approval`, `notify_slack` |
| `CR-05` | `ROTATION_EVASION` | `lock_account_permanent`, `notify_owner_email`, `notify_slack` |
| `CR-06` | `WEB_ATTACK` | `lock_ip_permanent`, `notify_slack` |

- 필수는 `NET-01`·`CR-01`·`CR-02`·`CR-03`. `CR-04`~`CR-06`과 `llm_postmortem` 단계는 선택 과제다(01의 7.6). 실행 함수가 없는 단계는 `SKIPPED`로 기록한다.
- 기존 복합 공격 알림 플레이북 `CRITICAL_MULTI_STAGE`는 **`security/correlate.py`의 `PLAYBOOKS`에 그대로 둔다.** 새 `security/playbooks.py`는 위 Track D 플레이북만 담당한다(기존 코드·테스트를 건드리지 않기 위해).

**`network_blocks.reason` 값**

| 값 | 쓰는 곳 |
|---|---|
| `NET_FLOOD` | NET-01, CR-02 |
| `KILL_CHAIN` | CR-01 |
| `ADMIN_MANUAL` | 사람이 직접 넣은 수동 차단. 관리자 화면에 수동 차단 기능은 없고, M1 확인 때 통합 담당자가 Supabase SQL로 한 줄 넣는다(03 점검서) |

**`playbook_runs.status`**: `OK`, `FAILED`, `SKIPPED`
**`playbook_runs.trigger_ref`**: `incident:<사건 id>:<규칙 ID>` (예: `incident:12:CR-01`). 모든 교차 계층 규칙은 사건을 열거나 병합한 뒤 플레이북을 실행하므로 사건 번호가 항상 있다.

---

## 변경 기록

| 날짜 | 번호 | 내용 | 합의 |
|---|---|---|---|
| 2026-10-12 | 전체 | 초안 작성 | — |
| 2026-10-12 | K1·K9·K10·K11 | `LW_NODE_NAME` 추가, 생존 신호를 PC별 저장, 화면 데이터를 내 대역·내 PC 것으로 거름(공용 DB 대응) | 계획 확정 회의(10/14)에서 확인 |
| 2026-10-12 | K8 | 새 DB 함수 위치 규칙: 기존 `db/*.py`에는 추가하지 않고 B는 `db/network_events.py`·`db/playbook_runs.py`, C는 `db/network_blocks.py`·`db/agent_heartbeats.py`에 둔다. 예외 `db.bump_session_version`은 뼈대 PR이 `db/users.py`에 자리를 만든다 | 같은 회의에서 확인 |
| 2026-10-12 | K3 | 기준 예시 서명값 기입: `2f744cec328f65506df5ad72df7fdd688c7a3cf3c6f90b1e0085849106179de2` (B0-1 머지 전에 미리 계산) | 같은 회의에서 확인 |
| 2026-10-12 | K1 | 수집 한도를 "센서별"에서 "보낸이(`X-LW-Sender`)별"로 고침(B1-1 구현 방식과 맞춤). 설정 읽는 방식을 실제 `config.py`대로 `os.environ.get`으로 고침 | 같은 회의에서 확인 |
| 2026-10-12 | K7·K8 | `requested_by`에 `script:<이름>` 추가. `ctx`에 `priority`·`matched_rules` 추가. `mailer.SKIPPED`는 C2-1이 새로 만든다고 명시 | 같은 회의에서 확인 |
| 2026-10-12 | K10·K11 | 차단 목록도 `NET_EDGE_SUBNET`으로 거른다고 명시, `network_layer` 통계는 공용 합계라고 명시. 해제 권한의 이유를 "(선택) L4 해제 버튼"으로 고침 | 같은 회의에서 확인 |
| 2026-10-12 | K12 | `trigger_ref`를 `incident:<사건 id>:<규칙 ID>` 하나로 정함(`event:<id>` 삭제). `ADMIN_MANUAL`은 M1 확인용 SQL 수동 차단. 기존 `CRITICAL_MULTI_STAGE`는 `correlate.py`에 그대로 둠. 필수·선택 규칙 구분 명시 | 같은 회의에서 확인 |
| 2026-10-12 | 전체 | **v1.0 확정**: 저장소 코드(`main` `6a7fc71`)·역할별 요청서와 대조 완료 | 10/14 회의에서 동의 |
| 2026-10-13 | K1 | `.env` 전용 값에 `LW_VICTIM_PASSWORD` 추가 — S4·S6은 공격 상자(attacker-2)에서 로그인해야 CR-03이 맞으므로 A2-1의 로그인 명령과 C3-1이 함께 쓴다 | 10/14 회의에서 확인 |
| 2026-10-13 | K7 | 플레이북이 `request_block`에 넘기는 값 명시: `block_l4_ttl`은 `SPOOFABLE`·`ttl_seconds=None`·`NET_FLOOD`, `block_l4`는 `CONNECTED`·`KILL_CHAIN`. ctx의 `CONNECTED`를 그대로 넘기면 CR-02가 영구 차단되는 문제 방지 | 같은 회의 |
| 2026-10-13 | K9 | heartbeat를 받을 때 상대 장비 정지도 확인해 알림(관리자 화면을 안 열어도 알림). fw-agent 10초 메모 정리 | 같은 회의 |
| 2026-10-13 | K8·K11 | 쿨다운을 DB에 두는 이유를 "여러 워커"에서 "여러 스레드·여러 PC·Vercel"로 고침(app은 gunicorn 워커 1개 + 스레드 — 확장 계획서 2.2). K11의 쿨다운·생존 신호 표는 본 계획서 2.3 ⑥에도 반영됨 | — |
