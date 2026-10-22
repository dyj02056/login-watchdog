# 54단계 — L4 차단과 집행관 (차단 장부·fw-agent)

◀ 53단계 (작성 예정) · [전체 목차](beginner-guide.md) · 55단계 ▶ (작성 예정)

> [52단계](guide52_net_ingest_correlation.md)에서 앱(형사)이 "이 주소는 막아야 한다"고 판단하면, 실제로 정문에서 그 주소의 통신을 끊는 일은 누가 할까요? 이 문서는 **판단 이후 실제로 막히기까지**를 다룹니다.
> 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 **차단 요청 함수·장부(C0-2·C1-1)** 와 **차단 목록 창구·fw-agent(C1-2·C1-3)**, 그리고 **M1 수동 차단 확인 결과**까지입니다(2026-10-22 main 기준). 조치 도구 3개·해제 연동(C2-1·C2-2)은 다음 절에서 다룹니다.

## 비유 — 법원 장부와 집행관

| 비유 | 실제 |
|---|---|
| 판결문을 장부에 적는 서기 | `security/netblock.py`의 `request_block()` / `request_unblock()` |
| 집행 장부 | Supabase `network_blocks` 표 (IP 한 개당 한 줄) |
| 장부를 보러 오는 집행관 | `fw-agent` 컨테이너 (`netwatch/fw_agent/fw_agent.py`) |
| 집행관 전용 창구 | 내부 API `GET /api/internal/blocks`, `POST /api/internal/blocks/ack` |
| 정문 출입 금지 명단 | gateway 안의 ipset 집합 `lw_block` + iptables DROP 규칙 1개 |
| "집행했습니다" 보고 | ack `APPLIED` → 보안 기록 `NET_BLOCKED`(CRITICAL) |
| 집행관 출근 확인 | 생존 신호 `POST /api/internal/heartbeat` → `agent_heartbeats` 표 |

서기(앱)는 **장부에 적기만** 하고 직접 문을 잠그지 않습니다. 문을 잠그는 권한(`NET_ADMIN`)은 집행관(fw-agent)만 갖습니다. 집행관은 반대로 장부(DB)를 직접 열지 못하고, 창구에 와서 "막을 목록 주세요 / 막았어요"만 말합니다.

**왜 이렇게 나눴나(계획 P6):** 방화벽 권한이 있는 컨테이너에 DB 키까지 주면, 그 컨테이너 하나가 털렸을 때 DB 전체가 털립니다. 그래서 fw-agent에는 서명 키(`NET_AGENT_SECRET`)와 앱 주소, 허용 목록만 넘깁니다.

## ② 차단 요청 함수와 장부 (C0-2·C1-1)

### 장부 한 줄의 상태 (계약서 K7·K9)

| 상태 | 뜻 | 누가 바꾸나 |
|---|---|---|
| `PENDING_APPLY` | 막아 달라는 요청이 적힘 | `request_block()` (나중에는 플레이북, 지금은 SQL로도 가능) |
| `APPLIED` | fw-agent가 실제로 막았음 | fw-agent의 ack |
| `PENDING_REMOVE` | 풀어 달라는 요청이 적힘 | `request_unblock()` (관리자 해제 연동은 C2-2) |
| `REMOVED` | 풀렸음 (해제 또는 만료) | fw-agent의 ack, 또는 창구의 만료 정리 |
| `FAILED` | 막기·풀기에 실패, `last_error`에 이유 | fw-agent의 ack |

### `request_block(ip, reason, evidence, ttl_seconds=None, requested_by="playbook")`

실제로 장부가 바뀌었을 때만 `True`를 돌려줍니다. 여러 번 불러도 결과가 같습니다(멱등).

| 순서 | 하는 일 | 이유 |
|---|---|---|
| 1 | 주소 검사: 대역(`/`)·IPv6·해석 불가면 거절 | 대역 차단은 같은 NAT 뒤 정상 사용자까지 막습니다. ipset `lw_block`은 IPv4 전용(`hash:ip`)입니다 |
| 2 | `reason`·`evidence`가 정해진 값인지 | DB 제약 오류가 나기 전에 여기서 `False`로 끝냅니다 |
| 3 | 허용 목록(`PERMANENT_LOCK_IP_ALLOWLIST`)이면 거절 | 관리자 PC·Docker 게이트웨이를 막으면 시연 중 관리자 화면에 못 들어갑니다. 앱 잠금(L7)과 같은 목록을 씁니다 |
| 4 | 만료 시각 계산 (아래 표) | TTL 계산은 **이 함수만** 합니다. 플레이북이 따로 계산하면 두 번 계산되거나 빠집니다 |
| 5 | 장부에 쓰기: 없으면 새 줄, 이미 막혀 있으면 **더 강한 요청일 때만** 갱신, 풀렸거나 실패한 줄은 재사용 | 같은 SYN Flood 경보가 몇 초 간격으로 와도 TTL이 매번 늘지 않게 합니다 |

**만료 시각 정하기**

| `evidence` | `ttl_seconds` | 결과 | 이유 |
|---|---|---|---|
| `SPOOFABLE` (SYN 등 주소 위조 가능) | 없음 | 1시간 × 2^(최근 30일 `NET_BLOCKED` 횟수), 최대 6시간 | 남의 주소를 사칭한 SYN만으로 그 주소 주인이 영원히 막히면 안 됩니다(계획 P2). 실제로 막혔던 횟수만 셉니다 |
| `SPOOFABLE` | 있음 | 그 값, 최대 6시간 | |
| `CONNECTED` (연결 완성, 위조 불가) | 없음 | **영구** (`expires_at` 비어 있음) | CR-01 킬체인 전용 |
| `CONNECTED` | 있음 | 그 값, 최대 6시간 | 일부러 TTL을 준 요청은 '임시'라는 뜻 |

설정값 이름: `NET_BLOCK_DEFAULT_TTL_SECONDS`(3600), `NET_BLOCK_MAX_TTL_SECONDS`(21600), `NET_BLOCK_REPEAT_DAYS`(30).

**`reason` 값 (계약서 K12)**

| 값 | 쓰는 곳 |
|---|---|
| `NET_FLOOD` | NET-01, CR-02 |
| `KILL_CHAIN` | CR-01 |
| `ADMIN_MANUAL` | 사람이 SQL로 직접 넣은 수동 차단 (관리자 화면에는 수동 차단 기능이 없음) |

`requested_by`는 `playbook:<이름>`, `admin:<관리자 아이디>`, `script:<이름>` 중 하나로, 누가 요청했는지 남기는 기록용 글자입니다.

### `request_unblock(ip, actor)`

`PENDING_APPLY`·`APPLIED`인 줄만 `PENDING_REMOVE`로 바꿉니다. 이미 풀렸거나 줄이 없으면 `False`(오류 아님) — 관리자가 L4 차단이 없는 IP의 잠금을 풀어도 문제가 없게 하려는 것입니다.

### 동시에 요청이 와도 하나만 (`db/network_blocks.py`)

Supabase REST에는 트랜잭션이 없습니다. 그래서 상태를 바꿀 때는 항상 `update_network_block_if_status(ip, 이전_상태들, 새_값)` — **"지금 상태가 ○○일 때만 바꾸기"** 로 합니다. 같은 줄을 두 곳에서 동시에 바꾸려 하면 먼저 바꾼 쪽만 성공하고, 나중 쪽은 바뀐 줄이 0개라 `False`가 됩니다. 새 줄을 넣을 때는 기본 키(`ip_address`) 중복 오류(23505)를 "이미 있음"으로 받아 다시 읽습니다.

## ③ 차단 목록 창구와 fw-agent (C1-2·C1-3)

### 창구 세 개 (계약서 K9, `routes/internal/`)

모두 서명이 없거나 틀리면 내용을 보기 전에 401입니다([52단계](guide52_net_ingest_correlation.md)의 도장 검사).

| 창구 | 부르는 쪽 | 하는 일 |
|---|---|---|
| `GET /blocks` | fw-agent (2초마다) | 먼저 **만료된 줄을 `REMOVED`로 정리**하고 `NET_BLOCKED`를 해결 처리한 뒤, `PENDING_APPLY`·`APPLIED`·`PENDING_REMOVE` 줄을 남은 초(`ttl_seconds`)와 함께 돌려줍니다 |
| `POST /blocks/ack` | fw-agent | `APPLIED`면 `PENDING_APPLY`→`APPLIED` 후 `record_net_blocked()`, `REMOVED`면 `PENDING_REMOVE`→`REMOVED` 후 `resolve_net_blocked()`, `FAILED`면 오류 문자열 저장 |
| `POST /heartbeat` | fw-agent(10초)·shipper(30초) | `agent_heartbeats`에 (장비, PC 이름) 한 줄로 저장하고, 상대 장비의 신호가 오래됐으면 Slack 알림 |

- **만료를 창구에서 정리하는 이유:** 앱에는 따로 도는 스케줄러가 없습니다. fw-agent가 2초마다 묻는 순간이 만료를 정리하기 가장 확실한 시점입니다.
- **같은 보고가 두 번 와도 한 번만:** ack도 조건부 UPDATE라 두 번째는 `{"changed": false}`가 되고 `NET_BLOCKED`가 두 번 생기지 않습니다.
- **PC 대역 밖 주소는 거절:** `NET_EDGE_SUBNET`이 있으면 그 대역의 주소만 목록에 주고 ack도 받습니다. 세 PC가 같은 DB를 써도 남의 PC 차단을 내 정문에 걸지 않게 하려는 것입니다.
- **생존 신호를 PC별로:** `LW_NODE_NAME`으로 나눠 저장해 세 PC가 서로 덮어쓰지 않습니다. 정지 알림은 `notification_cooldowns` 표로 10분(`AGENT_ALERT_COOLDOWN_SECONDS`)에 한 번만 보냅니다.

`NET_BLOCKED` 기록·해결 함수는 B가 만든 `security/net_ingest.py`(B1-2, 계약서 K6)에 있고, 같은 IP에 해결 안 된 `NET_BLOCKED`가 이미 있으면 새로 만들지 않습니다.

### fw-agent가 하는 일 (`netwatch/fw_agent/fw_agent.py`)

| 주기 | 하는 일 |
|---|---|
| 시작할 때 | ipset `lw_block`(hash:ip, timeout 지원)과 iptables `INPUT -m set --match-set lw_block src -j DROP` 규칙 1개를 만듭니다. 이미 있으면 그대로 둡니다 |
| 2초 (`POLL_INTERVAL`) | `GET /blocks` → `PENDING_APPLY`는 `ipset add … timeout <남은 초>` 후 ack `APPLIED`, `PENDING_REMOVE`는 `ipset del` 후 ack `REMOVED`. 실패하면 ack `FAILED` + 오류 |
| 60초 (`RECONCILE_INTERVAL`) | 실제 ipset과 받아 둔 목록을 통째로 비교해 어긋난 것(drift)을 바로잡습니다 — 누가 손으로 지웠거나 컨테이너가 재시작된 경우 |
| 10초 (`HEARTBEAT_INTERVAL`) | 생존 신호(`poll_failures`, `ipset_size`) |

- **IP마다 iptables 규칙을 늘리지 않고 집합에 넣고 빼기만 하는 이유:** 차단 수와 상관없이 검사 속도가 같고, TTL은 ipset의 timeout으로 커널이 직접 풀어 줍니다.
- **앱이 응답하지 않으면** 마지막으로 받은 목록을 그대로 둡니다. 빈 목록으로 보고 기존 차단을 지우지 않게 하려는 것입니다. 이미 걸린 TTL 차단은 커널이 시간에 맞춰 풉니다.
- **허용 목록 주소는 어떤 상태로 와도 막지 않습니다**(앱과 fw-agent 양쪽에서 검사).
- 명령은 `shell=False`로 실행해 IP 문자열이 셸을 거치지 않습니다.
- 개발 PC(Windows)에는 ipset이 없으므로 테스트는 명령을 기록만 하는 `FakeRunner`로 합니다. 진짜 방화벽 동작은 아래 M1 확인으로 봅니다.

### 한 번 막고 푸는 흐름

```text
request_block() 또는 SQL ─▶ network_blocks: PENDING_APPLY
                               │  (fw-agent 2초 폴링: GET /blocks)
                               ▼
                         ipset add lw_block <ip> timeout <남은 초>
                               │  POST /blocks/ack APPLIED
                               ▼
              network_blocks: APPLIED  +  security_events: NET_BLOCKED (CRITICAL)

request_unblock() 또는 SQL ─▶ PENDING_REMOVE ─▶ ipset del ─▶ ack REMOVED
                               ▼
              network_blocks: REMOVED  +  NET_BLOCKED 해결 처리(resolved_at)
```

## M1 수동 차단 확인 결과 (2026-10-22)

관리자 화면에는 수동 차단 기능이 없으므로, 통합 담당자가 Supabase SQL Editor로 `ADMIN_MANUAL` 차단을 한 줄 넣고, C의 PC(`172.28.13` 대역)에서 Docker 단지를 켠 채 fw-agent가 실제로 막고 푸는지 확인했습니다. 아직 아무도 쓰지 않는 `172.28.13.150`을 10분짜리로 막았습니다.

| 시점 | `network_blocks` | `security_events` (`NET_BLOCKED`) | C의 PC `ipset list lw_block` |
|---|---|---|---|
| 차단 뒤 | `APPLIED`, `applied_at` 08:01:28 UTC, `last_error` 없음 | `CRITICAL` 한 줄 생김(08:01:28 UTC), `resolved_at` 비어 있음 | `172.28.13.150 timeout 388` |
| 해제 뒤 | `REMOVED`, `last_error` 없음 | **같은 줄**의 `resolved_at`이 08:06:07 UTC로 채워짐 | 항목 0개 |

이 결과로 알 수 있는 것:

- `APPLIED` 약 0.8초 뒤 `NET_BLOCKED`가 생겼습니다. fw-agent의 보고를 받은 창구(C1-2)가 B1-2의 진짜 `record_net_blocked()`를 부른다는 뜻입니다. 테스트에서 가짜로 대신하던 부분이 실제로 이어졌습니다(03 점검서 교체 확인표 2·3번 통과).
- ipset의 남은 시간(388초)은 10분 차단을 넣고 3분쯤 지나 조회한 값과 맞습니다. 장부의 `expires_at`이 방화벽 timeout으로 제대로 옮겨졌습니다.
- 해제 때 새 줄이 생기지 않고 같은 `NET_BLOCKED` 줄이 해결 처리됐습니다.

## 직접 확인해 보기

```bash
# 차단 요청 함수·장부·창구·fw-agent 테스트 (실제 DB·방화벽은 건드리지 않음)
pytest tests/track_d/test_c_netblock.py tests/track_d/test_c_db_blocks.py tests/track_d/test_c_internal_api.py tests/track_d/test_c_fw_agent.py -q

# 단지를 켜고 fw-agent 로그·차단 목록 보기
docker compose up -d
docker compose logs --tail 20 fw-agent
docker compose exec fw-agent ipset list lw_block
```

수동 차단으로 직접 확인하려면 Supabase SQL Editor에서 아래를 차례로 실행합니다. 주소는 **자기 PC 대역**의 아직 안 쓰는 `.150`으로 바꾸고, `<관리자 아이디>`는 자기 관리자 아이디로 바꿉니다(비밀번호는 넣지 않습니다).

```sql
-- 1) 막아 달라는 요청 (10분)
insert into network_blocks (ip_address, reason, evidence, status, expires_at, requested_by)
values ('172.28.13.150', 'ADMIN_MANUAL', 'SPOOFABLE', 'PENDING_APPLY', now() + interval '10 minutes', 'admin:<관리자 아이디>')
on conflict (ip_address) do update
  set reason = excluded.reason, evidence = excluded.evidence, status = 'PENDING_APPLY',
      expires_at = excluded.expires_at, requested_by = excluded.requested_by, last_error = null;

-- 2) 몇 초 뒤: APPLIED이고 NET_BLOCKED가 생겼는지
select ip_address, status, applied_at, last_error from network_blocks where ip_address = '172.28.13.150';
select event_type, severity, detected_at, resolved_at from security_events
where ip_address = '172.28.13.150' and event_type = 'NET_BLOCKED' order by detected_at desc;

-- 3) 풀어 달라는 요청 → 몇 초 뒤 REMOVED, NET_BLOCKED의 resolved_at이 채워짐
update network_blocks set status = 'PENDING_REMOVE'
where ip_address = '172.28.13.150' and status in ('PENDING_APPLY', 'APPLIED');
```

- 2) 뒤에 `ipset list lw_block`에 그 주소가 보이고, 3) 뒤에는 사라져야 합니다.
- `APPLIED`인데 `NET_BLOCKED`가 안 생기면 앱 컨테이너가 옛 코드로 빌드된 것일 수 있습니다. `docker compose up -d --build` 후 다시 해 봅니다.
- 생존 신호는 Supabase `agent_heartbeats` 표에서 `fw-agent` 줄의 `last_seen_at`이 10초마다 바뀌는지로 봅니다.

## 이 단계에서 만들어지거나 바뀐 파일

- C0-2: [security/netblock.py](../../security/netblock.py)
- C1-1: [db/network_blocks.py](../../db/network_blocks.py), [db/agent_heartbeats.py](../../db/agent_heartbeats.py)
- C1-2: [routes/internal/blocks.py](../../routes/internal/blocks.py), [routes/internal/heartbeat.py](../../routes/internal/heartbeat.py)
- C1-3: [netwatch/fw_agent/](../../netwatch/fw_agent/)
- 테스트: [tests/track_d/](../../tests/track_d/)의 `test_c_netblock.py`, `test_c_db_blocks.py`, `test_c_internal_api.py`, `test_c_fw_agent.py`
