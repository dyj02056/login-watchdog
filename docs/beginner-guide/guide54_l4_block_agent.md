# 54단계 — L4 차단과 집행관 (차단 장부·fw-agent)

[◀ 53단계](guide53_playbook_engine.md) · [전체 목차](beginner-guide.md) · 55단계 ▶ (작성 예정)

> [52단계](guide52_net_ingest_correlation.md)에서 앱(형사)이 "이 주소는 막아야 한다"고 판단하면, 실제로 정문에서 그 주소의 통신을 끊는 일은 누가 할까요? 이 문서는 **판단 이후 실제로 막히기까지**를 다룹니다.
> 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 **차단 요청 함수·장부(C0-2·C1-1)**, **차단 목록 창구·fw-agent(C1-2·C1-3)**, **M1 수동 차단 확인 결과**, **조치 도구 3개·잠금 해제 연동(C2-1·C2-2)**, **S6에서 조치 도구가 실제로 돈 결과** 까지입니다(2026-10-26 main 기준). 이 조치들을 어떤 순서로 부르는지는 [53단계](guide53_playbook_engine.md)의 플레이북이 정합니다.

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

## ④ 조치 도구 3개 (C2-1, 계약서 K8)

정문 차단 말고도 집행관이 하는 일이 세 가지 더 있습니다. 모두 [53단계](guide53_playbook_engine.md)의 플레이북이 이름으로 찾아 부르는 함수이고, 주로 **의심 로그인 성공(CR-03)** 과 **모든 플레이북의 마지막 보고**에 쓰입니다.

| 도구 | 함수 | 쉬운 말 | 결과 |
|---|---|---|---|
| 세션 끊기 | `db.bump_session_version(user_id)` | 그 회원의 "세션 세대 번호"를 1 올려, 이미 로그인해 있던 모든 기기를 로그아웃시킴 | 올렸으면 `True`, 회원이 없거나 경쟁에서 3번 다 지면 `False` |
| 경고 메일 | `mailer.send_suspicious_login_notice(주소, ip, 시각)` | "의심스러운 로그인이 차단되었습니다" 메일을 계정 주인에게 보냄 | `SENT`·`REFUSED`·`FAILED`·`SKIPPED` |
| Slack 결과 보고 | `alert.send_playbook_alert(플레이북, ip, 규칙들, 단계 결과)` | 플레이북이 무엇을 했는지 단계별로 관리자 Slack에 보고 | 없음 |

### 세션 끊기 — 비밀번호 변경과 같은 방식

로그인 세션에는 회원의 "세대 번호"(`users.session_version`)가 함께 들어 있고, 요청마다 DB의 번호와 비교합니다. 번호를 1 올리면 그 전에 만들어진 세션은 모두 "옛 세대"가 되어 바로 끊깁니다. 비밀번호를 바꿨을 때 다른 기기를 로그아웃시키는 것과 같은 원리이고, **비밀번호 자체는 바꾸지 않습니다.**

- 번호는 "읽은 값 그대로일 때만" 올립니다(조건부 UPDATE). 회원이 마침 비밀번호를 바꾸는 순간과 겹쳐 번호가 한 번 덜 올라가면 의심 세션이 살아남기 때문에, 경쟁에서 지면 다시 읽어 **최대 3번** 시도합니다.
- 3번 다 지면 예외 대신 `False`를 돌려줍니다. 플레이북의 한 단계라서, 예외로 멈추면 뒤의 메일·Slack 단계까지 사라지기 때문입니다. 플레이북은 이 `False`를 `FAILED`로 기록합니다.

### 경고 메일 — 1시간에 한 통만 (메일 폭탄 방지, 계획 V3)

공격자가 같은 계정으로 로그인 성공을 여러 번 일으키면 플레이북도 여러 번 돌아 피해자 메일함이 경고로 가득 찰 수 있습니다. 그래서 같은 주소로는 `SUSPICIOUS_LOGIN_MAIL_COOLDOWN_SECONDS`(3600초)에 **한 통만** 보내고, 그 안이면 보내지 않고 `SKIPPED`를 돌려줍니다.

| 쿨다운을 어디에 두나 | 이유 |
|---|---|
| DB의 `notification_cooldowns` 표 (`db.try_acquire_cooldown(키, 초)`) | 앱의 여러 스레드, 같은 DB를 쓰는 세 PC, Vercel이 같은 주소를 함께 다룹니다. 프로그램 메모리에 두면 서로의 기록을 모릅니다 |
| 키 `mail:suspicious:<주소 소문자>` | 대소문자만 다른 주소로 쿨다운을 피하지 못하게 |

- 발송이 **`FAILED`**(메일 서버 일시 장애)면 잡았던 쿨다운을 `db.release_cooldown(키)`로 풉니다. 아무 메일도 가지 않았는데 1시간 동안 `SKIPPED`가 되면, 장애가 풀린 뒤 같은 공격이 다시 탐지돼도 피해자가 경고를 못 받기 때문입니다.
- **`REFUSED`**(받는 주소가 없음 등 영구 거부)는 다시 보내도 결과가 같으므로 쿨다운을 그대로 둡니다.
- Docker 단지에서는 메일이 실제로 나가지 않고 Mailpit(`http://localhost:8025`)에 잡힙니다.
- Mailpit은 로그인(SMTP 인증)을 지원하지 않습니다. `.env`에 배포용 Gmail 계정(`SMTP_USER`·`SMTP_PASSWORD`)이 남아 있으면 메일 함수가 로그인을 시도해 **모든 메일이 `FAILED`** 가 됩니다. 그래서 `docker-compose.yml`의 app이 두 값을 빈 값으로 덮어씁니다(2026-10-26 통합 보완 `1f2bb72`). `FAILED`라서 쿨다운은 풀린 채로 남으므로, 고친 뒤 첫 발송은 바로 나갑니다.

### Slack 결과 보고 — 실패를 맨 앞에 (계획 V6)

```text
⚠ 일부 조치 실패                       ← 실패한 단계가 하나라도 있을 때만
[HIGH] 로그인 워치독 플레이북 실행 알림: NET_FLOOD_TTL
대상 IP: 172.28.0.152
일치한 규칙: NET-01
단계별 결과:
✓ block_l4_ttl (OK)
```

단계 표시는 `✓` 성공, `✗` 실패, `–` 건너뜀입니다.

- "조치 완료"만 보고 넘어가면, 정문 차단이 실패해 공격이 계속 들어오는데도 관리자는 막힌 줄로 믿게 됩니다. 그래서 실패 여부를 첫 줄에서 바로 보이게 했습니다.
- 실패 원인은 **실패한 단계에만** 붙입니다. `SKIPPED`는 실패가 아닙니다(쿨다운 안이라 메일을 안 보냈거나 선택 과제 단계).
- 알림 함수는 우선순위(`priority`, `CRITICAL`이면 머리말 `[CRITICAL]`)를 받을 수 있지만, 지금은 플레이북이 넘기지 않아 모두 `[HIGH]`로 보입니다([53단계 "알려진 제한"](guide53_playbook_engine.md#알려진-제한)).

### 실제로 돌려 본 결과 — S6 의심 로그인 성공 (2026-10-26, 시연 대역 PC)

세 도구는 의심 로그인 성공(CR-03, [52단계 ⑤](guide52_net_ingest_correlation.md))이 맞았을 때 플레이북 `SUSPICIOUS_SUCCESS_LOGIN`이 차례로 부릅니다. C3-1 시나리오 점검으로 S6를 재현해 `playbook_runs`에 남은 단계 결과를 봤습니다(점검 결과: [docs/track-d/scenario-results.md](../track-d/scenario-results.md), 3회 연속 PASS).

| 실행 (KST) | 사건 | `invalidate_sessions` | `notify_owner_email` | `notify_slack` |
|---|---|---|---|---|
| 15:14 | `incident:56:CR-03` | OK | **OK** — Mailpit에 경고 메일 1통 | OK |
| 15:15 | `incident:60:CR-03` | OK | SKIPPED(조치 미실행) — 받는 주소 쿨다운 | OK |
| 15:40·15:41·15:42 (합격 3회) | `incident:76·81·85:CR-03` | OK | SKIPPED — 쿨다운(15:14 발송 뒤 1시간 안) | OK |

- **세션 끊기**는 매번 OK였습니다. victim 계정이 브라우저에 로그인해 있었다면 이때 모두 로그아웃됩니다.
- **경고 메일**은 실행마다 새 IP·새 사건이었지만, 쿨다운은 사건이 아니라 **받는 주소** 기준이라 첫 1통 뒤에는 SKIPPED였습니다. 의도한 동작입니다(위 "1시간에 한 통만").
- 같은 IP로 로그인을 한 번 더 보내도 같은 사건이라 플레이북이 다시 돌지 않았고, Mailpit의 메일 수도 늘지 않았습니다.
- 처음 시도에서는 메일 단계가 `FAILED`였습니다. 원인은 Mailpit SMTP 인증 문제였고, 위 "경고 메일" 절의 마지막 줄대로 고쳤습니다.

## ④ 잠금을 풀면 정문 차단도 함께 풀기 (C2-2)

관리자가 대시보드에서 어떤 IP의 **영구 잠금을 풀면**(`security/lockdown.py`의 `release()`), 그 IP의 정문 차단도 함께 "풀어 달라"(`netblock.request_unblock()`)로 바꿉니다.

| 해제 전 | `release("ip", 주소, ...)` 이후 |
|---|---|
| 앱 잠금(L7) + 정문 차단(L4, ipset) | 앱 잠금 해제 → 장부를 `PENDING_REMOVE`로 → fw-agent가 2초 안에 ipset에서 빼고 `REMOVED` 보고 |

- **왜 필요한가:** 앱 잠금만 풀고 정문 차단을 남겨 두면, 관리자가 풀어 준 IP가 여전히 사이트에 접속하지 못합니다. 관리자는 "풀었는데 왜 안 되지?"를 알 방법이 없습니다.
- **정문 해제가 실패해도 앱 잠금 해제 결과는 바뀌지 않습니다.** 앱 잠금은 이미 풀렸으므로, 정문 쪽 오류는 한 줄 로그만 남기고 해제 성공(`True`)과 Slack 알림은 그대로 둡니다.
- **정문 차단이 원래 없던 IP**면 `request_unblock()`이 `False`를 돌려주는데, 이것은 오류가 아닙니다. 대부분의 앱 잠금은 정문 차단 없이 걸리기 때문입니다.
- 계정 잠금(`target_kind="account"`) 해제는 정문 차단과 관계가 없어 이 연동을 하지 않습니다.
- `netblock`은 허용 목록 확인에 `lockdown`을 쓰므로, `lockdown`이 파일 맨 위에서 `netblock`을 불러오면 서로를 불러오는 고리(순환 import)가 생깁니다. 그래서 `release()` 안에서 필요할 때만 불러옵니다.
- `security/lockdown.py`는 B(`consider_incident_promotion()`)와 C(`release()`)가 함께 고치는 유일한 파일이라, B1-3이 먼저 머지된 뒤 C가 `release()` 안만 고쳤습니다.

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

**④ 절 확인 (C2-1·C2-2)**

```bash
# 세션 끊기·경고 메일 쿨다운·Slack 보고 테스트, 잠금 해제 → 정문 해제 연동 테스트
pytest tests/track_d/test_c_actions.py tests/track_d/test_c_release_unblock.py -q
```

- **Slack 보고:** 단지에서 SYN 폭주를 한 번 재현하면([52단계 "직접 확인해 보기"](guide52_net_ingest_correlation.md#직접-확인해-보기)) 팀 Slack 채널에 `[HIGH] … 플레이북 실행 알림: NET_FLOOD_TTL`이 옵니다. 알림의 IP 셋째 자리(11/12/13/0)로 어느 PC인지 구분합니다.
- **경고 메일 쿨다운:** Supabase에서 쿨다운 기록을 봅니다. S6(`python -m scripts.net.check_s6`, [netwatch/README.md](../../netwatch/README.md) 9장)를 돌려 경고 메일이 한 번 나간 뒤에 줄이 생깁니다.

```sql
select key, last_sent_at from notification_cooldowns
where key like 'mail:suspicious:%' order by last_sent_at desc limit 5;
```

- **잠금 해제 연동:** 영구 잠금과 정문 차단이 함께 걸린 IP(예: 킬체인 S4)를 관리자 화면 처리 작업대의 "영구 잠금"에서 해제한 뒤, 장부가 `REMOVED`가 되는지 봅니다.

```sql
select ip_address, status, removed_at from network_blocks where ip_address = '<해제한 IP>';
```

## 이 단계에서 만들어지거나 바뀐 파일

- C0-2: [security/netblock.py](../../security/netblock.py)
- C1-1: [db/network_blocks.py](../../db/network_blocks.py), [db/agent_heartbeats.py](../../db/agent_heartbeats.py)
- C1-2: [routes/internal/blocks.py](../../routes/internal/blocks.py), [routes/internal/heartbeat.py](../../routes/internal/heartbeat.py)
- C1-3: [netwatch/fw_agent/](../../netwatch/fw_agent/)
- C2-1: [db/users.py](../../db/users.py)(`bump_session_version`), [notify/mailer.py](../../notify/mailer.py)(`send_suspicious_login_notice`, `SKIPPED`), [notify/alert.py](../../notify/alert.py)(`send_playbook_alert`), [db/agent_heartbeats.py](../../db/agent_heartbeats.py)(`try_acquire_cooldown`, `release_cooldown`)
- C2-2: [security/lockdown.py](../../security/lockdown.py)의 `release()`
- 통합 보완(10/26): [docker-compose.yml](../../docker-compose.yml)의 app `SMTP_USER`·`SMTP_PASSWORD` 빈 값, [tests/track_d/test_i_compose_mail.py](../../tests/track_d/test_i_compose_mail.py)
- 테스트: [tests/track_d/](../../tests/track_d/)의 `test_c_netblock.py`, `test_c_db_blocks.py`, `test_c_internal_api.py`, `test_c_fw_agent.py`, `test_c_actions.py`, `test_c_release_unblock.py`
