# 57단계 — 차단 신뢰성과 L3 탐지 (10/29 점검 보완)

[◀ 56단계](guide56_feedback_hardening.md) · [전체 목차](beginner-guide.md)

> 56단계까지 센서 경보 → 판단 → 차단 → 해제 흐름을 만들고 예외 상황을 보완했습니다. 10/29 점검에서 "차단이 **실제로** 걸려 있는지", "센서가 **살아서** 제 일을 하는지"를 아무도 확인하지 않는 빈틈과, 이름은 L3/L4인데 L3를 잡는 것이 하나도 없다는 점이 드러났습니다. 이 단계는 그 빈틈을 메운 기록입니다.
> DB 변경은 [docs/migrations/guide57_track_d_reliability.sql](../migrations/guide57_track_d_reliability.sql) 한 개입니다. 계약서 변경은 [contracts.md](../track-d/contracts.md) 맨 아래 2026-10-29 줄에 모았습니다.

## 비유 — 건물 경비

| 비유 | 실제 |
|---|---|
| 우리 직원 사원증을 위조한 침입자 | 출발지를 core·gateway 주소로 꾸민 SYN 폭주 |
| "문 잠갔음" 장부와 실제 자물쇠 | `network_blocks`의 `APPLIED`와 iptables DROP 규칙 |
| 순찰 무전("이상 없음") | heartbeat의 `rules_ok`·`stalled_sensors`·`poll_failures` |
| 위조 신분증 감별 | edge 대역 밖 출발지 = 위조 확정(`SPOOFED_SRC`) |
| 출입 속도 제한 게이트 | ICMP 속도 제한 체인 `LW_L3` |

예를 들어 장부에는 "잠김"으로 적혀 있는데 자물쇠가 빠져 있으면, 경비는 안심하고 침입자는 그냥 들어옵니다. 이번 보완은 대부분 **장부와 실제가 같은지 계속 확인하는 일**입니다.

## 한눈에 보기

| # | 문제 | 고친 뒤 | 파일 |
|---|---|---|---|
| 1 | 출발지를 우리 core·gateway 주소로 꾸민 SYN이 그대로 NET-01 차단 대상이 됨 → 정문이 앱 응답을 버려 사이트 전체가 멈출 수 있음 | 인프라·특수 주소는 차단 요청·차단 목록·보안 이벤트 어디에도 들어가지 않음. fw-agent도 한 번 더 거부 | `security/netblock.py`, `routes/internal/blocks.py`, `security/net_ingest.py`, `fw_agent.py` |
| 2 | 차단 적용 실패(FAILED)가 목록에서 빠지고 알림도 없음 → 영구 차단이 일시 오류 한 번으로 조용히 안 걸림 | 실패하면 Slack 알림, 10초 간격으로 3번 다시 시도, 끝내 안 되면 "포기" 알림 | `routes/internal/blocks.py`, `db/network_blocks.py`, `notify/alert.py` |
| 3 | iptables 규칙이 지워져도 ipset엔 IP가 남아 "막혀 있음"으로 보임 | fw-agent가 60초마다 규칙을 되살리고, 규칙 상태를 heartbeat에 실어 빠지면 알림 | `fw_agent.py`, `routes/internal/heartbeat.py` |
| 4 | l4-detector가 죽어도 모름(Suricata의 60초 통계 때문에 "둘 다 멈춤"이 안 됨), 센서가 패킷을 놓쳐도 모름 | 60초 생존 줄 + 파일별 정지(`stalled_sensors`) + Suricata 패킷 누락률 알림 | `l4_detector.py`, `eve_shipper.py`, `heartbeat.py` |
| 5 | fw-agent가 살아 있지만 목록을 못 받으면 알림 없음 | `poll_failures` 15번(약 30초) 이상이면 알림 | `heartbeat.py` |
| 6 | L3를 잡는 것이 하나도 없음 | `ICMP_FLOOD`·`SPOOFED_SRC`·`GLOBAL_SYN_FLOOD` 기록·알림 + ICMP 속도 제한 | 센서·shipper·앱·fw-agent·화면 |
| 7 | 정문 용량이 작아 공격 상자 17개로 가득 참 | worker 수·연결 수·전체 상한·keep-alive 조정 | `netwatch/nginx/nginx.conf` |
| 8 | S7(위조 출발지)은 자동 점검이 한 번도 없었음 | `check_s7`·`check_s9` 추가, `run_all`에 포함 | `scripts/net/`, `lw.py` |

## ① 우리 주소는 막지 않는다

```text
공격자 ── SYN(출발지=172.30.0.4로 위조) ──▶ 정문 ── Suricata 경보(src=172.30.0.4)
                                                     │
          예전: NET-01 → request_block(172.30.0.4) → ipset → 정문이 앱 응답을 버림 → 사이트 멈춤
          지금: 수집 창구가 "인프라 주소"로 보고 보안 이벤트로 올리지 않음(기록만)
                request_block도 거절, /blocks도 빼고, fw-agent도 "infrastructure"로 거부
```

- **인프라 주소**: core 대역 `172.30.0.0/24`(설정과 상관없이 고정), `NET_EDGE_SUBNET`의 `.1`·`.10`, 루프백·멀티캐스트·예약·`0.0.0.0`·링크로컬.
- **대역 밖 출발지**: `NET_EDGE_SUBNET`이 설정돼 있는데 그 밖의 주소가 edge로 들어왔다면 위조입니다. 저장만 하고 올리지 않습니다.
- **`NET_EDGE_SUBNET` 형식 오류**: 예전에는 경고만 찍고 거르지 않은 목록을 내보냈습니다. 지금은 `/blocks`가 `503 misconfigured`로 멈추고, fw-agent의 폴링 실패 알림(⑤)으로 드러납니다. 값이 아예 비어 있으면 예전처럼 거르지 않습니다(기존 동작 유지) — 대신 인프라 주소는 항상 뺍니다.

## ② 적용 실패는 다시 시도하고 알린다

```text
PENDING_APPLY ── fw-agent ipset add 실패 ──▶ FAILED(failed_at 기록) ── Slack "L4 차단 적용 실패"
      ▲                                           │ 10초 뒤 GET /blocks
      └──── version+1, apply_attempts+1 ──────────┘ (최대 3번)
                                                  │ 3번 다 실패
                                                  ▼
                                   failed_at 비움 + Slack "포기 — 직접 확인 필요"
```

- 해제 실패(`PENDING_REMOVE` → `FAILED`)는 다시 시도하지 않습니다. reconcile이 ipset에서 빼므로 다시 할 일이 없습니다.
- fw-agent가 일부러 거부한 것(`allowlisted`·`out_of_subnet`·`infrastructure`)도 다시 시도하지 않습니다. 결과가 같기 때문입니다.
- 새 차단 요청(`request_block`)이 오면 횟수를 0부터 다시 셉니다.
- `apply_attempts`·`failed_at` 칸이 없는 DB(guide57 SQL 실행 전)에서는 재시도를 건너뛰고 알림만 보냅니다.

## ③ 규칙이 진짜 걸려 있는지

| heartbeat 칸 | 뜻 | 빠지면 |
|---|---|---|
| `rules_ok` | filter INPUT의 `lw_block` DROP(없으면 차단이 전혀 안 됨) | Slack "방화벽 규칙이 빠져 있습니다: INPUT" |
| `raw_ok` | raw PREROUTING의 `lw_block` DROP(연결 추적 절약용) | 기록만(INPUT이 있으면 차단은 됨) |
| `l3_ok` | `LW_L3` ICMP 속도 제한 체인과 점프 규칙 | Slack "…: LW_L3" |

fw-agent는 60초마다 `ensure_ready()`·`ensure_l3()`를 다시 불러 빠진 규칙을 되살립니다. 두 함수 모두 규칙이 이미 있으면 아무것도 바꾸지 않으므로 계속 불러도 안전합니다.

## ④·⑤ 살아 있지만 제 일을 못 하는 상태

| 상태 | 예전 | 지금 |
|---|---|---|
| l4-detector만 죽음 | eve.json이 Suricata 통계로 늘 늘어나 "둘 다 멈춤"이 안 됨 → 모름 | l4-detector가 60초마다 생존 줄을 쓰고, shipper가 파일별로 판단 → `stalled_sensors: ["l4"]` → 알림 |
| Suricata가 폭주를 못 따라가 패킷을 놓침 | 모름 | eve.json 통계의 `kernel_drops`를 heartbeat에 실어 5% 넘으면 알림 |
| fw-agent가 앱에 못 붙음(503 등) | heartbeat는 와서 "정지"가 아님 → 모름 | `poll_failures` 15번 이상이면 알림 |

`stalled`(두 파일 모두 멈춤)의 뜻은 그대로 두고, 파일별 정지는 새 칸 `stalled_sensors`에 따로 싣습니다. 기존 알림과 같은 쿨다운 키를 써서 두 번 가지 않습니다.

## ⑥ L3 탐지 — 막지 않고, 깎고, 알린다

| 경보 | 잡는 곳 | `src_ip` | 처리 |
|---|---|---|---|
| `ICMP_FLOOD`(L3) | Suricata `rules/l3.rules` sid 9000005(출발지별 1초 200개) | 실제 출발지 | `NET_ICMP_FLOOD` MEDIUM + 알림 |
| `SPOOFED_SRC`(L3) | Scapy — edge 대역 밖 출발지 10초 10개 이상 | 보인 가짜 주소 | 기록 + 알림만 |
| `GLOBAL_SYN_FLOOD`(L4) | Scapy — 전체 SYN 초당 1000개 이상 | `0.0.0.0` | 기록 + 알림만 |

- **막지 않는 이유:** 셋 다 출발지를 믿을 수 없습니다. 막으면 가짜 주소의 주인이 피해를 봅니다. 그래서 교차 규칙(CR-01 등)에도 넣지 않았습니다.
- **깎는 곳:** fw-agent가 정문 커널의 raw 표에 `LW_L3` 체인을 겁니다. 출발지별 초당 50개를 넘는 ICMP는 버리고, 출발지를 계속 바꾸는 폭주는 전체 초당 2000개로 깎습니다. 주소를 막는 게 아니라 양만 줄이는 것입니다.
- **알림 폭주 방지:** 센서(10초에 1회) → shipper(분 단위로 합침) → 앱(종류당 10분에 1통) 세 번 걸러집니다.
- **Scapy 부담:** 받는 패킷 조건을 `ip and ((tcp and dst host <.10>) or (not src net <edge>/24 and not src net 172.30.0.0/24))`로 바꿨습니다. gateway가 내보내는 응답 TCP는 더 이상 파이썬으로 올리지 않으므로 오히려 가벼워졌고, 위조 후보는 커널이 미리 골라 줍니다.
- **화면:** 공격 상세의 L3/L4 칸과 처리 작업대 이벤트 카드에 "ICMP 플러드·위조 출발지·전체 SYN 폭주"로 보입니다. 위조 출발지·전체 SYN 폭주는 출발지가 원래 대역 밖이라 대역 필터에서 빼고 보여 줍니다.

## ⑦ 정문 용량

| 설정 | 예전 | 지금 |
|---|---|---|
| `worker_processes` | (없음 = 1) | `auto` |
| `worker_connections` | 1024 | 4096 (`worker_rlimit_nofile 16384`) |
| 서버 전체 동시 연결 | 제한 없음 | 3000 (`limit_conn lw_total`) |
| `keepalive_timeout` | 75초(기본) | 15초 |
| `reset_timedout_connection` | off | on |

프록시는 손님 연결 하나에 앱 연결 하나를 더 쓰므로 예전 설정은 실제로 약 512명분이었습니다. IP별 30개 제한을 지키는 공격 상자 17개면 가득 찼습니다.

## ⑧ 자동 점검 S7·S9

| 시나리오 | 공격 | PASS 조건 |
|---|---|---|
| S7 ① | 출발지를 edge `.200~.254`로 돌려 쓰는 SYN | 돌려 쓴 주소 차단 없음, `GLOBAL_SYN_FLOOD` 기록 |
| S7 ② | 출발지를 core `172.30.0.250`으로 위조 | 차단·보안 이벤트 없음 |
| S7 ③ | 출발지를 edge `.140`으로 위조 | `SPOOFABLE` TTL 차단만, 앱 잠금 없음 |
| S7 ④ | 출발지를 `192.0.2.50`(대역 밖)으로 위조 | 차단 없음, `SPOOFED_SRC` 기록 |
| S9 | 한 출발지 ICMP echo 3000개 | `ICMP_FLOOD` 기록, 차단 없음, `LW_L3` DROP 누적 카운터 증가, TCP 연결 됨 |

- **위조 대역을 제한하는 이유:** gateway는 위조된 출발지로 응답을 돌려보냅니다. 아무 주소나 쓰면 응답이 실제 인터넷 주소로 나갑니다. 그래서 공격 상자의 `--spoof-source`는 이 PC edge 대역·core 대역·문서용 `192.0.2.0/24`만 받고, 출발지를 바꾸는 폭주도 hping3 `--rand-source` 대신 직접 만든 raw 소켓 전송기로 edge `.200~.254`만 돌려 씁니다.

**10/29 첫 실행에서 S9가 FAIL한 이유와 보정:** 앱은 정상이었습니다(`promoted=true`, `NET_ICMP_FLOOD` 기록 있음). 점검 스크립트가 PC 시계로 "시작 이후"를 거르는데, 보안 이벤트 시각은 Supabase 시계로 찍히고 시연 PC 시계가 DB보다 약 7초 앞서 있어 방금 생긴 이벤트가 빠졌습니다. 또 heartbeat의 `icmp_dropped`는 10초 증가분이라, 확인이 늦으면 0으로 덮였습니다. 그래서 S9는 경보의 `received_at`(DB 시계) 기준으로 찾고, `LW_L3` 카운터는 공격 전·후 누적값을 직접 비교하도록 바꿨습니다. S7·S9의 공격 상자 IP를 같은 실행에서 다시 고르던 문제(`.56`이 S7 → S9 → S4)도 함께 막았습니다.

## 남는 한계

- 위조될 수 있는 증거로는 주소를 막지 않습니다. L3 대응은 속도 제한까지입니다.
- 출발지를 매번 바꾸는 ICMP 폭주는 전체 한도로만 깎이고, 그동안 정상 ICMP도 함께 깎입니다. 종류별 경보 대신 `icmp_dropped` 증가로 드러납니다.
- `SPOOFED_SRC`는 edge 대역 **밖**으로 위조한 주소만 구분합니다.
- 공용 DB라 다른 PC의 `SPOOFED_SRC`·`GLOBAL_SYN_FLOOD`도 이벤트 카드에 보일 수 있습니다.

## 직접 확인해 보기

```bash
# 이번 보완의 테스트만
pytest tests/track_d/test_i_guide57_blocks.py tests/track_d/test_i_guide57_fw_agent.py tests/track_d/test_i_guide57_sensors.py tests/track_d/test_i_guide57_app.py tests/track_d/test_i_guide57_status.py tests/track_d/test_i_guide57_nginx.py tests/track_d/test_i_guide57_scenarios.py -q

# 단지에서 S7·S9
python -m scripts.net.check_s7
python -m scripts.net.check_s9
```

```sql
-- guide57 반영 확인: 칸 2줄, 제약 1줄이 나와야 한다
select column_name from information_schema.columns
 where table_name = 'network_blocks' and column_name in ('apply_attempts', 'failed_at');
select pg_get_constraintdef(oid) from pg_constraint where conname = 'network_events_category_check';
```

## 이 단계에서 만들어지거나 바뀐 파일

- 차단 장부: [security/netblock.py](../../security/netblock.py), [routes/internal/blocks.py](../../routes/internal/blocks.py), [db/network_blocks.py](../../db/network_blocks.py)
- 수집·알림: [routes/internal/ingest.py](../../routes/internal/ingest.py), [security/net_ingest.py](../../security/net_ingest.py), [routes/internal/heartbeat.py](../../routes/internal/heartbeat.py), [notify/alert.py](../../notify/alert.py)
- 화면: [routes/admin/status.py](../../routes/admin/status.py), [web/src/lib/labels.ts](../../web/src/lib/labels.ts)(+ `spa/`·`public/_next/` 다시 빌드)
- 센서: [netwatch/l4_detector/](../../netwatch/l4_detector/), [netwatch/shipper/eve_shipper.py](../../netwatch/shipper/eve_shipper.py), [netwatch/suricata/rules/l3.rules](../../netwatch/suricata/rules/l3.rules), [netwatch/suricata/suricata.yaml](../../netwatch/suricata/suricata.yaml)
- 정문·차단: [netwatch/fw_agent/fw_agent.py](../../netwatch/fw_agent/fw_agent.py), [netwatch/nginx/nginx.conf](../../netwatch/nginx/nginx.conf), [docker-compose.yml](../../docker-compose.yml)
- 공격 상자·점검: [netwatch/attacker/lw.py](../../netwatch/attacker/lw.py), [scripts/net/check_s7.py](../../scripts/net/check_s7.py), [scripts/net/check_s9.py](../../scripts/net/check_s9.py), [scripts/net/check_common.py](../../scripts/net/check_common.py), [scripts/net/run_all.py](../../scripts/net/run_all.py)
- 설정·DB: [config.py](../../config.py), [.env.example](../../.env.example), [docs/migrations/guide57_track_d_reliability.sql](../migrations/guide57_track_d_reliability.sql), [docs/schema.sql](../schema.sql)
- 테스트: `tests/track_d/test_i_guide57_*.py` 7개(기존 테스트 기대값은 바꾸지 않음)
