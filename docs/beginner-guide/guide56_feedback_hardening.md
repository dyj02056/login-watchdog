# 56단계 — 예외 상황 보완 (10/26 강사 피드백 반영)

[◀ 54단계](guide54_l4_block_agent.md) · [전체 목차](beginner-guide.md) · (55단계 관제 화면·시연은 작성 예정) · [57단계 ▶](guide57_reliability_l3.md)

> 51~54단계에서 센서 경보 → 판단 → 차단 → 해제 흐름을 만들었습니다. 이 단계는 기능을 더하지 않고, **이미 만든 흐름이 예외 상황에서도 끊기지 않게** 고친 기록입니다. 2026-10-26 강사님 피드백 6개와 추가로 짚어 주신 상황 3개를 코드에서 하나씩 확인했고, 모두 실제로 재현되는 문제여서 고쳤습니다.
> DB 변경은 [docs/migrations/guide56_track_d_hardening.sql](../migrations/guide56_track_d_hardening.sql) 한 개입니다(2026-10-26 공용 DB에 실행 완료).

## 비유 — 택배 물류센터

| 비유 | 실제 |
|---|---|
| 접수 창구의 하루 접수 한도 | 경보 수집 창구의 보낸이별 분당 한도(`NET_INGEST_RATE_LIMIT_PER_MINUTE`) |
| 송장 번호 | 차단 요청마다 오르는 `network_blocks.version` |
| "배송 완료" 문자 | fw-agent의 ACK |
| 반송 기한이 적힌 보관증 | fw-agent가 기억하는 "언제까지 막을지" |
| 작업 일지의 단계별 체크 | `playbook_runs`(단계별 결과) |

예를 들어 송장 번호 없이 "배송 완료" 문자만 오면, 같은 주소로 보낸 옛 택배와 새 택배 중 무엇이 도착했는지 알 수 없습니다. 이번 보완은 대부분 이런 **"무엇에 대한 확인인지"를 분명히 하는 일**입니다.

## 한눈에 보기

| # | 문제 (피드백) | 고친 뒤 | 파일 |
|---|---|---|---|
| 1 | 서명을 확인하기 **전에** 전송 한도를 세서, 위조 요청이 정상 센서의 한도를 써 버림. 429를 받은 경보는 그냥 버려짐 | 서명이 맞은 요청만 한도에서 차감. 바깥(gateway)에서는 `/api/internal/` 자체가 404. shipper는 429를 받으면 다시 보냄 | `app.py`, `netwatch/nginx/nginx.conf`, `netwatch/shipper/eve_shipper.py` |
| 2 | 앱이 멈춘 동안 TTL 차단이 만료되면, fw-agent가 옛 "남은 초"로 다시 막음(60초마다 끝없이) | "남은 초"가 아니라 "언제까지"로 계산. 그 시각이 지난 차단은 다시 넣지 않음 | `netwatch/fw_agent/fw_agent.py` |
| 3 | 규칙을 사건에 먼저 기록하고 차단을 실행해서, 차단이 실패해도 다음 경보에서는 "이미 처리함"으로 건너뜀 | 규칙에 해당함(`matched_rules`)과 조치 완료(`playbook_runs`)를 구분. 실패한 **조치 단계만** 다음 경보 때 다시 실행 | `security/correlate.py`, `security/playbooks.py`, `db/playbook_runs.py` |
| 4 | ACK에 IP와 결과만 있어서, 60초 차단에 대한 늦은 ACK가 그 사이 바뀐 영구 차단의 완료로 처리됨 | 요청마다 `version`을 올리고 ACK에도 실음. 같은 번호일 때만 상태를 바꿈 | `security/netblock.py`, `routes/internal/blocks.py`, `db/network_blocks.py`, fw-agent |
| 5 | 관리자 해제에서 L4 해제가 실패해도 전체 결과는 성공. 다시 눌러도 L7이 이미 풀려 L4까지 가지 않음 | L7·L4 결과를 따로 돌려줌. L7이 이미 풀렸어도 남은 L4 해제는 이어서 처리 | `security/lockdown.py`, `routes/admin/locks.py`, `scripts/management/unlock_ip.py` |
| 6 | S4가 차단 "요청"만 확인해서 `FAILED`·`applied_at` 없음도 PASS | `APPLIED` + `applied_at` 필수. 대상 IP는 실제로 막히고 다른 IP는 열려 있는지 확인. 원하면 해제 후 재접속까지 | `scripts/net/check_s4.py`, `netwatch/attacker/lw.py` |
| + | 여러 규칙이 같은 사건을 동시에 고치면 한쪽 규칙이 지워짐 | DB 함수 `append_matched_rule()`이 규칙을 원자적으로 덧붙임 | `db/incidents.py`, guide56 SQL |
| + | 같은 IP에서 두 번째 계정이 들어오면 그 계정의 기존 세션은 끊지 않음 | 계정마다 세션 끊기를 한 번씩 실행 | `security/correlate.py` |
| + | 차단 목록 응답에 `blocks` 칸이 없으면 "막을 것 없음"으로 받아 기존 차단을 지움 | 칸이 없거나 목록이 아니면 오류로 보고 마지막 상태를 유지 | fw-agent |

## ① 경보 수집 — 위조 요청이 정상 경보를 막지 못하게

```text
바깥(edge, 공격 상자) ──▶ gateway(nginx) ──X  /api/internal/*  → 404 (여기서 끊김)
shipper (core 망)   ──────────────────────▶ app:5000/api/internal/net-events
                                              │ 한도 넘었나? (보낸이별 분당 600회)
                                              │ 서명 검사 → 401이면 한도에서 차감하지 않음
                                              ▼ 정상 처리 → 1회 차감
```

- **한도를 언제 세나:** Flask-Limiter는 요청 전에 "넘었는지"를 확인하고, 응답이 나온 뒤에 1회를 차감합니다. `deduct_when=lambda r: r.status_code != 401`로 서명이 틀린 요청은 차감하지 않게 했습니다.
- **gateway에서 먼저 끊는 이유:** shipper와 fw-agent는 core 망에서 `app:5000`으로 바로 부르므로, 바깥에서 이 주소를 부를 일이 없습니다. 입구에서 끊는 것이 가장 싸고 확실합니다.
- **shipper의 429 처리:** 예전에는 429를 다른 4xx(형식 오류)처럼 바로 버렸습니다. 429는 "지금 바쁨"이므로 5xx처럼 1·2·4·8초 물러났다가 다시 보냅니다. `Retry-After` 헤더가 오면 그 값을 따르되 60초를 넘기지 않습니다. 서명은 시도마다 새 시각으로 다시 만듭니다.

## ② 통신이 끊긴 동안의 임시 차단

| 상황 | 예전 | 지금 |
|---|---|---|
| 10초 차단을 받음 → 앱이 멈춤 → 70초 뒤 reconcile | 커널이 지운 항목을 "빠졌다"고 보고 **10초로 다시 넣음**(60초마다 반복) | 받은 시각 + 10초가 지났으므로 **넣지 않고** 목록에서도 뺌 |
| 600초 차단 중 누가 손으로 지움 → 30초 뒤 reconcile | 600초로 다시 넣음 | 남은 570초로 다시 넣음 |
| 영구 차단이 빠짐 | 다시 넣음 | 다시 넣음(같음) |

- fw-agent는 목록을 받은 순간의 `time.monotonic()`을 기억합니다. PC 시계가 바뀌어도 경과 시간이 흔들리지 않는 시계입니다.
- 응답에 `"blocks"` 칸이 없으면 예전에는 빈 목록 `[]`로 받아 기존 차단을 전부 지울 수 있었습니다. 이제는 오류로 보고, 앱이 응답하지 않을 때와 똑같이 마지막 상태를 유지합니다. 진짜로 막을 것이 없을 때는 앱이 `"blocks": []`를 보냅니다.

## ③ "규칙에 해당함"과 "조치 완료"를 구분

```text
경보 ──▶ 규칙 NET-01 해당? ── 사건에 이미 NET-01 있음
                               │
                               ▼  playbook_runs에서 이 실행 근거(incident:41:NET-01)의 단계별 마지막 결과 확인
              block_l4_ttl = FAILED  → 이 단계만 다시 실행
              notify_slack = FAILED  → 다시 실행하지 않음(알림 반복 방지)
              block_l4_ttl = OK      → 아무것도 안 함
```

- 다시 실행하는 단계(`RETRYABLE_STEPS`): 영구 잠금(IP·계정), L4 차단(영구·TTL), 세션 끊기. 이 조치들은 이미 됐으면 `False`(→ `SKIPPED`)를 돌려주는 멱등 함수라 다시 불러도 안전합니다.
- 메일·Slack은 빼 두었습니다. 다시 돌리면 같은 경고가 반복해서 나가기 때문입니다.
- 기록 조회가 실패하면 아무것도 하지 않습니다. 확실하지 않을 때 조치를 반복하는 것보다 안전합니다.

## ④ 차단 완료 응답(ACK)에 요청 번호 붙이기

```text
① fw-agent가 읽음:   PENDING_APPLY, ttl 60,   version 3
② 앱이 영구로 강화:  PENDING_APPLY, 영구,     version 4
③ fw-agent ACK:      APPLIED, version 3  → 번호가 달라 무시(changed=false)
④ 다음 폴링(2초):    PENDING_APPLY, 영구, version 4 → ipset timeout 0(영구)로 갱신 → ACK version 4 → APPLIED
```

- 번호를 올리는 곳: `request_block()`의 새 요청·강화, `request_unblock()`(해제도 새 요청입니다). 새 줄은 DB 기본값 0으로 시작합니다.
- ACK의 `version`은 선택입니다. 없으면 예전처럼 상태만 봅니다. 그래서 guide56 SQL 실행 전 DB나 옛 fw-agent와도 함께 동작합니다.
- 해제 직전에 읽힌 옛 차단 요청의 늦은 `FAILED` ACK가 해제 요청(`PENDING_REMOVE`)을 덮어쓰던 문제도 같은 방법으로 막힙니다.

## ⑤ 관리자 해제 — 일부만 성공했을 때

| 상황 | 응답(`POST /api/permanent-locks/release`) |
|---|---|
| L7·L4 모두 해제 요청됨 | `200 {"success": true, "l4": "REQUESTED"}` |
| L4 차단이 원래 없음 | `200 {"success": true}` (예전과 같음) |
| L7은 풀렸는데 L4 해제 요청 실패 | `502 {"success": false, "l7": "RELEASED", "l4": "FAILED", "error": "… 다시 실행하세요"}` |
| 다시 실행: L7은 이미 풀림, L4만 남음 | `200 {"success": true, "l7": "NOT_LOCKED", "l4": "REQUESTED"}` |
| 둘 다 풀 것이 없음 | `404` (예전과 같음) |

- `lockdown.ensure_l4_released(ip, actor)`가 장부 상태를 보고 필요할 때만 해제를 요청합니다. 결과는 `NONE`·`REQUESTED`·`REMOVED`·`FAILED` 중 하나입니다. `FAILED` 상태의 장부 줄은 fw-agent의 reconcile이 ipset에서 빼므로 "막혀 있지 않음(`NONE`)"으로 봅니다.
- 운영 스크립트도 같습니다: `python scripts/management/unlock_ip.py --ip <주소> --permanent`는 앱 잠금이 이미 풀려 있으면 남은 L4 해제만 요청합니다.
- **남은 한계:** 관리자 화면의 "영구 잠금" 표는 L7이 풀리면 그 줄이 사라집니다. 그래서 L4만 남은 경우 화면에서 다시 누를 버튼이 없고, 위 스크립트나 API로 다시 실행해야 합니다.

## ⑥ S4 판정 — "요청됨"이 아니라 "실제로 막힘"

| 확인 | 예전 | 지금 |
|---|---|---|
| CR-01, 영구 잠금(ADMIN_ONLY), `evidence=CONNECTED`, `expires_at` 없음 | ✓ | ✓ |
| `status = APPLIED`, `applied_at` 있음 | ✗ (기다리기만 하고 판정에 안 씀) | ✓ — 30초 안에 안 되면 FAIL |
| 대상 IP → gateway TCP 연결이 **안 됨** | ✗ | ✓ (`lw.py probe`) |
| 다른 새 IP → gateway TCP 연결이 **됨** | ✗ | ✓ |
| 해제 → `REMOVED` → 대상 IP 다시 연결됨 | ✗ | `--with-release`일 때 ✓ |

- `probe`는 HTTP 요청 없이 TCP 연결만 해 봅니다. L7 잠금 상태여도 앱은 403 응답을 주므로 HTTP 결과로는 L4 차단을 구분할 수 없고, ipset DROP은 연결 자체를 버리기 때문입니다. 앱까지 요청이 가지 않으므로 대조용 IP에 DB 흔적이 남지 않습니다.
- `--with-release`는 DB를 바꾸므로(관리자 "영구 해제"와 같은 경로) 기본값은 꺼져 있습니다.

## 추가 상황 — 같은 사건을 동시에 고칠 때, 같은 IP의 다른 계정

- **규칙 동시 기록:** REST로는 배열에 원소 하나만 더할 수 없어, 읽은 목록 전체를 다시 썼습니다. "같은 규칙"의 중복은 조건으로 막았지만, NET-01과 CR-02가 동시에 오면 나중에 쓴 쪽이 앞의 규칙을 지웠습니다(S5b처럼 SYN과 HTTP 폭주가 동시에 오는 경우). 이제 DB 함수 `append_matched_rule()`이 `array_append`로 붙이고, 유형·등급도 지금 행의 값과 합칩니다. 함수가 없는 DB에서는 예전 방식으로 돌아갑니다.
- **같은 IP, 다른 계정:** CR-03 사건이 이미 처리된 IP에서 다른 계정이 로그인하면, 이번 로그인은 막고 그 계정의 기존 세션도 끊습니다. 실행 근거를 `incident:<id>:CR-03:user:<계정 id>`로 나눠 계정마다 한 번만 실행합니다. 메일·Slack은 사건당 한 번이면 충분해서 보내지 않습니다.

## 실제로 돌려 본 결과 (2026-10-26, 시연 대역 PC)

| 확인 | 결과 |
|---|---|
| `pytest tests/ -q` | 1,325개 통과(새 테스트 55개 포함) |
| `run_all --repeat 3` | PASS 12 · FAIL 0 · SKIP 6 — S4·S5·S5b·S8 각 3회 PASS, S6은 `LW_VICTIM_PASSWORD` 없이 돌려 SKIP, S7은 재현 명령 없음 SKIP |
| `check_s4 --with-release` | PASS — 차단 적용 → 대상만 막힘(대조 IP 연결됨) → 해제 → 재접속 |
| fw-agent를 멈추고 S4 | **FAIL**(현재 `PENDING_APPLY`, `applied_at` 없음) — 예전 판정이면 PASS였던 상황을 이제 잡아냄 |
| gateway로 `/api/internal/blocks` | 404 (`/login`은 200) |

run_all은 guide56 SQL을 실행하기 전에 돌렸습니다(예전 방식 fallback 상태). 결과는 [docs/track-d/scenario-results.md](../track-d/scenario-results.md)에 쌓입니다.

## 직접 확인해 보기

```bash
# 이번 보완의 테스트만
pytest tests/track_d/test_i_check_s4.py tests/track_d/test_i_shipper_429.py tests/track_d/test_i_fw_agent_expiry.py tests/track_d/test_i_release_partial.py tests/track_d/test_i_hardening.py -q

# 단지에서 S4 강화 판정 + 해제 후 재접속까지
python -m scripts.net.check_s4 --with-release
```

```sql
-- guide56 반영 확인: 칸·함수가 각 1줄씩 나와야 한다
select column_name from information_schema.columns where table_name = 'network_blocks' and column_name = 'version';
select proname from pg_proc where proname = 'append_matched_rule';

-- 요청 번호가 오르는지: 차단·강화·해제 때마다 version이 1씩 커진다
select ip_address, status, version, applied_at from network_blocks order by requested_at desc limit 5;
```

## 이 단계에서 만들어지거나 바뀐 파일

- 경보 수집: [app.py](../../app.py)(`deduct_when`), [netwatch/nginx/nginx.conf](../../netwatch/nginx/nginx.conf), [netwatch/shipper/eve_shipper.py](../../netwatch/shipper/eve_shipper.py)
- fw-agent: [netwatch/fw_agent/fw_agent.py](../../netwatch/fw_agent/fw_agent.py)
- 요청 번호: [security/netblock.py](../../security/netblock.py), [routes/internal/blocks.py](../../routes/internal/blocks.py), [db/network_blocks.py](../../db/network_blocks.py)
- 조치 재실행·계정별 세션: [security/correlate.py](../../security/correlate.py), [security/playbooks.py](../../security/playbooks.py), [db/playbook_runs.py](../../db/playbook_runs.py), [db/incidents.py](../../db/incidents.py)
- 관리자 해제: [security/lockdown.py](../../security/lockdown.py)(`ensure_l4_released`), [routes/admin/locks.py](../../routes/admin/locks.py), [scripts/management/unlock_ip.py](../../scripts/management/unlock_ip.py)
- 시나리오 점검: [scripts/net/check_s4.py](../../scripts/net/check_s4.py), [scripts/net/check_common.py](../../scripts/net/check_common.py), [scripts/net/run_all.py](../../scripts/net/run_all.py), [netwatch/attacker/lw.py](../../netwatch/attacker/lw.py)(`probe`)
- DB: [docs/migrations/guide56_track_d_hardening.sql](../migrations/guide56_track_d_hardening.sql)
- 계약서: [docs/track-d/contracts.md](../track-d/contracts.md) K1·K3·K9
- 테스트: `tests/track_d/test_i_check_s4.py`, `test_i_shipper_429.py`, `test_i_fw_agent_expiry.py`, `test_i_release_partial.py`, `test_i_hardening.py`. 기대값을 바꾼 기존 테스트 2개: `test_scaffold.py`·`test_b_ingest.py`의 한도 테스트(401은 이제 한도를 쓰지 않음)
