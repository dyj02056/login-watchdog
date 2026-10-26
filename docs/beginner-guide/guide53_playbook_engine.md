# 53단계 — 플레이북 엔진과 기록 보존

[◀ 52단계](guide52_net_ingest_correlation.md) · [전체 목차](beginner-guide.md) · [54단계 ▶](guide54_l4_block_agent.md)

> [52단계](guide52_net_ingest_correlation.md)의 교차 규칙이 "이건 같은 공격 흐름이다"라고 판단하면, 그다음에 **무엇을 어떤 순서로 할지**는 누가 정할까요? 이 문서는 그 순서표(플레이북)를 실행하는 엔진과, 새로 쌓이는 Track D 기록을 언제 지우는지(보존)를 다룹니다.
> 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 **플레이북 엔진(B2-2)** 과 **보존 SQL(B3-2)** 까지입니다(2026-10-26 main 기준). 실제 조치 함수(차단·세션 끊기·메일·Slack)가 하는 일은 [54단계](guide54_l4_block_agent.md)에서 다룹니다.

## 비유 — 대응 매뉴얼

건물에 불이 나면 경비원은 그 자리에서 할 일을 새로 궁리하지 않습니다. 벽에 붙은 **대응 매뉴얼**을 펴서 "1. 방화문 닫기 → 2. 관리사무소에 보고"를 순서대로 합니다.

| 비유 | 실제 |
|---|---|
| 상황별 대응 매뉴얼 | 플레이북 (`security/playbooks.py`의 `PLAYBOOKS`) |
| 매뉴얼의 한 줄(할 일) | 단계 (`block_l4_ttl`, `notify_slack` 등) |
| "이 일은 누구에게 시킨다" 연락처 | `ACTIONS` — 단계 이름 → 실제 함수 이름 |
| 매뉴얼을 펴서 순서대로 시키는 당직자 | `run(playbook, trigger_ref, ctx)` |
| 처리 일지 | `playbook_runs` 표 (단계마다 한 줄) |
| 일을 실제로 하는 사람 | 역할 C의 조치 함수([54단계](guide54_l4_block_agent.md)) |

**판단(B)과 실행(C)을 나눈 이유(계획 P5):** 형사(교차 규칙)는 "막아야 한다"까지만 정하고, 매뉴얼은 "어떤 순서로"만 정합니다. 실제로 막을지 말지의 마지막 안전 검사(허용 목록, 주소 형식 등)는 일을 하는 쪽(조치 함수)이 **스스로** 합니다. 그래서 매뉴얼에 실수가 있어도 관리자 PC를 막는 사고가 나지 않습니다.

## ④ 플레이북 엔진 (B2-2)

### 매뉴얼 목록 (계약서 K12)

| 플레이북 | 부르는 규칙 | 단계 (순서대로) |
|---|---|---|
| `NET_FLOOD_TTL` | NET-01 (SYN 폭주 단독) | `block_l4_ttl` → `notify_slack` |
| `NET_FLOOD` | CR-02 (SYN + HTTP 폭주) | `block_l4_ttl` → `notify_slack` |
| `KILL_CHAIN` | CR-01 (정찰 → 침투) | `lock_ip_permanent` → `block_l4` → `notify_slack` → `llm_postmortem` |
| `SUSPICIOUS_SUCCESS_LOGIN` | CR-03 (의심 로그인 성공, B3-1) | `invalidate_sessions` → `notify_owner_email` → `notify_slack` |
| `SUBNET_REVIEW`·`ROTATION_EVASION`·`WEB_ATTACK` | CR-04~06 | 선택 과제 — 이번 범위 밖 |

기존 복합 공격 알림(`CRITICAL_MULTI_STAGE`)은 `security/correlate.py`에 그대로 있습니다. 이 파일은 Track D 플레이북만 맡습니다.

### 단계 이름 → 실제 함수 (`ACTIONS`)

| 단계 | 부르는 함수 | 누가 만듦 |
|---|---|---|
| `block_l4_ttl` · `block_l4` | `security.netblock.request_block` | C (C0-2) |
| `lock_ip_permanent` | `security.lockdown.promote_ip` | 기존 |
| `invalidate_sessions` | `db.bump_session_version` | C (C2-1) |
| `notify_owner_email` | `notify.mailer.send_suspicious_login_notice` | C (C2-1) |
| `notify_slack` | `notify.alert.send_playbook_alert` | C (C2-1) |
| `llm_postmortem` | `services.llm_client.summarize_incident` | 선택 과제 |

함수를 **이름(문자열)으로 적어 두고 실행하는 순간에 찾습니다**(`importlib` + `getattr`). 이유는 두 가지입니다.

- 아직 만들어지지 않은 함수가 있어도 매뉴얼 전체가 멈추지 않고, 그 단계만 "건너뜀"이 됩니다.
- 테스트에서 함수를 가짜로 바꿔 끼우면(monkeypatch) 그 가짜가 실제로 불립니다. 파일을 읽는 순간 함수를 미리 잡아 두면 바꿔 끼워도 원래 함수가 불립니다.

### `run()`이 한 단계를 처리하는 순서

```text
단계 하나
  ├─ ctx에서 필요한 값으로 인자 만들기 ── 값이 없으면 ─▶ SKIPPED("필수 값 없음")
  ├─ 이름으로 함수 찾기 ─────────────── 함수가 없으면 ─▶ SKIPPED("조치 함수 없음")
  ├─ 함수 실행 ─────────────────────── 예외가 나면 ───▶ FAILED(예외 종류만 기록)
  ├─ 결과 판정 (아래 표)
  └─ playbook_runs에 한 줄 기록 ──── 기록이 실패해도 다음 단계는 계속
```

| 함수가 돌려준 값 | 단계 결과 | 뜻 |
|---|---|---|
| 정상 | `OK` | 조치함 |
| 차단 요청이 `False` | `SKIPPED` | 이미 같거나 더 강한 차단이 있어 바꿀 게 없었음(멱등) |
| 세션 끊기가 `False` | `FAILED` | 회원이 없거나 동시 변경 경쟁에서 3번 다 짐 — 의심 세션이 살아 있을 수 있음 |
| 메일이 `SKIPPED`·`REFUSED` | `SKIPPED` | 쿨다운 안이라 안 보냄 / 받는 주소 거부 |
| 메일이 `FAILED` | `FAILED` | 일시적 발송 실패 |

- **한 단계가 실패해도 다음 단계는 계속합니다.** 차단이 실패해도 Slack 알림은 가야 관리자가 알 수 있습니다.
- **이미 한 차단은 되돌리지 않습니다.** 뒤 단계(알림)가 실패했다고 막아 둔 공격을 다시 열면 안 되기 때문입니다.
- **오류 메시지는 기록하지 않고 예외 종류만** 남깁니다. 메시지에 DB 주소 같은 값이 섞일 수 있기 때문입니다.
- **실패한 단계만 다시 실행(10/26 보완):** `run(..., only_steps=[...])`로 일부 단계만 원래 순서대로 실행할 수 있습니다. 교차 규칙이 이미 기록된 사건에 다시 경보가 오면, `playbook_runs`에서 마지막 결과가 `FAILED`인 단계 중 `RETRYABLE_STEPS`(영구 잠금·L4 차단·세션 끊기)만 이렇게 다시 돌립니다. 메일·Slack은 반복 발송을 막으려고 빼 두었습니다([56단계](guide56_feedback_hardening.md) ③).
- 마지막 `notify_slack`은 **앞 단계 결과 목록을 함께** 받습니다. 그래서 Slack 알림에 "차단 OK, …"처럼 단계별 결과가 보이고, 실패가 있으면 첫 줄이 `⚠ 일부 조치 실패`가 됩니다(계획 V6).

### 정문 차단에 넘기는 값은 고정 (계약서 K7)

| 단계 | 넘기는 값 | 이유 |
|---|---|---|
| `block_l4_ttl` | `reason="NET_FLOOD"`, `evidence="SPOOFABLE"`, `ttl_seconds=None`, `requested_by="playbook:<플레이북>"` | 차단 시간(1시간, 반복 시 2배, 최대 6시간) 계산은 **차단 요청 함수만** 합니다. 여기서도 계산하면 두 번 계산되거나 빠집니다. CR-02는 연결 완성 증거가 있어도 `CONNECTED`로 넘기면 영구 차단이 되므로 `SPOOFABLE`로 고정합니다 |
| `block_l4` | `reason="KILL_CHAIN"`, `evidence="CONNECTED"`, `ttl_seconds=None` | CR-01 킬체인 전용 영구 차단. 다른 플레이북에서 이 단계가 불리면 실행하지 않고 `FAILED`로 기록합니다 |
| `lock_ip_permanent` | `reason="NETWORK_IDS"`, `recoverable="ADMIN_ONLY"`(킬체인) | 킬체인은 복구 대상이 아니라 관리자만 풀 수 있게 합니다 |

### 실제로 돌려 본 결과 (2026-10-26, 시연 대역 PC)

5초 측정에서 S5·S5b를 3번씩 재현했을 때 `playbook_runs`에 18줄이 남았습니다.

| 플레이북 | 단계 | 결과 |
|---|---|---|
| `NET_FLOOD_TTL` | `block_l4_ttl` · `notify_slack` | 각 6번 모두 `OK` |
| `NET_FLOOD` | `block_l4_ttl` · `notify_slack` | 각 3번 모두 `OK` |

`SKIPPED`가 0건이라는 것은 **C의 조치 함수가 계약서 이름 그대로 main에 있고, 매뉴얼이 실제로 그 함수를 불렀다**는 뜻입니다(03 점검서 교체 확인표 6·7번 통과). 측정값 자체는 [docs/track-d/measurements.md](../track-d/measurements.md)에 있습니다.

## ⑤ 기록 보존 — 오래된 Track D 기록 지우기 (B3-2)

Track D는 새 표 세 개에 기록을 계속 쌓습니다. 무료 DB 용량(500MB)을 지키기 위해, 기존 매일 정리 함수 `cleanup_old_logs()`가 이 표들도 함께 지우게 했습니다(`docs/migrations/guide53_track_d_retention.sql`).

| 표 | 보존 기간 | 지우지 않는 것 | 이유 |
|---|---|---|---|
| `network_events` (센서 원본 경보) | 7일 | — | 원본은 양이 많고, 판단에 필요한 내용은 이미 보안 기록으로 올라가 있습니다. 화면 통계도 최근 7일만 봅니다 |
| `playbook_runs` (처리 일지) | 90일 | — | 기존 처리 완료 보안 기록과 같은 기간. 사후 검토에 씁니다 |
| `network_blocks` (차단 장부) | `REMOVED`·`FAILED`만 30일 | `PENDING_APPLY`·`APPLIED`·`PENDING_REMOVE` | **지금 걸려 있거나 진행 중인 차단은 기간과 상관없이 남깁니다.** 지우면 fw-agent가 받아 갈 목록에서 사라져 차단이 엉킵니다 |

- **기존 정리는 한 글자도 바꾸지 않았습니다.** guide47의 함수 정의를 그대로 가져와 맨 뒤에 표 세 개만 덧붙였습니다. 매일 새벽 3시(한국 시간) 예약 작업 `daily-log-maintenance`도 그대로입니다.
- **차단 반복 계산에는 영향이 없습니다.** "최근 30일에 몇 번 막혔나"는 보안 기록의 `NET_BLOCKED`(처리 후 90일 보존)로 세기 때문입니다.
- **적용:** 2026-10-26 통합 담당자가 Supabase SQL Editor에서 두 번 실행해 오류가 없음을 확인했습니다. 되돌릴 때는 guide47의 `cleanup_old_logs` 정의를 다시 실행합니다.

## 알려진 제한

| 내용 | 영향 |
|---|---|
| Slack 알림 머리말이 항상 `[HIGH]` | 알림 함수는 우선순위(`priority`)를 받을 수 있지만, 매뉴얼이 아직 넘기지 않습니다. CR-01 킬체인(CRITICAL)도 `[HIGH]`로 보입니다 |
| S5b처럼 NET-01과 CR-02가 몇 초 안에 함께 맞으면 | 같은 IP에 매뉴얼이 두 번 돌아 Slack이 2통 갑니다. 첫 차단이 적용된 직후 두 번째 요청이 오면 그 적용을 "과거 차단 1회"로 세어 차단 시간이 2시간이 될 수 있습니다(10/26 측정에서 1회 관찰) |
| `llm_postmortem` | 선택 과제 — 이번 범위 밖. 킬체인 때 이 단계는 `SKIPPED`로 남습니다 |
| CR-02 반복 시 관리자 승인(`require_approval`) | 선택 과제 — 이번 범위 밖 |

## 직접 확인해 보기

```bash
# 매뉴얼 순서·실패 격리·건너뜀·차단 인자 고정 테스트 (실제 DB·Slack은 건드리지 않음)
pytest tests/track_d/test_b_playbooks.py -q

# 보존 SQL이 기존 정리를 그대로 두고 표 세 개만 더했는지 (SQL 파일을 글자로 검사)
pytest tests/track_d/test_b_retention.py -q
```

단지에서 SYN 폭주를 한 번 재현한 뒤([52단계 "직접 확인해 보기"](guide52_net_ingest_correlation.md#직접-확인해-보기)), Supabase SQL Editor에서 봅니다.

```sql
-- 최근 처리 일지: 단계마다 한 줄
select ran_at, playbook, step, status, error, trigger_ref
from playbook_runs order by ran_at desc limit 10;

-- 문제가 되는 건너뜀이 있는지 (통합일마다 확인)
select playbook, step, count(*) as skipped, max(ran_at) as last_at
from playbook_runs
where status = 'SKIPPED' and ran_at > now() - interval '1 day'
group by playbook, step order by last_at desc;

-- 보존 정리 미리보기: 지금 돌리면 표마다 몇 줄이 지워질지 (실제로 지우지 않음)
select * from cleanup_old_logs(true);
```

- `block_l4_ttl`·`notify_slack`이 `SKIPPED`면 C의 함수 이름이나 위치가 계약서와 다르다는 뜻입니다. 매뉴얼은 함수를 못 찾으면 오류 대신 `SKIPPED`로 넘어가므로 이 조회 없이는 모르고 지나갑니다.
- 정상인 `SKIPPED`: `llm_postmortem`(선택 과제), 회원 정보가 없는 사건의 `invalidate_sessions`·`notify_owner_email`, 이미 같은 차단이 있을 때의 `block_l4_ttl`.
- 미리보기 결과 맨 아래에 `network_events`·`playbook_runs`·`network_blocks` 세 줄이 있어야 보존 SQL이 적용된 것입니다.

## 이 단계에서 만들어지거나 바뀐 파일

- B2-2: [security/playbooks.py](../../security/playbooks.py), [db/playbook_runs.py](../../db/playbook_runs.py)(`insert_playbook_run`), [tests/track_d/test_b_playbooks.py](../../tests/track_d/test_b_playbooks.py)
- B3-2: [docs/migrations/guide53_track_d_retention.sql](../migrations/guide53_track_d_retention.sql), [docs/schema.sql](../schema.sql)(맨 아래 "Track D 보존" 구역), [tests/track_d/test_b_retention.py](../../tests/track_d/test_b_retention.py)
