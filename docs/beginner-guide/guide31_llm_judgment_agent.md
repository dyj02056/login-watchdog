# 31단계 — LLM 조기 경보 에이전트 (Track A)

[◀ 30단계](guide30_threshold_tuning.md) · [전체 목차](beginner-guide.md) · [32단계 ▶](guide32_incident_resolution.md)

> Week1 Day6(LLM Agent, 승인 게이트) 커리큘럼과 `login_watchdog_expansion_plan.md`의 Track A를 구현했습니다. 지금까지의 모든 탐지 로직(브루트포스, Web Scanning, 매크로/봇 등)은 "임계값을 넘었을 때"만 반응합니다. 이 단계는 그 반대 — **아직 임계값을 못 넘었지만 코앞인 구간**에서 Groq(LLM)에게 "지켜볼 필요가 있는지" 한 번 더 물어보고, 위험하다고 판단되면 관리자 승인 대기 목록에 올립니다.

## 왜 "넘은 후"가 아니라 "넘기 전"인가

처음 계획은 "임계값 근처(threshold-2 ~ threshold+2) 전체를 LLM에 맡기자"였지만, 논의 과정에서 방향을 좁혔습니다:

- **임계값을 이미 넘었다 = 규칙이 이미 확정 판단을 내린 상태**입니다. 여기서 LLM에게 다시 묻는 건 의미가 없고, 응답을 기다리는 사이 대응만 늦어집니다 — 이 구간은 지금처럼 규칙대로 즉시 자동 조치합니다(변경 없음).
- **LLM이 진짜 쓸모 있는 지점은 "아직 규칙에 안 걸린 코앞" 구간**입니다. 예를 들어 `FAILURE_THRESHOLD`가 5일 때 4번 실패한 상태는 지금 아무 일도 안 일어납니다. 공격자가 일부러 임계값 바로 아래에서 시도를 멈췄다가 다시 시도하는 식으로 규칙을 회피하면, 규칙만으로는 절대 못 잡습니다.

그래서 최종 설계는 **`threshold - EARLY_WARNING_BAND ~ threshold - 1`(기본 폭 2) 구간에서만, 아직 suspicious가 False인 경우에만** LLM을 부릅니다. 이미 suspicious가 True인 경로와는 절대 겹치지 않습니다.

## 적용 대상 — 기존 탐지 유형 7개 전부

| 유형 | 임계값(기본값) | 근처 구간(기본 폭 2) | 승인 시 실행되는 조치 |
|---|---|---|---|
| 로그인 브루트포스(IP) | `FAILURE_THRESHOLD`(5) | 3~4회 | IP 잠금 (`LOCK_IP`) |
| 계정 단위 분산 브루트포스 | `ACCOUNT_FAILURE_THRESHOLD`(8) | 6~7회 | 계정 잠금 (`LOCK_ACCOUNT`) |
| 회원가입 남용 | `SIGNUP_RATE_LIMIT`(5) | 3~4회 | HIGH 기록 (`ALERT_ONLY`) |
| Web Scanning | `WEB_SCANNING_ALERT_THRESHOLD`(10) | 8~9회 | Slack 알림 + MEDIUM 기록 |
| Unauthorized Access | `UNAUTHORIZED_ACCESS_ALERT_THRESHOLD`(10) | 8~9회 | Slack 알림 + MEDIUM 기록 |
| 반복 페이지 접근 | `PAGE_ACCESS_ALERT_THRESHOLD`(20) | 18~19회 | Slack 알림 + MEDIUM 기록 |
| 매크로/봇 패턴 | `MACRO_DISTINCT_API_THRESHOLD`(5) | 3~4회 | Slack 알림 + MEDIUM 기록 |

"승인 시 실행되는 조치"는 전부 **그 유형이 원래 임계값을 넘었을 때 이미 하던 조치**를 그대로 재사용합니다 — 새 조치를 만들지 않고, 실행 시점만 앞당깁니다. 로그인/계정 브루트포스만 실제로 잠그고 나머지는 원래도 관찰(알림+기록)까지만 하는 설계 철학(`soar.py`)을 그대로 이어받았습니다.

## 1. `llm_client.py` — Groq 호출 공통화

`scripts/daily_report.py`에만 있던 Groq 호출 로직(재시도/타임아웃/에러 처리)을 이 파일로 옮겼습니다. `daily_report.py`는 이제 `llm_client.ask_groq()`를 호출하는 얇은 래퍼가 됐습니다(동작은 동일).

```python
def judge_early_warning(label, target_kind, target_value, count, threshold) -> dict | None:
    ...
    raw_reply = ask_groq(prompt, json_mode=True)
    judgment = json.loads(raw_reply)
    return {"risky": bool(judgment["risky"]), "reason": str(judgment["reason"])}
```

Groq 호출이 실패하거나 응답 형식이 예상과 다르면 예외를 던지지 않고 `None`을 돌려줍니다 — 이 기능은 "덤으로 추가한 조기 경보"라서, 실패해도 로그인 흐름이나 기존 방어를 절대 막으면 안 되기 때문입니다.

## 2. 새 표 — `access_requests`

```sql
create table access_requests (
  request_id bigint generated always as identity primary key,
  event_type text not null,
  pending_action text not null check (pending_action in ('LOCK_IP', 'LOCK_ACCOUNT', 'ALERT_ONLY')),
  target_kind text not null check (target_kind in ('ip', 'account')),
  target_value text not null,
  path text,
  count int not null,
  threshold int not null,
  context_count int,
  context_ip text,
  llm_reason text not null,
  status text not null check (status in ('PENDING', 'APPROVED', 'REJECTED')) default 'PENDING',
  requested_at timestamptz not null default now(),
  decided_by_admin_id bigint references admin_users(id),
  decided_at timestamptz
);
```

`context_count`/`context_ip`는 승인 시 `enforce_lockout()`/`enforce_account_lockout()`에 그대로 넘겨야 하는 부가 정보(distinct_usernames, distinct_ips, triggering_ip)를 담아둡니다. `idx_access_requests_open_target` 부분 유니크 인덱스로 "같은 유형·대상에는 PENDING이 동시에 1건만" 존재하도록 DB가 직접 강제합니다(`security_incidents`의 `idx_security_incidents_open_ip`와 동일한 패턴).

## 3. `soar.py` — 판단과 실행

- `consider_early_warning(...)`: 이미 PENDING이 있으면 건너뛰고, 없으면 `llm_client.judge_early_warning()`을 불러 위험하면 `access_requests`에 등록 + Slack 알림.
- `execute_approved_request(request_id, admin_id)`: 관리자가 승인을 누르면 `pending_action`에 맞는 조치(`enforce_lockout`/`enforce_account_lockout`/기존 `notify_*`)를 실행하고 상태를 `APPROVED`로 확정.
- `reject_pending_request(request_id, admin_id)`: 아무 조치 없이 `REJECTED`로만 바꿈.

호출부는 7곳입니다 — `routes/auth.py`(로그인 IP/계정/회원가입), `app.py`(Web Scanning/반복 페이지 접근/매크로·봇), `helpers.py`(Unauthorized Access, `login_required`/`require_permission` 두 곳). 전부 기존 `if suspicious:` 분기 옆에 `elif`로 추가했습니다 — 이미 규칙이 조치를 실행하는 경로와 절대 겹치지 않습니다.

## 4. 권한 — `approve_pending_action`

승인/반려는 `unlock_ip`/`resolve_security_event`와 같은 급의 "IP·계정 보안 조치"라서, 그 두 액션과 동일하게 **security_admin과 super_admin 둘 다**에게 부여했습니다(security_viewer는 조회만 가능). `permissions.action`의 체크 제약을 이 값 하나 추가한 걸로 교체해야 합니다(스키마 SQL 참고).

## 5. `detector.is_signup_rate_limited()` 시그니처 변경

원래 `bool`만 돌려주던 이 함수를 다른 판정 함수들처럼 `(bool, count)` 튜플로 바꿨습니다 — 회원가입 남용 유형의 근처 구간 판단에 실제 시도 횟수가 필요해졌기 때문입니다. `routes/auth.py`의 유일한 호출부와 관련 테스트(`test_detector.py`, `test_app.py`)를 함께 수정했습니다.

## 6. 대시보드 — "AI 조기 경보" 표

`templates/admin_dashboard.html`에 "보안 이벤트" 표보다 위에 새 섹션을 추가했습니다 — 여기 있는 항목은 아직 아무 조치도 실행되지 않은 "대기 중인 결정"이라 다른 표들보다 먼저 눈에 띄어야 합니다. 요청 시각/유형/대상/현재·기준/AI 판단 근거/승인·반려 버튼을 보여주고, 기존 표들과 동일한 폴링(`/api/status`)·페이지네이션 방식을 씁니다.

## 실제로 확인한 것

`pytest tests/` 전체 307개 통과(기존 295개 + 이번 추가 `test_early_warning.py` 12개). 기존 테스트는 한 줄도 로직을 바꾸지 않고 전부 통과했고, `is_signup_rate_limited` 반환값 변경에 맞춰 관련 mock 5곳 + assert 2곳만 튜플 형태로 갱신했습니다.

Groq API 키(`GROQ_API_KEY`)가 없는 환경에서도 `judge_early_warning()`이 `None`을 돌려주고 `consider_early_warning()`이 조용히 넘어가는 것을 `test_early_warning.py`로 확인했습니다 — 이 기능이 꺼져 있어도(또는 API 키 미설정 상태여도) 기존 보안 기능은 전혀 영향받지 않습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- [llm_client.py](../../services/llm_client.py) — 신규, Groq 호출 공통화
- [scripts/daily_report.py](../../scripts/daily_report.py) — `llm_client.ask_groq()` 사용으로 리팩터링
- [db/access_requests.py](../../db/access_requests.py) — 신규
- [db/__init__.py](../../db/__init__.py)
- [db/admin.py](../../db/admin.py) — `get_admin_id_by_username()` 신규
- [soar.py](../../security/soar/) — `consider_early_warning()`/`execute_approved_request()`/`reject_pending_request()` 신규
- [alert.py](../../notify/alert.py) — `send_pending_approval_alert()` 신규
- [detector.py](../../security/detector.py) — `is_signup_rate_limited()` 반환 타입 변경
- [config.py](../../config.py) — `EARLY_WARNING_BAND` 신규
- [routes/auth.py](../../routes/auth.py), [app.py](../../app.py), [helpers.py](../../helpers/) — 근처 구간 호출부 7곳
- [routes/admin.py](../../routes/admin/) — 승인/반려 API, `/api/status`에 `access_requests` 추가
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [public/css/dashboard.css](../../public/css/dashboard.css)
- [public/js/dashboard/state.js](../../public/js/dashboard/state.js), [render.js](../../public/js/dashboard/render.js), [api.js](../../public/js/dashboard/api.js), [events.js](../../public/js/dashboard/events.js)
- [docs/schema.sql](../../docs/schema.sql) — `access_requests` 표 + `approve_pending_action` 권한
- [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py) — 시그니처 변경 반영
- [tests/test_early_warning.py](../../tests/test_early_warning.py) — 신규
