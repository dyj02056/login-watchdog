# 32단계 — 사건 해결을 잠금 해제와 분리 (관리자가 직접 "해결")

[◀ 31단계](guide31_llm_judgment_agent.md) · [전체 목차](beginner-guide.md)

> 27단계에서 만든 "연관 사건"(`security_incidents`)은 IP 잠금이 풀리는 순간 자동으로 "종료"됐습니다. 하지만 **접속 차단을 푸는 것**과 **관리자가 내용을 확인하고 조사를 끝냈다고 판단하는 것**은 다른 일입니다. 이 단계에서는 둘을 분리해서, 사건은 관리자가 대시보드의 "해결" 버튼을 눌러야만 닫히도록 바꿨습니다.

## 용어부터 정리

| 용어 | 뜻 | 누가 결정하나 |
|---|---|---|
| **잠금 해제** | IP가 다시 접속할 수 있게 하는 조치 | 5분 뒤 자동, 또는 관리자의 "즉시 해제" |
| **사건 해결** | 관리자가 내용을 확인하고 조사가 끝났다고 표시하는 판단 | **관리자만** ("해결" 버튼) |

## 왜 필요한가 — 기존 구조의 문제 3가지

1. **"종료"가 관리자의 판단이 아니었습니다.** 5분 뒤 자동 해제만으로 사건이 "종료"로 바뀌어서, 새벽에 발생한 복합 공격을 아침에 열어 보면 이미 "종료"로 보였습니다. 관리자가 검토하기 전에 사건이 끝난 것처럼 보이는 셈입니다.
2. **닫을 방법이 없는 사건이 있었습니다.** 사건은 잠금이 풀릴 때만 닫혔습니다. 그런데 웹 스캐닝 + 봇 탐지처럼 MEDIUM/HIGH 이벤트만으로 열린 사건은 잠금 자체가 없어서 영원히 "진행 중"으로 남았고, 계정 잠금(분산 브루트포스) 사건도 마찬가지였습니다. 버튼도 없었습니다.
3. **오래된 사건이 새 공격의 경고를 삼킬 수 있었습니다.** 같은 IP의 열린 사건에는 새 이벤트가 시간 제한 없이 계속 합쳐졌습니다. 이미 "복합 공격 발생" 알림을 보낸 사건(`escalated=True`)에 몇 주 뒤의 새 공격이 합쳐지면, 알림이 이미 나갔다고 보고 조용히 넘어가 버립니다.

## 바뀐 동작

| 상황 | 이전 | 이후 |
|---|---|---|
| IP 잠금 해제(수동·자동·터미널 스크립트) | 사건도 자동 `CLOSED` | 사건은 그대로. 접속 차단만 풀림 |
| 사건 종료 | 잠금이 풀리면 자동 | 관리자가 "해결"을 눌러야 `CLOSED` |
| 마지막 이벤트 후 30분 넘게 조용한 뒤 새 이벤트 | 옛 사건에 계속 병합 | 옛 사건은 `IDLE`, 새 사건이 열리고 알림도 다시 나감 |
| 해결 기록 | 없음 | 누가(`resolved_by`) 언제(`resolved_at`) 해결했는지 남음 |

사건 상태는 세 가지입니다.
- `OPEN` — 진행 중
- `IDLE` — 활동 없음. 마지막 이벤트로부터 30분 넘게 조용했는데 같은 IP에서 새 이벤트가 와서 새 사건이 따로 열린 상태. 옛 사건은 **아직 관리자 미해결**입니다.
- `CLOSED` — 관리자가 해결함

## 1. 병합 유예 시간 — 왜 30분인가

`config.INCIDENT_MERGE_IDLE_MINUTES`(기본 30, 환경변수로 변경 가능)입니다.

- **5~10분으로는 짧습니다.** IP 잠금이 5분이라, 잠금이 풀린 뒤 공격자가 재시도하는 정도의 공백에서 한 공격이 사건 여러 개로 쪼개집니다. 새 사건은 `escalated=False`로 시작하므로 같은 공격에 "복합 공격 발생" 알림이 반복됩니다.
- **몇 시간은 깁니다.** 공유 IP(회사·카페 와이파이) 등에서 서로 무관한 활동이 한 사건에 섞이고, 위 3번 문제가 그대로 남습니다.
- **30분**은 상관 창(5분)의 6배이고 잠금 주기(5분)를 여러 번 돌 만한 시간이라, 한 공격 흐름은 묶고 새 국면은 분리하는 균형점입니다. 이 값은 실제 공격 데이터로 검증한 것이 아니라 위 논리에 따른 초기값입니다.
- 상관 창(`INCIDENT_CORRELATION_WINDOW_MINUTES`)보다 작게 설정하면 의미가 없으므로 그 값으로 끌어올립니다.

## 2. `db/incidents.py` — 오래 조용한 사건은 IDLE로 옮기고 새로 연다

```python
existing = get_open_incident(ip)
if existing and _is_idle(existing):     # 마지막 이벤트로부터 30분 초과
    mark_incident_idle(existing["id"])  # 옛 사건: OPEN → IDLE (아직 관리자 미해결)
    existing = None                     # → 아래에서 새 사건(escalated=False)을 연다
```

별도 타이머는 두지 않았습니다. 이 프로젝트의 다른 "자동 해제"와 같은 방식으로, **새 이벤트가 들어올 때** 확인합니다.

`idx_security_incidents_open_ip`(IP당 `OPEN` 사건은 최대 1건)는 `status='OPEN'`에만 걸려 있어서 그대로 뒀습니다. 옛 사건이 `IDLE`로 빠져야 새 `OPEN` 사건을 만들 수 있고, 동시 요청이 겹치는 경쟁 조건에 대한 안전망(`23505` 충돌 시 병합)도 유지됩니다.

## 3. 사건 해결 — `resolve_incident()`

```python
def resolve_incident(incident_id, admin_username) -> bool:
    res = (
        db.get_client().table("security_incidents")
        .update({"status": "CLOSED", "resolved_at": db._now_iso(), "resolved_by": admin_username})
        .eq("id", incident_id)
        .in_("status", ["OPEN", "IDLE"])
        .execute()
    )
    return bool(res.data)
```

`OPEN` 또는 `IDLE`인 사건에만 적용되므로 이미 해결된 사건을 다시 눌러도 안전합니다(`False`를 돌려주고 원래 해결자·시각은 그대로 유지). `resolve_security_event()`와 같은 방식입니다.

잠금 해제 경로(`soar.manual_release`, `soar.try_release_expired_lockouts`, `scripts/unlock_ip.py`)에서는 사건을 닫던 호출(`close_open_incident_for_ip`)을 **삭제**했습니다. 잠금 해제는 CRITICAL 보안 이벤트만 정리하고 사건은 건드리지 않습니다.

## 4. API와 권한

`POST /api/security-incidents/resolve` ([routes/admin.py](../../routes/admin/))

- 권한은 새로 만든 `resolve_incident`입니다(`security_admin`, `super_admin`). "쓰기 API 하나당 권한 하나" 관례를 따랐습니다. `security_viewer`는 403입니다.
- 요청 본문은 `{"incident_id": 정수}`입니다. 정수가 아니면(없음, 문자열, `true`, 소수) 400입니다.
- **해결자는 요청 본문이 아니라 로그인 세션(`session["admin_username"]`)에서 가져옵니다.** 본문의 `resolved_by`를 넣어 위조해도 무시됩니다.

## 5. 대시보드 — "연관 사건" 표

- 상태 표시: 진행 중(빨강) / 활동 없음(주황) / 해결됨(초록)
- 새 "처리" 열: `OPEN`·`IDLE`이면 "해결" 버튼, `CLOSED`면 "해결자 · 시각"을 보여줍니다. 예전에 잠금 해제로 자동 종료된 사건은 기록이 없으므로 "-"입니다.
- "해결" 버튼은 되돌릴 수 없어서 `confirm()` 확인창을 한 번 거칩니다.
- 열이 6개에서 7개로 늘면서 열 너비 비율을 다시 나눴습니다. 처음에는 비율 합이 100%를 넘어 7번째 열이 카드 밖으로 밀려났고, 로컬에서 화면을 직접 열어 보고 발견해서 고쳤습니다.

## 6. DB 변경 — Supabase에서 먼저 실행해야 합니다

[docs/schema.sql](../schema.sql) 맨 아래 "사건 해결을 잠금 해제와 분리" 블록입니다. 코드를 배포하기 **전에** 실행해야 합니다. 코드가 먼저 나가면 `IDLE`로 바꾸는 순간 상태 제약 위반 오류가 납니다.

- `status` 체크 제약을 `('OPEN','IDLE','CLOSED')`로 교체 (기존 제약의 실제 이름을 자동으로 찾아 지움)
- `resolved_at`, `resolved_by` 컬럼 추가
- `permissions` 제약에 `resolve_incident` 추가, `security_admin`/`super_admin`에 부여

## 실제로 확인한 것

- `pytest tests/` 전체 **330개 통과**(변경 전 316개 + 이번 추가 14개). 기존 테스트 5개(`test_soar.py` 3개, `test_unlock_ip.py` 2개)는 "잠금 해제하면 사건이 닫힌다"를 검증하던 것을 "닫히지 않는다"로 뒤집었습니다.
- **로컬 브라우저 테스트**: 진짜 Supabase 없이 `security_incidents` 표만 메모리에서 흉내낸 가짜 DB를 붙이고 진짜 앱 코드(라우트, `db/incidents.py`, 자바스크립트)를 실행했습니다. 확인한 것: 잠금 해제 후에도 사건이 `OPEN` 유지, "해결" 클릭 시 해결자·시각 기록, `IDLE` 사건 해결, 이미 해결된 사건 재해결 시 변화 없음, 본문 위조 무시, 잘못된 입력 400, 10분 공백에는 계속 병합, 45분 공백에는 옛 사건이 `IDLE`이 되고 새 사건과 새 알림이 생성됨.
- 실제 Supabase에서의 확인은 위 6번 SQL을 실행한 뒤 따로 해야 합니다.

## 알려진 한계

- `OPEN` → `IDLE` 전환은 새 이벤트가 들어올 때만 일어납니다(별도 타이머 없음). 새 이벤트가 없는 사건은 30분이 지나도 화면에 "진행 중"으로 남습니다.
- 관리자가 "해결"을 누르지 않은 사건은 계속 남습니다. 주기적으로 확인해서 닫아야 합니다.
- CRITICAL 보안 이벤트(`security_events`)는 기존대로 잠금이 풀릴 때 자동 처리됩니다. 이번에는 사건(`security_incidents`)만 분리했습니다.
- "해결" 버튼은 역할과 관계없이 보이고, 권한이 없으면 서버가 403으로 거절합니다(기존 "처리 완료", "즉시 해제" 버튼과 같은 방식).

## 이 단계에서 만들어지거나 바뀐 파일

- [db/incidents.py](../../db/incidents.py) — `resolve_incident()`, `mark_incident_idle()`, `_is_idle()` 신규, `record_incident()` 변경, `close_open_incident_for_ip()` 삭제
- [db/\_\_init\_\_.py](../../db/__init__.py) — 내보내기 목록 갱신
- [config.py](../../config.py) — `INCIDENT_MERGE_IDLE_MINUTES` 신규
- [soar.py](../../security/soar/), [scripts/unlock_ip.py](../../scripts/unlock_ip.py) — 잠금 해제 경로에서 사건을 닫던 호출 제거
- [routes/admin.py](../../routes/admin/) — `POST /api/security-incidents/resolve` 신규
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [public/css/dashboard.css](../../public/css/dashboard.css), [public/js/dashboard/render.js](../../public/js/dashboard/render.js), [api.js](../../public/js/dashboard/api.js), [events.js](../../public/js/dashboard/events.js) — "처리" 열과 "해결" 버튼
- [docs/schema.sql](../schema.sql) — 상태 제약, `resolved_at`/`resolved_by`, `resolve_incident` 권한
- [docs/feature-reference/ERD.svg](../feature-reference/ERD.svg), [db-schema-guide.md](../feature-reference/db-schema-guide.md), [01-feature-order.md](../feature-reference/01-feature-order.md), [02-layer-order.md](../feature-reference/02-layer-order.md), [README.md](../../README.md) — 문서 갱신
- [tests/test_db.py](../../tests/test_db.py), [tests/test_app.py](../../tests/test_app.py), [tests/test_soar.py](../../tests/test_soar.py), [tests/test_unlock_ip.py](../../tests/test_unlock_ip.py) — 신규·수정
