# 28단계 — SOAR 플레이북 고도화 (Track C 2/4)

[◀ 27단계](guide27_siem_correlation.md) · [전체 목차](beginner-guide.md) · [29단계 ▶](guide29_macro_bot_detection.md)

> keyword.md 5과목(SOAR 플레이북)을 반영하는 Track C의 두 번째 단계입니다. 27단계에서 만든 "사건철"(`security_incidents`)은 서로 다른 공격 유형이 겹치면 하나로 묶어주긴 했지만, 그 사건이 얼마나 심각한지와 무관하게 대응은 항상 똑같았습니다(각 이벤트별 개별 알림뿐). 이번 단계에서 "사건이 특정 조건을 넘으면 → 이런 대응을 추가로 한다"는 매뉴얼(플레이북)을 선언적으로 연결했습니다.

## 원래 계획서와 다르게 간 지점

원래 확장계획 문서는 `PLAYBOOKS = {"DISTRIBUTED_BF": [lock_account, notify_slack, require_approval]}` 형태를 제시했지만, `require_approval`은 Track B의 예외 승인 큐(`access_requests`)가 있어야 의미가 생기는데 Track B는 아직 guide26(기본 구조)까지만 되어 있습니다. 그래서 이번 단계는 **존재하지 않는 승인 게이트를 흉내내지 않고**, 지금 실제로 할 수 있는 일 — "사건이 심각한 수준에 도달하면 관리자에게 별도의 강조 알림을 보낸다" — 로 범위를 좁혔습니다. 기존 `soar.py`의 개별 조치 함수(IP/계정 잠금 등)도 그대로 두고 건드리지 않았습니다.

## 1. 플레이북을 어디에 둘 것인가 — `soar.py`가 아니라 `correlate.py`

`soar.py`가 이미 `correlate.py`를 import하고 있습니다(이벤트 기록 직후 상관분석 훅을 부르기 위해, 27단계). 만약 플레이북 실행을 `soar.py`에 두고 `correlate.py`가 그걸 호출하게 하면 반대 방향 import가 생겨 **순환 참조**가 됩니다. `correlate.py`는 사건이 얼마나 심각해졌는지 이미 알고 있는 유일한 곳이므로, 여기서 곧바로 `alert.py`를 불러 실행하는 것이 `soar.py`가 `alert.py`를 직접 부르는 것과 같은 자연스러운 구조입니다.

```python
# correlate.py
PLAYBOOKS = {
    "CRITICAL_MULTI_STAGE": ["send_incident_escalation_alert"],
}
```

## 2. 왜 함수 객체가 아니라 이름(문자열)을 담는가 — 실제로 겪은 버그

처음에는 `PLAYBOOKS = {"CRITICAL_MULTI_STAGE": [alert.send_incident_escalation_alert]}`처럼 함수 객체를 직접 담았습니다. 그런데 이렇게 하면 이 딕셔너리는 **`correlate.py`가 처음 읽힐 때(import 시점) 딱 한 번** `alert.send_incident_escalation_alert`가 가리키는 함수를 미리 꺼내서 저장해둡니다. 테스트에서 `monkeypatch.setattr(alert, "send_incident_escalation_alert", 가짜함수)`로 나중에 바꿔치기해도, 이 딕셔너리 안의 참조는 여전히 원래 함수를 가리키고 있어서 **가짜 함수가 호출되지 않는** 조용한 버그가 났습니다(실제로 첫 테스트 실행에서 발견).

`db.py`/`alert.py`를 부르는 이 프로젝트의 모든 코드가 `db.함수명(...)`/`alert.함수명(...)` 형태로만 쓰고 `from db import 함수명`처럼 이름을 직접 꺼내 쓰지 않는 이유도 같습니다 — "부르는 순간에 그 모듈의 최신 속성을 다시 찾아야" 테스트에서의 바꿔치기가 통합니다. 그래서 `PLAYBOOKS`도 함수 객체 대신 이름을 담고, 실행할 때 `getattr(alert, action_name)`으로 그 순간의 함수를 다시 찾도록 고쳤습니다:

```python
def _maybe_escalate(ip: str, incident: dict) -> None:
    if incident["escalated"]:
        return
    if incident["severity_max"] != "CRITICAL":
        return
    if len(incident["event_types"]) < config.INCIDENT_ESCALATION_MIN_EVENT_TYPES:
        return

    for action_name in PLAYBOOKS["CRITICAL_MULTI_STAGE"]:
        action = getattr(alert, action_name)
        action(ip, incident["event_types"], incident["severity_max"])
    db.mark_incident_escalated(incident["id"])
```

## 3. 에스컬레이션 조건 — "2개 이상"보다 한 단계 높게

27단계의 상관분석 자체는 서로 다른 유형이 **2개 이상**이면 사건으로 묶습니다. 하지만 그 정도로 매번 관리자에게 "복합 공격 발생!" 같은 긴급 알림까지 보내면 알림 피로가 생깁니다. 그래서 에스컬레이션은 한 단계 더 엄격하게 잡았습니다: `severity_max == "CRITICAL"` **이고** 서로 다른 유형이 `config.INCIDENT_ESCALATION_MIN_EVENT_TYPES`(기본 3) 개 이상일 때만 실행됩니다.

## 4. 재알림 방지 — `escalated` 플래그

사건은 새 이벤트가 들어올 때마다 계속 갱신됩니다(27단계). `escalated` 컬럼이 없으면, 이미 조건을 넘은 사건에 4번째, 5번째 이벤트가 또 붙을 때마다 매번 에스컬레이션 알림이 반복 발송됩니다 — `soar.enforce_lockout()`이 "잠그는 순간에 딱 한 번만" 알리는 것과 같은 원칙으로, 알림을 보낸 사건은 `db.mark_incident_escalated()`로 표시해서 다시 알리지 않습니다. 사건이 닫혔다가(CLOSED) 같은 IP에서 새로 열리면 새 행이므로 `escalated`는 자동으로 `False`부터 다시 시작합니다.

```sql
-- docs/schema.sql
alter table security_incidents add column escalated boolean not null default false;
```

## 5. `db.record_incident()`가 이제 값을 돌려준다

27단계까지는 `record_incident()`가 아무것도 리턴하지 않았습니다. `correlate.py`가 에스컬레이션 여부를 판단하려면 "방금 병합/생성된 사건이 지금 어떤 상태인지"(`id`, `event_types`, `severity_max`, `escalated`)를 알아야 하므로, 병합 경로(`_merge_into_existing`)와 신규 생성 경로 양쪽 모두 이 정보를 딕셔너리로 돌려주도록 고쳤습니다. 경쟁 조건으로 삽입이 충돌(23505)해서 병합으로 대체되는 경로도 동일하게 최종 상태를 돌려줍니다.

## 6. `alert.py` — 새 알림 함수

```python
def send_incident_escalation_alert(ip, event_types, severity_max):
    message = (
        ":bangbang: [CRITICAL] 로그인 워치독 SOAR 플레이북 알림\n"
        f"IP: {ip}\n"
        f"연관된 공격 유형 {len(event_types)}종: {', '.join(event_types)}\n"
        ...
    )
    _send_slack_message(message)
```

기존 `send_lockout_alert()` 등 개별 이벤트 알림은 그대로 각자 나갑니다 — 이 알림은 "그 이벤트들이 사실 한 IP에서 겹치고 있다"는 상관관계 자체를 강조하는 것이 목적입니다.

## 실제로 확인한 것

`pytest tests/` 전체 274개 통과(guide27 시점 268개 + 이번 추가 6개 — `test_correlate.py` 4개: 에스컬레이션 실행/이미 처리된 사건은 재실행 안 함/CRITICAL 아니면 안 함/유형 개수 미달이면 안 함, `test_db.py` 2개: `mark_incident_escalated`, `_insert_incident` 직접 검증). 기존 `record_incident` 관련 테스트 3개는 반환값 검증을 추가해 갱신했습니다.

로컬 서버 + 실제 Supabase로 라이브 검증도 했습니다. `security_incidents`에 `escalated` 컬럼을 실제 DB에 추가한 뒤, `scripts/bruteforce_sim.py` → `scripts/web_scanning_sim.py`를 같은 IP(127.0.0.1)로 순서대로 실행했습니다(27단계 검증과 동일하게, 이번에도 트래픽량 때문에 `HTTP_FLOOD`가 자연스럽게 섞여 유형이 3개가 됐습니다). 실행 직후 `/api/status` 응답에서 해당 사건이 `"escalated": true`로 바뀌어 있는 것을 확인했고, 관리자 대시보드 "연관 사건" 표에도 CRITICAL·`BRUTE_FORCE, HTTP_FLOOD, WEB_SCANNING`·"진행 중"으로 정상적으로 나타났습니다. IP 잠금을 해제하자 `status`가 `CLOSED`로, `escalated`는 `true`로 유지된 채(재알림 방지 플래그이므로 사건이 끝나도 값을 되돌릴 필요가 없음) 정상 종료되는 것도 확인했습니다. 이 환경은 `SLACK_WEBHOOK_URL`이 설정되어 있어 실제 Slack 채널로 에스컬레이션 메시지가 전송됐습니다(콘솔 대체 출력은 발생하지 않음). 테스트용 관리자 계정(`trackc2_verify_tmp`)은 확인 후 삭제했습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- [docs/schema.sql](../schema.sql) — `security_incidents.escalated` 컬럼 추가
- [config.py](../../config.py) — `INCIDENT_ESCALATION_MIN_EVENT_TYPES` 추가
- [correlate.py](../../correlate.py) — `PLAYBOOKS`, `_maybe_escalate()` 추가
- [alert.py](../../alert.py) — `send_incident_escalation_alert()` 신규
- [db/incidents.py](../../db/incidents.py) — `record_incident()`가 최종 사건 상태를 리턴하도록 변경, `mark_incident_escalated()` 신규
- [db/__init__.py](../../db/__init__.py)
- [tests/test_correlate.py](../../tests/test_correlate.py), [tests/test_db.py](../../tests/test_db.py)
