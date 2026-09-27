# 27단계 — SIEM 상관분석 엔진 (Track C 1/4)

[◀ 26단계](guide26_rbac_foundation.md) · [전체 목차](beginner-guide.md) · [28단계 ▶](guide28_soar_playbook.md)

> SKT aleph 교육과정 keyword.md 4과목(이상탐지/SIEM 상관분석)을 반영하는 Track C의 첫 단계입니다. 지금까지 `security_events`는 이벤트 하나하나를 독립적으로만 기록했습니다 — 같은 IP가 짧은 시간 안에 브루트포스도 시도하고, 존재하지 않는 페이지도 스캔하고, 관리자 API도 두드렸다면 신고서 세 장이 각각 따로 쌓일 뿐, "이게 한 출처가 벌인 하나의 사건"이라는 건 아무도 연결해주지 않았습니다. 이번 단계에서 그 흩어진 신고를 "사건철"로 묶는 상관분석 엔진(`correlate.py`, `security_incidents`)을 추가했습니다.

## 왜 필요한가

`security_events`는 파출소에 접수되는 낱장 신고서와 같습니다. 신고서 한 장 한 장은 잘 쌓이지만 서로 연결 짓는 사람이 없습니다. 실제 공격은 종종 "정찰(웹 스캐닝) → 공격(브루트포스)"처럼 여러 단계를 거치는데, 지금 구조로는 관리자가 대시보드에서 그 흐름을 알아채려면 여러 신고를 수동으로 대조해봐야 했습니다.

다만 **모든 이벤트를 다 묶는 것은 아닙니다.** 같은 IP가 로그인 실패만 반복하다 잠긴 단발성 사건은 지금처럼 `security_events` 한 줄로 끝납니다. "같은 IP가 짧은 시간 안에 서로 다른 유형의 신고를 2개 이상 냈을 때"만 골라서 사건으로 묶습니다.

## 1. 새 표 — `security_incidents`

[docs/schema.sql](../schema.sql)에 추가했습니다.

```sql
create table security_incidents (
  id bigint generated always as identity primary key,
  ip_address text not null,
  event_types text[] not null,
  severity_max text not null check (severity_max in ('MEDIUM', 'HIGH', 'CRITICAL')),
  status text not null check (status in ('OPEN', 'CLOSED')) default 'OPEN',
  first_event_at timestamptz not null,
  last_event_at timestamptz not null
);
create unique index idx_security_incidents_open_ip
  on security_incidents (ip_address)
  where status = 'OPEN';
```

같은 IP는 OPEN 상태 사건이 항상 최대 1건만 존재하도록 이 유니크 인덱스가 강제합니다 — `idx_security_events_high_open_incident`(guide22/23)와 같은 이유(확인과 삽입 사이의 짧은 틈에 동시 요청이 겹치는 경쟁 조건 방지)입니다.

## 2. `correlate.py` — "형사" 역할

`detector.py`/`soar.py`와 같은 판단·실행 분리 원칙을 그대로 따릅니다. `correlate.py`는 "사건으로 묶어야 하는가?"만 판단하고, 실제 조회·삽입·병합은 [db/incidents.py](../../db/incidents.py)가 맡습니다.

```python
# correlate.py
def check_and_correlate(ip: str, event_type: str, severity: str) -> None:
    distinct_types = db.get_recent_distinct_event_types(
        ip, config.INCIDENT_CORRELATION_WINDOW_MINUTES
    )
    if len(distinct_types) < 2:
        return
    db.record_incident(ip, distinct_types, severity)
```

시간 창은 `config.INCIDENT_CORRELATION_WINDOW_MINUTES`(기본 5분)로 개별 임계값 판정에 쓰는 `DETECTION_WINDOW_SECONDS`(60초)보다 훨씬 넉넉하게 잡았습니다 — 개별 임계값은 "지금 이 순간의 폭주"를 잡는 것이지만, 상관분석은 여러 단계에 걸친 공격 흐름을 잡아야 해서 더 넓은 시간대를 봐야 하기 때문입니다.

`db/incidents.py`의 `record_incident()`는 이미 열린 사건이 있으면 `event_types`(합집합)와 `severity_max`(더 높은 등급)를 병합해서 갱신하고, 없으면 새로 엽니다. 확인과 삽입 사이의 경쟁 조건은 `insert_security_event_or_bump()`(guide23)와 동일한 방식으로, 유니크 인덱스 충돌(23505)을 붙잡아 병합으로 대체하는 안전망을 둡니다.

## 3. `soar.py`에 훅 연결 — `_record_event()`

`soar.py` 안에 `db.insert_security_event()`를 부르는 곳이 7군데 흩어져 있었습니다. 이 호출들을 새 내부 헬퍼 `_record_event()` 하나로 모으고, 그 안에서 `correlate.check_and_correlate()`를 함께 호출하도록 했습니다.

```python
# soar.py
def _record_event(event_type, severity, ip, path, count, action, username=None):
    if username is not None:
        db.insert_security_event(event_type, severity, ip, path, count, action, username=username)
    else:
        db.insert_security_event(event_type, severity, ip, path, count, action)
    correlate.check_and_correlate(ip, event_type, severity)
```

이렇게 한 곳으로 모은 이유: 상관분석 훅을 매번 손으로 챙겨 부르게 하면, 나중에 새 조치 함수를 추가할 때 훅을 빠뜨리기 쉽습니다. `record_rejection()`(HIGH, `insert_security_event_or_bump` 사용)만 시그니처가 달라 `_record_event()`를 거치지 않고 별도로 `correlate.check_and_correlate()`를 부릅니다.

사건이 끝나는 시점도 짝을 맞췄습니다 — IP 잠금이 풀릴 때(`try_release_expired_lockouts`, `manual_release`) `resolve_security_events_for_ip()`와 나란히 `db.close_open_incident_for_ip()`를 불러 열린 사건도 함께 닫습니다. (계정 단위 잠금 `try_release_expired_account_lockouts`은 사건이 IP 단위로만 키를 갖기 때문에 이번 단계에서는 연결하지 않았습니다 — 알려진 범위 제한입니다.)

## 4. 관리자 대시보드 — "연관 사건" 표

`security_incidents`를 만드는 것만으로는 관리자가 직접 확인할 방법이 없었습니다. `GET /api/status`(대시보드가 2~3초마다 폴링하는 API)에 `list_security_incidents()` 조회를 하나 더 추가해서(기존 8개 쿼리와 같은 `ThreadPoolExecutor` 배치에 병렬로), "보안 이벤트" 표 바로 아래 새 "연관 사건" 표를 그립니다.

```python
# routes/admin.py — api_status()
security_incidents_future = executor.submit(
    db.list_security_incidents, security_incidents_page, config.ADMIN_PAGE_SIZE
)
```

읽기 전용 표입니다 — "보안 이벤트" 표와 달리 "처리 완료" 버튼이 없습니다. 사건은 IP 잠금이 풀리는 순간 `close_open_incident_for_ip()`가 자동으로 "종료"(CLOSED) 처리하므로, 관리자가 수동으로 닫을 일이 없기 때문입니다. 표에는 시작/마지막 활동 시각, 최고 위험등급, 묶인 event_type 목록(쉼표로 구분), IP, 상태(진행 중/종료)를 보여줍니다.

## 5. Track B와의 관계

Track B(RBAC, guide26)는 guide26에서 1/3 단계(기본 구조)까지만 완료된 상태입니다. 이번 Track C는 Track B의 나머지 단계(예외승인/감사추적)를 기다리지 않고 독립적으로 진행했습니다 — `security_incidents`는 `admin_users`/`roles`/`permissions`와 아무 의존 관계가 없습니다.

## 6. 라이브 검증에서 발견한 문제 — `scripts/unlock_ip.py`가 사건을 안 닫던 버그

`soar.manual_release()`(대시보드 "즉시 해제" 버튼)에는 `close_open_incident_for_ip()`를 연결했지만, 터미널 전용 스크립트 [scripts/unlock_ip.py](../../scripts/unlock_ip.py)는 `soar.py`를 거치지 않고 `db.release_lockout()`/`db.resolve_security_events_for_ip()`를 직접 부르는 별도 구현이라, 이 훅이 빠져 있었습니다. 그대로 뒀다면 이 스크립트로 IP를 풀 때마다 사건이 영원히 "진행 중"으로 남는 조용한 버그가 됐을 것입니다. 실제로 로컬 서버 + 시뮬레이션 스크립트로 라이브 검증을 하던 중 이 경로를 직접 타면서 발견해서, `close_open_incident_for_ip()` 호출을 추가하고 `tests/test_unlock_ip.py`에 검증을 더했습니다.

## 실제로 확인한 것

`pytest tests/` 전체 268개 통과(guide26 시점 253개 + 이번 추가 15개: `db/incidents.py` 관련 10개, `correlate.py` 관련 3개, `soar.py` 연동 확인 2개; `scripts/unlock_ip.py` 수정은 기존 테스트에 검증 추가). 기존 `test_soar.py`의 7개 테스트는 새로 추가된 상관분석 훅을 명시적으로 꺼둔 채(no-op으로 monkeypatch) 원래 검증하던 "잠그기 → 알리기 → 이벤트 기록" 순서를 그대로 재확인했고, 훅 자체의 동작(올바른 인자로 불리는지, 서로 다른 유형이 2개 미만이면 아무 것도 안 하는지, 병합/충돌 처리)은 새 테스트에서 별도로 확인했습니다.

로컬 서버(`python app.py`) + 실제 Supabase로도 전체 흐름을 검증했습니다: `scripts/bruteforce_sim.py`(브루트포스, CRITICAL)와 `scripts/web_scanning_sim.py`(웹 스캐닝, MEDIUM)를 같은 IP(127.0.0.1)로 순서대로 실행하자 — 마침 두 스크립트 사이 트래픽으로 전역 HTTP 플러딩 방어(`HTTP_FLOOD`, HIGH)까지 함께 걸려 세 가지 서로 다른 event_type이 겹쳤고 — `security_incidents`에 `event_types: ["BRUTE_FORCE", "HTTP_FLOOD", "WEB_SCANNING"]`, `severity_max: "CRITICAL"`, `status: "OPEN"` 사건이 실제로 생성되어 관리자 대시보드 "연관 사건" 표에 나타나는 것을 확인했습니다. 이후 IP 잠금을 해제하자 같은 사건이 `status: "CLOSED"`("종료")로 자동 전환되는 것도 확인했습니다. 테스트용으로 만든 관리자 계정(`trackc_verify_tmp`)은 확인 후 삭제했습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- [docs/schema.sql](../schema.sql) — `security_incidents` 표 + `idx_security_incidents_open_ip`
- [config.py](../../config.py) — `INCIDENT_CORRELATION_WINDOW_MINUTES` 추가
- [correlate.py](../../correlate.py) — 신규, `check_and_correlate()`
- [db/incidents.py](../../db/incidents.py) — 신규, `get_recent_distinct_event_types()`, `get_open_incident()`, `record_incident()`, `close_open_incident_for_ip()`, `list_security_incidents()`
- [db/__init__.py](../../db/__init__.py)
- [soar.py](../../soar.py) — `_record_event()` 내부 헬퍼 추가, 7개 조치 함수가 이를 경유하도록 변경, 잠금 해제 경로에 `close_open_incident_for_ip()` 연결
- [routes/admin.py](../../routes/admin.py) — `/api/status`에 `security_incidents`/`security_incidents_total_pages` 추가
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html) — "연관 사건" 표 섹션
- [public/js/dashboard/state.js](../../public/js/dashboard/state.js), [api.js](../../public/js/dashboard/api.js), [render.js](../../public/js/dashboard/render.js), [events.js](../../public/js/dashboard/events.js)
- [public/css/dashboard.css](../../public/css/dashboard.css)
- [README.md](../../README.md)
- [scripts/unlock_ip.py](../../scripts/unlock_ip.py) — 라이브 검증 중 발견한 버그 수정, `close_open_incident_for_ip()` 연결
- [tests/test_db.py](../../tests/test_db.py), [tests/test_soar.py](../../tests/test_soar.py), [tests/test_app.py](../../tests/test_app.py), [tests/test_unlock_ip.py](../../tests/test_unlock_ip.py), [tests/test_correlate.py](../../tests/test_correlate.py)(신규)
