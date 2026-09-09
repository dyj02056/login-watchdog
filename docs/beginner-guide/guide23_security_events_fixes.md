# 23단계 — 보안 이벤트 코드 리뷰에서 발견된 4가지 문제 수정

[◀ 22단계](guide22_security_grading.md) · [전체 목차](beginner-guide.md)

> 22단계에서 만든 통합 보안 위험등급 기능이 실제로 안전한지 점검하려고, 프로젝트 전체를 다시 훑어 보완점을 찾는 리뷰를 진행했습니다. 백엔드/보안 담당과 프런트엔드·테스트·문서 담당, 두 관점으로 나눠 조사한 뒤 실제 코드를 열어 하나씩 재확인했고, 그중 우선순위가 높은 4가지를 골라 고쳤습니다. 4번 항목은 고치는 방식이 두 갈래로 갈릴 수 있어 미리 질문으로 방향을 확정한 뒤 구현했습니다.

### 우리가 한 일 (진행 순서)

| # | 문제 | 성격 |
|---|---|---|
| 1 | `scripts/unlock_ip.py`로 풀면 CRITICAL 보안 이벤트가 영원히 "자동 해제 대기"로 남음 | 기존 결함 보완 |
| 2 | CRITICAL 이벤트를 API로 직접 "처리 완료" 처리할 수 있었음(서버 쪽 등급 검증 없음) | 기존 결함 보완 |
| 3 | HIGH 이벤트의 count가 최초 거부 시점 값에 영원히 고정됨 | 설계 개선 |
| 4 | 동시 요청이 겹치면 미해결 이벤트가 중복 생성될 수 있는 경쟁 조건 | 신규 설계(DB 제약) |

---

## 1. `unlock_ip.py`가 잠금만 풀고 보안 이벤트는 방치했다

### 무엇이 문제였는가
관리자 본인 IP가 잠겨서 대시보드 접속 자체가 막혔을 때 쓰라고 만든 뒷문 스크립트 [scripts/unlock_ip.py](../../scripts/unlock_ip.py)가 `db.release_lockout()`만 호출했습니다. 대시보드의 "즉시 해제" 버튼(`soar.manual_release()`)과 자동 만료(`soar.try_release_expired_lockouts()`)는 둘 다 잠금을 풀 때 그 IP의 CRITICAL 보안 이벤트도 함께 "처리 완료"로 표시하는데(22단계에서 만든 `resolve_security_events_for_ip()`), 이 스크립트만 그 절차를 빠뜨리고 있었습니다.

### 왜 위험한가
이 스크립트가 정확히 필요한 상황(브루트포스 시뮬레이션 중 관리자 본인 IP까지 잠겨서 로그인 화면 자체가 막힌 경우)에서 쓰면, 로그인은 다시 되는데 보안 이벤트 표에는 그 사건이 "자동 해제 대기" 상태로 영원히 남습니다. 관리자가 나중에 이 표를 보고 "아직 처리 안 된 사건이 있나?"라고 착각하게 됩니다.

### 어떻게 고쳤는가
`unlock_one()`, `unlock_all()` 두 곳 모두 `db.release_lockout()` 바로 다음 줄에 `db.resolve_security_events_for_ip()`를 추가해서, 대시보드 버튼과 완전히 같은 절차를 밟게 했습니다.

```python
# scripts/unlock_ip.py — unlock_one()
db.release_lockout(ip)
db.resolve_security_events_for_ip(ip)
```

### 실제로 확인한 것
`tests/test_unlock_ip.py`의 관련 테스트 2개에 이 호출 검증을 추가했습니다. 실제로 IP를 잠근 뒤 이 스크립트로 풀어봤더니, 해당 CRITICAL 이벤트가 즉시 "처리 완료"로 바뀌는 것을 로컬 서버와 배포 사이트 양쪽에서 직접 확인했습니다. `pytest tests/ -v` 전체(160개) 통과.

### 이 단계에서 만들어지거나 바뀐 파일
- [scripts/unlock_ip.py](../../scripts/unlock_ip.py)
- [tests/test_unlock_ip.py](../../tests/test_unlock_ip.py)

---

## 2. CRITICAL 이벤트를 API로 직접 "처리 완료" 처리할 수 있었다

### 무엇이 문제였는가
"처리 완료" 버튼을 CRITICAL 행에는 안 보여주는 게 화면(`dashboard.js`)에만 있던 규칙이었습니다. 실제로 그 버튼이 부르는 서버 함수 `db.resolve_security_event()`는 이벤트 id와 미해결 여부만 확인하고, **등급은 전혀 확인하지 않았습니다.**

### 왜 위험한가
로그인된 관리자라면(화면 버튼을 거치지 않고) `/api/security-events/resolve`를 CRITICAL 이벤트 id로 직접 호출해서, IP가 여전히 잠긴 상태인데도 그 이벤트만 "처리 완료"로 표시할 수 있었습니다. "CRITICAL은 잠금이 풀릴 때만 자동으로 처리된다"는 설계 원칙이 화면에서만 지켜지고 서버에서는 강제되지 않는 상태였습니다.

### 어떻게 고쳤는가
`db.resolve_security_event()`의 쿼리 조건에 `.neq("severity", "CRITICAL")`을 추가했습니다.

```python
# db.py — resolve_security_event()
res = (
    get_client()
    .table("security_events")
    .update({"resolved_at": _now_iso()})
    .eq("id", event_id)
    .neq("severity", "CRITICAL")
    .is_("resolved_at", "null")
    .execute()
)
return bool(res.data)
```

CRITICAL 이벤트 id를 넘기면 이 조건에 걸려 아무 행도 바뀌지 않고, 이미 처리된 이벤트를 다시 누른 것과 똑같이 `False`를 돌려줍니다. `app.py`의 라우트는 손댈 필요가 없었습니다 — 실패를 `{"success": false}`로 그대로 전달하는 기존 동작이 이 경우에도 자연스럽게 맞아떨어졌습니다.

### 실제로 확인한 것
`tests/test_db.py`에 "CRITICAL 이벤트는 이 함수로 처리되지 않는다" 검증 테스트를 추가했습니다. 실제로 IP가 아직 잠긴 상태에서 그 CRITICAL 이벤트 id로 API를 직접 호출해봤더니 `{"success": false}` 응답, 미해결 상태 그대로 유지되는 것을 로컬·배포 사이트 양쪽에서 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [db.py](../../db.py) (`resolve_security_event`)
- [tests/test_db.py](../../tests/test_db.py)

---

## 3. HIGH 이벤트의 count가 최초 값에 고정됐다

### 무엇이 문제였는가
가입·게시글·댓글 요청 거부(HIGH 등급)는 거부되는 동안 시도 자체가 로그에 안 남습니다(22단계에서 이미 알고 택한 설계). 그래서 `soar.record_rejection()`이 매번 각 라우트의 제한값(예: `SIGNUP_RATE_LIMIT=5`)을 그대로 기록했는데, 미해결 이벤트가 있으면 아예 새로 기록하지 않다 보니 **이 숫자가 사건이 열려있는 내내 절대 바뀌지 않았습니다.**

### 왜 위험한가
봇이 6번만 찔러보고 멈추든, 60초 창 안에서 계속 재시도해 수천 번을 찔러보든, 대시보드에는 항상 똑같은 숫자(예: `5`)만 찍혔습니다. 관리자가 이 표만 보고는 "사소한 실수"와 "지속적인 공격"을 전혀 구분할 수 없었습니다.

### 어떻게 고쳤는가
미해결 이벤트가 있으면 무시하는 대신, 그 행의 count를 반복될 때마다 1씩 올리도록 바꿨습니다. `db.py`의 `has_unresolved_security_event(ip, event_type) -> bool`을 `get_unresolved_security_event(ip, event_type) -> dict | None`으로 확장해(존재 여부뿐 아니라 id·count도 함께 돌려줌) 같은 쿼리 한 번으로 이어서 쓸 수 있게 하고, `update_security_event_count(event_id, count)`를 새로 추가했습니다.

```python
# soar.py — record_rejection()
existing = db.get_unresolved_security_event(ip, event_type)
if existing:
    db.update_security_event_count(existing["id"], existing["count"] + 1)
    return
db.insert_security_event_or_bump(event_type, "HIGH", ip, path, count, "REJECTED")
```

### 실제로 확인한 것
`tests/test_soar.py`/`tests/test_db.py`에 관련 테스트를 갱신·추가했습니다. 실제로 `/signup`을 여러 차례에 걸쳐 총 13번 추가로 거부시켜봤더니, 새 행이 쌓이는 대신 **같은 행 하나의 count가 5 → 17로 정확히 누적**되는 것을 확인했습니다(5 + 6 + 6 = 17). 대시보드 화면에도 그대로 반영됐습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [db.py](../../db.py) (`get_unresolved_security_event`, `update_security_event_count` 추가)
- [soar.py](../../soar.py) (`record_rejection` 수정)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_soar.py](../../tests/test_soar.py)

---

## 4. 동시 요청이 겹치면 중복 행이 생길 수 있었다 — DB 제약으로 원천 차단

### 무엇이 문제였는가
3번에서 고친 "미해결 이벤트가 있는지 확인 → 없으면 새로 삽입" 로직에는, 확인하는 순간과 실제로 삽입하는 순간 사이에 아주 짧은 틈이 있습니다. 같은 IP에서 거의 동시에 요청 두 개가 이 함수를 통과하면, 둘 다 "미해결 이벤트 없음"을 보고 각자 새로 삽입해버릴 수 있습니다(경쟁 조건). 그러면 3번에서 막으려던 "같은 사건인데 행이 여러 개 쌓이는" 문제가 드물게 재발합니다.

### 어떻게 고쳤는가 — 그리고 무엇을 먼저 결정해야 했는가
코드만으로는 이 틈을 완전히 없앨 수 없어서, **DB 자체에 안전장치를 걸지, 아니면 발생 확률이 낮으니 문서에만 한계로 남길지** 먼저 질문으로 결정했습니다. "가장 확실한 방법(DB 유니크 인덱스)"을 선택했습니다.

`docs/schema.sql`에 부분 유니크 인덱스를 추가했습니다 — 같은 IP·이벤트 유형이면서 아직 미해결이고 **등급이 HIGH인** 행은 항상 최대 1건만 존재하도록 Postgres가 직접 강제합니다.

```sql
create unique index idx_security_events_high_open_incident
  on security_events (ip_address, event_type)
  where resolved_at is null and severity = 'HIGH';
```

CRITICAL/MEDIUM은 조건에서 뺐습니다 — CRITICAL은 같은 IP가 다시 잠기기 전에 이미 이벤트가 정리되고, MEDIUM(Web Scanning 등)은 애초에 "미해결이면 건너뛰기"가 아니라 임계값을 다시 넘길 때마다 새로 기록하는 구조라서, 조건 없이 전체 표에 걸었다면 MEDIUM의 정상적인 재알림이 막힐 뻔했습니다.

삽입이 이 제약에 걸려 실패하면(동시 요청이 실제로 겹친 순간) 새로 만드는 대신 자동으로 count를 올리도록, `db.py`에 `insert_security_event_or_bump()`를 추가했습니다.

```python
# db.py
def insert_security_event_or_bump(event_type, severity, ip, path, count, action):
    try:
        insert_security_event(event_type, severity, ip, path, count, action)
    except APIError as e:
        if e.code != "23505":  # unique_violation이 아니면 그대로 다시 던짐
            raise
        existing = get_unresolved_security_event(ip, event_type)
        if existing:
            update_security_event_count(existing["id"], existing["count"] + 1)
```

### 실제로 확인한 것
`tests/test_db.py`에 충돌 상황을 가짜로 재현하는 테스트(정상 삽입 경로 / `23505` 충돌 시 자동 병합 경로 / 그 외 오류는 그대로 전파)를 추가했습니다. 이걸로 끝내지 않고, **사용자가 Supabase에 인덱스를 실제로 적용한 뒤** 검증 스크립트로 진짜 데이터베이스에 같은 IP·유형으로 두 번째 삽입을 직접 시도해봤습니다 — 진짜 Postgres가 `23505 duplicate key value violates unique constraint "idx_security_events_high_open_incident"` 오류로 거부했고, `insert_security_event_or_bump()`가 그 오류를 받아 새 행 대신 기존 행(같은 id)의 count를 정확히 1 올리는 것까지 실제 데이터베이스로 확인했습니다.

**Supabase 반영 필요**: 위 인덱스 생성 SQL을 Supabase SQL Editor에서 직접 실행해야 합니다. (실행 완료 및 실제 충돌 상황까지 재현해 확인함)

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`idx_security_events_high_open_incident` 부분 유니크 인덱스 추가)
- [db.py](../../db.py) (`insert_security_event_or_bump` 추가)
- [soar.py](../../soar.py) (`record_rejection`이 `insert_security_event_or_bump` 사용하도록 수정)
- [tests/test_db.py](../../tests/test_db.py)

---

## 배포까지 확인한 것

네 가지 수정 모두 `main`과 `seongwon`/`demo-ip-spoof`/`jaeho`/`seunghoon`/`yoojieun` 6개 브랜치에 반영했고(강제 푸시 없이 병합), Vercel이 자동으로 프로덕션에 배포한 뒤 1번·2번 항목을 실제 배포 사이트(`login-watchdog.vercel.app`)에서도 브루트포스 시뮬레이션으로 재현해 로컬과 동일하게 동작하는 것을 확인했습니다.
