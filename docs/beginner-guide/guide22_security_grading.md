# 22단계 — 통합 보안 위험등급 시스템 (`security-risk-response-summary.md` 후속 조치)

[◀ 21단계](guide21_anomaly_detection.md) · [전체 목차](beginner-guide.md) · [23단계 ▶](guide23_security_events_fixes.md)

> 캡스톤 검토 문서 `security-risk-response-summary.md`(프로젝트 저장소 밖에서 관리되는 리뷰 문서)가 지적한 문제 — "대응 로직(잠금/거부/알림)은 이미 다 구현돼 있지만, 이걸 위험등급(CRITICAL/HIGH/MEDIUM/LOW)이라는 공통 값으로 저장·조회·표시하는 기능은 없다" — 를 해결하기 위해 통합 이벤트 표(`security_events`)와 관리자 대시보드 UI를 추가했습니다. 실제 구현에 들어가기 전에 4가지 설계 결정(LOW 저장 여부, MEDIUM 중복 방지 위치, HIGH 이벤트 기록 여부, `resolved_at`을 채우는 기준)을 먼저 질문으로 확정했고, Plan 서브에이전트의 설계 검토에서 실제 버그 1건과 설계 결함 1건을 미리 잡아낸 뒤에 코드를 작성했습니다.

### 우리가 한 일 (진행 순서)

| # | 항목 | 성격 |
|---|---|---|
| 1 | `security_events` 통합 이벤트 표 신설 (MEDIUM/HIGH/CRITICAL만 저장) | 신규 설계 |
| 2 | MEDIUM 알림의 "중복 방지" 판단을 `app.py`에서 `detector.py`로 이동 | 리팩터링 |
| 3 | HIGH(가입·게시글·댓글 거부) 이벤트를 상태 기반 중복 방지와 함께 기록 | 신규 탐지/기록 |
| 4 | CRITICAL(IP 잠금)이 풀릴 때 이벤트를 자동으로 "처리 완료" 처리 | 신규 로직 |
| 5 | 관리자 대시보드에 "보안 이벤트" 표 + 등급 배지 + 처리 완료 버튼 추가 | 화면 |
| 6 | Slack 메시지 첫 줄에 위험등급 표시 | 알림 개선 |

---

## 1. `security_events` 통합 이벤트 표를 신설했다

### 무엇이 문제였는가
`security-risk-response-summary.md` 4절이 정확히 지적한 대로, CRITICAL(잠금)·HIGH(요청 거부)·MEDIUM(관찰 알림) 대응은 이미 다 구현돼 있었지만 이 셋을 "위험등급"이라는 같은 이름의 값으로 묶어서 저장·조회하는 표가 없었습니다. 관리자가 "지금까지 CRITICAL 몇 건, HIGH 몇 건 발생했는지"를 한눈에 보려면 `lockouts`, `not_found_attempts`, `unauthorized_attempts` 등 표 여러 개를 각각 따로 조회해야 했습니다.

### 왜 이렇게 설계했는가
LOW(임계치 미도달) 등급은 이 표에 넣지 않기로 했습니다 — 임계치 미달은 정상 트래픽에서도 계속 발생하는 상태라, 여기에 다 기록하면 표가 순식간에 폭증해서 정작 중요한 CRITICAL/HIGH/MEDIUM 행이 묻히기 때문입니다. LOW의 추세는 지금처럼 `login_attempts`, `not_found_attempts` 같은 기존 개별 표를 조회해서 봅니다.

```sql
-- docs/schema.sql
create table security_events (
  id bigint generated always as identity primary key,
  event_type text not null,
  severity text not null check (severity in ('MEDIUM', 'HIGH', 'CRITICAL')),
  ip_address text not null,
  path text,
  count int not null,
  action text not null,
  detected_at timestamptz not null default now(),
  resolved_at timestamptz
);
```

`db.py`에는 이 표를 다루는 함수 5개를 추가했습니다 — `insert_security_event`(기록), `list_security_events`(페이지네이션 조회, 기존 `list_recent_attempts`와 동일한 패턴), `resolve_security_event`(관리자가 수동으로 처리 완료 표시), `resolve_security_events_for_ip`(잠금 해제 시 자동 처리, 4번 항목 참고), `has_unresolved_security_event`(3번 항목의 중복 방지에 사용).

### 실제로 확인한 것
`tests/test_db.py`에 5개 함수 각각에 대한 단위 테스트를 추가했습니다(가짜 Supabase 클라이언트 `_FakeQuery`에 그동안 없던 `.is_()` 메서드도 함께 추가). `pytest tests/ -v` 전체(155개) 통과를 확인했습니다.

**Supabase 반영 필요**: `docs/schema.sql` 맨 아래 추가된 `security_events` 표 생성 SQL을 Supabase SQL Editor에서 직접 실행해야 합니다. (2026-09-09, 실행 완료 및 실 서버로 동작 확인함)

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`security_events` 표 추가)
- [db.py](../../db.py) (5개 함수 신규 추가)
- [tests/test_db.py](../../tests/test_db.py)

---

## 2. MEDIUM 알림의 "중복 방지" 판단을 `detector.py`로 옮겼다

### 무엇이 문제였는가
Web Scanning/Unauthorized Access/반복 페이지 접근(MEDIUM 등급) 세 곳 모두 "같은 사건으로 Slack 알림이 반복 발송되지 않게" `app.py`가 호출부에서 직접 `count == 임계값 + 1`을 계산해 판단하고 있었습니다. 판정 로직(`detector.py`)과 그 판정에 쓰이는 부가 정보가 서로 다른 파일에 흩어져 있던 셈입니다.

### 어떻게 고쳤는가
`is_web_scanning`/`is_unauthorized_access_suspicious`/`is_page_access_suspicious` 세 함수의 반환값을 `(수상한가, 횟수)` 2-tuple에서 `(수상한가, 횟수, 방금_임계값을_넘겼는가)` 3-tuple로 확장했습니다. 계산 내용 자체는 그대로 옮겨왔을 뿐이라 동작은 바뀌지 않습니다.

```python
# detector.py
def is_web_scanning(ip: str) -> tuple[bool, int, bool]:
    count = db.count_recent_not_found_attempts(ip)
    suspicious = count > WEB_SCANNING_ALERT_THRESHOLD
    is_first_over_threshold = count == WEB_SCANNING_ALERT_THRESHOLD + 1
    return suspicious, count, is_first_over_threshold
```

```python
# app.py — 세 호출부 모두 동일하게 변경
suspicious, count, is_first_over_threshold = detector.is_web_scanning(ip)
if suspicious and is_first_over_threshold:
    soar.notify_web_scanning(ip, count, request.path)
```

CRITICAL(로그인 잠금)의 중복 방지는 `is_locked()` 상태 확인이라는 별도 방식이라 그대로 뒀습니다 — 임계값 카운트가 아니라 "지금 잠긴 상태인가"로 판단하는 구조라, MEDIUM과 같은 방식으로 통합할 이유가 없었습니다.

### 실제로 확인한 것
반환값이 바뀌면서 `tests/conftest.py`의 공용 fixture(`is_page_access_suspicious` 기본 stub)와 `tests/test_app.py`의 기존 16곳, `tests/test_detector.py`의 기존 6개 테스트를 전부 3-tuple에 맞게 고쳐야 했습니다. 이 중 `conftest.py`는 Plan 서브에이전트가 설계 검토 단계에서 미리 잡아준 부분입니다 — 여기를 놓치면 이 fixture를 쓰는 테스트 전체가 깨질 뻔했습니다. 경계값 테스트(정확히 임계값+1일 때만 `True`, 그보다 한참 지난 뒤에는 `False`)도 함수별로 추가했습니다. `pytest tests/ -v` 전체(155개) 통과.

### 이 단계에서 만들어지거나 바뀐 파일
- [detector.py](../../detector.py) (`is_web_scanning`/`is_unauthorized_access_suspicious`/`is_page_access_suspicious` 반환값 확장)
- [app.py](../../app.py) (세 호출부 수정)
- [tests/conftest.py](../../tests/conftest.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py)

---

## 3. HIGH(요청 거부) 이벤트를 상태 기반 중복 방지와 함께 기록했다

### 무엇이 문제였는가
가입·게시글·댓글 빈도 제한에 걸려 요청이 거부될 때(`is_signup_rate_limited` 등), 사용자에게는 안내 문구가 뜨지만 관리자 쪽에는 Slack 알림도 이벤트 기록도 전혀 없었습니다 — 이 등급의 이상행위가 얼마나 자주 발생하는지 관리자가 확인할 방법이 아예 없는 상태였습니다.

### 왜 중복 방지가 필요했는가
처음에는 거부될 때마다 그냥 기록하면 될 것 같았지만, `is_signup_rate_limited` 같은 함수는 차단되는 동안 시도 자체를 로그에 남기지 않아서 횟수(count)가 차단 기간 내내 그대로 고정됩니다 — MEDIUM처럼 "지금이 막 임계값을 넘긴 순간"이라는 신호가 없다는 뜻입니다. 이 사실을 설계 검토 단계에서 Plan 서브에이전트가 지적해줬습니다: 그대로 매 거부마다 기록하면 봇 한 대가 60초 창 안에 계속 요청을 보낼 때마다 새 행이 쌓여서 `security_events`가 HIGH로 도배되고, 정작 중요한 CRITICAL/MEDIUM 행이 묻히게 됩니다 — LOW 등급을 아예 표에서 뺀 것과 똑같은 이유의 문제였습니다.

### 어떻게 고쳤는가
`is_locked()`와 같은 "이미 열린 사건이 있으면 새로 만들지 않는다"는 상태 기반 방식을 재사용했습니다.

```python
# soar.py
def record_rejection(event_type: str, ip: str, path: str, count: int) -> None:
    if db.has_unresolved_security_event(ip, event_type):
        return
    db.insert_security_event(event_type, "HIGH", ip, path, count, "REJECTED")
```

가입·게시글(새 글/수정)·댓글 4개 호출부에서 거부 시 이 함수를 부르도록 했고, `count`에는 정확한 실시간 횟수 대신 각 라우트의 제한값(`config.SIGNUP_RATE_LIMIT` 등)을 넘겼습니다 — 거부됐다는 건 이미 그 값 이상이라는 뜻이라, 탐지 함수의 반환값 형태(순수 `bool`)를 바꾸지 않고도 충분했습니다.

### 실제로 확인한 것
`tests/test_soar.py`에 dedup 동작(미해결 이벤트가 있으면 삽입 안 함 / 없으면 삽입함) 테스트를, `tests/test_app.py`에 4개 호출부 각각이 `soar.record_rejection`을 올바른 값으로 부르는지 테스트를 추가했습니다. 실제 서버를 띄워서도 확인했습니다 — `/signup`에 6회 연속 요청을 보내 6번째에 이벤트 1건이 생기는 것, 처리 완료 후 같은 창 안에서 다시 6회를 보내도 새 이벤트가 딱 1건만 더 생기는 것(나머지 5건은 중복 삽입되지 않음)을 직접 확인했습니다. `pytest tests/ -v` 전체(155개) 통과.

### 이 단계에서 만들어지거나 바뀐 파일
- [soar.py](../../soar.py) (`record_rejection` 신규 추가)
- [app.py](../../app.py) (`signup_submit`/`board_new_submit`/`board_edit_submit`/`board_comment_submit` 4곳)
- [tests/test_soar.py](../../tests/test_soar.py), [tests/test_app.py](../../tests/test_app.py)

---

## 4. CRITICAL 잠금이 풀릴 때 이벤트를 자동으로 "처리 완료" 처리했다

### 무엇이 문제였는가 / 어떻게 결정했는가
`resolved_at`을 언제 채울지가 등급마다 다릅니다. 미리 질문으로 확정한 규칙: CRITICAL(IP 잠금)은 잠금이 풀리는 순간 그 사건도 끝난 것으로 보고 **자동으로** 처리 완료 처리하고, HIGH/MEDIUM은 그런 "자동 해제" 개념이 없으므로 관리자가 대시보드에서 직접 눌러야 처리 완료로 바뀝니다.

### 어떻게 고쳤는가
CRITICAL 잠금은 `soar.try_release_expired_lockouts()`(자동 만료)와 `soar.manual_release()`(관리자의 "즉시 해제" 버튼) 두 경로로 풀리는데, 둘 다 `db.release_lockout(ip)` 직후에 `db.resolve_security_events_for_ip(ip)`를 호출하도록 한 줄씩 추가했습니다.

```python
# soar.py
def manual_release(ip: str) -> bool:
    active_ips = {row["ip_address"] for row in db.list_active_lockouts()}
    if ip not in active_ips:
        return False
    db.release_lockout(ip)
    db.resolve_security_events_for_ip(ip)  # CRITICAL 이벤트도 함께 처리 완료로
    return True
```

HIGH/MEDIUM용으로는 새 API(`POST /api/security-events/resolve`)와 `db.resolve_security_event(event_id)`를 추가해서, 관리자 대시보드의 "처리 완료" 버튼이 이 API를 부릅니다.

### 실제로 확인한 것
`tests/test_soar.py`의 기존 해제 테스트 3개에 `resolve_security_events_for_ip` 호출 검증을 추가했고, `/api/security-events/resolve`에는 `/api/unlock`과 동일한 3가지 테스트(event_id 누락 시 400, 성공 시 처리, CSRF 헤더 없으면 거부)를 추가했습니다. 실 서버 테스트에서 브루트포스 잠금 → "즉시 해제" → 해당 CRITICAL 이벤트가 자동으로 "처리 완료"로 바뀌는 것, 그리고 HIGH 이벤트는 대시보드의 실제 버튼을 직접 클릭해(이벤트 위임 코드 경로까지 포함) 처리 완료로 바뀌는 것 둘 다 확인했습니다. `pytest tests/ -v` 전체(155개) 통과.

### 이 단계에서 만들어지거나 바뀐 파일
- [soar.py](../../soar.py) (`try_release_expired_lockouts`, `manual_release`에 한 줄씩 추가)
- [app.py](../../app.py) (`/api/security-events/resolve` 신규 라우트)
- [tests/test_soar.py](../../tests/test_soar.py), [tests/test_app.py](../../tests/test_app.py)

---

## 5. 관리자 대시보드에 "보안 이벤트" 표를 추가했다

### 무엇이 문제였는가
표는 만들었지만, 관리자가 실제로 이걸 볼 화면이 없으면 아무 의미가 없습니다.

### 어떻게 고쳤는가
기존 5개 표(최근 로그인 시도/회원/게시글/댓글/관리자 로그인 기록)와 완전히 같은 구조(빈 `<tbody>` + `<nav>` 페이지네이션, `/api/status` 폴링, `ThreadPoolExecutor`로 병렬 조회)를 그대로 재사용해 "보안 이벤트" 표를 추가했습니다. `/api/status`가 병렬로 실행하는 쿼리가 7개에서 8개로 늘었습니다.

등급별로 배지 색을 다르게 표시하기 위해 `public/css/tokens.css`에 HIGH용 `--warning`/`--warning-soft` 색상 토큰을 새로 추가했습니다(CRITICAL은 기존 `--danger`, MEDIUM은 기존 `--accent` 재사용). "처리 완료" 버튼은 `resolved_at`이 비어있고 CRITICAL이 아닌 행에만 나타나고, CRITICAL 미해결 행에는 대신 "자동 해제 대기" 문구가 뜹니다(4번 항목 참고).

### 실제로 확인한 것
로컬 서버를 띄워 관리자로 로그인한 뒤, 브루트포스 시뮬레이션(`scripts/bruteforce_sim.py`)과 `/signup` 반복 요청으로 실제 이벤트를 발생시켜 표에 정확한 등급 배지·유형·상태가 뜨는지, "처리 완료" 버튼이 실제로 동작하는지 직접 확인했습니다(3·4번 항목 참고). 서버 로그·브라우저 콘솔에 관련 에러가 없는 것도 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html) ("보안 이벤트" 섹션 추가)
- [public/js/dashboard.js](../../public/js/dashboard.js) (`renderSecurityEventsTable`, `resolveEvent` 등 추가)
- [public/css/tokens.css](../../public/css/tokens.css) (`--warning`/`--warning-soft` 추가)
- [public/css/dashboard.css](../../public/css/dashboard.css) (`.severity-badge`, `.resolve-event-btn` 스타일 추가)
- [app.py](../../app.py) (`/api/status`에 보안 이벤트 목록 추가)

---

## 6. Slack 메시지 첫 줄에 위험등급을 표시했다

### 어떻게 고쳤는가
CRITICAL 알림(`send_lockout_alert`) 첫 줄에 `[CRITICAL]`을, MEDIUM 알림(`send_web_scanning_alert` 등) 첫 줄에 `[MEDIUM]`을 추가했습니다. 관리자 로그인에서 발생한 잠금은 `is_admin` 매개변수를 새로 받아서 "관리자 로그인 무차별 대입"으로 별도 표시하도록 했습니다(일반 Brute Force/Password Spraying과 구분).

```python
# alert.py
message = (
    ":rotating_light: [CRITICAL] 로그인 워치독 알림\n"
    ...
)
```

### 실제로 확인한 것
`alert.py`의 메시지 문자열을 직접 검증하는 기존 테스트는 없었지만(테스트는 `soar.py`가 `alert.py`를 올바른 인자로 부르는지만 확인), `tests/test_soar.py`의 잠금 테스트를 `is_admin` 매개변수까지 포함해 검증하도록 보강했습니다. `pytest tests/ -v` 전체(155개) 통과.

### 이 단계에서 만들어지거나 바뀐 파일
- [alert.py](../../alert.py) (`send_lockout_alert`에 `is_admin` 매개변수 추가, 4개 함수 모두 등급 라벨 추가)
- [soar.py](../../soar.py) (`enforce_lockout`이 `is_admin`을 그대로 전달)
- [app.py](../../app.py) (`admin_login_submit()`에서 `is_admin=True`로 호출)
- [tests/test_soar.py](../../tests/test_soar.py)

---

## 이번 단계에서 범위 밖으로 남겨둔 것

- **Automated Scraping 탐지 로직 자체**: `security-risk-response-summary.md` 6절이 제안한 신규 탐지(IP별 조회 수, 순차적 리소스 ID 접근 패턴 등)는 이번 범위에 포함하지 않았습니다. 이번 작업은 "이미 존재하는 4개 탐지기(Brute Force류/Web Scanning류/Rate-limit류)에 위험등급을 붙이고 통합 조회 기능을 만드는 것"이었고, 새 탐지 자체는 21단계의 5번 항목(Automated Scraping)과 마찬가지로 별도 후속 작업으로 남겨뒀습니다.
- **이벤트별 필터 / IP별 이력 화면**: 관리자 대시보드에 등급별 필터나 IP 클릭 시 이력 조회 같은 기능은 아직 없습니다. 지금은 "보안 이벤트" 표 하나에 최신순으로 전부 나열되고, 페이지네이션으로만 넘겨봅니다.
