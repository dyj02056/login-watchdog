# 29단계 — API 엔드포인트별 매크로/봇 탐지 (Track C 3/4)

[◀ 28단계](guide28_soar_playbook.md) · [전체 목차](beginner-guide.md) · [30단계 ▶](guide30_threshold_tuning.md)

> 21단계(`guide21_anomaly_detection.md`)에서 `attack_response_state.md` 구현 대상 6번(Macro/Bot — 범용 API 반복 제한)을 사용자가 "1~5번부터 갖춰지면 명확해질 것"이라며 보류했었습니다. 그 뒤 L7 공격 보강(Tier 2)으로 전역 rate-limit(`GLOBAL_RATE_LIMIT_PER_MINUTE`)이 생겼지만, 이건 "IP당 전체 요청 횟수"만 보는 단순 볼류메트릭 기준이라 원래 6번이 염두에 뒀던 "API별로 세분화된 패턴 탐지"와는 결이 달랐습니다. 이번 단계에서 그 남은 부분을 구현해서 보류 항목을 해소했습니다.

## 왜 필요한가 — 기존 탐지의 사각지대

실제 코드를 확인해보니 `app.py`의 `track_page_access()`는 두 가지로 범위가 좁습니다:
- **GET 요청만** 본다 (`if request.method != "GET": return`)
- **같은 경로 하나**를 반복 요청하는지만 본다

즉 `/api/*`로 오는 POST 요청(글 삭제, 잠금 해제 등)이나, "여러 API를 옮겨 다니며 두드리는 패턴"은 지금까지 전혀 관찰되지 않았습니다.

## 탐지 기준

**"같은 IP가 `DETECTION_WINDOW_SECONDS`(60초) 안에 서로 다른 `/api/*` 경로를 `MACRO_DISTINCT_API_THRESHOLD`(기본 5)개 초과해서 호출했는가."**

기존 `count_recent_distinct_usernames()`(같은 IP가 시도한 서로 다른 아이디 개수 — Password Spraying 구분용)와 완전히 같은 발상을 "아이디" 대신 "API 경로"에 적용한 것입니다. 사람이 화면을 눌러가며 여러 기능을 쓰면 이 정도 속도로 6가지 넘는 API를 옮겨 다니기 어렵지만, 스크립트는 쉽게 합니다.

## 1. 새 표 — `api_access_log`

```sql
create table api_access_log (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  method text not null,
  requested_at timestamptz not null default now()
);
```

`not_found_attempts`/`unauthorized_attempts`/`page_access_attempts`와 같은 목적의 요청 로그입니다. 다른 표들과 다른 점은 **메서드(GET/POST)도 함께 기록**한다는 것 — API는 대부분 POST(글 삭제, 잠금 해제 등)라서, 메서드를 안 가리는 새 관찰 지점이 필요했습니다.

## 2. 새 훅 — `track_api_access()` (기존 훅과 별도로 둔 이유)

```python
# app.py
@app.before_request
def track_api_access():
    if request.url_rule is None or not request.path.startswith("/api/"):
        return
    if request.endpoint in _PAGE_ACCESS_EXCLUDED_ENDPOINTS:
        return

    ip = get_request_ip()
    db.log_api_access(ip, request.path, request.method)

    suspicious, count, is_first_over_threshold = detector.is_macro_pattern_suspicious(ip)
    if suspicious and is_first_over_threshold:
        soar.notify_macro_pattern(ip, count)
```

`track_page_access()`에 이 로직을 끼워 넣지 않고 별도 훅으로 만들었습니다 — 하나는 "GET, 같은 경로 하나의 반복"을, 다른 하나는 "메서드 무관, 서로 다른 여러 경로에 걸친 패턴"을 봅니다. 서로 다른 종류의 수상함이라 하나로 합치면 조건문이 뒤섞여 읽기 어려워집니다.

대시보드 자동 폴링 API(`admin.api_status`, `board.api_board_comments_latest`)는 `_PAGE_ACCESS_EXCLUDED_ENDPOINTS`를 그대로 재사용해서 제외했습니다 — 이 API들은 경로 하나만 반복 호출하므로 애초에 "서로 다른 경로 개수" 탐지에는 걸리지 않지만, 표를 불필요하게 불리지 않도록 처음부터 기록하지 않습니다.

## 3. 등급은 MEDIUM(관찰) — 그리고 C-1/C-2에 자동 편입

```python
# soar.py
def notify_macro_pattern(ip: str, count: int) -> None:
    alert.send_macro_pattern_alert(ip, count)
    _record_event("API_MACRO_PATTERN", "MEDIUM", ip, None, count, "ALERTED")
```

`WEB_SCANNING`/`UNAUTHORIZED_ACCESS`와 동급인 MEDIUM(관찰)입니다 — API를 여러 개 옮겨 다니는 것 자체는 피해가 확정된 게 아니라 "패턴이 수상하다"는 신호이므로, 곧바로 잠그지 않고 기록·알림까지만 자동화합니다. `_record_event()`를 거치므로 27~28단계에서 만든 **SIEM 상관분석/SOAR 플레이북에 별도 배선 없이 자동으로 편입**됩니다 — 예를 들어 같은 IP가 매크로/봇 패턴과 동시에 브루트포스까지 겹치면, 그것만으로 `security_incidents`에 묶이고 조건을 넘으면 에스컬레이션 알림까지 자동으로 이어집니다.

## 4. 검증 스크립트 — 왜 `security_viewer` 계정으로 테스트하는가

`scripts/macro_bot_sim.py`는 이미 로그인된 관리자 계정으로 서로 다른 관리자 API 6개(잠금 해제, 보안 이벤트 처리, 회원 삭제, 회원가입 설정, 게시글 삭제, 댓글 삭제)를 순서대로 호출합니다. 실제로 뭔가 삭제되면 안 되므로, **아무 권한도 없는 `security_viewer` 역할 계정**으로 호출하도록 설계했습니다 — `require_permission` 데코레이터가 모든 호출을 403으로 거절하지만, `before_request` 훅은 뷰 함수(그리고 그 안의 권한 검사)보다 먼저 실행되므로 403으로 끝나는 요청도 매크로/봇 탐지 로그에는 정상적으로 기록됩니다.

## 5. 라이브 검증에서 발견한 문제 — 콘솔 출력의 em-dash가 Windows에서 죽는다

`scripts/macro_bot_sim.py`를 실제로 Windows 콘솔(cp949 코드페이지)에서 실행하자, 마지막 안내 문구에 넣어둔 em-dash(`—`) 때문에 `UnicodeEncodeError`로 스크립트가 죽었습니다 — 탐지 자체는 이미 정상적으로 끝난 뒤였지만 결과 안내 출력에서 실패했습니다. 기존 스크립트(`bruteforce_sim.py`, `web_scanning_sim.py` 등)를 확인해보니, 이들도 소스 코드 **주석**에는 em-dash를 자유롭게 쓰지만 실제 `print()`로 콘솔에 찍는 문자열에는 한 번도 쓰지 않았습니다 — 이 프로젝트가 이미 암묵적으로 지켜온 규칙이었던 셈입니다. 해당 문구를 일반 괄호/줄바꿈으로 바꿔서 고쳤습니다.

## 실제로 확인한 것

`pytest tests/` 전체 286개 통과(guide28 시점 274개 + 이번 추가 12개 — `test_detector.py` 3개, `test_db.py` 2개, `test_soar.py` 1개, `test_app.py` 6개).

로컬 서버 + 실제 Supabase로 라이브 검증도 했습니다. `api_access_log` 테이블을 실제 DB에 추가한 뒤, `security_viewer`(무권한) 테스트 계정으로 `scripts/macro_bot_sim.py`를 실행해서 서로 다른 관리자 API 6개를 순서대로 호출했습니다. 모든 호출이 403(권한 없음)으로 안전하게 거절되면서도, `api_access_log`에 6건이 기록되고 `security_events`에 `event_type=API_MACRO_PATTERN, severity=MEDIUM, count=6, action=ALERTED` 이벤트가 실제로 생성되는 것을 DB 조회로 확인했습니다. 이 이벤트 하나만으로는 서로 다른 유형이 1개뿐이라 27단계의 SIEM 상관분석(`security_incidents`)이 새로 사건을 열지 않는 것도 함께 확인했습니다 — "2개 이상일 때만 묶는다"는 설계가 실제로도 과민 반응하지 않음을 보여줍니다. 테스트용 계정(`trackc3_verify_tmp`)은 확인 후 삭제했습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- [docs/schema.sql](../schema.sql) — `api_access_log` 표 신규
- [config.py](../../config.py) — `MACRO_DISTINCT_API_THRESHOLD` 추가
- [db/api_access_log.py](../../db/api_access_log.py) — 신규, `log_api_access()`, `count_recent_distinct_api_paths()`
- [db/__init__.py](../../db/__init__.py)
- [detector.py](../../detector.py) — `is_macro_pattern_suspicious()` 추가
- [alert.py](../../alert.py) — `send_macro_pattern_alert()` 신규
- [soar.py](../../soar.py) — `notify_macro_pattern()` 신규
- [app.py](../../app.py) — `track_api_access()` 훅 신규
- [scripts/macro_bot_sim.py](../../scripts/macro_bot_sim.py) — 신규 검증 스크립트
- [tests/conftest.py](../../tests/conftest.py) — `flask_app` 기본 mock에 `log_api_access`/`is_macro_pattern_suspicious` 추가
- [tests/test_detector.py](../../tests/test_detector.py), [tests/test_db.py](../../tests/test_db.py), [tests/test_soar.py](../../tests/test_soar.py), [tests/test_app.py](../../tests/test_app.py)
