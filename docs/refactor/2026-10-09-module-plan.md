# 모듈화 계획 (2026-10-09) — 200줄 이상 파일 분류와 폴더 정리

> 상태: **완료** (0~6단계 모두 적용, 결과는 맨 아래 7절). 이전 작업
> [2026-09-15-file-split.md](2026-09-15-file-split.md)의 원칙을 그대로 이어간다.

## 0. 목표와 원칙

문제는 두 가지다.

1. **루트에 파이썬 파일이 13개** 흩어져 있다(`soar.py`, `alert.py`, `lockdown.py` ...).
   어떤 파일이 "탐지"이고 어떤 파일이 "대응/알림"인지 폴더만 봐서는 알 수 없다.
2. **한 파일에 책임이 여러 개 섞인 큰 파일**이 남아 있다(`routes/admin.py` 798줄,
   `soar.py` 497줄, `helpers.py` 314줄 ...).

그래서 두 종류의 작업을 한다.

- **묶기(group)**: 비슷한 일을 하는 루트 모듈을 폴더 하나로 모은다.
- **쪼개기(split)**: 책임이 여러 개인 큰 파일만 `db/`처럼 "같은 이름의 패키지 +
  `__init__.py` 재내보내기(re-export)"로 나눈다.

`db/` 분리 때 정한 원칙을 그대로 지킨다.

| 원칙 | 이유 |
|---|---|
| 순수 리팩터링 — URL·응답·동작 변경 없음 | 테스트가 그대로 통과해야 함 |
| 쪼갠 패키지는 `__init__.py`가 전부 재내보내기 | 호출부 `soar.enforce_lockout(...)` 그대로 |
| 패키지 내부끼리 부를 땐 **패키지 속성으로** 호출 (`soar.x()`) | `monkeypatch.setattr(soar, "x", ...)`가 계속 먹히도록 |
| `app.py`는 루트에 남긴다 | Vercel이 루트 `app.py`의 `app`을 자동 감지 |
| `tests/`는 쪼개지 않는다 (import 줄만 수정) | 이번 범위 밖, 별도 작업 |
| 200줄 넘어도 **한 가지 일만 하는 파일은 그대로** | 파일 수를 줄이는 게 목적이지 늘리는 게 아님 |

---

## 1. 200줄 이상 파일 분류 (테스트·문서 제외)

판정: **쪼갬** = 책임이 여럿 / **이동** = 폴더로 묶기만 / **유지** = 지금 그대로

### 1-1. 루트 파이썬 모듈

| 파일 | 줄 | 하는 일 | 판정 | 가는 곳 |
|---|---:|---|---|---|
| `soar.py` | 497 | 잠금 집행 + 알림 + 해제 + LLM 조기 경보/승인 | **쪼갬 + 이동** | `security/soar/` |
| `app.py` | 397 | Flask 생성, 에러 핸들러, before_request, blueprint 등록 | 유지 (선택: 훅 분리) | 루트 |
| `alert.py` | 332 | Slack 알림 메시지 함수 모음 (한 가지 일) | 이동 | `notify/alert.py` |
| `helpers.py` | 314 | IP/위치, 봇 판정, 기기 쿠키, 관리자 세션, 데코레이터 | **쪼갬** | `helpers/` |
| `lockdown.py` | 296 | 영구 잠금 승격/해제/복구 | 이동 | `security/lockdown.py` |
| `mailer.py` | 286 | SMTP 발송 + 메일 본문 함수 (한 가지 일) | 이동 | `notify/mailer.py` |
| `config.py` | 249 | 환경변수 상수 | 유지 | 루트 |
| `detector.py` | 248 | 임계값 판정 함수 (한 가지 일) | 이동 | `security/detector.py` |
| `email_verification.py` | 242 | 이메일 인증·변경·비밀번호 재설정 토큰 흐름 | 이동 | `services/email_verification.py` |
| `llm_client.py` | 214 | Groq 호출 + 조기 경보 판정 프롬프트 | 이동 | `services/llm_client.py` |
| *(200줄 미만)* `correlate.py` 86, `geoip.py` 108, `ip_utils.py` 68 | | | 이동 | `security/`, `services/`, `services/` |

### 1-2. `routes/`

| 파일 | 줄 | 판정 | 비고 |
|---|---:|---|---|
| `routes/admin.py` | 798 | **쪼갬** → `routes/admin/` | 로그인 / 대시보드·`/api/status` / 잠금 조치 / 사건 처리 / 관리 기능이 한 파일 |
| `routes/recovery.py` | 389 | 일부 이동 | `run_with_fixed_response_time()` 묶음(~75줄)을 `helpers/`로 — `password.py`가 다른 라우트 파일을 import하는 구조 제거 |
| `routes/auth.py` | 320 | 일부 이동 | `EMAIL_PATTERN`을 `config.py`로 — `member.py`가 `routes.auth`를 import하는 구조 제거 |
| `routes/member.py` | 275 | 유지 | |
| `routes/board.py` | 272 | 유지 | |

### 1-3. `db/` — 이미 모듈화 완료

| 파일 | 줄 | 판정 |
|---|---:|---|
| `db/recovery.py` | 389 | 선택: `recovery.py` + `ip_exemptions.py` (표 2개라 경계가 깔끔) |
| `db/__init__.py` | 358 | 유지 (재내보내기 목록이라 긴 게 정상) |
| `db/security_events.py` | 339 | 선택: `access_logs.py`(not_found/unauthorized/page_access 표) + `security_events.py` |
| `db/lockouts.py` 243, `incidents.py` 226, `users.py` 223, `admin.py` 219, `account_lockouts.py` 204 | | 유지 |

### 1-4. `scripts/`

| 파일 | 줄 | 판정 |
|---|---:|---|
| `password_spraying_sim.py` 511, `spam_sim.py` 475, `repeated_access_sim.py` 361, `signup_abuse_sim.py` 312, `unauthorized_access_sim.py` 255, `bruteforce_sim.py` 205 | | **중복 추출**: `is_local_host`, `fetch_csrf_token`, `CsrfTokenParser`가 최대 6개 파일에 반복 → `scripts/simulation/_sim_common.py` |
| `daily_report.py` 275, `unlock_account.py` 218 | | 유지 |

이 계획을 세울 때는 `scripts/` 안의 파일 **위치를 바꾸지 않기로** 했다 — `docs/beginner-guide/` 20개 이상 문서가
`python scripts/xxx.py` 경로를 안내하고 있었기 때문이다. 이후 `scripts/`를 `simulation/`·`management/`·`demo/`로
나누면서(아래 "후속 작업") 문서의 경로도 함께 고쳤다. 이 문서의 표에 적힌 `scripts/simulation/_sim_common.py` 등은
**지금 위치**로 적은 것이다(계획 당시에는 `scripts/_sim_common.py`).

### 1-5. 프론트엔드

| 파일 | 줄 | 판정 |
|---|---:|---|
| `public/js/dashboard/render.js` | 556 | **쪼갬** — 잠금 카드 / 일반 표 / 보안 이벤트 표 |
| `public/js/dashboard/api.js` | 504 | **쪼갬** — 조회(폴링) / 상태 변경 요청 |
| `public/css/dashboard.css` 469, `member.css` 275, `board.css` 242 | | 유지 (페이지별로 이미 나뉨) |
| `templates/admin_dashboard.html` | 348 | 선택: 섹션별 `{% include %}` 조각 |

---

## 2. 목표 구조

```
login-watchdog/
├─ app.py                     # 유지 (Vercel 진입점)
├─ config.py                  # 유지 (+ EMAIL_PATTERN)
│
├─ security/                  # 보안 엔진: 탐지 → 상관분석 → 대응
│  ├─ __init__.py             # 비워둠 (설명 주석만)
│  ├─ detector.py             # ← detector.py   (판정)
│  ├─ correlate.py            # ← correlate.py  (SIEM 상관분석)
│  ├─ lockdown.py             # ← lockdown.py   (영구 잠금)
│  └─ soar/                   # ← soar.py 497줄 (집행)
│     ├─ __init__.py          # 전부 재내보내기
│     ├─ _events.py           # _record_event
│     ├─ lockouts.py          # enforce_*, try_release_expired_*, manual_release_*  (~230)
│     ├─ observe.py           # notify_*, record_rejection                        (~95)
│     └─ early_warning.py     # consider_early_warning, execute/reject 승인 요청   (~160)
│
├─ notify/                    # 바깥으로 알리는 채널
│  ├─ __init__.py
│  ├─ alert.py                # ← alert.py  (Slack)
│  └─ mailer.py               # ← mailer.py (SMTP)
│
├─ services/                  # 외부 연동·계정 부가 기능
│  ├─ __init__.py
│  ├─ email_verification.py   # ← email_verification.py
│  ├─ llm_client.py           # ← llm_client.py (Groq)
│  ├─ geoip.py                # ← geoip.py (ip-api)
│  └─ ip_utils.py             # ← ip_utils.py
│
├─ helpers/                   # ← helpers.py 314줄 (라우트 공용, 이름 유지)
│  ├─ __init__.py             # 전부 재내보내기 → `from helpers import ...` 그대로
│  ├─ request.py              # get_request_ip, is_bot_submission, HONEYPOT_FIELD_NAME,
│  │                          # mask_username, public_base_url, hash_secret, _attach_locations
│  ├─ device.py               # get_device_hash, new_device_token, set_device_cookie
│  ├─ auth.py                 # 관리자/회원 세션, _load_current_admin, _reject_admin_request,
│  │                          # login_required, require_permission, member_login_required
│  ├─ timing.py               # ← routes/recovery.py의 run_with_fixed_response_time 묶음
│  └─ hooks.py                # ← app.py의 보안 헤더·404·before_request 관찰 훅 (6단계)
│
├─ routes/
│  ├─ admin/                  # ← routes/admin.py 798줄
│  │  ├─ __init__.py          # admin_bp = Blueprint("admin", ...) 생성 후 하위 모듈 import
│  │  ├─ login.py             # /admin/login, /admin/logout                         (~120)
│  │  ├─ status.py            # /admin/dashboard, /api/status 와 보조 함수          (~290)
│  │  ├─ locks.py             # unlock 3종, permanent-locks, ip-exemptions,
│  │  │                       # recovery-requests revoke                           (~200)
│  │  ├─ incidents.py         # access-requests approve/reject, events/incidents resolve (~80)
│  │  └─ manage.py            # users, settings/signup, board 삭제, admin-users     (~110)
│  ├─ auth.py, board.py, email.py, member.py, password.py, recovery.py   # 유지
│
├─ db/                        # 완료 (선택 분할만)
├─ scripts/
│  ├─ _sim_common.py          # 새로: is_local_host, fetch_csrf_token, CsrfTokenParser
│  └─ (나머지 위치 그대로)
└─ public/js/dashboard/
   ├─ render.js               # 재내보내기 전용 (`export * from './render/...'`)
   ├─ render/locks.js         # renderLockoutCards, renderPermanentLocks,
   │                          # renderRecoveryRequests, renderIpExemptions
   ├─ render/tables.js        # attempts, adminLoginLog, users, adminUsers, posts, comments, signupStatus
   ├─ render/security.js      # securityEvents, securityIncidents, accessRequests
   ├─ api.js                  # SECTIONS, fetchSection, fetchStatus, goToPage (조회)
   └─ actions.js              # sendAction + unlock/resolve/delete/approve/... 18개 (상태 변경)
```

결과: 루트 `.py` **13개 → 2개** (`app.py`, `config.py`). 가장 큰 실행 파일이
798줄 → 약 290줄.

### 왜 이렇게 묶는가

`security/`는 이 프로젝트의 핵심 흐름(`detector`가 판정 → `correlate`가 묶음 →
`soar`/`lockdown`이 집행)을 한 폴더에 담는다. 가이드 문서의 SIEM/SOAR 설명과
폴더가 1:1로 맞는다. `notify/`는 "밖으로 내보내는 것"(Slack, 메일)만, `services/`는
"밖에서 받아오거나 계정 부가 흐름"(LLM, GeoIP, 이메일 토큰)만 담는다.

**모듈 이름은 바꾸지 않는다** (`soar`, `detector`, `alert` ...). 바뀌는 건 import 줄뿐이다:

```python
# 전
import soar
import alert
# 후
from security import soar
from notify import alert
```

이후 코드의 `soar.enforce_lockout(...)`, 테스트의
`monkeypatch.setattr(soar, "enforce_lockout", ...)`는 같은 모듈 객체를 가리키므로
**한 글자도 안 바뀐다**.

---

## 3. 까다로운 지점 (미리 확인한 것)

1. **import 줄 수정량** — 루트 모듈을 import하는 파일 수:
   `config` 44, `soar` 23, `detector` 16, `lockdown` 13, `helpers` 12, `mailer` 11,
   `alert` 10, `email_verification` 9, `correlate` 6, `ip_utils` 5, `geoip` 4, `llm_client` 3.
   `config`/`helpers`는 이름·위치를 유지하므로 실제 수정은 약 100줄. 기계적 치환이라
   폴더 하나씩(`notify` → `services` → `security`) 옮기고 매번 `pytest`를 돌린다.

2. **soar 내부 상호 호출** — 테스트가 `soar.try_release_expired_lockouts`,
   `soar.record_rejection`, `soar.notify_*`, `soar.manual_release*`, `soar.enforce_*`를
   바꿔치기한다. `soar/` 하위 모듈끼리 이 함수들을 부를 땐 반드시
   `from security import soar` 후 `soar.enforce_lockout(...)`처럼 **패키지 속성으로** 호출한다
   (`db/`와 같은 이유).

3. **alert / mailer 내부 호출** — 테스트가 `alert._send_slack_message`,
   `mailer._send_mail`, `mailer.report_failure`를 바꿔치기한다. 이 둘은 쪼개지 않고 파일째
   옮기므로 문제없다. (나중에 쪼갠다면 2번과 같은 규칙 적용.)

4. **`routes/admin/` 테스트 연결점** — 테스트가 직접 건드리는 내부 이름 3개:
   - `tests/conftest.py:79` `routes.admin._expiry_release_state`
   - `tests/test_dashboard_speed.py:81` `routes.admin._attach_locations`
   - `tests/test_dashboard_speed.py:118` `routes.admin.time`

   셋 다 `status.py`로 가므로 테스트 3줄을 `routes.admin.status`로 바꾼다
   (재내보내기로 우회하면 바꿔치기가 `status.py` 안까지 닿지 않는다).
   Blueprint 이름은 그대로 `"admin"`이라 `url_for("admin.xxx")`, 템플릿,
   `app.py`의 `_PAGE_ACCESS_EXCLUDED_ENDPOINTS`는 **수정 불필요**.

5. **`run_with_fixed_response_time` 이동** — `tests/test_recovery.py`가
   `recovery.run_with_fixed_response_time`를 9번 부른다. `routes/recovery.py`에
   `from helpers import run_with_fixed_response_time`을 남겨두면 그대로 통과.
   이 함수는 `config.RECOVERY_MIN_RESPONSE_SECONDS`를 호출 시점에 읽으므로
   (`routes/recovery.py:100`) 테스트의 값 바꿔치기도 그대로 먹힌다.

6. **순환 import** — 예상 의존 방향:
   `routes → helpers → security.soar → notify, services.llm_client, db`,
   `services.email_verification → helpers, notify.mailer`.
   `helpers`가 `services.email_verification`을 import하지 않는 한 순환 없음.
   `security/__init__.py`, `notify/__init__.py`, `services/__init__.py`는
   **재내보내기 없이 비워둔다** — 폴더 import만으로 전부 로드되는 것을 막기 위해.

7. **scripts 공용 모듈** — `python scripts/x_sim.py`로 실행하면 `scripts/`가
   `sys.path[0]`이라 `from _sim_common import ...`가 되지만,
   `tests/test_password_spraying_sim.py`는 `from scripts import password_spraying_sim`으로
   가져온다. 다른 테스트들처럼 `scripts/`를 `sys.path`에 넣거나 sim 쪽에서 두 경우를 다
   처리해야 한다. 또 6개 파일의 `is_local_host`가 **완전히 같은지 먼저 diff** — 다른 것은
   합치지 않는다(`password_spraying_sim.py`는 `validate_host`/`is_loopback_address`로 더 엄격함).

8. **JS** — `render.js`를 재내보내기 전용으로 남기면 `api.js`/`events.js`의 import는
   그대로. `api.js` → `actions.js` 분리는 `events.js` import 줄만 바뀐다.
   `formatDateTime`(render.js 내부)은 `utils.js`로 옮긴다.

---

## 4. 작업 순서

작게, 하나씩. **매 단계 끝에 `pytest` 전체 통과 + 커밋.**

| 단계 | 내용 | 위험 | 호출부 변경 |
|---|---|---|---|
| 0 | 오래된 주석 정리: `routes/admin.py:153`("전부 login_required"), `:292`(표 7개), `:305`(쿼리 9개), `:308`(2~3초), `:445`(api_unlock은 실제로 `require_permission`) | 없음 | 없음 |
| 1 | `routes/admin.py` → `routes/admin/` | 중 | 테스트 3줄 |
| 2 | `helpers.py` → `helpers/` + `timing.py` 이동 + `EMAIL_PATTERN` → `config` | 낮음 | `routes/password.py`, `routes/member.py` import 각 1줄 |
| 3a | `notify/` 만들고 `alert`, `mailer` 이동 | 낮음 | ~21줄 |
| 3b | `services/` 만들고 4개 이동 | 낮음 | ~21줄 |
| 3c | `security/` 만들고 `detector`, `correlate`, `lockdown` 이동 | 중 | ~35줄 |
| 3d | `soar.py` → `security/soar/` 쪼개기 | 중 | ~23줄 |
| 4 | JS `render.js` / `api.js` 분할 | 낮음 | `events.js` 1줄 |
| 5 | `scripts/simulation/_sim_common.py` 추출 | 낮음 | sim 파일들 |
| 6 (선택) | `db/recovery.py`, `db/security_events.py` 분할, `app.py` 훅 분리, 대시보드 템플릿 include | 낮음 | 없음 |

각 단계 후 문서도 같이 고친다: 파일 머리 주석의 경로, `README.md`의 구조 설명,
`docs/architecture-map.html`. 가이드 문서(`docs/beginner-guide/`)는 당시 기록이므로
고치지 않는다.

## 5. 검증

1. 단계마다 `pytest` 전체 통과.
2. `git grep -nE "^\s*import (soar|detector|alert|mailer|lockdown|correlate|llm_client|email_verification|geoip|ip_utils)\b"` 결과가 0줄인지 확인 (옛 import 잔존 여부).
3. 3·4단계 후 개발 서버로 수동 확인: `/login`, `/admin/login` → 대시보드 진입,
   `/api/status` 폴링으로 표가 채워짐, 잠금 해제 버튼, 콘솔에 JS 모듈 404 없음.
4. Vercel 프리뷰 배포 한 번 — 루트 `app.py` 감지와 새 폴더 import가 서버리스에서도 되는지.

---

## 7. 결과 (2026-10-09)

단계마다 `pytest` 전체를 돌렸고, 매번 **693 passed**(작업 전과 같은 수)였다.

| 단계 | 결과 | 테스트 |
|---|---|---|
| 0 | `routes/admin.py` 오래된 주석 5곳 + 같은 종류 3곳(`login_required가 이미…` → `require_permission`) 정리 | 693 passed |
| 1 | `routes/admin/` 5개 파일(login 135 / status 307 / locks 184 / incidents 91 / manage 140줄). 테스트 4곳을 `routes.admin.status`로 변경(3절 4번의 3곳 + 소스 파일 경로를 직접 읽는 `test_all_dashboard_queries_go_out_in_one_wave`) | 693 passed |
| 2 | `helpers/` 4개 파일 + `run_with_fixed_response_time` 이동 + `EMAIL_PATTERN` → `config` — 라우트끼리 import하던 곳 2개 제거 | 693 passed |
| 3a~c | `notify/`, `services/`, `security/`로 이동, import 줄 일괄 변경 | 693 passed |
| 3d | `security/soar/` 4개 파일(lockouts 213 / early_warning 175 / observe 106 / _events 33줄) | 693 passed |
| 4 | `render.js` → `render/` 3개 + 재내보내기, `api.js` → `api.js`(조회 179) + `actions.js`(변경 336). `test_every_action_request_marks_its_button_busy`가 `actions.js`를 읽도록 변경. 브라우저에서 모듈 import와 render 함수 14개 실행 확인 | 693 passed |
| 5 | `scripts/simulation/_sim_common.py` (`is_local_host` 4곳, CSRF 추출기 2곳) | 693 passed |
| 6 | `db/access_logs.py`, `db/ip_exemptions.py` 분리 / `app.py` 훅 → `helpers/hooks.py` (397 → 255줄) / 대시보드 템플릿 → `templates/admin_dashboard/` 조각 3개 | 693 passed |

### 계획과 달라진 점

- `security/soar/notify.py` → **`observe.py`**: 최상위 `notify/` 패키지와 이름이 겹쳐 헷갈려서 바꿨다.
  하는 일("잠그지 않고 관찰만")도 이 이름이 더 정확하다.
- `early_warning.py`가 `record_rejection`/`notify_*`/`enforce_*`를 부르는 곳(승인 실행, `_ALERT_ONLY_DISPATCH`)은
  전부 `soar.xxx()`로 바꿨다 — 3절 2번의 이유. `soar._run_pending_action`은 테스트가 직접 부르므로 재내보내기에 포함했다.
- `fetch_csrf_token`은 `bruteforce_sim`(세션으로 GET)과 `macro_bot_sim`(HTML 문자열 파싱)의 시그니처가 달라 합치지 않았다.
  `signup_abuse_sim`에 있던 `is_local_host`는 쓰이지 않던 코드라 import 없이 지웠다.
- `PAGE_ACCESS_EXCLUDED_ENDPOINTS`: `helpers/hooks.py`로 옮기면서 다른 파일(`app.py`의 Limiter)이 쓰는 공개 값이 되어
  앞의 밑줄을 뗐다. 훅 등록 순서(`csrf_protect → _check_request_limit → track_page_access → track_api_access`,
  after_request `__inject_headers → set_security_headers`)는 옮기기 전과 같음을 확인했다.
- 템플릿 조각은 설명 주석을 파일 **끝**에 `{#- … #}`로 붙였다 — 맨 앞에 두면 공백 제거(`-`)가 첫 줄 들여쓰기까지
  지워서 결과 HTML이 달라졌다. 나누기 전후의 렌더링 결과를 바이트 단위로 비교해 같음을 확인했다.

### 검증 중 발견한 것

- 경로 언급 치환 정규식에서 ``가 한글을 단어 문자로 봐서 `soar.py가` 같은 주석이 안 바뀌었다 —
  ASCII 경계(`(?![A-Za-z0-9_])`)로 바꿔 다시 처리했다.
- `scripts/simulation/high/signup_abuse_sim.py`는 argparse를 쓰지 않아서 `--help`를 줘도 실제로 실행된다(로컬 서버에 가입 요청 3회).
  이번 작업과 무관한 기존 동작이다.
- `tests/test_app.py`의 `geoip`, `tests/test_recovery.py`의 `lockdown` import는 작업 전부터 쓰이지 않던 것이라 그대로 뒀다.

## 후속 작업 — `scripts/` 용도별 폴더 분리 (2026-10-09, 같은 날 이어서)

모듈 분리 뒤에도 `scripts/` 바로 아래에 공격 시뮬레이터와 운영 도구가 섞여 20개 가까이 있어, 용도별 폴더로 나눴다.
파일 내용은 그대로이고 위치와 `sys.path` 계산(한 단계 깊어진 만큼 `parent`를 늘림)만 바꿨다. 배경과 새 시뮬레이터는
[guide49_scripts_reorganization.md](../beginner-guide/guide49_scripts_reorganization.md)에 정리했다.

| 폴더 | 들어 있는 것 |
|---|---|
| `scripts/simulation/` | 공통 부품 `_sim_common.py` + 위험등급별 `critical/`·`high/`·`medium/` 시뮬레이터 |
| `scripts/management/` | `create_admin`, `daily_report`, `delete_security_events`, `send_test_mail`, `tune_thresholds`, `unlock_account`, `unlock_ip` |
| `scripts/demo/` | `demo_server.py`, `check_simulations.py`, `memory_supabase.py` |

- 문서(README, `docs/` 전체, `plan.md`, `research.md`)의 `scripts/xxx.py` 경로를 새 경로로 치환했다.
  치환 뒤 문서 안 상대 링크가 모두 실제 파일을 가리키는지 확인했다.
- 테스트(`test_unlock_ip`, `test_unlock_permanent`, `test_tune_thresholds`, `test_send_test_mail`, `test_password_spraying_sim`,
  `test_admin_account_lockout`)는 새 위치에서 스크립트를 가져오도록 고쳤다.
