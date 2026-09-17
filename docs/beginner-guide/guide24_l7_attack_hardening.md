# 24단계 — L7 공격 유형 점검과 보강 (분산 브루트포스 / 보안 헤더 / 봇 차단 등)

[◀ 23단계](guide23_security_events_fixes.md) · [전체 목차](beginner-guide.md)


> 이 프로젝트가 실제로 막고 있는 공격 유형은 "IP 하나가 짧은 시간에 반복 두드리는" 브루트포스류와 CSRF/XSS 기본 방어뿐이라는 점을 먼저 코드로 확인하고, L7(애플리케이션 계층) 공격 유형 중 아직 적용되지 않은 9가지를 정리했습니다. 그중 코드로 실질적인 대응이 가능한 7가지를 이 프로젝트의 기존 위험등급(CRITICAL/HIGH/MEDIUM/LOW) 순으로 4단계(Tier)에 나눠 구현하고, 매 Tier가 끝날 때마다 로컬 서버로 실제 동작을 확인했습니다. 나머지 2가지(Slowloris, 게시판 스크래핑)는 코드 대응 대상이 아니라고 판단해 README 알려진 제한사항에 문서화만 했습니다.

### 미적용 L7 공격 유형 9가지와 위험등급 분류

| # | 항목 | 분류 | 대응 여부 |
|---|---|---|---|
| 1 | 분산형/저속형 브루트포스 (여러 IP로 나눠서 한 계정만 노림) | CRITICAL | Tier 1에서 대응 |
| 2 | 보안 응답 헤더 미설정 (클릭재킹/CSP 부재) | HIGH | Tier 2에서 대응 |
| 3 | L7 볼류메트릭 플러딩 (일반 GET 페이지 대량 요청) | HIGH | Tier 2에서 대응 |
| 4 | 봇 차단(CAPTCHA/허니팟) 부재 | MEDIUM | Tier 3에서 대응 |
| 5 | 계정 존재 여부 타이밍 사이드채널 | MEDIUM | Tier 3에서 대응 |
| 6 | SSRF (`TRUST_FORWARDED_FOR=true`일 때 조건부) | MEDIUM/LOW | Tier 3에서 대응 |
| 7 | 오픈 리다이렉트 (CSRF 에러 핸들러) | LOW | Tier 4에서 대응 |
| 8 | Slowloris류 느린 요청 공격 | LOW | 스코프 밖 — 문서화만 |
| 9 | IDOR/게시글 순차 스크래핑 | LOW | 설계상 허용 범위 — 문서화만 |

---

## Tier 1 (CRITICAL) — 분산/저속 브루트포스 방어 (계정 기반 잠금)

### 무엇이 문제였는가
기존 잠금은 전부 IP 기준(`db.count_recent_failures(ip)`, `lockouts` 표)이었습니다. 공격자가 IP를 여러 개 돌려가며(봇넷·프록시 로테이션) 같은 계정만 노리면, 각 IP의 실패 횟수는 임계값(5회)을 넘지 않아 탐지 자체가 안 됐습니다.

### 어떻게 고쳤는가
`lockouts`(IP 잠금)와 짝을 이루는 `account_lockouts`(계정 잠금) 표를 새로 추가했습니다. IP와 무관하게 "이 계정이 총 몇 번 실패당했는가"를 세는 `db.count_recent_failures_by_username()`을 새 임계값 `ACCOUNT_FAILURE_THRESHOLD`(기본 8회, IP 임계값 5보다 높게 잡아 정상 사용자를 덜 건드림)와 비교해서, 초과하면 계정 자체를 잠급니다.

```python
# routes/auth.py — login_submit()
if detector.is_locked(ip) or detector.is_account_locked(username):
    # 아이디/비밀번호 확인 자체를 건너뛰고 즉시 거부

...
account_suspicious, account_failure_count = detector.is_account_suspicious(username)
if account_suspicious:
    distinct_ips = detector.count_distinct_ips_by_username(username)
    soar.enforce_account_lockout(username, account_failure_count, distinct_ips, ip)
```

`detector.py`(판사)에 `is_account_suspicious`/`is_account_locked`, `soar.py`(집행관)에 `enforce_account_lockout`/`try_release_expired_account_lockouts`를 기존 IP 잠금 함수와 대칭되게 추가해 이 프로젝트의 "판사/집행관" 아키텍처를 그대로 유지했습니다. CRITICAL 이벤트에도 어느 계정이 잠겼는지 남기기 위해 `security_events`에 nullable `username` 컬럼을 추가했습니다.

### 실제로 확인한 것
`tests/test_detector.py`/`test_soar.py`/`test_db.py`/`test_app.py`에 신규 시나리오 추가(전체 170개 통과). 로컬 서버에서 서로 다른 IP로 나눠 실패시켜 8회를 넘기면 계정이 잠기고, 잠긴 뒤에는 올바른 비밀번호로도 로그인이 거부되는 것을 확인했습니다.

**Supabase 반영 필요**: `account_lockouts` 테이블 생성과 `security_events.username` 컬럼 추가 SQL을 Supabase SQL Editor에서 직접 실행해야 합니다(`docs/schema.sql` 상단에 정리해둠). **사용자가 실행 완료함.**

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`account_lockouts` 테이블, `security_events.username` 컬럼)
- [db/account_lockouts.py](../../db/account_lockouts.py) (신규)
- [db/attempts.py](../../db/attempts.py), [db/security_events.py](../../db/security_events.py)
- [config.py](../../config.py) (`ACCOUNT_FAILURE_THRESHOLD`)
- [detector.py](../../detector.py), [soar.py](../../soar.py), [alert.py](../../alert.py)
- [routes/auth.py](../../routes/auth.py) (`login_submit`)
- [tests/test_detector.py](../../tests/test_detector.py), [tests/test_soar.py](../../tests/test_soar.py), [tests/test_db.py](../../tests/test_db.py), [tests/test_app.py](../../tests/test_app.py)

---

## Tier 2 (HIGH) — 보안 응답 헤더 + 전역 HTTP 플러딩 방어

### 무엇이 문제였는가
방어적 HTTP 응답 헤더(`X-Frame-Options`, `Content-Security-Policy` 등)가 전혀 없어서, 관리자 대시보드를 투명한 `<iframe>`에 몰래 끼워 클릭을 유도하는 클릭재킹에 열려 있었습니다. 또한 로그인/가입/글쓰기 같은 특정 폼에만 빈도 제한이 있었고, 일반 GET 페이지는 아무리 요청이 쏟아져도 다 받아줬습니다.

### 어떻게 고쳤는가
`app.py`에 `@app.after_request` 훅을 추가해 모든 응답에 `X-Frame-Options: DENY`, `Content-Security-Policy`(`frame-ancestors 'none'` 포함), `X-Content-Type-Options: nosniff`, `Referrer-Policy`를 붙였습니다. CSP는 `'unsafe-inline'` 없이 엄격하게(`script-src 'self'`) 설정했는데, 이 때문에 `board_detail.html`에 남아있던 인라인 `onsubmit="confirm(...)"` 두 곳을 `board.js`의 외부 이벤트 리스너로 옮겨야 했습니다.

전역 요청 한도는 `flask-limiter`를 새로 추가해서 구현했습니다. `key_func`으로 기존 `helpers.get_request_ip`를 재사용하고, `default_limits_exempt_when`으로 board.js/dashboard.js의 자동 폴링 엔드포인트(기존 `_PAGE_ACCESS_EXCLUDED_ENDPOINTS` 집합 그대로 재사용)만 제외했습니다.

```python
limiter = Limiter(
    key_func=get_request_ip,
    app=app,
    default_limits=[f"{config.GLOBAL_RATE_LIMIT_PER_MINUTE} per minute"],
    default_limits_exempt_when=lambda: request.endpoint in _PAGE_ACCESS_EXCLUDED_ENDPOINTS,
)
```

### 실제로 확인한 것
`curl -I`로 4개 보안 헤더가 모든 응답에 붙는 것을 확인. 브라우저로 회원가입 → 로그인 → 게시판 글쓰기 → 삭제(외부 JS 확인창)까지 직접 조작해 CSP 위반 콘솔 에러가 없는 것을 확인. `/login`에 연속 130회 요청을 보내 **정확히 121번째부터 429**가 시작되는 것(임계값 120/분과 일치), 관리자 대시보드에 `HIGH · HTTP_FLOOD` 이벤트가 기록되는 것을 확인.

### 이 단계에서 만들어지거나 바뀐 파일
- [config.py](../../config.py) (`GLOBAL_RATE_LIMIT_PER_MINUTE`)
- [requirements.txt](../../requirements.txt) (`flask-limiter`)
- [app.py](../../app.py) (`Limiter`, `RateLimitExceeded` 핸들러, `set_security_headers`)
- [templates/board_detail.html](../../templates/board_detail.html), [public/js/board.js](../../public/js/board.js)

---

## Tier 3 (MEDIUM) — 타이밍 사이드채널 제거 / 봇 차단(허니팟) / SSRF 입력 검증

### 3-1. 로그인 타이밍 사이드채널
`verify_user_credentials`/`verify_admin_credentials` 둘 다 아이디가 없으면 `check_password_hash()`를 건너뛰고 즉시 `False`를 반환했습니다. 이 해시 비교는 일부러 느린 연산이라, "즉시 반환"과 "해시 비교 후 반환" 사이의 응답 시간 차이로 계정 존재 여부를 추측할 수 있었습니다. 미리 만들어둔 더미 해시로 아이디가 없을 때도 항상 같은 비교를 거치도록 고쳤습니다.

### 3-2. 봇 차단 — 허니팟
reCAPTCHA 같은 외부 서비스는 API 키가 필요해 데모 프로젝트 성격과 안 맞아서, 무료·의존성 없는 허니팟 필드 방식을 택했습니다. 로그인/가입/관리자 로그인/글쓰기·수정/댓글 폼에 CSS(`.hp-field`)로 화면에서 숨긴 `website` 입력칸을 심어두고, 이 칸이 채워져 있으면 자동화 스크립트로 간주해 즉시 거부하고 `MEDIUM · BOT_DETECTED` 이벤트만 기록합니다(Slack 알림 없음).

### 3-3. SSRF 입력 검증
`geoip.py`가 `ip` 값을 검증 없이 외부 API 주소(`_API_URL.format(ip=ip)`)에 그대로 꽂았습니다. `TRUST_FORWARDED_FOR=true`(데모 전용 설정)일 때는 이 값이 클라이언트가 보낸 `X-Forwarded-For` 헤더에서 그대로 오므로, `helpers.get_request_ip()`와 `geoip._fetch_location()` 두 곳 모두에 `ipaddress.ip_address()` 형식 검증을 추가했습니다.

### 실제로 확인한 것
- 허니팟 필드를 채워 회원가입 시도 → 계정 미생성, `MEDIUM · BOT_DETECTED` 이벤트 기록 확인. 정상 가입(필드 비움)은 그대로 동작.
- `check_password_hash`가 아이디 없음 케이스에도 실제로 호출되는지 스파이 테스트로 확인.
- `TRUST_FORWARDED_FOR=true` 환경에서 조작된 `X-Forwarded-For`(`http://169.254.169.254/...`)로 로그인 시도 → 크래시 없이 처리되고, 저장된 IP가 조작값이 아닌 실제 접속 IP로 대체됨을 확인. 반면 정상 형식의 스푸핑 IP(데모 기능)는 여전히 정상 반영되어, 검증 추가가 기존 데모 기능을 깨지 않았음을 확인.

### 이 단계에서 만들어지거나 바뀐 파일
- [db/users.py](../../db/users.py), [db/admin.py](../../db/admin.py) (`_DUMMY_PASSWORD_HASH`)
- [helpers.py](../../helpers.py) (`is_bot_submission`, `get_request_ip` SSRF 검증)
- [geoip.py](../../geoip.py)
- [soar.py](../../soar.py) (`notify_bot_detected`)
- [public/css/tokens.css](../../public/css/tokens.css) (`.hp-field`)
- [templates/login_form.html](../../templates/login_form.html), [signup.html](../../templates/signup.html), [board_form.html](../../templates/board_form.html), [board_detail.html](../../templates/board_detail.html)
- [routes/auth.py](../../routes/auth.py), [routes/admin.py](../../routes/admin.py), [routes/board.py](../../routes/board.py)
- [tests/test_helpers.py](../../tests/test_helpers.py) (신규), [tests/test_db.py](../../tests/test_db.py), [tests/test_geoip.py](../../tests/test_geoip.py), [tests/test_app.py](../../tests/test_app.py)

---

## Tier 4 (LOW) — 오픈 리다이렉트 수정 + 문서화

### 무엇이 문제였는가
CSRF 에러 핸들러(`app.py`)가 `request.referrer` 값을 검증 없이 그대로 `redirect()`에 넘겼습니다. Referer는 브라우저가 설정하는 값이라 완전히 자유로운 오픈 리다이렉트는 아니지만, 공격자 사이트에서 이 핸들러로 링크를 걸면 이론상 그 값을 신뢰하는 경로가 있었습니다.

### 어떻게 고쳤는가
`urlparse(referrer).netloc`이 `request.host`와 같을 때만 그 값을 쓰고, 다르거나 없으면 로그인 화면으로 폴백합니다.

```python
referrer = request.referrer
if referrer and urlparse(referrer).netloc == request.host:
    return redirect(referrer), 400
return redirect(url_for("auth.login")), 400
```

### 실제로 확인한 것
`tests/test_app.py`에 세 가지 경우(같은 출처 유지, 다른 출처 차단, Referer 없음) 테스트 추가. 로컬 서버에 `curl`로 Referer 헤더를 각각 조작해서 보내 `Location` 헤더가 의도한 대로 나오는 것을 실제로 확인.

### 문서화만 한 항목
- **Slowloris류 느린 요청 공격** — Flask 앱이 아니라 인프라(리버스 프록시/WAF) 레벨에서 막아야 할 유형이라 애초에 이 프로젝트 스코프 밖입니다.
- **게시판 IDOR/스크래핑** — 게시판은 "회원 전체 공개" 설계이므로, 로그인한 회원이 글 id를 순차 조회하는 것 자체는 정책 위반이 아닙니다(의도된 설계).

두 항목 모두 README "알려진 제한사항"에 반영했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [app.py](../../app.py) (`handle_csrf_error`)
- [tests/test_app.py](../../tests/test_app.py)
- [README.md](../../README.md)

---

## 전체 검증 결과

4개 Tier를 통틀어 `pytest tests/ -v` 전체 187개 테스트 통과. 각 Tier가 끝날 때마다 로컬 서버(`python app.py`)를 직접 띄워 브라우저·`curl`로 실제 동작을 확인한 뒤 다음 Tier로 넘어갔습니다. 테스트로 만든 계정/게시글은 실제 Supabase에 남기지 않도록 매번 정리했습니다.
