# 로그인 워치독 — 상세 구현 계획 (plan.md)

> 작성일: 2026-09-02
> 근거 문서: `login_watchdog_supabase.md`(기획서), `login_watchdog_briefing_supabase.html`(브리핑), `research.md`(분석)
>
> **주의: 이 문서는 계획입니다. 코드는 아직 한 줄도 작성하지 않습니다.**
> `research.md`가 지적한 8개 모호점 중 구현 순서에 영향을 주는 항목들은 아래에서 **기본안(제안)**으로 확정해 두었습니다. 각 결정에는 "확정 필요" 표시를 남겼으니, 실제 코딩 착수 전 팀 합의로 뒤집을 수 있습니다.
>
> **변경 사항(2026-09-02, 1차)**: 원 기획서·브리핑 문서는 알림 채널로 텔레그램 봇을 명시하지만, 팀 결정에 따라 **Slack(Incoming Webhook)** 으로 대체합니다.
>
> **변경 사항(2026-09-02, 2차)**: 관리자 인증 방식을 `ADMIN_TOKEN` 공유 비밀값에서 **관리자 계정 + 세션 로그인**으로 전환합니다. 관리자는 감시 대상(`/login`)이 아닌 별도 경로 `/admin/login`으로만 인증하므로, IP 잠금 로직이 관리자에게는 애초에 적용되지 않습니다(허용목록 대신 라우트 분리로 해결). Slack 웹훅 워크스페이스/채널 선정은 계속 보류 상태로 둡니다.

---

## 0. 현 목표

15일 일정 중 **4~8일차 핵심 기능**(기획서 4장의 4-1·4-2·4-3, 즉 오프라인 실행 프로그램 + Slack 알림 + 웹 대시보드)을 실제로 구현 가능한 수준까지 파일 단위로 설계한다. 9~12일차 스트레치 기능(공격 시뮬레이션 자동화, AI 로그 요약, `docs/` 시각자료)은 이번 계획의 범위 밖이며 7장 "제외할 범위"에 명시한다.

핵심 성공 기준(기획서 9장 체크포인트를 Slack 알림 + 관리자 인증 기준으로 갱신):
- 일부러 5번 틀리게 로그인 → 화면 잠금 표시 + Slack 알림이 동시에 확인된다.
- 관리자 계정으로 `/admin/login`에 로그인하면 그 기록이 대시보드에 남고, 로그인하지 않은 상태에서는 대시보드와 해제 API에 접근할 수 없다.

---

## 1. 이번 계획에서 새로 확정하는 설계 결정 (research.md 질문 대응)

`research.md` 6장의 모호점 중, 스키마·라우트 설계에 영향을 주는 항목만 먼저 결정한다. 나머지(잠금 응답 형식 등)도 함께 정리한다.

| # | research.md 질문 | 채택안 | 확정 필요 여부 |
|---|---|---|---|
| 1 | 잠금 상태 영속화 | `lockouts` 테이블 신규 추가(2-2절) | **확정** — 팀 합의 완료 |
| 2 | 계정 잠금 vs IP 잠금 | **IP 잠금**으로 통일(README에 "IP 기준"이라고 명시). 단, 관리자는 `/login`이 아닌 별도 `/admin/login` 경로로만 인증하므로 감시 대상 IP 잠금 로직이 관리자에게는 적용되지 않음 — 별도 IP 허용목록을 두지 않고 라우트 분리로 해결 | **확정** — 팀 합의 완료 |
| 3 | 관리자 인증 수준 | `ADMIN_TOKEN` 공유 비밀값 방식을 폐기하고, `admin_users` 테이블 + Flask 세션 로그인(`/admin/login`)으로 전환. 로그인 성공/실패를 `admin_login_log`에 기록해 대시보드에 노출. 수동 해제(`/api/unlock`)는 세션에 로그인된 관리자만 호출 가능 | **확정** — 팀 합의 완료 |
| 4 | 알림 채널 연동 방식(원안: 텔레그램) | **Slack Incoming Webhook**으로 대체, `requests.post(webhook_url, json=...)` 한 줄 호출(이유: 2절 기술 스택 참고) | **보류** — 어느 Slack 워크스페이스·채널에 웹훅을 걸지는 추후 결정. `alert.py` 인터페이스는 먼저 구현하고, `SLACK_WEBHOOK_URL`이 비어 있으면 콘솔 로그로 대체(구현 시 판단) |
| 5 | 잠금 응답 형식 | `/login`은 서버 렌더 HTML(플래시 메시지 "잠긴 계정입니다" 문구 포함)로 응답 — 브라우저와 `bruteforce_sim.py`의 텍스트 매칭 둘 다 만족 | 제안 |
| 6 | `/api/status` 스펙 | 3-4절에서 JSON 스키마 확정 | 제안, D 담당과 합의 필요 |
| 7 | IP 판별(로컬 환경 전원 127.0.0.1) | 데모 전용 플래그(`TRUST_FORWARDED_FOR=true`)일 때만 `X-Forwarded-For` 헤더를 신뢰해 시뮬레이터가 가짜 IP를 주입하게 허용 | 확정 필요 — 프로덕션 안전 원칙과 충돌하므로 데모 전용임을 코드 주석/README에 명시 |
| 8 | `daily_report.py` 스펙 | 이번 계획 범위에서 제외(7장) | - |

---

## 2. 기술 스택 선택과 이유

기획서 6장에서 이미 스택이 정해져 있으므로 재검토가 아니라 **각 선택지의 채택 이유**만 정리한다.

| 영역 | 채택 | 이유 |
|---|---|---|
| 백엔드 | Flask (Blueprint 없이 단일 `app.py`) | 팀 규모(4인, 비전공자)와 기능 수(라우트 6~7개)를 고려하면 Blueprint로 모듈을 쪼갤 필요가 없음. 파일이 커지면 그때 분리 |
| DB | Supabase(PostgreSQL) | 기획서 확정 사항 — 팀원 4명이 로컬에서 개발해도 동일 로그를 실시간 공유해야 하므로 로컬 SQLite 대비 필수 |
| DB 클라이언트 | `supabase-py` (동기 클라이언트) | Flask가 동기 프레임워크이므로 비동기 클라이언트 도입 시 얻는 이득이 없고 복잡도만 증가 |
| 알림 | Slack Incoming Webhook + `requests` 직접 POST | 원 기획서는 텔레그램 봇 API를 명시했으나 팀 결정으로 Slack으로 대체. Incoming Webhook은 채널당 고정 URL 하나에 `{"text": "..."}` JSON을 POST하면 끝나는 가장 단순한 방식. 워크스페이스/채널 선정은 1절 결정 #4에 따라 보류 중이지만, 인터페이스가 단순해 나중에 URL만 채우면 바로 동작함 |
| 관리자 인증 | Flask 세션(`session`) + `werkzeug.security`(`generate_password_hash`/`check_password_hash`) | Flask 설치 시 이미 포함된 표준 의존성이라 별도 패키지 없이 비밀번호 해시 저장과 서명된 세션 쿠키(`SECRET_KEY`)를 바로 쓸 수 있음. `ADMIN_TOKEN` 공유 비밀값보다 "누가 언제 로그인했는지" 감사 로그를 남길 수 있어 1절 결정 #3과 부합 |
| 프런트엔드 | Jinja2 템플릿 + 바닐라 JS(`fetch`, `setInterval`) | 기획서 확정 사항. React 등 SPA 프레임워크 도입은 팀 학습 곡선 대비 이득이 없음 |
| 잠금 상태 저장 | 신규 테이블 `lockouts` (PostgreSQL) | `login_attempts`는 append-only 로그 테이블이라 "현재 상태"(잠김/해제, 해제 예정 시각)를 표현하기에 부적합. 상태와 로그를 분리하는 것이 표준적인 설계이며, 해제 시 단순히 이 테이블의 행을 삭제/업데이트하면 되므로 로직이 단순해짐 |
| 상수 관리 | 신규 파일 `config.py` | research.md 5-1절이 지적한 "임계값 5, 윈도우 60초, 해제시간 300초가 3개 파일에 흩어질 위험"을 없애기 위해 단일 상수 모듈 도입 |
| 테스트 | `pytest` | Python 표준에 가까운 선택지, 팀이 이미 Python 스택이므로 추가 학습 비용 없음 |

---

## 3. 변경할 파일 경로 및 파일별 수정 내용

저장소가 비어 있으므로 전부 **신규 생성**이다. 생성 순서(의존성 기준)대로 나열한다.

### 3-1. `config.py` (신규 — 기획서에 없던 파일, 이유는 2절 참고)

**변경 이유**: 임계값(5회), 탐지 윈도우(60초), 잠금 지속시간(5분)을 한 곳에서 관리해 `detector.py`/`soar.py`/`app.py`가 서로 다른 값을 하드코딩하는 사고를 방지.

**내용**:
```python
FAILURE_THRESHOLD = 5
DETECTION_WINDOW_SECONDS = 60
LOCKOUT_DURATION_SECONDS = 300  # 5분
TRUST_FORWARDED_FOR = False  # 데모 시연 시 .env로 override
```
- `.env`로 override 가능하도록 `os.environ.get(...)` 패턴 사용 검토(확정 필요 없음, 구현 시 판단).

### 3-2. `.env.example`, `.gitignore`

**변경 이유**: 기획서 8장 규칙 그대로. Supabase 키 유출 방지가 최우선. 관리자 세션 서명키·부트스트랩 계정 정보도 동일하게 보호.

**내용**:
- `.env.example`: `SUPABASE_URL`, `SUPABASE_KEY`, `SLACK_WEBHOOK_URL`, `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `TRUST_FORWARDED_FOR` 키 이름만(값 없이) 기재
- `.gitignore`: `.env`, `__pycache__/`, `*.pyc`, `.pytest_cache/`

### 3-3. Supabase 스키마 (SQL, 마이그레이션 문서로 관리 — 실행 파일 아님)

**변경 이유**: research.md 5-2절 "가장 심각한 위험"인 잠금 상태 미표현 문제 해결, 1절 결정 #3에 따른 관리자 계정/로그인 감사 로그 추가.

**내용** (`docs/schema.sql` 또는 README에 SQL 블록으로 기록, 실제로는 Supabase SQL 편집기에서 1회 실행):
```sql
create table login_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  username text not null,
  success boolean not null,
  attempted_at timestamptz not null default now()
);
create index idx_login_attempts_ip_time on login_attempts (ip_address, attempted_at);

create table lockouts (
  ip_address text primary key,
  locked_at timestamptz not null default now(),
  unlock_at timestamptz not null,
  failure_count int not null,
  active boolean not null default true
);

create table admin_users (
  id bigint generated always as identity primary key,
  username text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table admin_login_log (
  id bigint generated always as identity primary key,
  username text not null,
  success boolean not null,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);
```
- `login_attempts`에 인덱스 추가: research.md 5-4절이 지적한 성능 위험(인덱스 없음) 해결.
- `lockouts.active`: 수동 해제 시 삭제 대신 `active=false`로 갱신하면 "해제 이력"도 남길 수 있음(감사 로그 목적) — 단순화가 필요하면 삭제 방식으로 바꿔도 무방(확정 필요 없음, 구현 시 팀 판단).
- `admin_users`: 이번 계획에서는 회원가입 화면 없이 앱 최초 기동 시 자동으로 1개 계정만 시드(3-4절 `ensure_bootstrap_admin()` 참고). 여러 관리자를 두는 기능은 7절에서 범위 밖으로 명시.
- `admin_login_log`: 관리자 로그인 성공/실패를 모두 기록해 대시보드에 노출(0절 성공 기준 반영).

### 3-4. `db.py`

**변경 이유**: Supabase 연동을 단일 진입점으로 강제(research.md 5-1절 중복 구현 위험 대응).

**필요한 함수**:
- `get_client() -> Client`: 환경변수 검증 후 Supabase 클라이언트 반환(모듈 전역 싱글턴)
- `log_attempt(ip: str, username: str, success: bool) -> None`: `login_attempts` insert (기획서 6장 예시 코드 그대로)
- `count_recent_failures(ip: str, window_seconds: int = DETECTION_WINDOW_SECONDS) -> int`: 기획서 6장 예시 코드 그대로
- `create_lockout(ip: str, failure_count: int, duration_seconds: int = LOCKOUT_DURATION_SECONDS) -> None`: `lockouts`에 upsert
- `get_active_lockout(ip: str) -> dict | None`: `unlock_at > now()` 이고 `active=true`인 행 조회
- `release_lockout(ip: str) -> None`: `active=false`로 갱신(수동 해제·자동 만료 공용)
- `list_recent_attempts(limit: int = 50) -> list[dict]`: 대시보드용 최근 로그 조회
- `list_active_lockouts() -> list[dict]`: 대시보드용 현재 잠금 목록
- `ensure_bootstrap_admin() -> None`: `admin_users`가 비어 있으면 `.env`의 `ADMIN_USERNAME`/`ADMIN_PASSWORD`를 `generate_password_hash()`로 해시해 1개 계정 생성. 앱 시작 시 1회 호출(3-8절 참고)
- `verify_admin_credentials(username: str, password: str) -> bool`: `admin_users`에서 `username` 조회 후 `check_password_hash()`로 비밀번호 검증
- `log_admin_attempt(username: str, success: bool, ip: str) -> None`: `admin_login_log` insert
- `list_admin_login_log(limit: int = 20) -> list[dict]`: 대시보드용 관리자 로그인 기록 조회

### 3-5. `detector.py`

**변경 이유**: "판정"과 "실행"을 분리해 SOAR 로직이 판정 로직을 재구현하지 않게 함.

**필요한 함수**:
- `is_suspicious(ip: str) -> tuple[bool, int]`: `db.count_recent_failures(ip)` 호출 후 `(실패횟수 > FAILURE_THRESHOLD, 실패횟수)` 반환
- `is_locked(ip: str) -> bool`: `db.get_active_lockout(ip)`가 존재하고 아직 `unlock_at`이 지나지 않았는지 확인

이 두 함수는 `/login`(감시 대상) 경로에서만 호출되며, `/admin/login`은 별도 인증 경로이므로 호출하지 않는다(1절 결정 #2).

### 3-6. `soar.py`

**변경 이유**: 판정 결과를 실제 조치(잠금 실행, 알림 발송, 해제)로 연결.

**필요한 함수**:
- `enforce_lockout(ip: str, failure_count: int) -> None`: `db.create_lockout()` 호출 → `alert.send_lockout_alert()` 호출(잠금 순간에만 알림, 기획서 4-2절 "알림 피로 방지" 원칙 반영)
- `try_release_expired_lockouts() -> None`: 만료된(`unlock_at <= now()`) 잠금을 조회해 `db.release_lockout()` 호출 — `/login` 요청이 들어올 때마다, 혹은 대시보드 폴링 시 호출해 "5분 후 자동 해제"를 별도 스케줄러 없이 구현(APScheduler 등 백그라운드 잡 도입은 범위 밖, 7절 참고)
- `manual_release(ip: str) -> bool`: `db.release_lockout()` 호출, 성공 여부 반환. **호출 권한 검증은 이 함수의 책임이 아니라 `app.py`의 `login_required` 데코레이터가 담당**(1절 결정 #3에 따라 `ADMIN_TOKEN` 검증 로직 제거)

### 3-7. `alert.py`

**변경 이유**: Slack 알림 발송 로직을 SOAR와 분리해 재사용 가능하게 함. (원 기획서는 텔레그램 봇이었으나 1절 결정에 따라 Slack Incoming Webhook으로 대체)

**필요한 함수**:
- `send_lockout_alert(ip: str, failure_count: int, locked_at: datetime) -> None`: 기획서 4-2절 형식대로 "시각, 시도 IP, 실패 횟수, 조치 결과"를 한 문장으로 조립해 `.env`의 `SLACK_WEBHOOK_URL`에 `requests.post(url, json={"text": message})`로 전송. `SLACK_WEBHOOK_URL`이 비어 있으면(1절 결정 #4가 보류 중이므로) 실제 전송 대신 콘솔에 메시지를 로그만 남기고 반환 — 워크스페이스가 정해지기 전에도 나머지 구현을 막지 않기 위함
- 실패(네트워크 오류, 4xx 등) 시 예외를 삼키고 로그만 남길지, 상위로 전파할지는 4-3 "에러 처리 방침"에서 결정
- Slack Incoming Webhook은 요청 본문이 `{"text": "..."}` 하나로 끝나므로 텔레그램의 `chat_id` 같은 별도 수신자 식별값이 필요 없음 — `.env`에는 `SLACK_WEBHOOK_URL` 한 개만 추가하면 됨

### 3-8. `app.py`

**변경 이유**: 전체 파이프라인을 엮는 Flask 진입점.

**시작 시 처리**:
- 모듈 로드 시 `db.ensure_bootstrap_admin()` 호출(관리자 계정 최초 시드)
- `app.secret_key = os.environ["SECRET_KEY"]` 설정(세션 서명용)

**인증 데코레이터**:
- `login_required(view)`: `session.get("admin_username")`이 없으면 HTML 라우트는 `/admin/login`으로 redirect, JSON 라우트(`/api/status`, `/api/unlock`)는 401 JSON 응답

**라우트**:
- `GET /login`: `login.html` 렌더(빈 폼) — 감시 대상 가짜 로그인 페이지, 인증 불필요
- `POST /login`:
  1. `soar.try_release_expired_lockouts()` 호출(만료 잠금 정리)
  2. IP 추출 — `TRUST_FORWARDED_FOR` 플래그에 따라 `request.headers.get("X-Forwarded-For")` 또는 `request.remote_addr`
  3. `detector.is_locked(ip)` 참이면 → 즉시 "잠긴 계정입니다" 플래시 메시지로 `login.html` 재렌더(계정 검증 자체를 건너뜀)
  4. 아니면 아이디/비밀번호를 하드코딩된 테스트 계정과 비교(성공/실패는 데모용이므로 실제 인증 시스템 불필요, 7절 참고) → `db.log_attempt(ip, username, success)`
  5. 실패였다면 `detector.is_suspicious(ip)` 호출 → 초과 시 `soar.enforce_lockout(ip, count)`
  6. 결과에 따라 성공/실패/잠금 메시지로 `login.html` 렌더
- `GET /admin/login`: `admin_login.html` 렌더(빈 폼) — 이미 로그인 상태면 `/dashboard`로 redirect
- `POST /admin/login`:
  1. `db.verify_admin_credentials(username, password)` 호출
  2. IP 추출(위와 동일 로직) 후 `db.log_admin_attempt(username, success, ip)` 기록
  3. 성공 시 `session["admin_username"] = username` 설정 후 `/dashboard`로 redirect
  4. 실패 시 "아이디 또는 비밀번호가 올바르지 않습니다" 플래시 메시지로 `admin_login.html` 재렌더
- `POST /admin/logout`: `session.clear()` 후 `/admin/login`으로 redirect (`login_required` 적용)
- `GET /dashboard` (`login_required` 적용): `dashboard.html` 렌더(정적 뼈대, 데이터는 JS가 `/api/status`로 채움)
- `GET /api/status` (`login_required` 적용): JSON 응답(3-4절의 스키마)
- `POST /api/unlock` (`login_required` 적용): body에서 `ip`만 수신(세션이 이미 인증을 보장하므로 `admin_token` 불필요) → `soar.manual_release(ip)` 호출 → 성공/실패 JSON 응답

**`/api/status` 응답 스키마 (확정안)**:
```json
{
  "recent_attempts": [
    {"ip_address": "127.0.0.1", "username": "testuser", "success": false, "attempted_at": "2026-09-02T10:00:00Z"}
  ],
  "active_lockouts": [
    {"ip_address": "127.0.0.1", "locked_at": "2026-09-02T10:00:05Z", "unlock_at": "2026-09-02T10:05:05Z", "failure_count": 6}
  ],
  "admin_login_log": [
    {"username": "admin", "success": true, "ip_address": "127.0.0.1", "attempted_at": "2026-09-02T09:55:00Z"}
  ]
}
```

### 3-9. `templates/login.html`

**변경 이유**: 감시 대상이 되는 가짜 로그인 화면.

**내용**: 아이디/비밀번호 폼(POST `/login`), 서버가 넘겨준 플래시 메시지(성공/실패/잠금 3종) 표시 영역. 관리자 인증과는 무관 — 로그인 링크 등을 노출하지 않는다(1절 결정 #2 반영, 감시 대상과 관리자 경로 분리 유지).

### 3-10. `templates/admin_login.html` (신규 — 1절 결정 #3 반영)

**변경 이유**: 관리자 전용 로그인 화면. 감시 대상 `/login`과 완전히 분리된 경로이므로 IP 잠금의 영향을 받지 않는다.

**내용**: 아이디/비밀번호 폼(POST `/admin/login`), 실패 시 플래시 메시지 표시 영역.

### 3-11. `templates/dashboard.html`, `static/css/dashboard.css`, `static/js/dashboard.js`

**변경 이유**: 관리자 모니터링 화면. 이제 `login_required`로 보호되므로 미로그인 상태에서는 `/admin/login`으로 리다이렉트된다.

**필요한 함수(JS)**:
- `fetchStatus()`: `/api/status` GET 후 DOM 갱신, `setInterval(fetchStatus, 2500)`로 폴링(기획서 4-3절 "2~3초 폴링" 반영). 401 응답을 받으면 `/admin/login`으로 이동(세션 만료 처리)
- `renderAttemptsTable(attempts)`, `renderLockoutCards(lockouts)`, `renderAdminLoginLog(log)`(신규 — 관리자 로그인 기록 표시)
- `unlockIp(ip)`: 관리자가 버튼 클릭 시 `/api/unlock`에 `{ip}`만 담아 POST — 브라우저가 세션 쿠키를 자동 전송하므로 별도 토큰 입력 필드는 불필요(1절 결정 #3 반영)
- 화면 상단에 "로그아웃"(`POST /admin/logout`) 버튼 추가

### 3-12. `requirements.txt`

**내용**: `flask`, `supabase`, `python-dotenv`, `requests`, `pytest`(dev). 비밀번호 해시(`werkzeug.security`)와 세션(`flask.session`)은 Flask 설치 시 이미 포함되므로 추가 패키지가 필요 없음. 텔레그램 전용 라이브러리(`python-telegram-bot`)는 불필요 — Slack Incoming Webhook은 `requests`만으로 충분(2절 결정).

---

## 4. 예상 코드 흐름

### 4-1. 정상 로그인 (실패 5회 미만)
```
브라우저 → POST /login → app.py
  → soar.try_release_expired_lockouts()
  → detector.is_locked(ip) == False
  → 계정 검증 (성공 or 실패)
  → db.log_attempt(ip, username, success)
  → success=True: "로그인 성공" 렌더
  → success=False: detector.is_suspicious(ip) == (False, n<=5)
  → "로그인 실패" 렌더
```

### 4-2. 공격 시나리오 (60초 내 6번째 실패 시점)
```
6번째 POST /login (실패)
  → db.log_attempt(ip, username, False)
  → detector.is_suspicious(ip) == (True, 6)
  → soar.enforce_lockout(ip, 6)
      → db.create_lockout(ip, 6, duration=300)
      → alert.send_lockout_alert(ip, 6, now)  # Slack 웹훅 발송(URL 미설정 시 콘솔 로그)
  → "잠긴 계정입니다" 렌더
```

### 4-3. 잠금 중 재시도
```
POST /login (잠금 상태)
  → soar.try_release_expired_lockouts()  # 아직 미만료
  → detector.is_locked(ip) == True
  → db.log_attempt() 호출 여부는 확정 필요(아래 5절 고려사항 참고)
  → "잠긴 계정입니다" 즉시 응답 (계정 검증 스킵)
```
- 이 흐름은 `/login`(감시 대상)에만 적용된다. `/admin/login`은 별도 경로이므로 관리자가 같은 IP로 접속해도 이 잠금의 영향을 받지 않는다(1절 결정 #2).

### 4-4. 자동 해제
```
잠금 후 5분이 지난 뒤 들어오는 다음 요청(로그인 시도 또는 대시보드 폴링)
  → soar.try_release_expired_lockouts()
  → unlock_at <= now() 인 lockouts 행 발견 → db.release_lockout(ip)
  → 이후 요청부터 detector.is_locked(ip) == False
```
- 별도 백그라운드 스케줄러 없이 "다음 요청 시점에 지연 정리"하는 방식 — 트래픽이 없으면 실제 해제 반영이 늦어질 수 있음(5절 고려사항).

### 4-5. 수동 해제 (관리자 세션 필요)
```
대시보드 "즉시 해제" 버튼 클릭 → JS: POST /api/unlock {ip}
  → app.py: login_required가 세션 확인(session["admin_username"] 존재해야 통과)
  → soar.manual_release(ip)
      → db.release_lockout(ip)
  → 200 OK → 대시보드 다음 폴링(≤2.5초 내)에 잠금 카드 사라짐
```

### 4-6. 대시보드 폴링
```
setInterval(2500ms) → fetch('/api/status')  # 세션 쿠키 자동 포함
  → app.py: login_required 통과 확인
  → db.list_recent_attempts(50) + db.list_active_lockouts() + db.list_admin_login_log(20)
  → JSON 응답
  → JS: renderAttemptsTable() + renderLockoutCards() + renderAdminLoginLog()
```

### 4-7. 관리자 로그인 (신규 — 1절 결정 #3)
```
관리자 → GET /admin/login → admin_login.html 렌더
관리자 → POST /admin/login {username, password}
  → app.py: db.verify_admin_credentials(username, password)
  → db.log_admin_attempt(username, success, ip)
  → 성공: session["admin_username"] = username 설정 → /dashboard로 redirect
  → 실패: "아이디 또는 비밀번호가 올바르지 않습니다" 플래시 메시지로 admin_login.html 재렌더
```
- 앱 최초 기동 시 `db.ensure_bootstrap_admin()`이 `admin_users`가 비어 있으면 `.env`의 `ADMIN_USERNAME`/`ADMIN_PASSWORD`로 계정 1개를 자동 생성하므로, 팀은 회원가입 화면 없이 바로 로그인할 수 있다.

---

## 5. 고려 사항 (구현 시 반드시 재확인)

- **잠금 중 로그인 시도도 `login_attempts`에 기록할 것인가?** 기록하면 "잠금 중에도 몇 번 더 두드렸는지" 대시보드에 보여줄 수 있지만, 매 요청마다 insert가 발생해 5-4절 쿼터 소모가 늘어남. 기본안: 기록하지 않고 즉시 거부(쿼터 절약 우선). 확정 필요.
- **`try_release_expired_lockouts()`를 언제 호출할지**: `/login` POST와 `/api/status` GET 양쪽에서 호출하면 트래픽이 없어도 대시보드 폴링이 자동 해제를 사실상 실시간으로 처리해줌 — 이 방식을 기본안으로 채택.
- **경쟁 조건(race condition)**: research.md 5-2절 지적대로 팀원 4명이 각자 로컬 서버를 동시에 띄우면 동일 IP에 대해 동시에 `enforce_lockout`이 호출될 수 있음. `lockouts.ip_address`를 PRIMARY KEY로 설정했으므로 두 번째 insert는 실패(또는 upsert로 덮어씀) — Supabase의 unique constraint가 최소한의 안전망 역할을 하지만, Slack 알림 중복 발송까지는 막지 못함. 완전한 해결은 범위 밖(7절), 관찰만 해두고 시연 시 팀원 1명만 공격 시뮬레이션을 실행하도록 운영으로 회피 권장.
- **`/login` 실패 시 사용자 존재 여부 노출 금지**: 성공/실패 메시지가 "아이디가 없음"과 "비밀번호 틀림"을 구분하지 않도록 통일된 문구 사용(일반적인 보안 관례, 기획서에 명시는 없으나 반영 권장).
- **테스트 계정 하드코딩**: 데모 목적상 `app.py`에 `TEST_USERNAME`/`TEST_PASSWORD_HASH` 상수로 계정 1개만 두는 것을 기본안으로 함(회원가입 기능은 범위 밖). 관리자 계정(`admin_users`)과는 별개 개념 — 감시 대상 로그인은 여전히 데모용 하드코딩, 관리자 로그인만 실제 해시 저장 방식을 씀.
- **관리자 부트스트랩 계정 재발급**: `.env`의 `ADMIN_USERNAME`/`ADMIN_PASSWORD`를 바꿔도 이미 `admin_users`에 행이 있으면 `ensure_bootstrap_admin()`은 아무 것도 하지 않음(최초 1회만 시드). 비밀번호를 바꾸려면 Supabase에서 해당 행을 직접 삭제하거나 갱신해야 함 — 확정 필요 없음, README에 안내만 추가.
- **`SECRET_KEY` 관리**: Flask 세션 쿠키 서명에 쓰이는 값이므로 `SUPABASE_KEY`와 동일한 수준으로 `.env`에 두고 `.gitignore`로 보호. 로컬 데모 환경이라도 저장소에 커밋되지 않도록 주의.

---

## 6. 테스트 검증 방법

### 6-1. 단위 테스트 (`pytest`, 신규 `tests/` 디렉터리)
- `test_detector.py`: `db.count_recent_failures`를 monkeypatch해 `is_suspicious()`가 임계값 경계(4/5/6회)에서 올바르게 동작하는지 검증
- `test_soar.py`: `db.create_lockout`/`release_lockout`을 mock해 `enforce_lockout()`이 잠금+알림을 순서대로 호출하는지, `manual_release()`가 ip만으로 정상 동작하는지 검증(권한 검증은 라우트 레벨 테스트로 이동)
- `test_db.py`(신규): `verify_admin_credentials()`가 올바른/틀린 비밀번호를 해시 비교로 정확히 구분하는지 검증
- `test_config.py`: 상수 값이 기획서 수치(5회, 60초, 300초)와 일치하는지 회귀 테스트

### 6-2. 통합 테스트 — 로컬 Supabase 프로젝트 대상 (실제 네트워크 호출)
- 기획서 10장의 검증 스크립트(`scripts/bruteforce_sim.py`, 이번 계획 범위 밖이지만 검증 도구로는 재사용)를 로컬 `python app.py` 서버에 실행 → 6번째 시도에서 "잠긴 계정" 문구 확인
- 5분 대기 후 재시도 → 자동 해제 확인(수동 시간 단축 테스트 시 `LOCKOUT_DURATION_SECONDS`를 `.env`에서 10초 등으로 임시 조정 — `config.py`가 override를 지원하는 이유)
- 로그인하지 않은 상태로 `/dashboard`, `/api/status`, `/api/unlock` 접근 → 리다이렉트/401 확인
- `/admin/login`으로 로그인 후 위 세 라우트에 정상 접근되는지, 대시보드 버튼 클릭 시 즉시 해제되는지 확인

### 6-3. 체크포인트 기반 수동 시나리오 (기획서 9장 그대로 채택, 관리자 인증 항목 추가)
1. 로그인 페이지 접속 가능 + Supabase 테이블에 테스트 데이터 1건 저장 확인
2. Slack 채널에 웹훅 테스트 메시지 1건 수신 확인(웹훅 URL 확정 후)
3. 일부러 5번 초과로 틀리게 로그인 → 화면 잠금 표시 + Slack 알림 동시 확인
4. 대시보드 폴링이 2~3초 내 잠금 상태를 반영하는지 육안 확인
5. 관리자 해제 버튼 클릭 → 대시보드와 실제 `/login` 응답이 즉시 풀리는지 확인
6. `/admin/login`으로 로그인 → 대시보드에 로그인 기록이 표시되는지 확인, 로그아웃 후 `/dashboard` 접근 시 로그인 페이지로 이동하는지 확인

### 6-4. 쿼터 점검 (5-4절 위험 대응)
- 대시보드를 30분간 열어둔 상태에서 Supabase 대시보드의 API 요청량을 확인해 무료 티어(월 5만 건) 대비 실제 소모량을 1회 실측 — 예상치(문서상 600~900회/30분/인)와 실측치를 비교해 폴링 주기(2초 vs 3초) 최종 결정에 반영

---

## 7. 제외할 범위 (이번 plan.md 대상 아님)

- `scripts/bruteforce_sim.py` 자동화 스크립트 자체의 신규 기능 확장(랜덤 딜레이, argparse화, `rich` 출력) — 기획서 9-4절 스트레치
- `scripts/daily_report.py` (AI 기반 일일 로그 요약, LLM 연동) — research.md 질문 8 그대로 정의 부족, 핵심 기능 완료 후 재검토
- Supabase Realtime 구독(폴링 대체) — 기획서 4-3절에 "여유가 있다면"으로 명시된 스트레치
- IP 위치 조회(ip-api.com 연동)
- PyInstaller `.exe` 패키징
- GitHub Actions lint 배지, `docs/architecture.png`·`demo.gif`·`before-after.png`·`scenario.md` 등 시각자료 제작(D 담당의 별도 산출물)
- 정식 회원가입/비밀번호 해시 저장 등 실사용자 인증 시스템(`/login` 감시 대상 계정 한정) — 테스트 계정 1개로 대체, 회원가입 기능 없음(5절 고려사항). 관리자 계정(`admin_users`)은 1절 결정 #3에 따라 해시 저장 방식을 쓰지만, 회원가입 화면 없이 부트스트랩 1개 계정으로 한정됨
- 계정(사용자명) 단위 잠금 — 이번 계획은 IP 단위로 한정(1절 결정 #2)
- 백그라운드 스케줄러(APScheduler 등)를 이용한 정시 자동 해제 — "다음 요청 시 지연 정리" 방식으로 대체(4-4절)
- 다중 관리자 계정/역할 기반 접근 제어 — 관리자 계정은 부트스트랩 1개로 한정(회원가입 기능 없음), RBAC 없음(1절 결정 #3 갱신)

---

## 8. 다음 행동

1. 남은 미확정 항목(1절 결정 #4 — Slack 웹훅 워크스페이스/채널 선정)을 팀이 확정. 나머지(잠금 상태 저장, IP vs 계정, 관리자 인증·IP 예외)는 이번 갱신으로 확정 완료.
2. 확정되면 3-3절 SQL을 Supabase에 1회 실행(`login_attempts` + `lockouts` + `admin_users` + `admin_login_log` 테이블, 인덱스 포함)
3. `.env`에 `SUPABASE_URL`, `SUPABASE_KEY`, `SLACK_WEBHOOK_URL`(보류 시 빈 값 가능), `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `TRUST_FORWARDED_FOR` 값을 채움
4. 3절 순서(`config.py` → `.env.example`/`.gitignore` → `db.py` → `detector.py`/`soar.py`/`alert.py` → `app.py`(관리자 인증 포함) → 템플릿/정적 파일) 그대로 구현 착수
