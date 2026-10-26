# 설치·실행 상세

> 요약은 [루트 README](../README.md)에 있습니다. 이 문서는 README에서 옮겨 온 세부 내용입니다.

README의 "빠른 시작"을 자세히 풀어 쓴 문서입니다. Supabase 마이그레이션 순서, 환경변수 전체 표, 데모 서버, 접속 주소를 다룹니다. Track D Docker 단지는 [netwatch/README.md](../netwatch/README.md)를 보세요.

## 1. 저장소 클론
```bash
git clone https://github.com/dyj02056/login-watchdog.git
cd login-watchdog
```

## 2. 가상환경 생성 및 패키지 설치
```bash
python -m venv venv
source venv/Scripts/activate   # Windows PowerShell: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 3. Supabase 프로젝트 준비
1. [supabase.com](https://supabase.com)에서 프로젝트 생성
2. **SQL Editor**에서 [docs/schema.sql](schema.sql) 내용 전체 실행 (테이블 35개 생성 — 표별 설명은 [docs/feature-reference/db-schema-guide.md](feature-reference/db-schema-guide.md), 관계도는 [ERD.svg](feature-reference/ERD.svg)). 영구 잠금 기능(guide33)을 쓰려면 기존 DB에는 [docs/migrations/guide33_permanent_lock.sql](migrations/guide33_permanent_lock.sql)을, 비밀번호 변경 기능(guide35)을 쓰려면 [docs/migrations/guide35_password_change.sql](migrations/guide35_password_change.sql)을 **추가로** 실행해야 합니다(`schema.sql` 맨 아래에도 같은 내용이 들어 있고, 여러 번 실행해도 안전합니다). 특히 guide35 SQL은 **새 코드를 배포하기 전에** 실행해야 합니다 — 없으면 회원 화면 전체가 오류가 납니다. 관리자 계정 단위 잠금(guide38)을 쓰려면 [docs/migrations/guide38_admin_account_lockout.sql](migrations/guide38_admin_account_lockout.sql)도 **배포 전에** 실행해야 합니다 — 없으면 `/admin/login`과 대시보드가 오류가 납니다. 이메일 인증(guide40)은 [docs/migrations/guide40_email_verification.sql](migrations/guide40_email_verification.sql)을 **배포 전에** 실행해야 합니다 — 없으면 회원가입과 회원 화면이 오류가 납니다. 로그 자동 정리(guide44)는 [docs/migrations/guide44_log_retention.sql](migrations/guide44_log_retention.sql)을 실행한 뒤 [docs/migrations/guide47_daily_log_summary.sql](migrations/guide47_daily_log_summary.sql)까지 실행하면 켜집니다(앱 코드와 무관해서 언제 실행해도 됩니다). Track D(로컬 Docker 단지)를 쓰려면 [docs/migrations/guide52_track_d.sql](migrations/guide52_track_d.sql)(표 5개·칸 추가)과 [guide53_track_d_retention.sql](migrations/guide53_track_d_retention.sql)(보존 기간), [guide56_track_d_hardening.sql](migrations/guide56_track_d_hardening.sql)(차단 요청 번호 칸·규칙 덧붙이기 함수)을 차례로 실행합니다 — 모두 추가만 하므로 Track D를 쓰지 않는 배포 앱에도 영향이 없습니다. guide56은 실행 전에도 앱이 예전 방식으로 동작합니다
3. **Project Settings → API**에서 `Project URL`과 `service_role` key 확인

## 4. 환경변수 설정
`.env.example`을 복사해 `.env`를 만들고 아래 값을 채웁니다. (`.env`는 `.gitignore`로 보호되어 커밋되지 않습니다.)

```bash
cp .env.example .env
```

| 키 | 설명 |
|---|---|
| `SUPABASE_URL` | Supabase 프로젝트 루트 주소 (`https://xxxx.supabase.co`, 끝에 `/rest/v1/` 등 경로를 붙이지 않음) |
| `SUPABASE_KEY` | `service_role` key (서버 전용, 절대 노출 금지) |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook 주소. 비워두면 알림이 콘솔 로그로 대체됨 |
| `SECRET_KEY` | Flask 세션 쿠키 서명용 임의 문자열 (예: `python -c "import secrets; print(secrets.token_hex(32))"`) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | 서버 최초 기동 시 자동 생성될 관리자 계정 (이미 계정이 있으면 무시됨). RBAC 도입 후 이 계정을 `super_admin`으로 지정하려면 `docs/schema.sql`의 `update admin_users set role = 'super_admin' where username = '...'`을 이 값과 맞게 수정해서 실행해야 함 |
| `TRUST_FORWARDED_FOR` | `X-Forwarded-For` 헤더 신뢰 여부. **데모/시연 전용, 운영에서는 반드시 `false`** |
| `PERMANENT_LOCK_*` | 영구 잠금 정책 — `STRIKE_COUNT`/`ACCOUNT_STRIKE_COUNT`(기본 2회째 승격), `STRIKE_WINDOW_DAYS`(30), `AUTO_ON_HIGH`(false=HIGH 사건은 관리자 승인 대기), `AUTO_CLOSE_INCIDENT`(false), `IP_ALLOWLIST`(기본 `127.0.0.1,::1` — **관리자 PC IP를 꼭 추가**) |
| `MAIL_BACKEND` / `SMTP_*` / `MAIL_FROM` / `PUBLIC_BASE_URL` | 복구 메일 발송. 개발은 `console`(터미널 출력, 운영에서는 거부됨) 또는 Mailpit(`docker compose -f docker-compose.mailpit.yml up -d`, `SMTP_HOST=127.0.0.1` `SMTP_PORT=1025` `SMTP_STARTTLS=false`, 받은 메일은 http://127.0.0.1:8025. 앱을 Docker 없이 직접 실행할 때만 쓰고, Track D `docker compose up`에는 Mailpit이 이미 들어 있어 이름·포트가 충돌하므로 함께 띄우지 않는다). **배포(Vercel)** 는 `MAIL_BACKEND=smtp` + Gmail SMTP(앱 비밀번호) 설정이 필요합니다 — 환경변수 목록과 점검 방법은 [guide34a_email_recovery.md](beginner-guide/guide34a_email_recovery.md)의 "배포(Vercel)에서 복구 메일 보내기" 참고. `PUBLIC_BASE_URL`은 복구 링크의 기준 주소로, Host 헤더 대신 이 값만 씁니다. 설정은 `python scripts/management/send_test_mail.py --to 내주소@gmail.com`으로 미리 확인할 수 있습니다 |
| `FLASK_ENV` | 배포(Vercel)에서는 반드시 `production` — 세션·기기 쿠키에 Secure가 붙고, 토큰을 로그에 찍는 console 메일 백엔드가 차단됩니다. 로컬 HTTP 서버에서 이 값을 켜면 로그인 쿠키가 전송되지 않으니 로컬에서는 비워 두세요 |
| (선택) `IPV6_PREFIX_LENGTH` | IPv6를 몇 비트 대역 단위로 세고 잠글지(기본 64, guide42). 회선 하나에 /56·/48을 주는 환경이면 줄입니다 |
| (선택) `PASSWORD_RESET_MAX_PER_DAY` / `PASSWORD_RESET_MAX_PER_IP_PER_HOUR` / `PASSWORD_RESET_RATE_LIMIT_PER_MINUTE` | 비밀번호 찾기(guide41): 회원당 하루 3회, IP당 시간당 5회, 요청·재설정 제출 IP당 분당 10회. 응답 시간은 `RECOVERY_MIN_RESPONSE_SECONDS`를 같이 씁니다 |
| (선택) `EMAIL_TOKEN_TTL_MINUTES` / `EMAIL_TOKEN_COOLDOWN_SECONDS` / `EMAIL_TOKEN_MAX_PER_DAY` / `EMAIL_CONFIRM_RATE_LIMIT_PER_MINUTE` | 이메일 인증·변경 확인 링크(guide40): 유효 15분, 같은 회원·용도 재발송 60초 간격·하루 5회, 확인 제출 IP당 분당 10회 |
| (선택) `ADMIN_ACCOUNT_FAILURE_THRESHOLD` / `ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS` | 관리자 계정 단위 잠금 기준(기본 8회 초과 / 900초=15분, guide38). IP와 무관하게 한 관리자 아이디의 실패를 셉니다 |
| (선택) `ADMIN_SESSION_MAX_HOURS` | 관리자 세션 최대 수명(시간, 기본 8). 로그인 시각부터 세며, 지나면 다시 로그인해야 합니다(guide37) |
| (선택) `RECOVERY_*`, `IP_EXEMPTION_*`, `SMTP_USE_SSL`, `SMTP_TIMEOUT_SECONDS`, `MAIL_FAILURE_ALERT_COOLDOWN_SECONDS` | 복구 정책(토큰 유효 15분, 요청 한도, 응답 고정 5초, 보호관찰 24시간 등)과 메일 세부 설정. 기본값으로 충분하며 전체 목록은 [.env.example](../.env.example)과 [guide34a](beginner-guide/guide34a_email_recovery.md) 참고 |
| (선택) `GROQ_API_KEY` | LLM 조기 경보와 `daily_report.py --ai`의 AI 총평에 쓰는 Groq API 키. 비워두면 조기 경보만 조용히 건너뛰고 나머지 기능은 그대로 동작 |
| (선택) `SPA_ENABLED` | `false`로 두면 Next.js 화면 대신 예전 Jinja 화면(`templates/`)을 씁니다(기본은 빌드가 있으면 켜짐, guide48). 문제가 생겼을 때 되돌리는 스위치 |
| (선택) `ADMIN_STATUS_CACHE_SECONDS` / `ADMIN_STATS_CACHE_SECONDS` | `/api/status`(기본 3초)·`/api/stats`(기본 10초) 조회 결과를 이 시간 안에는 한 번만 만들어 모든 탭이 나눠 씁니다. 0이면 캐시를 끕니다 |
| (선택) `RECOVERY_BACKGROUND_WORK` | 복구 메일을 응답 뒤 백그라운드에서 보낼지(기본 `false` — 서버리스는 응답 뒤에 멈추므로 요청 안에서 끝냄). 상시 실행 서버(로컬·gunicorn)에서만 `true` |
| (선택) 탐지 임계값·폴링 주기 | `FAILURE_THRESHOLD`(5), `ACCOUNT_FAILURE_THRESHOLD`(8), `DETECTION_WINDOW_SECONDS`(60), `LOCKOUT_DURATION_SECONDS`(300), `EARLY_WARNING_BAND`(2), `ADMIN_DASHBOARD_POLL_MS`(5000) 등 — 전체 목록과 기본값은 [config.py](../config.py) 참고 |
| `VERCEL_AUTOMATION_BYPASS_SECRET` | Vercel Authentication(프리뷰 배포 보호)을 우회하는 Protection Bypass Secret. `scripts/simulation/critical/bruteforce_sim.py`로 Vercel 프리뷰 배포를 대상으로 테스트할 때만 필요, 로컬 서버·운영 배포에는 불필요 |

## 5. 서버 실행
```bash
python app.py
```
Next.js 화면의 빌드 결과(`spa/`, `public/_next/`)는 저장소에 들어 있어서 따로 빌드하지 않아도 그대로 뜹니다. 화면 소스(`web/`)를 고쳤다면 먼저 빌드하세요.
```bash
cd web
npm ci          # 처음 한 번
npm run build   # 빌드 후 spa/ 와 public/_next/ 를 갱신
```
7일치 샘플 로그로 관제 화면만 확인하려면(Supabase 접속 없음) 가상환경을 켠 뒤 `python scripts/demo/generate_demo_logs.py`(처음 한 번, 약 2분) → `python scripts/demo/demo_server.py` 후 http://127.0.0.1:5077/__demo_login 을 엽니다. AI 조기경보를 진짜 Groq로 판정하려면 `--use-groq`, 실제 Supabase에도 넣으려면 `scripts/demo/load_demo_to_supabase.py --apply`(선택, 미리보기가 기본·`--purge`로 삭제)를 씁니다. 자세한 내용은 [guide50_demo_sample_logs.md](beginner-guide/guide50_demo_sample_logs.md) 참고

기본적으로 `http://localhost:5000`에서 실행됩니다. 해당 포트가 이미 사용 중이면 `PORT` 환경변수로 다른 포트를 지정할 수 있습니다(`PORT=5050 python app.py`).

## 6. 접속 주소

| 주소 | 설명 |
|---|---|
| `/signup` | 회원가입 (감시 대상 계정 생성) |
| `/login` | 감시 대상 로그인 — 이 화면에서의 실패 시도가 탐지 대상. 로그인 성공 시 `/dashboard`로 이동 |
| `/dashboard` | 회원 대시보드 — 인사말, 이메일 인증 안내 (회원 로그인 필요) |
| `/dashboard/history` · `/dashboard/profile` | 본인 로그인 기록 · 프로필(표시 이름, 이메일 변경, 비밀번호 변경) |
| `/recovery` · `/recovery/verify` | 잠긴 계정·IP를 이메일 인증으로 푸는 복구 요청 화면 · 6자리 코드 입력 화면 |
| `/password/forgot` · `/password/reset` | 비밀번호 찾기(인증된 이메일로 재설정 링크) · 메일 링크가 여는 새 비밀번호 입력 화면 |
| `/email/confirm` | 메일 링크가 여는 이메일 인증·변경 확인 화면 |
| `/admin/login` | 관리자 로그인 |
| `/admin/dashboard` | 관제 보드 ① 위협 현황 — KPI·차트·히트맵·공격 흐름·공격자 표 (관리자 로그인 필요) |
| `/admin/attack` | 관제 보드 ② 공격 상세 모니터링 — Top 5·국가별 흐름·최근 보안 이벤트 |
| `/admin/ops` | 관제 보드 ③ 처리 작업대 — 보안 이벤트·연관 사건·AI 조기 경보·잠금(임시/영구) 관리·회원·게시판·관리자 계정 관리 |
| `/board` | 게시판 목록 (회원 로그인 필요) |
| `/board/new` | 새 게시글 작성 (회원 로그인 필요) |
| `/board/<id>` · `/board/<id>/edit` | 게시글 상세 · 댓글 / 글 수정 (회원 로그인 필요, 수정은 본인 글만) |
| `/api/status` · `/api/stats` | 관리자 화면이 폴링하는 JSON — `status`는 처리 작업대용 표 묶음, `stats`는 위협 현황·공격 상세의 차트·히트맵 집계(`db/stats.py`). 관리자 로그인 필요 |
