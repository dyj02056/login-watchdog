# 로그인 워치독 (login-watchdog)

같은 IP에서 짧은 시간 안에 로그인을 반복해서 틀리면 자동으로 감지해 IP를 잠그고, Slack으로 알림을 보내고, 관리자가 대시보드에서 실시간으로 확인·해제할 수 있는 브루트포스 방어 데모 프로젝트입니다.

원래는 애플리케이션 계층(L7) 공격 — 브루트포스, 가입/게시글/댓글 도배, 웹 스캐닝, 미인증 API 호출, 클릭재킹, 봇 트래픽, SSRF, 오픈 리다이렉트 등 — 을 위험등급(CRITICAL/HIGH/MEDIUM/LOW)별로 탐지·대응하는 데 집중했습니다. 이제는 그 기반 위에서 **네트워크(L3)/전송(L4) 계층 공격**까지 관찰·대응 범위를 넓히는 것을 다음 목표로 하고 있습니다(SYN Flood, 포트 스캐닝 등 — 현재는 미구현, [알려진 제한사항](#알려진-제한사항) 참고).

**배포 주소**: https://login-watchdog.vercel.app (Vercel — 회원가입/로그인/관리자 대시보드까지 실제 스모크 테스트로 검증됨)

## 주요 기능

- **회원가입 / 로그인** — Supabase에 저장된 실제 계정으로 로그인하는 감시 대상 화면 (`/signup`, `/login`)
- **브루트포스 탐지 + 자동 잠금** — 같은 IP가 60초 안에 5회 초과 로그인 실패 시 해당 IP를 5분간 자동 잠금
- **Slack 알림** — 잠금이 발생하는 순간 Slack 채널에 시각·IP·실패 횟수·조치 내용을 전송 (웹훅 미설정 시 콘솔 로그로 자동 대체)
- **회원 대시보드** (`/dashboard`) — 로그인한 회원 본인의 인사말 화면. 최근 로그인 기록(접속 국가/도시 포함) 조회, 표시 이름·이메일 프로필 수정 가능
- **관리자 대시보드** (`/admin/dashboard`) — 세션 로그인으로 보호되는 별도 화면에서 최근 로그인 시도(접속 위치 포함), 현재 잠긴 IP, 등록된 회원 목록(삭제 가능), 회원가입 On/Off, 관리자 로그인 기록을 실시간(폴링) 확인 + "즉시 해제" 버튼으로 수동 잠금 해제
- **통합 보안 위험등급** — Brute Force/Password Spraying/관리자 로그인 무차별 대입(CRITICAL), 가입·게시글·댓글 도배 거부(HIGH), Web Scanning·Unauthorized Access·반복 페이지 접근 관찰(MEDIUM)을 공통 `security_events` 표에 등급과 함께 기록. 관리자 대시보드 맨 위 "보안 이벤트" 표에서 등급 배지와 함께 조회하고, HIGH/MEDIUM은 "처리 완료" 버튼으로 처리(CRITICAL은 잠금 해제 시 자동 처리). Slack 메시지 첫 줄에도 등급 표시
- **IP 위치 조회** — [ip-api.com](https://ip-api.com)으로 접속 IP의 국가·도시를 조회해 회원/관리자 대시보드에 표시. 조회 결과는 Supabase(`ip_locations`)에 캐시되어 같은 IP를 반복 조회하지 않음(무료 API의 분당 45건 한도 대응)
- **게시판·댓글** (`/board`) — 로그인한 회원 전용 게시판. 글 작성/수정/삭제(본인 글만), 댓글 작성/삭제(본인 댓글만), 페이지 번호 방식 목록, 새 댓글이 달리면 알림 배너 표시. 관리자 대시보드에서는 별도로 전체 게시글·댓글을 조회·삭제 가능. 자세한 설계 배경은 [docs/board-comment/](docs/board-comment) 참고
- **L7 공격 방어 보강** — IP를 나눠 시도하는 분산/저속 브루트포스에 대한 계정 단위 잠금(CRITICAL), 클릭재킹/CSP 방어용 보안 응답 헤더와 전역 HTTP 플러딩 방어(HIGH), 로그인/가입/글쓰기/댓글 폼의 허니팟 봇 차단과 로그인 타이밍 사이드채널 제거·SSRF 입력 검증(MEDIUM), CSRF 에러 핸들러 오픈 리다이렉트 수정(LOW)까지 위험등급별로 대응. 자세한 내용은 [docs/beginner-guide/guide24_l7_attack_hardening.md](docs/beginner-guide/guide24_l7_attack_hardening.md) 참고
- **관리자 역할 기반 접근 제어(RBAC)** — 관리자 계정이 `security_viewer`(조회만) / `security_admin`(IP 잠금 해제·보안 이벤트 처리) / `super_admin`(회원·게시글·댓글 삭제, 회원가입 On/Off까지 전부)으로 나뉘어, 로그인만 되면 뭐든 할 수 있던 이진 구조를 액션 단위 권한으로 세분화. 요청마다 실시간으로 역할을 조회해 권한 회수가 재로그인 없이 즉시 반영됨. 새 관리자 계정은 회원가입 화면이 아니라 `scripts/create_admin.py`로 생성. 자세한 내용은 [docs/beginner-guide/guide26_rbac_foundation.md](docs/beginner-guide/guide26_rbac_foundation.md) 참고

## 기술 스택

| 영역 | 사용 기술 |
|---|---|
| 백엔드 | Flask (Blueprint 4개로 라우트 분리, `routes/` 참고) + Flask-Limiter (전역 요청 빈도 제한) |
| 데이터베이스 | Supabase (PostgreSQL) |
| 알림 | Slack Incoming Webhook |
| 인증 | Flask 세션 + `werkzeug.security` (비밀번호 해시) |
| 프런트엔드 | Jinja2 템플릿 + 바닐라 JS |
| 테스트 | pytest |

## 시작하기 (Getting Started)

### 1. 저장소 클론
```bash
git clone https://github.com/dyj02056/login-watchdog.git
cd login-watchdog
```

### 2. 가상환경 생성 및 패키지 설치
```bash
python -m venv venv
source venv/Scripts/activate   # Windows PowerShell: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Supabase 프로젝트 준비
1. [supabase.com](https://supabase.com)에서 프로젝트 생성
2. **SQL Editor**에서 [docs/schema.sql](docs/schema.sql) 내용 전체 실행 (`users`, `login_attempts`, `lockouts`, `account_lockouts`, `admin_users`, `admin_login_log`, `app_settings`, `ip_locations`, `signup_attempts`, `posts`, `comments`, `post_attempts`, `comment_attempts`, `not_found_attempts`, `unauthorized_attempts`, `page_access_attempts`, `security_events`, `roles`, `permissions` 19개 테이블 생성)
3. **Project Settings → API**에서 `Project URL`과 `service_role` key 확인

### 4. 환경변수 설정
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
| `VERCEL_AUTOMATION_BYPASS_SECRET` | Vercel Authentication(프리뷰 배포 보호)을 우회하는 Protection Bypass Secret. `scripts/bruteforce_sim.py`로 Vercel 프리뷰 배포를 대상으로 테스트할 때만 필요, 로컬 서버·운영 배포에는 불필요 |

### 5. 서버 실행
```bash
python app.py
```
기본적으로 `http://localhost:5000`에서 실행됩니다. 해당 포트가 이미 사용 중이면 `PORT` 환경변수로 다른 포트를 지정할 수 있습니다(`PORT=5050 python app.py`).

### 6. 접속 주소

| 주소 | 설명 |
|---|---|
| `/signup` | 회원가입 (감시 대상 계정 생성) |
| `/login` | 감시 대상 로그인 — 이 화면에서의 실패 시도가 탐지 대상. 로그인 성공 시 `/dashboard`로 이동 |
| `/dashboard` | 회원 대시보드 — 인사말, 로그인 기록·프로필 조회/수정 (회원 로그인 필요) |
| `/admin/login` | 관리자 로그인 |
| `/admin/dashboard` | 관리자 대시보드 — 잠긴 IP·회원 관리·회원가입 On/Off·게시판 관리 (관리자 로그인 필요) |
| `/board` | 게시판 목록 (회원 로그인 필요) |
| `/board/new` | 새 게시글 작성 (회원 로그인 필요) |
| `/board/<id>` | 게시글 상세 · 댓글 (회원 로그인 필요) |

## 화면 미리보기

### 인증

<table>
<tr>
<td align="center"><b>로그인</b><br>(관리자 로그인 <code>/admin/login</code>도 동일 화면 공유)</td>
<td align="center"><b>회원가입</b></td>
</tr>
<tr>
<td><img src="docs/screenshots/login.png" width="380"></td>
<td><img src="docs/screenshots/signup.png" width="380"></td>
</tr>
</table>

### 회원 대시보드

<table>
<tr>
<td align="center"><b>대시보드</b></td>
<td align="center"><b>로그인 기록</b></td>
<td align="center"><b>프로필</b></td>
</tr>
<tr>
<td><img src="docs/screenshots/member_dashboard.png" width="270"></td>
<td><img src="docs/screenshots/member_history.png" width="270"></td>
<td><img src="docs/screenshots/member_profile.png" width="270"></td>
</tr>
</table>

### 게시판

<table>
<tr>
<td align="center"><b>목록</b></td>
<td align="center"><b>글쓰기</b></td>
<td align="center"><b>상세 · 댓글</b></td>
</tr>
<tr>
<td><img src="docs/screenshots/board_list.png" width="270"></td>
<td><img src="docs/screenshots/board_new.png" width="270"></td>
<td><img src="docs/screenshots/board_detail.png" width="270"></td>
</tr>
</table>

> 관리자 대시보드(`/admin/dashboard`) 스크린샷은 실제 접속 로그(IP·위치 등 민감 정보)가 노출되어 이 문서에는 포함하지 않았습니다.

## 테스트 실행

```bash
pytest tests/
```
실제 Supabase에 접속하지 않고 가짜 데이터(monkeypatch)로 판정 로직만 검증하므로 몇 초 안에 끝납니다. 현재 총 238개 테스트가 모두 통과합니다.

## 유지보수 스크립트
(김재호)
Web Scanning 탐지는 `py scripts/web_scanning_sim.py --host http://127.0.0.1:5000`으로
GET 11회를 보내 재현할 수 있습니다. [실행 조건과 알림 확인 방법](docs/web-scanning-demo.md)을 참고하세요.

`scripts/` 아래에 있으며, 웹 서버(`app.py`)와 별개로 터미널에서 직접 실행하는 도구들입니다. 실행 전 가상환경 활성화가 필요합니다(`.\venv\Scripts\Activate.ps1` 등).

| 스크립트 | 역할 |
|---|---|
| `scripts/bruteforce_sim.py` | `/login`에 일부러 틀린 비밀번호를 반복 제출해, 설정된 횟수(기본 5회 초과)에서 실제로 IP가 잠기는지 검증하는 시뮬레이터. 팀이 소유한 로컬 서버만 대상으로 하며, 그 외 주소는 `--i-know-what-im-doing` 없이는 거부됨. `--ip`로 가짜 공격자 IP를 지정하거나, Vercel 프리뷰 배포처럼 Vercel Authentication이 걸린 주소를 대상으로 할 때는 `--bypass-secret`으로 우회할 수도 있음(아래 참고) |
| `scripts/daily_report.py` | 최근 N시간(기본 24시간)의 로그인 시도/잠금 현황을 콘솔에 텍스트로 요약 |
| `scripts/unlock_ip.py` | 지금 잠겨있는 IP를 조회하거나 즉시 해제. `/admin/login`도 `/login`과 같은 IP 기준 잠금을 공유하므로, 브루트포스 시뮬레이션 도중 관리자 계정 IP까지 함께 잠기면 대시보드의 "즉시 해제" 버튼조차 쓸 수 없는 상황이 생기는데(로그인 자체가 막혀서), 이때 서버·로그인 없이 터미널에서 바로 풀 때 사용 |
| `scripts/create_admin.py` | `security_viewer`/`security_admin`/`super_admin` 역할을 가진 새 관리자 계정을 생성. `admin_users`는 회원가입 화면이 없어서(위 "관리자 역할 기반 접근 제어" 참고), 부트스트랩 계정 외의 관리자는 이 스크립트로만 만들 수 있음 |

`bruteforce_sim.py`의 `--ip` 옵션: 로컬 환경에서는 팀원 전원이 다 같은 `127.0.0.1`로 접속하게 되어 "서로 다른 공격자 IP에서 왔다"는 상황을 재현할 수 없다. `--ip 1.2.3.4`를 주면 그 값을 `X-Forwarded-For` 헤더에 실어 보내는데, 이 헤더는 대상 서버의 `.env`에서 `TRUST_FORWARDED_FOR=true`로 켜뒀을 때만 실제 접속 IP처럼 반영된다(운영 환경 기본값인 `false`에서는 서버가 헤더를 무시하고 진짜 접속 IP를 그대로 씀 — 배포 사이트에서 이 옵션이 안전하게 아무 효과가 없는 이유).
```bash
python scripts/bruteforce_sim.py --host http://127.0.0.1:5000 --username test1 --ip 1.2.3.4
```

`bruteforce_sim.py`의 `--bypass-secret` 옵션: Vercel 프리뷰 배포(`*.vercel.app`)는 기본적으로 Vercel Authentication으로 보호되어 있어, 팀원이 아니면 `/login` 화면 자체에 접근하지 못한다. `--bypass-secret`에 Vercel의 Protection Bypass Secret 값을 넘기면 `x-vercel-protection-bypass` 헤더로 실어 보내 이 보호를 우회한다. 생략하면 `.env`의 `VERCEL_AUTOMATION_BYPASS_SECRET` 값을 자동으로 사용하며, 로컬 서버를 대상으로 할 때는 지정해도 아무 효과가 없다.
```bash
python scripts/bruteforce_sim.py --host https://<브랜치>-git-<프리뷰경로>.vercel.app --username test1 --i-know-what-im-doing
```

`unlock_ip.py` 사용 예:
```bash
python scripts/unlock_ip.py                # 현재 활성 잠금 목록만 조회 (아무것도 바꾸지 않음)
python scripts/unlock_ip.py --ip 127.0.0.1  # 이 IP 하나만 즉시 해제
python scripts/unlock_ip.py --all           # 활성 잠금 전부 즉시 해제
```

`create_admin.py` 사용 예:
```bash
python scripts/create_admin.py --username sktviewer123 --password <비밀번호> --role security_viewer
python scripts/create_admin.py --username sktadmin123 --password <비밀번호> --role security_admin
```

## 프로젝트 구조

`app.py`(1,108줄)와 `db.py`(1,030줄)가 파일 하나에 너무 많은 책임을 담고 있어 원하는 코드를 찾기 어려워졌던 것을 계기로, 각각 `routes/` Blueprint 4개와 `db/` 표 묶음별 패키지로 쪼갰습니다(배경은 [docs/refactor/2026-09-15-file-split.md](docs/refactor/2026-09-15-file-split.md) 참고). 호출부(`app.py`/`detector.py`/`soar.py`/`scripts/*.py`/테스트)는 지금도 예전처럼 `import db` 후 `db.log_attempt(...)`처럼 쓰며, 어느 파일이 실제로 그 함수를 담고 있는지는 몰라도 됩니다.

```
login-watchdog/
├── app.py                         # Flask 진입점(축소) — 앱 생성, 세션/CSRF 설정, 에러 핸들러, before_request, Blueprint 4개 등록
├── helpers.py                     # 라우트 전체가 공유하는 문지기 데코레이터(login_required/require_permission/member_login_required)·공용 함수
├── routes/                        # Blueprint 4개 — 실제 화면 라우트 (app.py에서 분리)
│   ├── auth.py                    #   auth_bp: /signup, /login
│   ├── admin.py                   #   admin_bp: /admin/login, /admin/dashboard, /api/*(관리자용, RBAC로 세분화)
│   ├── board.py                   #   board_bp: /board/*
│   └── member.py                  #   member_bp: /dashboard/*
├── db/                             # Supabase 연동 — 표 묶음별로 분리된 패키지 (db.py에서 분리)
│   ├── __init__.py                 #   하위 모듈 함수를 전부 다시 내보내기(re-export), 호출부는 여전히 db.함수명()으로 사용
│   ├── _client.py                  #   get_client(), _now_iso() — Supabase 연결
│   ├── attempts.py                 #   login_attempts (로그인 시도 기록)
│   ├── lockouts.py                 #   lockouts (IP 잠금 현재 상태)
│   ├── account_lockouts.py         #   account_lockouts (계정 단위 잠금, 분산 브루트포스 대응)
│   ├── admin.py                    #   admin_users, admin_login_log (관리자 계정/로그인 기록/역할)
│   ├── roles.py                    #   roles, permissions (RBAC — 역할별 허용 액션)
│   ├── users.py                    #   users (회원 계정)
│   ├── settings.py                 #   app_settings, signup_attempts (설정값, 가입 빈도 제한)
│   ├── geoip_cache.py              #   ip_locations (IP 위치 조회 캐시)
│   ├── board.py                    #   posts, comments, post_attempts, comment_attempts (게시판)
│   └── security_events.py          #   not_found/unauthorized/page_access_attempts, security_events
├── detector.py                    # 브루트포스 판정 로직
├── soar.py                        # 판정 결과에 따른 조치(잠금/해제) 실행
├── alert.py                       # Slack 알림 전송
├── geoip.py                       # IP 위치(국가·도시) 조회, 캐싱
├── config.py                      # 임계값·윈도우·잠금시간 등 상수
├── templates/                     # Jinja2 HTML 템플릿
├── public/css, public/js/dashboard/ # 스타일 및 대시보드 자바스크립트(ES 모듈 6개)
├── tests/                         # pytest 단위 테스트
├── scripts/                       # 유지보수 스크립트 (bruteforce_sim.py, daily_report.py, unlock_ip.py, create_admin.py 등 — 위 "유지보수 스크립트" 참고)
├── docs/schema.sql                # Supabase 테이블 정의
├── docs/beginner-guide/           # 비전공자용 단계별 구현 해설서 (26개 파일로 분리)
├── docs/board-comment/            # 게시판·댓글 기능 설계 문서(분석 → 결정 → 계획 → 결과)
├── docs/refactor/                 # app.py/db.py/dashboard.js 파일 분리 리팩터링 배경 기록
└── plan.md, research.md           # 설계 근거 문서
```

## 더 자세히 알고 싶다면

- [plan.md](plan.md) — 각 파일을 왜 이렇게 설계했는지에 대한 상세 근거
- [docs/beginner-guide/beginner-guide.md](docs/beginner-guide/beginner-guide.md) — 개발 지식이 없어도 이해할 수 있도록 각 구현 단계를 코드와 함께 풀어쓴 해설서. 단계별로 `guide01_setup.md` ~ `guide26_rbac_foundation.md` 파일로 나뉘어 있고, 이 파일 안의 목차에서 바로 이동할 수 있습니다.
- [docs/board-comment/](docs/board-comment) — 게시판·댓글 기능을 왜 이렇게 설계했는지(구현 전 분석 → 모호한 질문 11개 결정 → 구현 계획 → 결과 보고) 순서대로 기록한 문서 4종
- [docs/refactor/2026-09-15-file-split.md](docs/refactor/2026-09-15-file-split.md) — `app.py`/`db.py`/`dashboard.js`를 각각 `routes/`+`helpers.py`, `db/` 패키지, `public/js/dashboard/` ES 모듈로 나눈 리팩터링 배경과 과정

## 알려진 제한사항

- **IP 단위 잠금** — 계정이 아니라 접속 IP를 기준으로 잠급니다. 같은 공유 IP(회사·카페 와이파이 등)의 여러 사용자가 한 명의 실패 때문에 함께 잠길 수 있습니다. `/admin/login`도 `/login`과 같은 IP 기준 잠금을 공유하므로, 같은 컴퓨터에서 브루트포스를 시뮬레이션하다 관리자 계정 IP까지 함께 잠기면 대시보드의 "즉시 해제" 버튼도 쓸 수 없습니다(로그인 자체가 막혀서) — 이때는 `scripts/unlock_ip.py`로 터미널에서 바로 풀 수 있습니다.
- **관리자 계정은 여전히 회원가입 화면 없음** — `.env` 값으로 서버 최초 기동 시 부트스트랩 계정 1명만 자동 생성됩니다. 역할 구분(RBAC: `security_viewer`/`security_admin`/`super_admin`)은 guide26부터 지원하지만, 새 관리자 계정을 추가하려면 여전히 `scripts/create_admin.py`를 터미널에서 직접 실행해야 합니다(관리자 대시보드 안에서 계정을 만드는 화면은 없음). 또한 `super_admin` 인원수를 1명으로 강제하는 로직도 없어서(운영 정책으로만 지켜지는 중), 최종 책임자 계정이 유일한 super_admin일 때 그 계정이 잠기거나 삭제되면 Supabase에 직접 접속하지 않고는 아무도 새 super_admin을 만들 수 없습니다.
- **자동 해제는 "정시"가 아니라 "다음 요청 시"** — 백그라운드 타이머 없이, `/login` 요청이나 대시보드 폴링이 들어올 때 만료된 잠금을 정리합니다. 한동안 요청이 없으면 5분이 지나도 실제 해제가 늦어질 수 있습니다.
- **`TRUST_FORWARDED_FOR`는 데모 전용** — 켜두면 요청 헤더의 IP를 신뢰합니다(형식이 올바른 IP인지는 검증하지만, 그 값 자체가 진짜 요청자의 IP인지는 확인할 수 없습니다). 운영 환경에서 켜두면 공격자가 헤더에 임의의(형식은 유효한) IP를 넣는 것만으로 IP 잠금을 우회할 수 있어 위험합니다.
- **동시 실행 시 경쟁 조건(race condition) 가능성** — 여러 사람이 동시에 같은 IP로 브루트포스를 시뮬레이션하면 Slack 알림이 중복 발송되거나 잠금 처리가 겹칠 수 있습니다. 시연 시 한 명만 시뮬레이션 실행을 권장합니다.
- **대시보드는 실시간이 아니라 폴링 방식** — 웹소켓 기반 실시간 스트리밍이 아니라 일정 주기(기본 5초, `ADMIN_DASHBOARD_POLL_MS`)로 새로고침합니다. 최대 그 주기만큼 화면이 실제 상태보다 늦게 보일 수 있습니다. 원래는 Supabase 무료 쿼터 보호를 위해 10초로 늘렸었지만, 공격 대응 상황을 더 빠르게 확인할 수 있도록 5초로 다시 줄였습니다 — 오래 켜두는 환경에서 쿼터가 걱정되면 `.env`에서 다시 늘릴 수 있습니다. 주기 조절 방법은 [docs/beginner-guide/guide09_quota.md](docs/beginner-guide/guide09_quota.md)를 참고하세요.
- **계정 단위 잠금은 수동 해제 미지원** — IP 잠금과 달리 `account_lockouts`(분산 브루트포스 대응)는 관리자 대시보드의 "즉시 해제" 버튼이 아직 없어, 5분 자동 해제만 기다릴 수 있습니다.
- **대시보드 화면은 아직 역할을 모름** — RBAC는 서버 API(`require_permission`)에서만 강제됩니다. `dashboard.js`는 로그인한 관리자의 역할과 무관하게 버튼(회원 삭제, 회원가입 토글 등)을 전부 그려서 보여주고, 권한이 없는 역할이 눌러도 서버가 403으로 막을 뿐 화면에 "권한 없음" 안내는 뜨지 않고 조용히 실패합니다.
- **L3/L4(네트워크/전송 계층) 공격 대응은 아직 없음** — 현재 방어 로직은 전부 HTTP 요청(L7) 내용을 근거로 판단합니다. SYN Flood, 포트 스캐닝처럼 그보다 아래 계층에서 발생하는 공격은 별도의 관찰 지점(리버스 프록시/방화벽 등) 설계가 필요하며, 이 프로젝트의 다음 확장 목표입니다.
- **개발용 서버 사용** — `app.run(debug=True)`는 Flask가 공식적으로 "운영 배포에 쓰지 말라"고 명시하는 개발용 서버입니다. 외부 공개 서비스로 배포하려면 별도의 프로덕션 WSGI 서버(gunicorn 등)로 교체해야 합니다.
- **감시 대상 계정은 데모 수준 인증** — 이메일 인증, 비밀번호 재설정, 계정 잠금 셀프 해제 같은 기능은 제공하지 않습니다. `/login`은 실사용 서비스가 아니라 브루트포스 탐지를 시연하기 위한 화면입니다.
- **IP 위치 조회는 참고용** — ip-api.com 무료 API는 HTTPS를 지원하지 않고(서버 간 통신이라 브라우저 보안 경고와는 무관), 도시 단위 정확도가 완벽하지 않을 수 있습니다. `127.0.0.1` 같은 사설 IP는 항상 "위치 확인 불가"로 표시됩니다.
- **게시판은 회원 전용, 대댓글·첨부파일 미지원** — 비로그인 사용자는 글 목록조차 볼 수 없고, 댓글은 단일 depth(답글 불가)이며 이미지/파일 첨부도 지원하지 않습니다. 회원이 탈퇴해도 작성한 글·댓글은 삭제되지 않고 흔적만 남습니다(감사 로그와 동일한 정책). 새 댓글 알림은 웹소켓이 아니라 폴링(기본 5초, `BOARD_COMMENT_POLL_MS`) 방식입니다. 설계 배경은 [docs/board-comment/02-design-decisions.md](docs/board-comment/02-design-decisions.md) 참고.
- **게시글 id 순차 조회(스크래핑) 미차단** — 로그인만 하면 다른 회원의 글 id를 하나씩 순차 조회해 게시판 전체를 스크래핑하는 것 자체는 막지 않습니다. 게시판이 "회원 전체 공개" 설계이므로 이는 버그가 아니라 의도된 범위입니다.
- **Slowloris 등 저속 연결형 DoS는 스코프 밖** — 연결을 아주 느리게 유지해 서버 자원을 고갈시키는 공격은 애플리케이션 코드가 아니라 리버스 프록시·WAF 같은 인프라 레벨에서 막아야 하는 유형이라 이 프로젝트에서는 다루지 않습니다.

## test 문장입니다 branch