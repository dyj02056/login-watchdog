# 프로젝트 구조 (파일 단위)

> 요약은 [루트 README](../README.md)에 있습니다. 이 문서는 README에서 옮겨 온 세부 내용입니다.

`app.py`(1,108줄)와 `db.py`(1,030줄)가 파일 하나에 너무 많은 책임을 담고 있어 원하는 코드를 찾기 어려워졌던 것을 계기로, 각각 `routes/` Blueprint와 `db/` 표 묶음별 패키지로 쪼갰습니다(배경은 [docs/refactor/2026-09-15-file-split.md](refactor/2026-09-15-file-split.md) 참고). 이후 루트에 흩어져 있던 모듈 13개를 기능별 폴더(`security/`, `notify/`, `services/`, `helpers/`)로 묶고, 200줄이 훨씬 넘던 `routes/admin.py`·`soar.py`·`helpers.py`·대시보드 JS도 기능 묶음별로 나눴습니다(배경은 [docs/refactor/2026-10-09-module-plan.md](refactor/2026-10-09-module-plan.md) 참고). 모듈 이름은 그대로라서 호출부는 `from security import soar` 후 `soar.enforce_lockout(...)`, `import db` 후 `db.log_attempt(...)`처럼 쓰며, 패키지 안의 어느 파일이 실제로 그 함수를 담고 있는지는 몰라도 됩니다.

```
login-watchdog/
├── PRODUCT.md                     # 관제 화면 디자인 기준(사용자·톤·원칙)
├── app.py                         # Flask 진입점(Vercel이 루트의 app을 찾음) — 앱 생성, 세션/CSRF/요청 한도 설정, Blueprint 등록
├── config.py                      # 임계값·윈도우·잠금시간·입력 형식 규칙 등 상수
├── security/                      # 보안 엔진: 탐지 → 상관분석 → 대응
│   ├── detector.py                #   "수상한가?" 판정 (임계값 비교, 잠금 상태 조회)
│   ├── correlate.py               #   같은 IP의 서로 다른 이벤트를 사건으로 묶기 (SIEM) + Track D 교차 규칙 NET-01·CR-01~03
│   ├── lockdown.py                #   영구 잠금 승격·해제·이메일 복구 반영 (해제 시 L4 차단도 해제 요청)
│   ├── net_ingest.py              #   Track D: 네트워크 경보 → 보안 이벤트 승격, NET_BLOCKED 기록·해결
│   ├── netblock.py                #   Track D: L4 차단·해제 요청을 network_blocks 장부에 기록(TTL 계산, 허용 목록 거부)
│   ├── playbooks.py               #   Track D: 규칙별 대응 절차(플레이북) 실행·단계 기록
│   └── soar/                      #   판정 결과를 실제 조치로 실행 (SOAR) — 함수는 __init__.py가 재내보내기
│       ├── lockouts.py            #     enforce_*(잠금 집행), try_release_expired_*/manual_release_*(해제)
│       ├── observe.py             #     notify_*(알림 + 기록만), record_rejection(HIGH 거부 기록)
│       ├── early_warning.py       #     LLM 조기 경보, 관리자 승인/반려
│       └── _events.py             #     이벤트 기록 + 상관분석 훅(공용)
├── notify/                        # 밖으로 알리는 채널
│   ├── alert.py                   #   Slack 알림
│   └── mailer.py                  #   메일 발송 (console/SMTP, 실패 원인 분류 + Slack 알림)
├── services/                      # 외부 연동·계정 부가 흐름
│   ├── email_verification.py      #   이메일 인증·변경 확인·비밀번호 재설정 토큰
│   ├── llm_client.py              #   Groq LLM 호출, 조기 경보 판정
│   ├── geoip.py                   #   IP 위치(국가·도시) 조회, 캐싱
│   └── ip_utils.py                #   IP 정규화(IPv6 /64 대역)
├── helpers/                       # 라우트 공용 함수 — `from helpers import ...`로 사용 (__init__.py가 재내보내기)
│   ├── auth.py                    #   관리자/회원 세션, login_required/require_permission/member_login_required
│   ├── request_utils.py           #   get_request_ip, 허니팟, 위치 붙이기, 아이디 가리기
│   ├── device.py                  #   hash_secret, 기기 쿠키
│   ├── timing.py                  #   응답 시간 고정(계정 존재 여부 노출 방지)
│   ├── spa.py                     #   Next.js 정적 화면 서빙 + 기존 라우트 응답을 JSON 봉투로 바꾸는 어댑터
│   └── hooks.py                   #   모든 요청에 걸리는 훅(보안 헤더, 404 기록 + 404 화면 연결, 반복 접근·매크로 관찰)
├── routes/                        # Blueprint — 실제 화면 라우트
│   ├── auth.py                    #   auth_bp: /signup, /login
│   ├── admin/                     #   admin_bp: /admin/*, /api/*(관리자용, RBAC로 세분화)
│   │   ├── login.py               #     /admin/login, /admin/logout
│   │   ├── status.py              #     /admin/dashboard, /api/status(대시보드 폴링)
│   │   ├── locks.py               #     잠금 해제, 영구 잠금, IP 예외·복구 요청 회수
│   │   ├── incidents.py           #     AI 조기 경보 승인/반려, 보안 이벤트·연관 사건 처리
│   │   └── manage.py              #     회원·회원가입 설정·게시판·관리자 계정 관리
│   ├── board.py                   #   board_bp: /board/*
│   ├── member.py                  #   member_bp: /dashboard/* (프로필, 비밀번호 변경)
│   ├── email.py                   #   email_bp: /email/confirm (이메일 인증 링크)
│   ├── password.py                #   password_bp: /password/* (비밀번호 찾기)
│   ├── recovery.py                #   recovery_bp: /recovery/* (영구 잠금 이메일 인증 복구)
│   └── internal/                  #   Track D 내부 창구 /api/internal/* (HMAC 서명 필수, CSRF 제외)
│       ├── _hmac.py               #     보낸이별 키로 서명·시각 검사
│       ├── ingest.py              #     POST net-events — shipper가 보낸 센서 경보 접수
│       ├── blocks.py              #     GET blocks / POST blocks/ack — fw-agent의 차단 목록·결과 보고
│       └── heartbeat.py           #     POST heartbeat — shipper·fw-agent 생존 신호
├── db/                            # Supabase 연동 — 표 묶음별 패키지, 호출부는 db.함수명()으로 사용
│   ├── __init__.py                #   하위 모듈 함수를 전부 다시 내보내기(re-export)
│   ├── _client.py                 #   get_client(), _now_iso() — Supabase 연결(HTTP/1.1 + 조회 1회 재시도)
│   ├── attempts.py                #   login_attempts (로그인 시도 기록)
│   ├── lockouts.py                #   lockouts (IP 잠금 현재 상태 — 임시/영구)
│   ├── lock_history.py            #   lock_history (잠금 이력 — 영구 승격 횟수 판단)
│   ├── recovery.py                #   recovery_requests, users.email_status (이메일 복구)
│   ├── ip_exemptions.py           #   ip_lock_exemptions (IP 영구 잠금 본인 기기 예외)
│   ├── account_lockouts.py        #   account_lockouts (계정 단위 잠금, 분산 브루트포스 대응)
│   ├── admin.py                   #   admin_users, admin_login_log (관리자 계정/로그인 기록/역할)
│   ├── admin_lockouts.py          #   admin_account_lockouts (관리자 계정 단위 잠금)
│   ├── roles.py                   #   roles, permissions (RBAC — 역할별 허용 액션)
│   ├── stats.py                   #   관제 화면(/api/stats) 집계 — 시간대별·7일 로그량·히트맵·신규 공격자 (새 표 없음)
│   ├── users.py                   #   users (회원 계정)
│   ├── settings.py                #   app_settings, signup_attempts (설정값, 가입 빈도 제한)
│   ├── geoip_cache.py             #   ip_locations (IP 위치 조회 캐시)
│   ├── board.py                   #   posts, comments, post_attempts, comment_attempts (게시판)
│   ├── access_logs.py             #   not_found/unauthorized/page_access_attempts (요청 로그)
│   ├── security_events.py         #   security_events (위험등급 이벤트)
│   ├── incidents.py               #   security_incidents (SIEM 상관분석)
│   ├── access_requests.py         #   access_requests (AI 조기 경보 승인 대기)
│   ├── email_tokens.py            #   email_tokens (이메일 인증·변경·비밀번호 재설정 링크)
│   ├── api_access_log.py          #   api_access_log (매크로/봇 탐지)
│   ├── network_events.py          #   Track D: network_events (센서 경보 원본) + 교차 규칙용 조회
│   ├── network_blocks.py          #   Track D: network_blocks (L4 차단 장부)
│   ├── agent_heartbeats.py        #   Track D: agent_heartbeats (장비 생존 신호), notification_cooldowns (알림 쿨다운)
│   └── playbook_runs.py           #   Track D: playbook_runs (플레이북 단계 기록)
├── netwatch/                      # Track D Docker 단지 구성품 — 실행 안내는 netwatch/README.md
│   ├── nginx/                     #   정문(gateway) 설정 — X-Forwarded-For를 실제 출발지로 덮어씀, 바깥에서 /api/internal/은 404
│   ├── suricata/                  #   센서(시그니처 IDS) 설정·우리 규칙(local.rules)
│   ├── l4_detector/               #   Scapy L4 측정기(SYN 비율·포트 수)
│   ├── shipper/                   #   센서 기록을 서명해 앱으로 보내는 배달원
│   ├── fw_agent/                  #   차단 목록을 받아 ipset에 넣고 빼는 차단 프로그램
│   └── attacker/                  #   연습용 공격 상자(lw.py: scan·webscan·brute·scanner-ua·login·synflood·httpflood)
├── docker-compose.yml, Dockerfile # Track D 단지 정의(edge·core·egress 네트워크, 서비스 7개 + 공격 상자) / 앱 컨테이너(gunicorn)
├── web/                           # Next.js(React, TypeScript) 화면 소스 — src/app(화면 주소), src/components, src/lib(api·폴링), src/styles. `npm run build`가 spa/·public/_next/를 만든다 (web/README.md, guide48)
├── spa/                           # Next.js 빌드 결과 HTML(화면 껍데기) — Flask가 helpers/spa.py로 서빙, 저장소에 커밋
├── templates/                     # 예전 Jinja2 화면 — spa/가 없거나 SPA_ENABLED=false일 때 폴백 (admin_dashboard/ — 대시보드 표 조각)
├── public/_next/                  # Next.js 빌드 결과 JS·CSS·폰트(해시 이름, 길게 캐시) — 커밋 대상
├── public/css, public/js/dashboard/ # 폴백용 Jinja 화면의 스타일 및 대시보드 자바스크립트(ES 모듈 — api.js 조회, actions.js 변경, render/ 표 그리기)
├── tests/                         # pytest 단위 테스트
├── scripts/                       # 터미널 도구 — docs/scripts.md 참고
│   ├── simulation/                #   공격 시뮬레이터: critical/(브루트포스·분산·관리자·영구 잠금·사건화) · high/(도배·HTTP 플러딩·복구 폭주) · medium/(웹 스캐닝·허니팟·매크로 등), _sim_common.py(공용 부품)
│   ├── management/                #   운영 도구: unlock_ip/unlock_account, create_admin, daily_report, tune_thresholds, delete_security_events, send_test_mail
│   ├── demo/                      #   generate_demo_logs.py(7일치 샘플 로그 생성) + demo_server.py(그 로그로 화면 확인) + load_demo_to_supabase.py(선택: 실제 DB 적재), check_simulations.py + memory_supabase.py(시뮬레이션 일괄 점검)
│   └── net/                       #   Track D 점검: run_all.py·check_s*.py(시나리오 채점), measure_detect_to_block.py(탐지→차단 시간)
├── docs/schema.sql                # Supabase 테이블 정의
├── docs/migrations/               # 기존 DB에 추가로 실행할 SQL (guide33 영구 잠금, guide35 비밀번호 변경, guide38 관리자 계정 잠금, guide40 이메일 인증, guide44 로그 자동 정리, guide47 일별 요약, guide52 Track D 표·칸, guide53 Track D 보존, guide56 Track D 예외 상황 보완)
├── docs/track-d/                  # Track D 연동 계약서(contracts.md), 탐지→차단 측정 결과, 시나리오 점검 결과, 순서도 해설
├── .github/workflows/             # tests.yml(push/PR마다 pytest + Next.js 타입 검사·빌드 결과 일치 확인 + Suricata 규칙 검사), supabase-keep-alive.yml(무료 Supabase가 멈추지 않게 매일 호출), pages.yml(순서도 해설 GitHub Pages)
├── vercel.json                    # Vercel 설정 — spa/ 포함, _next 정적 파일 장기 캐시
├── docker-compose.mailpit.yml     # 개발용 가짜 메일 서버(Mailpit) — 앱을 Docker 없이 실행할 때만 (Track D 단지에는 Mailpit이 이미 들어 있음)
├── docs/beginner-guide/           # 비전공자용 단계별 구현 해설서 (단계별 파일로 분리)
├── docs/board-comment/            # 게시판·댓글 기능 설계 문서(분석 → 결정 → 계획 → 결과)
├── docs/scenario.md, vpn-demo-guide.md, web-scanning-demo.md # 시연 대본 · VPN으로 서로 다른 IP를 쓰는 시연 · 웹 스캐닝 재현
├── docs/refactor/                 # 파일 분리·모듈화 리팩터링 배경 기록
└── plan.md, research.md           # 설계 근거 문서
```
