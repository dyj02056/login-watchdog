# 터미널 도구(scripts/) 안내

> 요약은 [루트 README](../README.md)에 있습니다. 이 문서는 README에서 옮겨 온 세부 내용입니다.

Web Scanning 탐지는 `py scripts/simulation/medium/web_scanning_sim.py --host http://127.0.0.1:5000`으로
GET 11회를 보내 재현할 수 있습니다. [실행 조건과 알림 확인 방법](web-scanning-demo.md)을 참고하세요.

`scripts/` 아래에 있으며, 웹 서버(`app.py`)와 별개로 터미널에서 직접 실행하는 도구들입니다. 용도별로 폴더가 나뉩니다 — `scripts/simulation/`(공격 시뮬레이터, 위험등급 `critical/`·`high/`·`medium/`별 폴더 + 공용 부품 `_sim_common.py`), `scripts/management/`(운영 도구: 잠금 해제·계정 생성·리포트 등), `scripts/demo/`(가짜 데이터 데모 서버·시뮬레이션 일괄 점검). 실행 전 가상환경 활성화가 필요합니다(`.\venv\Scripts\Activate.ps1` 등).

| 스크립트 | 역할 |
|---|---|
| `scripts/simulation/critical/bruteforce_sim.py` | `/login`에 일부러 틀린 비밀번호를 반복 제출해, 설정된 횟수(기본 5회 초과)에서 실제로 IP가 잠기는지 검증하는 시뮬레이터. 팀이 소유한 로컬 서버만 대상으로 하며, 그 외 주소는 `--i-know-what-im-doing` 없이는 거부됨. `--ip`로 가짜 공격자 IP를 지정하거나, Vercel 프리뷰 배포처럼 Vercel Authentication이 걸린 주소를 대상으로 할 때는 `--bypass-secret`으로 우회할 수도 있음(아래 참고) |
| `scripts/management/daily_report.py` | 최근 N시간(기본 24시간, `--hours`) 또는 지정 기간(`--start`/`--end`)의 로그인 시도·잠금 현황을 텍스트로 요약(`--output`으로 파일 저장). `--ai`를 붙이면 Groq가 쓴 AI 보안 총평을 덧붙임 |
| `scripts/management/unlock_ip.py` | 지금 잠겨있는 IP를 조회하거나 즉시 해제. `/admin/login`도 `/login`과 같은 IP 기준 잠금을 공유하므로, 브루트포스 시뮬레이션 도중 관리자 계정 IP까지 함께 잠기면 대시보드의 "즉시 해제" 버튼조차 쓸 수 없는 상황이 생기는데(로그인 자체가 막혀서), 이때 서버·로그인 없이 터미널에서 바로 풀 때 사용. 영구 잠금은 `--permanent`를 붙여야만 풀리고(`--note`로 해제 사유 기록), 없으면 건너뜀 |
| `scripts/management/unlock_account.py` | 잠긴 계정(분산 브루트포스 대응 계정 잠금)을 조회하거나 즉시 해제. 영구 잠금은 `unlock_ip.py`와 같이 `--permanent`가 있어야 풀림 |
| `scripts/management/send_test_mail.py` | 지금 메일 설정(SMTP)으로 테스트 메일 한 통을 보내 접속·인증·발송이 되는지 확인. 실패하면 원인(`CONFIG`/`AUTH`/`CONNECT`/`OTHER`)과 고칠 곳을 알려주며, 비밀번호는 출력하지 않음 |
| `scripts/management/create_admin.py` | `security_viewer`/`security_admin`/`super_admin` 역할을 가진 새 관리자 계정을 생성. 대시보드 "관리자 계정 관리" 카드는 `super_admin`이 `security_viewer`/`security_admin`만 만들 수 있는 것과 달리, 이 스크립트는 터미널 접근 자체가 신뢰된 작업이라는 전제로 `super_admin`도 만들 수 있음(예: 최초 팀원 온보딩) |
| `scripts/simulation/medium/macro_bot_sim.py` | 이미 만들어진 관리자 계정으로 로그인한 뒤, 서로 다른 관리자 API 6개를 순서대로 호출해 매크로/봇 탐지가 실제로 알림을 울리는지 검증. `security_viewer`(무권한) 계정으로 실행하면 6번 모두 403으로 안전하게 거절되면서도 탐지 로그는 정상적으로 남음 |
| `scripts/management/delete_security_events.py` | 보안 이벤트를 터미널에서 영구 삭제(`--id` 한 건 / `--resolved` 처리 완료된 것 전부 / `--all` 전부). 옵션 없이 실행하면 건수만 조회 |
| `scripts/simulation/critical/password_spraying_sim.py` · `high/signup_abuse_sim.py` · `high/spam_sim.py` · `medium/repeated_access_sim.py` · `medium/unauthorized_access_sim.py` · `medium/web_scanning_sim.py` | 패스워드 스프레이·가입 도배·글 도배·반복 페이지 접근·미인증 API 접근·웹 스캐닝을 로컬 서버에 재현해 탐지·알림을 확인하는 시뮬레이터(공용 부품은 `scripts/simulation/_sim_common.py`). 기본 대상은 로컬 서버이며, 본인 소유·허가된 서버에만 사용(일부는 로컬이 아닌 주소를 `--i-know-what-im-doing` 없이 거부) |
| `scripts/management/tune_thresholds.py` | 최근 N일(기본 7일)간 CRITICAL 잠금 중 자동 만료 전에 수동으로 조기 해제된 비율을 event_type별로 집계하는 완전한 읽기 전용 리포트. 비율이 높으면 임계값이 너무 예민할 수 있다는 신호 |
| `scripts/simulation/critical/` 신규 5종 | `distributed_bruteforce_sim`(IP를 바꿔 한 계정을 노리는 계정 단위 잠금) · `admin_bruteforce_sim`(`/admin/login` IP 잠금) · `admin_distributed_bruteforce_sim`(관리자 계정 단위 잠금) · `permanent_lock_sim`(임시 잠금 2회 → 영구 잠금, 기본 305초 대기) · `incident_correlation_sim`(정찰→침투→브루트포스 다단계 → 사건화·영구 차단). 가짜 IP는 서버 `TRUST_FORWARDED_FOR=true`일 때만 반영 |
| `scripts/simulation/high/` 신규 3종 | `http_flood_sim`(전역 요청 한도 429) · `comment_spam_sim`(댓글 도배, 테스트 계정 필요) · `recovery_flood_sim --target recovery\|recovery-verify\|password-forgot\|password-reset\|email-confirm`(엔드포인트별 좁은 한도 429) |
| `scripts/simulation/medium/honeypot_bot_sim.py` | 숨김 `website` 칸을 채워 `/login`·`/signup`에 제출하는 봇을 흉내 내 `BOT_DETECTED`로 걸러지는지 검증 |
| `scripts/demo/generate_demo_logs.py` | **7일치 샘플 로그 생성기.** 로컬 서버를 켜고 가짜 회원을 실제 `/signup`으로 가입시킨 뒤, 정상 접속과 공격 시뮬레이션 21종을 시각 순서대로 돌려 `scripts/demo/output/demo_logs.json`에 저장한다(진짜 Supabase·Slack·메일·Groq 미접속). 공격자 IP는 17개국의 실제 할당 대역에서 뽑고, AI 조기경보는 기본적으로 로컬 판정기로 만들고, `--use-groq`를 주면 진짜 Groq API로 판정한다(`.env`의 `GROQ_API_KEY` 필요, 샘플 데이터가 Groq로 전송됨). `--seed 숫자`(같은 숫자 = 같은 결과), `--days`, `--members` |
| `scripts/demo/demo_server.py` | 위 JSON을 읽어 Supabase·Slack·메일 없이 관제 화면(`/admin/*`)·회원 화면을 띄우는 데모 서버(포트 5077). 열 때마다 기록 시각을 "지금" 기준으로 옮겨 항상 최근 7일처럼 보인다. `/__demo_login`(관리자)·`/__demo_member`(회원)으로 로그인 |
| `scripts/demo/load_demo_to_supabase.py` | (선택) 같은 샘플 로그를 **실제 Supabase**에 넣는다. 기본은 미리보기, `--apply`로 적재(DB 주소 입력 확인), `--purge`로 넣은 행만 삭제. 회원 비밀번호는 로그인 불가 값으로 넣고 관리자 계정은 넣지 않는다. 별도의 빈 프로젝트에 넣는 것을 권장 |
| `scripts/demo/demo_data.py` | 위 세 스크립트가 같이 쓰는 재료(나라별 IP 대역, 가짜 회원 이름, 시각 이동 규칙) |
| `scripts/demo/memory_supabase.py` | 메모리에 사는 가짜 Supabase(`MemoryClient`). 표를 리스트로 들고 있어 insert한 행을 기억하고 조건으로 걸러 세므로 "5번 틀리면 잠금" 같은 탐지가 진짜처럼 동작합니다. `check_simulations.py`가 씀 |
| `scripts/demo/check_simulations.py` | 시뮬레이션 전체를 한 번에 점검. 메모리 DB(`memory_supabase.py`)를 붙인 서버를 127.0.0.1:5000에 띄워 시뮬레이션을 실행하고, 서버가 기대한 보안 이벤트를 실제로 기록했는지 대조한다(진짜 Supabase·Slack·메일 미접속). `python scripts/demo/check_simulations.py [이름 일부]` |

**Track D 점검 스크립트** (`scripts/net/`, Docker 단지를 켠 뒤 내 PC에서 실행 — 공격은 일회용 공격 상자 컨테이너로 보내고 DB는 읽기만 함, 자세한 내용은 [netwatch/README.md](../netwatch/README.md) 7·9장)

| 스크립트 | 역할 |
|---|---|
| `scripts/net/run_all.py` | 시연 시나리오 S4·S5·S5b·S6·S8(S7)을 `--repeat N`번 돌려 기대 결과가 DB·응답·메일에 생겼는지 PASS/FAIL로 채점하고 `docs/track-d/scenario-results.md`에 덧붙임. 시나리오 하나만은 `check_s4.py`~`check_s8.py` |
| `scripts/net/measure_detect_to_block.py` | SYN 폭주를 탐지한 뒤 정문에서 L4로 막기까지 걸린 시간을 DB 시각으로 재 `docs/track-d/measurements.md`에 기록(`--scenario s5\|s5b --repeat 3`) |

`bruteforce_sim.py`의 `--ip` 옵션: 로컬 환경에서는 팀원 전원이 다 같은 `127.0.0.1`로 접속하게 되어 "서로 다른 공격자 IP에서 왔다"는 상황을 재현할 수 없다. `--ip 1.2.3.4`를 주면 그 값을 `X-Forwarded-For` 헤더에 실어 보내는데, 이 헤더는 대상 서버의 `.env`에서 `TRUST_FORWARDED_FOR=true`로 켜뒀을 때만 실제 접속 IP처럼 반영된다(운영 환경 기본값인 `false`에서는 서버가 헤더를 무시하고 진짜 접속 IP를 그대로 씀 — 배포 사이트에서 이 옵션이 안전하게 아무 효과가 없는 이유).
```bash
python scripts/simulation/critical/bruteforce_sim.py --host http://127.0.0.1:5000 --username test1 --ip 1.2.3.4
```

`bruteforce_sim.py`의 `--bypass-secret` 옵션: Vercel 프리뷰 배포(`*.vercel.app`)는 기본적으로 Vercel Authentication으로 보호되어 있어, 팀원이 아니면 `/login` 화면 자체에 접근하지 못한다. `--bypass-secret`에 Vercel의 Protection Bypass Secret 값을 넘기면 `x-vercel-protection-bypass` 헤더로 실어 보내 이 보호를 우회한다. 생략하면 `.env`의 `VERCEL_AUTOMATION_BYPASS_SECRET` 값을 자동으로 사용하며, 로컬 서버를 대상으로 할 때는 지정해도 아무 효과가 없다.
```bash
python scripts/simulation/critical/bruteforce_sim.py --host https://<브랜치>-git-<프리뷰경로>.vercel.app --username test1 --i-know-what-im-doing
```

`unlock_ip.py` 사용 예:
```bash
python scripts/management/unlock_ip.py                # 현재 활성 잠금 목록만 조회 (아무것도 바꾸지 않음)
python scripts/management/unlock_ip.py --ip 127.0.0.1  # 이 IP 하나만 즉시 해제
python scripts/management/unlock_ip.py --all           # 활성 잠금 전부 즉시 해제 (영구 잠금은 건너뜀)
python scripts/management/unlock_ip.py --ip 1.2.3.4 --permanent --note "오탐 확인"   # 영구 잠금 해제 (사유 기록)
python scripts/management/unlock_account.py --username alice --permanent --note "본인 확인 완료"
```

`send_test_mail.py` 사용 예 (배포 전에 메일 설정 확인):
```bash
python scripts/management/send_test_mail.py --to 내이메일@gmail.com
```

`create_admin.py` 사용 예:
```bash
python scripts/management/create_admin.py --username sktviewer123 --password <비밀번호> --role security_viewer
python scripts/management/create_admin.py --username sktadmin123 --password <비밀번호> --role security_admin
```
