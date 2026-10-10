# 49단계 — `scripts/` 정리와 시뮬레이션 일괄 점검

[◀ 48단계](guide48_nextjs_dashboard.md) · [전체 목차](beginner-guide.md)

> 기능은 그대로이고, 터미널에서 쓰는 도구를 **용도별 폴더**로 나눴습니다. 그리고 지금까지 빠져 있던 공격 시뮬레이션 10종을 채우고, 시뮬레이션 전부를 한 번에 점검하는 도구를 만들었습니다.

## 왜 바꿨나

`scripts/` 바로 아래에 파일이 20개 가까이 쌓여, 무엇이 "공격을 흉내 내는 것"이고 무엇이 "운영자가 쓰는 도구"인지 파일 이름만으로는 알기 어려웠습니다. 또 위험등급 CRITICAL/HIGH 중에는 시뮬레이터가 없어서, 기능을 고친 뒤 "아직 탐지가 되는가"를 사람이 손으로 확인해야 했습니다.

## 폴더 구조

```
scripts/
├── simulation/                  공격 시뮬레이터 — 서버가 탐지하는지 확인한다
│   ├── _sim_common.py           공용 부품(로컬 서버 확인, CSRF 토큰 읽기 등) — 예전 scripts/_sim_common.py
│   ├── critical/                CRITICAL 등급
│   ├── high/                    HIGH 등급
│   └── medium/                  MEDIUM 등급
├── management/                  운영 도구 — 잠금 해제, 계정 생성, 리포트
└── demo/                        시연·점검용 — 가짜 데이터 서버, 시뮬레이션 일괄 점검
```

### 옛 경로 → 새 경로

| 폴더 | 파일 |
|---|---|
| `simulation/critical/` | `bruteforce_sim.py`, `password_spraying_sim.py` (옮김) · `distributed_bruteforce_sim.py`, `admin_bruteforce_sim.py`, `admin_distributed_bruteforce_sim.py`, `permanent_lock_sim.py`, `incident_correlation_sim.py` (새로 추가) |
| `simulation/high/` | `signup_abuse_sim.py`, `spam_sim.py` (옮김) · `http_flood_sim.py`, `comment_spam_sim.py`, `recovery_flood_sim.py` (새로 추가) |
| `simulation/medium/` | `macro_bot_sim.py`, `repeated_access_sim.py`, `unauthorized_access_sim.py`, `web_scanning_sim.py` (옮김) · `honeypot_bot_sim.py` (새로 추가) |
| `management/` | `create_admin.py`, `daily_report.py`, `delete_security_events.py`, `send_test_mail.py`, `tune_thresholds.py`, `unlock_account.py`, `unlock_ip.py` |
| `demo/` | `demo_server.py` (옮김) · `check_simulations.py`, `memory_supabase.py` (새로 추가) · 이후 `generate_demo_logs.py` 등 샘플 로그 도구가 더해졌다([50단계](guide50_demo_sample_logs.md)) |

이전 단계 문서에 `python scripts/unlock_ip.py`처럼 적힌 곳은 모두 새 경로(`scripts/management/unlock_ip.py`)로 고쳐 두었습니다. 스크립트가 프로젝트 루트의 `config.py`·`db`를 찾는 부분(`sys.path`)도 한 단계 깊어진 폴더에 맞게 고쳤습니다.

## 새 시뮬레이터가 확인하는 것

| 시뮬레이터 | 흉내 내는 공격 | 기대하는 결과 (보안 이벤트) |
|---|---|---|
| `critical/distributed_bruteforce_sim.py` | IP를 바꿔 가며 한 계정만 노림 | 계정 단위 잠금, `DISTRIBUTED_BRUTE_FORCE` (guide24) |
| `critical/admin_bruteforce_sim.py` | `/admin/login` 무차별 대입 | IP 잠금, `ADMIN_BRUTE_FORCE` |
| `critical/admin_distributed_bruteforce_sim.py` | 관리자 아이디 하나를 여러 IP로 | 관리자 계정 단위 잠금, `ADMIN_DISTRIBUTED_BRUTE_FORCE` (guide38) |
| `critical/permanent_lock_sim.py` | 임시 잠금을 두 번 받는 상습범 | 영구 잠금, `PERMANENT_LOCK` (guide33) |
| `critical/incident_correlation_sim.py` | 정찰 → 침투 → 브루트포스 다단계 | 사건으로 묶임 + 영구 차단 (guide27·28) |
| `high/http_flood_sim.py` | 같은 IP의 대량 GET | 429, `HTTP_FLOOD` (guide24) |
| `high/comment_spam_sim.py` | 댓글 도배 | `COMMENT_RATE_LIMIT` |
| `high/recovery_flood_sim.py --target …` | 복구·비밀번호 찾기·이메일 확인 엔드포인트 폭주 | 엔드포인트별 좁은 한도 429 (guide37·40·41·43) |
| `medium/honeypot_bot_sim.py` | 숨김 칸까지 채우는 봇 | `BOT_DETECTED`, 실패로 세지 않음 (guide24) |

공통 안전 규칙은 예전 시뮬레이터와 같습니다: **본인 소유의 로컬 서버만** 대상으로 하고, 가짜 공격자 IP(`--ip`, `X-Forwarded-For`)는 서버가 `TRUST_FORWARDED_FOR=true`일 때만 반영됩니다. 꺼져 있으면 진짜 접속 IP가 잠기므로 그때는 `scripts/management/unlock_ip.py`로 풉니다.

## 한 번에 점검하기 — `check_simulations.py`

```bash
python scripts/demo/check_simulations.py              # 시뮬레이션 전부
python scripts/demo/check_simulations.py honeypot     # 이름에 'honeypot'이 들어간 것만
```

1. **메모리 DB를 붙인 서버**를 `127.0.0.1:5000`에 띄웁니다. 진짜 Supabase·Slack·메일에는 아무것도 보내지 않습니다.
2. 시뮬레이션을 하나씩 실행하기 전에 기록·잠금·요청 한도 카운터를 비웁니다.
3. 각각에 대해 (a) 종료 코드가 0인지, (b) 서버가 기대한 `(event_type, severity)`를 `security_events`에 실제로 남겼는지 대조해 `PASS`/`FAIL`로 보여줍니다. 실패하면 누락된 이벤트와 시뮬레이션 출력 끝 15줄을 함께 보여줍니다.

`python app.py`로 띄운 개발 서버가 5000번을 쓰고 있으면 먼저 끄세요. 몇몇 시뮬레이션(`signup_abuse_sim`, `unauthorized_access_sim`)이 5000번을 고정으로 쓰기 때문입니다. `permanent_lock_sim`이 5분을 기다리지 않도록 점검기는 임시 잠금을 3초로, 복구 요청의 고정 대기를 0초로 줄여 서버를 띄웁니다.

### 메모리 DB — `memory_supabase.py`

이 가짜 Supabase(`MemoryClient`)는 표를 파이썬 리스트로 들고 있어서 `insert`한 행을 기억하고 `eq`·`gt`·`in_`·`or_` 같은 조건으로 걸러 셉니다. 그래서 "60초 안에 5번 틀리면 잠금" 같은 탐지가 진짜처럼 동작합니다. `db` 패키지가 실제로 쓰는 연산(`select(count)`/`insert`/`update`/`delete`/`upsert`와 필터·정렬)만 흉내 냅니다. 개발·점검용이며 운영에서는 쓰지 않습니다. (50단계에서 `demo_server.py`도 이 메모리 DB를 쓰도록 바뀌었고, 표별 기본값·기본키·`users(username)` 연결 조회 등을 보완했습니다 — [guide50](guide50_demo_sample_logs.md).)

## 실제로 확인한 것

- 옛 경로(`scripts/xxx.py`)를 가리키던 README·docs의 설명과 링크를 새 경로로 바꾼 뒤, 문서 안 상대 링크가 모두 실제 파일을 가리키는지 확인했습니다.
- 테스트(`tests/test_unlock_ip.py`, `test_tune_thresholds.py`, `test_send_test_mail.py` 등)가 새 위치의 스크립트를 가져오도록 고쳤고, 전체 테스트가 통과합니다.
