# 로그인 워치독 시연 시나리오

발표·시연 때 기능을 **공격 → 탐지 → 대응 → 복구** 순서로 보여주기 위한 대본입니다. 각 단계는 앞 단계의 결과를 이어서 쓰므로 순서대로 진행하는 것을 권장합니다. 기능별 코드 설명은 [01-feature-order.md](feature-reference/01-feature-order.md), 구현 해설은 [beginner-guide](beginner-guide/beginner-guide.md)를 참고하세요.

## 0. 준비

| 항목 | 내용 |
|---|---|
| 서버 | 로컬: `python app.py` (http://127.0.0.1:5000) / 배포: https://login-watchdog.vercel.app |
| 가짜 공격 IP | 로컬 시연에서는 `.env`에 `TRUST_FORWARDED_FOR=true`, 시뮬레이터에 `--ip`로 지정. **배포에서는 절대 켜지 않습니다** |
| 메일 | 로컬은 Mailpit(`docker compose -f docker-compose.mailpit.yml up -d`, 메일함 http://127.0.0.1:8025) 또는 `MAIL_BACKEND=console`. 배포는 Gmail SMTP(앱 비밀번호, guide34a) |
| 관리자 | `super_admin` 계정 1개, 가능하면 `security_admin` 계정 1개(권한 차이 시연용) |
| 테스트 회원 | 받을 수 있는 이메일로 가입한 회원 1개(복구 메일 시연용) |
| 화면 배치 | 관제 보드가 3개로 나뉘어 있습니다 — **위협 현황**(`/admin/dashboard`: KPI·시간대별 추이·히트맵·공격 흐름도), **공격 상세**(`/admin/attack`: Top 5·국가별 흐름·실시간 이벤트), **처리 작업대**(`/admin/ops`: 잠금·보안 이벤트·AI 조기 경보·영구 잠금 카드 등 버튼으로 처리하는 모든 기능). 이 대본의 "카드"·"표"는 따로 적지 않으면 처리 작업대에 있습니다. 한쪽에는 위협 현황(또는 공격 상세), 다른 쪽에는 처리 작업대를 띄워 두면 5초마다 결과가 갱신됨(탭이 **보이는 상태**여야 갱신됨 — 다른 탭으로 가면 폴링이 멈췄다가 돌아오면 즉시 갱신) |
| 시연용 샘플 로그(선택) | 실제 공격을 돌리지 않고 대시보드만 보여 줄 때: 가상환경을 켠 뒤 `python scripts/demo/generate_demo_logs.py`(약 2분)로 7일치 기록을 만들고 `python scripts/demo/demo_server.py` → http://127.0.0.1:5077/__demo_login. 진짜 DB·Slack·메일 미접속. 배포 대시보드에 보여야 하면 `load_demo_to_supabase.py --apply`(선택, [guide50](beginner-guide/guide50_demo_sample_logs.md)) |
| 시연 전 점검(선택) | `python scripts/demo/check_simulations.py` — 가짜 DB를 붙인 서버에서 시뮬레이터 전부를 돌려 기대한 보안 이벤트가 기록되는지 PASS/FAIL로 확인합니다(진짜 DB·Slack·메일 미접속, 5000번 포트를 쓰므로 `python app.py`는 끄고 실행). 화면 구성만 먼저 보고 싶다면 `python scripts/demo/demo_server.py` → http://127.0.0.1:5077/__demo_login |
| AI 조기 경보(1-1) | `.env`에 `GROQ_API_KEY`가 있어야 동작. 없으면 조기 경보 단계만 조용히 건너뛰고 나머지 시연은 그대로 됨 |
| 허용 목록 | 시연자 PC의 IP를 `PERMANENT_LOCK_IP_ALLOWLIST`에 넣어 두기(본인이 잠기는 사고 방지). 가짜 IP(`--ip`)는 넣지 않음 |

## 1. 브루트포스 → 자동 잠금 (3분)

1. `python scripts/simulation/critical/bruteforce_sim.py --host http://127.0.0.1:5000 --username demo --ip 203.0.113.10`
2. 6번째 실패에서 "잠긴 계정입니다" — IP가 5분 잠김
3. **보여줄 곳**: 대시보드 "현재 잠긴 IP / 계정" 카드, "보안 이벤트"의 `BRUTE_FORCE`(CRITICAL), Slack 알림
4. 같은 아이디를 여러 개로 바꿔 시도하면 `PASSWORD_SPRAYING`으로 구분되는 것도 보여줄 수 있음(`scripts/simulation/critical/password_spraying_sim.py`)
5. IP를 바꿔 가며 한 회원 계정만 노리는 분산 브루트포스는 `scripts/simulation/critical/distributed_bruteforce_sim.py` 한 번으로 재현됨 — 한 번도 실패하지 않은 새 IP에서도 계정이 잠겨 있으면 성공(`DISTRIBUTED_BRUTE_FORCE`)

## 1-1. 임계값 코앞 → AI 조기 경보 (2분, 선택)

1. 새 가짜 IP로 기준(5회 초과) **바로 아래까지만** 실패: `python scripts/simulation/critical/bruteforce_sim.py --username demo --attempts 4 --ip 203.0.113.30`
2. 3~5회째 구간(기준 − `EARLY_WARNING_BAND`)에서 LLM(Groq)에게 "지켜볼 필요가 있는지" 묻고, 위험하다고 판단하면 승인 대기로 등록
3. **보여줄 곳**: 대시보드 맨 위쪽 "AI 조기 경보" 표(유형·현재/기준·AI 판단 근거), Slack "[AI 조기 경보]" 알림 — 아직 잠기지 않은 상태라는 점
4. "승인"을 누르면 원래 기준을 넘었을 때 하던 조치(IP 잠금)가 지금 실행되고, "반려"하면 아무 일도 일어나지 않음
5. LLM이 위험하지 않다고 판단하면 표에 아무것도 생기지 않음 — 그것도 정상 동작(같은 입력이면 같은 결론이 나오도록 temperature를 낮게 고정)

## 2. 여러 공격이 겹치면 사건으로 묶임 (2분)

1. 같은 가짜 IP로 `python scripts/simulation/medium/web_scanning_sim.py --host http://127.0.0.1:5000` (존재하지 않는 경로 반복)
2. **보여줄 곳**: "연관 사건 (SIEM 상관분석)" 표에 한 IP의 여러 공격 유형이 한 줄로 묶임
3. 사건은 잠금이 풀려도 남아 있고, 관리자가 "해결"을 눌러야 닫힌다는 점을 설명

## 3. 반복 위반 → 영구 잠금 (3분)

1. `python scripts/management/unlock_ip.py --ip 203.0.113.10`으로 임시 잠금만 풀고, 1번을 다시 실행
2. 30일 안에 두 번째 잠금이라 **영구 잠금**으로 승격 — 로그인 화면이 "이 네트워크는 차단되어 있습니다"로 바뀌고, 올바른 비밀번호로도 막힘
3. **보여줄 곳**: "영구 잠금" 카드("영구" 배지, 승격 사유 "반복 위반"), 보안 이벤트의 `PERMANENT_LOCK`, 같은 IP에서 회원가입도 거부됨
4. 2번의 사건이 CRITICAL이었다면 이 단계 전에 이미 영구 잠금됐을 수 있음 — 그것도 "사건 등급 기반 승격"으로 설명

## 4. 이메일 인증 복구 (4분)

1. 영구 잠긴 IP에서 로그인 화면의 "본인 인증으로 잠금 해제" → 테스트 회원 아이디 입력
2. 응답이 약 5초 걸리고, 없는 아이디를 넣어도 똑같은 문구·시간으로 응답하는 것을 보여줌(계정 존재 여부 숨김)
3. 메일함에서 링크 확인 → **같은 브라우저**에서 열고 [해제]
4. 같은 IP의 다른 브라우저는 계속 차단되고, 이 회원·이 기기만 로그인되는 것을 보여줌
5. 다른 브라우저에서 같은 링크를 열면 "요청한 기기에서만"이라고 거부되는 것도 보여줌
5-a. 다른 브라우저의 "코드로 인증하기"에 테스트 회원 아이디·없는 아이디를 각각 넣으면 **똑같은 실패 문구**가 나오고, 틀린 코드를 여러 번 넣어도 요청한 기기의 "남은 시도"는 줄지 않는 것(남의 복구 취소 불가)을 보여줌(guide39)
6. **보여줄 곳**: "복구 요청" 카드(완료), "IP 예외" 카드(새 출입증)

## 5. 관리자 권한 분리 (2분)

1. `security_admin`으로 로그인 → "영구 잠금" 카드에 "super_admin 전용"만 보이고 해제 버튼이 없음
2. `super_admin`으로 로그인 → "영구 해제" 클릭 → 사유를 비우면 진행되지 않음 → 사유 입력 후 해제
3. "IP 예외" 카드의 "회수"로 4번에서 발급된 출입증 회수

## 5-1. 관리자 계정 분산 브루트포스 → 계정 잠금 (2분)

1. IP를 바꿔가며 IP당 4회씩(IP 잠금에 안 걸리게) 관리자 로그인에 실패:
   `python scripts/simulation/critical/bruteforce_sim.py --admin --username demo_admin --attempts 4 --ip 203.0.113.21` → `.22` → `.23`
   (한 번에 재현하려면 `python scripts/simulation/critical/admin_distributed_bruteforce_sim.py`)
2. 앞의 두 번은 `[FAIL]`(IP 잠금 안 걸림)이 정상, 세 번째에 총 9회가 되어 **관리자 계정**이 잠김
3. **보여줄 곳**: "현재 잠긴 IP / 계정"의 "관리자 계정 잠금" 카드(security_admin에게는 "해제는 super_admin만 가능"), 보안 이벤트 `ADMIN_DISTRIBUTED_BRUTE_FORCE`, Slack "관리자 계정: demo_admin"
4. 없는 아이디(`demo_admin`)여도 똑같이 잠긴다는 점 — 응답으로 관리자 아이디 존재 여부를 알 수 없음
5. 허용 목록 PC에서는 같은 계정이 잠겨 있어도 로그인할 수 있다는 점(관리자 쫓아내기 방지)을 설명

## 5-2. (선택) 그 밖의 공격 유형 한 줄 시연 (각 1분)

새 시뮬레이터로 등급별 방어를 짧게 보여줄 수 있습니다. 모두 로컬 서버 대상이고, 가짜 IP는 `TRUST_FORWARDED_FOR=true`일 때만 반영됩니다.

| 보여줄 것 | 명령 | 기대 결과 |
|---|---|---|
| 관리자 로그인 무차별 대입(CRITICAL) | `python scripts/simulation/critical/admin_bruteforce_sim.py` | `ADMIN_BRUTE_FORCE`, 관리자 IP 잠금 |
| 전역 HTTP 플러딩(HIGH) | `python scripts/simulation/high/http_flood_sim.py` | 429, `HTTP_FLOOD` |
| 복구·비밀번호 찾기 폭주(HIGH) | `python scripts/simulation/high/recovery_flood_sim.py --target recovery` (`recovery-verify`·`password-forgot`·`password-reset`·`email-confirm`도 가능) | 엔드포인트별 좁은 한도 429 |
| 댓글 도배(HIGH) | `python scripts/simulation/high/comment_spam_sim.py --username <회원> --password <비밀번호>` | `COMMENT_RATE_LIMIT` |
| 허니팟 봇(MEDIUM) | `python scripts/simulation/medium/honeypot_bot_sim.py` | `BOT_DETECTED`, 로그인 실패로 세지 않음 |
| 다단계 공격 → 사건화·영구 차단(CRITICAL) | `python scripts/simulation/critical/incident_correlation_sim.py` | 정찰→침투→브루트포스가 한 사건으로 묶이고 영구 차단 |

**보여줄 곳**: 위협 현황(`/admin/dashboard`)의 공격자 히트맵·공격 흐름도, 공격 상세(`/admin/attack`)의 최근 이벤트, 처리 작업대의 보안 이벤트 표.

## 6. 비밀번호 변경 → 다른 기기 로그아웃 (2분)

1. 두 브라우저에서 같은 회원으로 로그인
2. 한쪽에서 '내 프로필' → 비밀번호 변경
3. 다른 쪽에서 아무 화면으로 이동 → 자동 로그아웃 + 안내
4. 현재 비밀번호를 일부러 틀리면 로그인 실패처럼 기록되는 것(관리자 "최근 로그인 시도")도 보여줄 수 있음
5. 가입 이메일로 "비밀번호가 변경되었습니다" 알림 도착 확인

## 6-1. 이메일 인증 + 이메일 변경 보호 (3분)

1. 새 회원으로 가입 → 가입 이메일에 인증 메일 도착, 대시보드에 "이메일 인증이 필요합니다" 배너
2. 메일 링크 → 확인 화면 → [인증] → 프로필에 "인증됨" 배지, 관리자 대시보드 회원 목록에도 "인증됨"
3. 프로필에서 새 이메일 + **틀린** 현재 비밀번호 → 거절되고 "최근 로그인 시도"에 실패로 기록되는 것
4. 올바른 비밀번호로 다시 요청 → 프로필에 "확인 대기 중", **이메일은 아직 그대로**
5. 새 주소의 메일 링크 → [이메일 변경] → 이메일 변경 + 기존 주소에 "이메일이 변경되었습니다" 알림
6. (선택) 다른 회원이 쓰는 주소로 변경 요청 → 화면은 똑같이 "확인 메일을 보냈습니다", 그 주소에는 "이미 등록된 주소" 안내만 도착

## 6-2. 비밀번호 찾기 (2분)

1. 6-1에서 이메일을 인증한 회원으로, 로그인 화면의 "비밀번호 찾기" → 아이디 입력
2. 없는 아이디·미인증 회원 아이디도 넣어 보면 **똑같은 안내**가 나오고 메일은 인증된 회원에게만 간다는 점
3. 메일 링크 → 7자 비밀번호로 시도 → "최소 8자" (링크는 아직 유효) → 올바른 비밀번호로 재설정
4. 다른 브라우저에 로그인해 둔 같은 회원이 다음 화면 이동에서 로그아웃되는 것, 재설정 알림 메일, 같은 링크 재사용 불가

## 6-3. (선택) 로그 정리 · 일별 요약 확인 (1분)

앱 화면이 아니라 Supabase **SQL Editor**에서 보여줍니다(guide44/47 SQL을 실행해 둔 경우).

1. `select last_summarized_day from log_summary_state;` — 매일 새벽 3시(한국 시간) 어제까지 요약됨
2. `select day, sum(count) from log_daily_summary where source = 'login_attempts' and category = 'failure' group by day order by day;` — 날짜별 로그인 실패 추이(원본이 지워진 날짜도 남음)
3. `select * from cleanup_old_logs(true) where deleted_rows > 0;` — 지금 정리하면 몇 건이 지워질지 미리 보기(아무것도 지우지 않음)

## 7. 정리

- `python scripts/management/unlock_ip.py --all --permanent --note "시연 정리"` — 시연에서 만든 잠금 전부 해제
- `python scripts/management/unlock_account.py --admin --all` — 시연에서 잠근 관리자 계정 해제
- 대시보드에서 시연용 사건 "해결", 시연용 IP 예외 "회수", 남은 "AI 조기 경보" 반려
- `TRUST_FORWARDED_FOR`를 다시 `false`로 되돌리기

## 시연 시 주의

- 여러 사람이 동시에 시뮬레이터를 돌리면 잠금·알림이 겹칠 수 있습니다. 한 사람만 실행하세요.
- 관리자 로그인 화면에서 실패를 반복하면 관리자 IP가 잠기고, 두 번째에는 **관리자만 풀 수 있는 영구 잠금**이 됩니다. 이때는 `python scripts/management/unlock_ip.py --ip <IP> --permanent`로 풉니다.
- 무료 Vercel 플랜은 런타임 로그를 1시간만 보관합니다. 배포에서 시연한다면 로그 확인은 바로 직후에 하세요.
