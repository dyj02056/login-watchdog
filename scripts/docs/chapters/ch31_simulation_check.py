# 31단원 — 시뮬레이션 일괄 점검 흐름도 명세 (앱 밖 터미널 도구)

from scripts.docs.dsl import Scenario, call

SLUG = "31-simulation-check"
TITLE = "31. 시뮬레이션 일괄 점검"
SUBTITLE = "공격 시뮬레이터 21종을 한 번에 돌려 '기대한 이벤트가 기록되는지' 확인하는 점검기와 샘플 로그 도구의 코드 흐름도"

CHK = "scripts/demo/check_simulations.py"
GEN = "scripts/demo/generate_demo_logs.py"

FILE_ROLES = {
    CHK: "메모리 DB 를 붙인 서버를 띄우고 시뮬레이터를 하나씩 실행해 PASS/FAIL 을 보여주는 점검기. 진짜 Supabase·Slack·메일에는 접속하지 않는다.",
    "scripts/demo/memory_supabase.py": "db 패키지가 쓰는 PostgREST 쿼리 체인을 흉내 내는 메모리 가짜 Supabase.",
    "scripts/simulation/critical/bruteforce_sim.py": "브루트포스 공격을 흉내 내는 시뮬레이터(CRITICAL 대표 예).",
    "scripts/simulation/_sim_common.py": "시뮬레이터들이 같이 쓰는 도구. 내 컴퓨터가 아닌 서버에는 실행되지 않게 막는 안전장치가 있다.",
    GEN: "7일치 샘플 로그 생성기. 가짜 회원 가입 + 공격 시뮬레이션을 시각 순서대로 실행해 JSON 으로 저장한다.",
    "scripts/demo/demo_server.py": "샘플 로그 JSON 으로 관제 화면만 띄우는 데모 서버. 아무 데도 접속하지 않는다.",
    "scripts/demo/demo_data.py": "나라별 IP 대역·가짜 회원 이름·시각 이동 규칙.",
    "scripts/demo/load_demo_to_supabase.py": "(선택) 샘플 로그를 실제 Supabase 에 넣거나(--apply) 넣은 행만 지우는(--purge) 도구.",
}

s1 = Scenario("check", "시뮬레이터 일괄 점검 (check_simulations.py)",
              "탐지 기능을 고칠 때마다 '다른 공격은 아직 잡히는가'를 시뮬레이터 20여 개로 손수 확인하기는 어렵습니다. 한 번에 돌려서 결과를 대조합니다.")
s1.screen("python scripts/demo/check_simulations.py", "이름 일부를 인자로 주면(예: honeypot) 그것만 실행합니다. 5000번 포트를 쓰므로 python app.py 로 띄운 개발 서버는 먼저 꺼야 합니다.",
          fn=f"{CHK}:main", hl=("keyword = sys.argv[1] if len(sys.argv) > 1 else \"\"", "seed()"))
s1.step("① 환경을 고정한다 (.env 값 무시)", "진짜 DB·Slack·메일·Groq 에 접속하지 않도록 값을 모두 덮어씁니다. 임시 잠금은 3초, 복구 대기는 0초로 줄여 시뮬레이션이 5분씩 기다리지 않게 합니다.",
        kind="screen", col=0, snippet=(CHK, "os.environ.update({", "re:^\\}\\)"), label="환경 고정")
s1.step("② 진짜 DB 대신 메모리 DB 를 끼운다", "db 패키지가 쓰는 연결을 메모리 가짜 클라이언트로 바꿔치기해서, 앱 코드는 하나도 안 바꾸고 점검합니다.",
        kind="screen", col=0, snippet=(CHK, "client = MemoryClient()", "db.get_client = lambda: client"), label="메모리 DB 주입",
        calls=[call(snippet=("scripts/demo/memory_supabase.py", "class MemoryClient:", "return Query(self.store, name)"), title="메모리에 사는 가짜 Supabase", plain="insert 한 행을 실제로 기억하고 where 조건으로 걸러 셉니다. 그래야 '5번 틀리면 잠금' 같은 탐지가 진짜처럼 동작합니다.", label="MemoryClient", kind="helper")])
s1.step("③ 시뮬레이션을 하나씩 실행", "사례마다 기록·잠금을 비우고 요청 한도 카운터를 초기화한 뒤, 시뮬레이터를 별도 프로세스로 실행합니다. 로컬 서버(127.0.0.1:5000)를 공격 대상으로 씁니다.",
        kind="screen", col=0, snippet=(CHK, "def main():", "re:^    return 1 if failures else 0"), label="main()",
        hl=("reset_between_runs()", "code, output = done.returncode, done.stdout + done.stderr"),
        calls=[call(snippet=(CHK, "CASES = [", '    ("critical", "critical/password_spraying_sim.py"'), title="점검 사례 목록", plain="(등급, 시뮬레이터, 인자, 기대 이벤트) 21건. 예: bruteforce_sim → (BRUTE_FORCE, CRITICAL).", label="CASES"),
               call("scripts/simulation/critical/bruteforce_sim.py:run", "시뮬레이터 예: 브루트포스", "로컬 서버에만 실행되도록 안전장치가 걸려 있습니다.")])
s1.step("④ 기대한 이벤트가 기록됐는지 대조", "두 가지를 봅니다: ① 시뮬레이션이 성공(종료 코드 0)했는가 ② 서버가 기대한 (event_type, severity) 를 security_events 에 실제로 기록했는가. 둘 다 맞아야 PASS 입니다.",
        kind="screen", col=0, snippet=(CHK, "def main():", "re:^    return 1 if failures else 0"), label="main()",
        hl=("recorded = events()", "ok = code == 0 and not missing"),
        calls=[call(f"{CHK}:events", "기록된 (유형, 등급) 목록", "메모리 DB 의 security_events 에서 읽습니다.")])
s1.step("⑤ PASS / FAIL 출력", "실패하면 누락된 이벤트와 시뮬레이션 출력의 끝 15줄을 함께 보여줘서 원인을 바로 찾을 수 있습니다. 마지막에 '합계: N PASS / M FAIL / 총 K건' 을 출력합니다.",
        kind="screen", col=0, snippet=(CHK, "def main():", "re:^    return 1 if failures else 0"), label="main()",
        hl=("rp(f\"[{'PASS' if ok else 'FAIL'}]", 'rp(f"\\n합계:'))

s2 = Scenario("demo", "7일치 샘플 로그 만들기 (generate_demo_logs.py)",
              "시연·스크린샷용 기록을 서버가 직접 만들게 하는 도구입니다. 메모리 DB 서버를 켜고 가짜 회원을 실제 /signup 으로 가입시킨 뒤, 정상 접속과 공격 시뮬레이션 21종을 시각 순서대로 실행합니다. 진짜 Supabase·Slack·메일에는 접속하지 않습니다.")
s2.screen("python scripts/demo/generate_demo_logs.py", "같은 --seed 면 같은 결과가 나옵니다.",
          fn=f"{GEN}:main", hl=('parser.add_argument("--seed"', "args = parser.parse_args()"))
s2.step("① 실행 계획을 세운다 (묶음 목록)", "가짜 회원 가입·정상 접속·공격 시뮬레이션을 지난 7일 안의 시각에 배정하고, 마지막에 '방금 일어난 공격'(진행 중 사건·활성 잠금·승인 대기)을 둡니다.",
        kind="screen", col=0, fn=f"{GEN}:build_plan", hl="def build_plan(ctx: Context, days: int)")
s2.step("② 가짜 회원을 실제 /signup 으로 가입", "화면과 같은 경로로 가입시켜서 가입 도배 방어·허니팟 등 실제 코드를 그대로 통과합니다.",
        kind="screen", col=0, fn=f"{GEN}:signup", hl="def signup(ctx: Context, member: dict)")
s2.step("③ 공격 시뮬레이션 실행", "묶음마다 시뮬레이터를 하위 프로세스로 실행합니다. X-Forwarded-For 로 가짜 공격자 IP 를 흉내 냅니다(TRUST_FORWARDED_FOR=true 일 때만 반영).",
        kind="screen", col=0, fn=f"{GEN}:run_attack", hl=("command = builder(ctx, batch.ip)", "return done.returncode == 0"))
s2.step("④ 기록 시각을 계획한 시각으로 옮기고 IP 를 바꾼다", "묶음이 끝날 때마다 그 묶음이 만든 행의 시각을 배정한 시각으로 옮기고, 시뮬레이션이 쓴 IP 를 17개국의 실제 할당 대역 IP 로 바꿉니다. 3초짜리 임시 잠금은 실제 설정(5분)처럼 고칩니다.",
        kind="screen", col=0, fn=f"{GEN}:finish_batch", hl=("rows = list(changed_rows(before))", "settle_locks(datetime.now(timezone.utc))"),
        calls=[call(f"{GEN}:remap_foreign_ips", "IP 를 나라별 대역으로", "외부 접속 없이 직접 고른 대역에서 뽑습니다."),
               call(f"{GEN}:move_to", "묶음 전체의 시각 이동", "앞뒤 순서는 그대로 두고 같은 만큼 옮깁니다.")])
s2.step("⑤ 일별 요약표 · 관리자 처리 이력 · 복구 기록을 채운다", "26단원과 같은 모양의 요약표를 만들고, 관리자가 승인·해결한 이력과 이메일 복구 요청·IP 예외 같은 일부 기록은 직접 만든 행으로 채웁니다.",
        kind="screen", col=0, snippet=(GEN, "settle_locks(now)", "client.store.tables[\"ip_locations\"] = [r for r in client.store.tables[\"ip_locations\"] if r[\"ip_address\"] in used]"), label="마무리",
        calls=[call(f"{GEN}:build_daily_summary", "일별 요약표", "log_daily_summary / log_daily_breakdown 를 만듭니다."),
               call(f"{GEN}:admin_decisions", "관리자 처리 이력", "승인·반려·해결 이력을 만듭니다.")])
s2.step("⑥ JSON 으로 저장", "scripts/demo/output/demo_logs.json 에 저장합니다. 이 파일을 demo_server.py 가 읽어 관제 화면을 띄웁니다(열 때마다 시각을 '지금' 기준으로 옮김).",
        kind="screen", col=0, snippet=(GEN, 'path = Path(args.out)', 'path.write_text(json.dumps(dump, ensure_ascii=False, indent=1), encoding="utf-8")'), label="JSON 저장",
        calls=[call("scripts/demo/demo_data.py:shift_dump_to_now", "열 때마다 시각을 지금 기준으로", "며칠 전에 만든 파일도 항상 최근 7일처럼 보이게 합니다."),
               call("scripts/demo/load_demo_to_supabase.py:main", "(선택) 실제 Supabase 에 적재", "기본은 미리보기, --apply 로 적재, --purge 로 넣은 행만 삭제합니다.")])

SCENARIOS = [s1.build(), s2.build()]
