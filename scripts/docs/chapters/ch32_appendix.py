# 32단원 — 부록 흐름도 명세 ('실행 순서'가 아니라 '어디에 무엇이 있나'를 보여주는 파일 지도형)
# 카드 사이에 순서 화살표가 없고(chain=False), 카드를 누르면 그 분야의 대표 코드가 열린다.

from scripts.docs.dsl import Scenario, call

SLUG = "32-appendix"
TITLE = "32. 부록"
SUBTITLE = "프로젝트 전체를 '계층별 파일 · 기능별 테스트 · 공격별 시뮬레이터 · DB 표'로 찾아보는 파일 지도"

SQL = "docs/schema.sql"
END = "re:^\\);"

FILE_ROLES = {
    SQL: "DB 전체 정의 파일(표·함수·예약 작업). 부록의 'DB 표 지도'가 여기서 표 정의를 보여준다.",
    "app.py": "Flask 앱을 만들고 화면(Blueprint)을 등록하는 시작 파일.",
    "scripts/management/tune_thresholds.py": "임계값 튜닝 리포트(14단원) 스크립트.",
}


def T(name, label):
    return {"snippet": SQL, "from": f"create table {name} (", "to": END, "label": label}


def TX(name, label):
    return {"snippet": SQL, "from": f"create table if not exists {name} (", "to": END, "label": label}


# ---------------------------------------------------------------- A) 계층별 파일 지도
a = Scenario("layers", "계층별 파일 지도",
             "이 프로젝트는 '판단(Layer 2)'과 '실행(Layer 3)'을 분리하고, 그 위에 '사람의 최종 확인(Layer 4)'을 얹은 구조입니다. 각 카드를 누르면 그 계층의 대표 함수를 볼 수 있습니다.",
             chain=False)
a.screen("서버가 켜질 때 화면(Blueprint)이 등록된다", "회원·관리자·게시판·복구·이메일·비밀번호 화면이 여기서 한꺼번에 연결됩니다. 모든 계층의 시작점입니다.",
         snippet=("app.py", "app.register_blueprint(auth_bp)", "app.register_blueprint(password_bp)"), label="app.py 화면 등록")
a.step("Layer 1. 기반 기능 (1~4단원) — 사용자가 직접 쓰는 화면", "감시할 대상(로그인·가입·게시판·위치 조회)이 먼저 있어야 탐지가 의미를 갖습니다.",
       kind="screen", col=1, items=[{"ref": "routes/auth.py:signup_submit"}, {"ref": "routes/auth.py:login_submit"}, {"ref": "routes/member.py:member_dashboard"},
                                    {"ref": "routes/board.py:board_new_submit"}, {"ref": "services/geoip.py:get_locations"}])
a.step("Layer 2. 탐지 (5~7단원) — '판사'", "security/detector.py 는 DB 를 읽기만 하고 아무것도 바꾸지 않습니다. 판정(True/False)만 돌려줍니다.",
       kind="helper", col=1, items=[{"ref": "detector.is_suspicious"}, {"ref": "detector.is_account_suspicious"}, {"ref": "detector.is_web_scanning"}, {"ref": "detector.is_macro_pattern_suspicious"}])
a.step("Layer 3. 대응 (8~11단원) — '집행관'·'형사'", "판정을 받아 실제로 잠그고·알리고·엮고, 필요하면 AI 에게 묻습니다.",
       kind="route", col=1, items=[{"ref": "soar.enforce_lockout"}, {"ref": "soar.notify_web_scanning"}, {"ref": "security/correlate.py:check_and_correlate"},
                                   {"ref": "soar.consider_early_warning"}, {"ref": "services/llm_client.py:judge_early_warning"}])
a.step("Layer 4. 관리 (12~14단원) — 사람의 최종 판단", "자동으로 돌더라도 사람이 보고 되돌릴 수 있어야 합니다.",
       kind="db", col=1, items=[{"ref": "routes/admin/status.py:api_status"}, {"ref": "helpers/auth.py:require_permission"}, {"ref": "scripts/management/tune_thresholds.py:build_report"}])
a.step("Layer 5. 방어 강화 · 확장 (15~31단원)", "개별 취약점 보강(헤더·요청 한도·허용 목록·타이밍), 영구 잠금·복구·이메일 인증·연결 안정화·화면 어댑터 등이 기존 계층에 붙었습니다.",
       kind="config", col=1, items=[{"ref": "helpers/hooks.py:set_security_headers"}, {"ref": "app.py:handle_rate_limit_exceeded"}, {"ref": "helpers.is_bot_submission"},
                                    {"ref": "security/lockdown.py:promote_ip"}, {"ref": "routes/recovery.py:recovery_request_submit"}, {"ref": "services/email_verification.py:request_password_reset"},
                                    {"ref": "helpers/request_utils.py:get_request_ip"}, {"ref": "db/_client.py:get_client"}])

# ---------------------------------------------------------------- B) 기능 → 테스트
b = Scenario("tests", "기능 → 자동 테스트 파일",
             "기능을 고쳤을 때 다른 곳이 망가지지 않았는지 pytest 로 자동 확인합니다(현재 718개, 몇 초 안에 끝남). 카드를 누르면 그 분야 테스트 한 개를 예로 볼 수 있습니다.",
             chain=False)
b.screen("pytest 한 줄로 전체 실행", "테스트 한 개는 이렇게 생겼습니다 — '실패 5번이 기준(임계값)인지'를 확인하는 가장 단순한 예입니다.",
         fn="tests/test_config.py:test_failure_threshold_is_5")
b.step("탐지 · 대응 · 상관분석 (5~11단원)", "판정 함수·집행 함수·상관분석이 의도대로 동작하는지 확인합니다. test_detector.py · test_soar.py · test_correlate.py · test_early_warning.py",
       kind="helper", col=1, items=[{"ref": "tests/test_detector.py:test_is_suspicious_false_when_failures_below_threshold"}, {"ref": "tests/test_soar.py:test_enforce_lockout_creates_lockout_then_sends_alert"},
                                    {"ref": "tests/test_correlate.py:test_check_and_correlate_does_nothing_when_fewer_than_two_distinct_types"}])
b.step("화면 · 훅 · 공용 도구 (1~4·15단원)", "라우트 전반, 보안 헤더·에러 핸들러·훅, 공용 함수, 위치 조회. test_app.py · test_helpers.py · test_geoip.py · test_config.py",
       kind="route", col=1, items=[{"ref": "tests/test_app.py:test_login_page_loads"}, {"ref": "tests/test_helpers.py:test_get_request_ip_uses_remote_addr_by_default"},
                                   {"ref": "tests/test_geoip.py:test_format_location_with_country_and_city"}])
b.step("영구 잠금 · 복구 · 비밀번호 (16~25단원)", "승격·해제·복구 메일·비밀번호 변경/찾기·관리자 세션·계정 단위 잠금·이메일 인증. test_permanent_lock.py · test_recovery.py · test_password_reset.py 등",
       kind="db", col=1, items=[{"ref": "tests/test_permanent_lock.py:test_ip_below_strike_count_only_records_history"}, {"ref": "tests/test_recovery.py:test_smtp_backend_sends_with_timeout_starttls_and_includes_link_and_code"},
                                {"ref": "tests/test_password_reset.py:test_verified_account_gets_a_reset_link_and_only_the_hash_is_stored"}])
b.step("DB · 화면 JS (19·27·28단원)", "DB 연결 재시도·데이터 계층과 폴링 같은 브라우저 쪽 규칙. test_db.py · test_db_client.py · test_polling.py · test_dashboard_speed.py",
       kind="config", col=1, items=[{"ref": "tests/test_db.py:test_verify_admin_credentials_true_for_correct_password"}, {"ref": "tests/test_polling.py:test_no_screen_polls_with_set_interval_anymore"}])

# ---------------------------------------------------------------- C) 공격 → 시뮬레이터
c = Scenario("sims", "공격 → 시뮬레이터",
             "시뮬레이터는 위험등급별 폴더(critical/high/medium)에 있고, 31단원의 일괄 점검기가 한 번에 돌립니다. 모두 내 컴퓨터(로컬) 서버에만 실행되도록 안전장치가 걸려 있습니다.",
             chain=False)
c.screen("안전장치: 로컬 서버가 아니면 실행 거부", "정말 본인 소유의 서버가 아니라면 종료 코드 2로 끝납니다. 실제 서비스나 타인의 서버에는 절대 실행하지 마세요.",
         fn="scripts/simulation/_sim_common.py:require_local_or_exit")
c.step("critical — 잠금까지 일어나는 공격", "브루트포스 · 분산 브루트포스 · 관리자 브루트포스 · 관리자 분산 · 영구 잠금 승격 · 사건화 · Password Spraying",
       kind="helper", col=1, items=[{"ref": "scripts/simulation/critical/bruteforce_sim.py:run"}, {"ref": "scripts/simulation/critical/distributed_bruteforce_sim.py:run"},
                                    {"ref": "scripts/simulation/critical/admin_bruteforce_sim.py:run"}, {"ref": "scripts/simulation/critical/admin_distributed_bruteforce_sim.py:run"},
                                    {"ref": "scripts/simulation/critical/permanent_lock_sim.py:run"}, {"ref": "scripts/simulation/critical/incident_correlation_sim.py:run"},
                                    {"ref": "scripts/simulation/critical/password_spraying_sim.py:main"}])
c.step("high — 요청 거부(HIGH)가 일어나는 공격", "가입 도배 · 글/댓글 도배 · HTTP 플러딩 · 복구·비밀번호 찾기·이메일 확인 폭주",
       kind="route", col=1, items=[{"ref": "scripts/simulation/high/signup_abuse_sim.py:run"}, {"ref": "scripts/simulation/high/spam_sim.py:run"}, {"ref": "scripts/simulation/high/comment_spam_sim.py:run"},
                                   {"ref": "scripts/simulation/high/http_flood_sim.py:run"}, {"ref": "scripts/simulation/high/recovery_flood_sim.py:run"}])
c.step("medium — 알림·기록(MEDIUM)만 하는 공격", "Web Scanning · Unauthorized Access · 반복 페이지 접근 · API 매크로/봇 · 허니팟 봇",
       kind="db", col=1, items=[{"ref": "scripts/simulation/medium/web_scanning_sim.py:run"}, {"ref": "scripts/simulation/medium/unauthorized_access_sim.py:main"},
                                {"ref": "scripts/simulation/medium/repeated_access_sim.py:run"}, {"ref": "scripts/simulation/medium/macro_bot_sim.py:run"}, {"ref": "scripts/simulation/medium/honeypot_bot_sim.py:run"}])

# ---------------------------------------------------------------- D) DB 표 지도
d = Scenario("tables", "DB 표 지도 (30개 표)",
             "처음 19개 표에 RBAC·상관분석·조기 경보 등으로 표가 늘었고, 영구 잠금·관리자 계정 잠금·이메일 인증·로그 요약이 추가되어 지금은 30개입니다. 카드를 누르면 표 정의(SQL)를 볼 수 있습니다.",
             chain=False)
d.screen("DB 연결은 db/_client.py 한 곳", "모든 db 함수가 같은 연결을 씁니다. 표 정의는 docs/schema.sql 에 모여 있고, 기존 DB 에 더 실행할 SQL 은 docs/migrations/ 에 있습니다.",
         fn="db/_client.py:get_client")
d.step("회원 · 관리자 · 권한", "users(회원) · admin_users(관리자) · roles · permissions(RBAC)",
       kind="db", col=1, items=[T("users", "users"), T("admin_users", "admin_users"), T("roles", "roles"), T("permissions", "permissions")])
d.step("로그인 · 접근 기록", "login_attempts · admin_login_log · signup_attempts · not_found_attempts · unauthorized_attempts · page_access_attempts · api_access_log (모두 '추가만' 하는 기록)",
       kind="db", col=1, items=[T("login_attempts", "login_attempts"), T("admin_login_log", "admin_login_log"), T("signup_attempts", "signup_attempts"), T("not_found_attempts", "not_found_attempts"),
                                T("unauthorized_attempts", "unauthorized_attempts"), T("page_access_attempts", "page_access_attempts"), T("api_access_log", "api_access_log")])
d.step("잠금", "lockouts(IP) · account_lockouts(회원 계정) · admin_account_lockouts(관리자 계정) · lock_history(잠금 이력, 반복 횟수의 근거)",
       kind="db", col=1, items=[T("lockouts", "lockouts"), T("account_lockouts", "account_lockouts"), TX("admin_account_lockouts", "admin_account_lockouts"), TX("lock_history", "lock_history")])
d.step("이벤트 · 사건 · AI 승인", "security_events(위험등급 이벤트) · security_incidents(SIEM 사건) · access_requests(관리자 승인 대기)",
       kind="db", col=1, items=[T("security_events", "security_events"), T("security_incidents", "security_incidents"), T("access_requests", "access_requests")])
d.step("복구 · 이메일", "recovery_requests · ip_lock_exemptions(IP 예외) · email_tokens(인증·변경·재설정 링크)",
       kind="db", col=1, items=[TX("recovery_requests", "recovery_requests"), TX("ip_lock_exemptions", "ip_lock_exemptions"), TX("email_tokens", "email_tokens")])
d.step("게시판 · 설정 · 캐시", "posts · comments · post_attempts · comment_attempts · app_settings(가입 허용 여부) · ip_locations(위치 캐시)",
       kind="db", col=1, items=[T("posts", "posts"), T("comments", "comments"), T("post_attempts", "post_attempts"), T("comment_attempts", "comment_attempts"), T("app_settings", "app_settings"), T("ip_locations", "ip_locations")])
d.step("로그 요약 (26단원)", "log_daily_summary · log_daily_breakdown · log_summary_state",
       kind="db", col=1, items=[{"snippet": SQL, "from": "create table if not exists log_daily_summary (", "to": END, "label": "log_daily_summary", "nth": 2},
                                TX("log_daily_breakdown", "log_daily_breakdown"), TX("log_summary_state", "log_summary_state")])

SCENARIOS = [a.build(), b.build(), c.build(), d.build()]
