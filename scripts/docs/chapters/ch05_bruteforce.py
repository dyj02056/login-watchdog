# 5단원 — 브루트포스 탐지 + 자동 IP 잠금 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "05-bruteforce"
TITLE = "5. 브루트포스 탐지 + 자동 IP 잠금"
SUBTITLE = "로그인 실패가 쌓였을 때 '수상한가?'를 판정하고 IP·계정을 잠그기까지의 코드 흐름도"

FILE_ROLES = {
    "routes/auth.py": "로그인 요청을 받아 '확인 → 기록 → 판정 → 집행' 순서를 지휘하는 입구 파일.",
    "security/detector.py": "판사 역할. DB에 '지금 상태가 어때?'만 물어 True/False를 돌려준다. 아무것도 저장·변경하지 않는다.",
    "security/soar/lockouts.py": "집행관 역할. 판정 결과대로 IP·계정을 실제로 잠그고, 알리고, 기록한다.",
    "security/soar/_events.py": "보안 이벤트(위험등급)를 기록하고 상관분석 훅을 부르는 공용 함수. (8·9단원)",
    "security/lockdown.py": "임시 잠금 이력을 남기고 영구 잠금으로 올릴지 판단한다. (16단원)",
    "notify/alert.py": "Slack으로 알림을 보내는 파일. 외부 서비스와의 통신만 전담한다.",
    "db/attempts.py": "로그인 시도(login_attempts 표)를 기록하고 '최근 N초 실패 몇 번'을 세는 저장소 파일.",
    "db/lockouts.py": "IP 잠금(lockouts 표)을 만들고 현재 잠금을 조회하는 저장소 파일.",
    "db/account_lockouts.py": "계정 잠금(account_lockouts 표)을 만들고 조회하는 저장소 파일.",
    "config.py": "임계값·시간 창·잠금 시간 같은 프로젝트 공용 설정값 모음.",
}

LOGIN = "routes/auth.py:login_submit"

# ---------------------------------------------------------------- 1) 잠금 확인 + 기록
s1 = Scenario("check", "잠금 확인 → 시도 기록",
              "탐지는 로그인 요청이 들어오자마자 시작됩니다. 먼저 '이미 잠긴 상대인가?'를 보고, 안 잠겼다면 비밀번호를 확인한 뒤 성공·실패를 반드시 기록합니다. 이 기록이 탐지의 재료입니다.")
s1.screen("로그인 폼 제출 (POST /login)", "5단원의 모든 흐름은 login_submit() 안에서 일어납니다.",
          fn=LOGIN, hl=('@auth_bp.route("/login", methods=["POST"])', "def login_submit"))
s1.step("① 이미 잠긴 IP인가?", "잠겨 있으면 비밀번호를 확인하지도 않고 거부합니다. 잠금 여부 판단은 판사(detector)가, 실제 조회는 db가 합니다.",
        fn=LOGIN, hl=("exemption = None", "if detector.is_account_locked(username)"), reject="잠긴 계정입니다. 잠시 후 다시 시도해주세요.",
        calls=[call("detector.is_locked", "IP 잠금 여부", "잠금 기록이 있으면 True.",
                    then=[call("db.get_active_lockout", "유효한 IP 잠금 찾기", "active 이면서 아직 풀릴 시각이 안 지난 잠금을 찾습니다.")]),
               call("detector.get_ip_lock_state", "임시 / 영구 구분", "영구 잠금 IP는 이메일 복구 예외만 통과합니다.", later="16단원")])
s1.step("② 이미 잠긴 계정인가?", "여러 IP가 나눠서 한 계정을 공격하는 경우를 막는 '계정 단위' 잠금도 확인합니다.",
        fn=LOGIN, hl=("if detector.is_account_locked(username)", "return _login_form(recovery_link=True)"), reject="잠긴 계정입니다. … 본인 인증으로 잠금 해제 안내",
        calls=[call("detector.is_account_locked", "계정 잠금 여부", "잠금 기록이 있으면 True.",
                    then=[call("db.get_active_account_lockout", "유효한 계정 잠금 찾기", "account_lockouts 표에서 찾습니다.")])])
s1.step("③ 비밀번호 확인 + 시도 기록", "성공이든 실패든 한 줄 남깁니다. 이후 모든 '최근 N초 실패 횟수'는 이 표를 세어서 나옵니다.",
        fn=LOGIN, hl=("success = db.verify_user_credentials", "db.log_attempt(ip, username, success)"),
        calls=[call("db.verify_user_credentials", "비밀번호 확인", "저장된 해시와 비교합니다(1단원)."),
               call("db.log_attempt", "시도 한 줄 저장", "login_attempts 표에 IP·아이디·성공 여부를 추가합니다.")])

# ---------------------------------------------------------------- 2) IP 단위
s2 = Scenario("ip", "IP 단위 탐지 → 5분 잠금",
              "같은 IP에서 60초 안에 실패가 5회를 넘으면(= 6번째 실패) 그 IP를 5분간 잠급니다. 판정은 detector, 집행은 soar가 맡습니다.")
s2.screen("로그인 실패 직후", "비밀번호가 틀려 시도가 기록된 순간입니다. 여기서부터 '수상한가?'를 따져봅니다.",
          fn=LOGIN, hl=("# 실패했다면, 먼저 이 IP가", "suspicious, failure_count = detector.is_suspicious(ip)"))
s2.step("① 최근 60초 안에 몇 번 틀렸나? (판정)", "실패 횟수가 기준치(5회)를 '초과'하면 수상. 6번째 실패에서 처음 True가 됩니다.",
        fn=LOGIN, hl=("suspicious, failure_count = detector.is_suspicious(ip)", "if suspicious:"),
        calls=[call("detector.is_suspicious", "IP 기준 판정", "(수상한가?, 실패 횟수) 두 값을 돌려줍니다.",
                    then=[call("db.count_recent_failures", "최근 실패 횟수 세기", "login_attempts 에서 이 IP + 실패 + 최근 60초만 셉니다.")]),
               call(snippet=("config.py", "FAILURE_THRESHOLD =", "LOCKOUT_DURATION_SECONDS ="), title="임계값 설정", plain="실패 5회 초과 · 60초 창 · 5분 잠금.",
                    label="config.py 임계값", hl=("FAILURE_THRESHOLD =", "LOCKOUT_DURATION_SECONDS ="))])
s2.step("② 계정 1개 집중? 여러 계정 순회?", "이 IP가 시도한 '서로 다른 아이디 개수'를 셉니다. 1개면 Brute Force, 2개 이상이면 Password Spraying으로 구분됩니다(판정 코드는 같고 이 값으로만 구분).",
        fn=LOGIN, hl=("distinct_usernames = detector.count_distinct_usernames(ip)", "soar.enforce_lockout(ip, failure_count, distinct_usernames)"),
        calls=[call("detector.count_distinct_usernames", "서로 다른 아이디 개수", "db가 센 값을 그대로 전달합니다.",
                    then=[call("db.count_recent_distinct_usernames", "최근 60초 아이디 종류 세기", "같은 IP가 시도한 아이디의 종류 수를 셉니다.")])])
s2.step("③ 5분 잠금을 DB에 저장", "집행관이 '이 IP는 지금부터 5분간 잠김'을 기록합니다. 이후 로그인 요청은 ①(잠금 확인)에서 바로 거부됩니다.",
        fn="soar.enforce_lockout", hl="db.create_lockout(ip, failure_count)",
        calls=[call("db.create_lockout", "IP 잠금 저장", "lockouts 표에 잠금 시작·해제 시각과 함께 저장합니다.")])
s2.step("④ Slack 알림 (잠그는 순간 딱 한 번)", "잠긴 상태에서 시도가 계속돼도 알림은 새로 잠그는 순간에만 보냅니다. 알림 폭탄으로 중요한 알림을 놓치지 않기 위해서입니다.",
        fn="soar.enforce_lockout", hl=("alert.send_lockout_alert(", "is_admin"),
        calls=[call("notify/alert.py:send_lockout_alert", "Slack 알림 전송", "IP·실패 횟수·공격 유형·조치 내용을 담아 보냅니다.")])
s2.step("⑤ 위험등급(CRITICAL) 이벤트 기록", "공격 유형(BRUTE_FORCE / PASSWORD_SPRAYING / ADMIN_BRUTE_FORCE)을 정해 security_events 에 기록합니다.",
        fn="soar.enforce_lockout", hl=("if is_admin:", '_record_event(event_type, "CRITICAL", ip, None, failure_count, "LOCKED")'),
        calls=[call("security/soar/_events.py:_record_event", "보안 이벤트 기록 + 상관분석 훅", "이벤트를 저장하고 곧바로 상관분석(9단원)을 호출합니다.", later="8단원")])
s2.step("⑥ 잠금 이력 + 영구 승격 판단", "일정 기간 안에 반복해서 잠기면 영구 잠금으로 올립니다.",
        fn="soar.enforce_lockout", hl='lockdown.after_temporary_lock("ip"',
        calls=[call("security/lockdown.py:after_temporary_lock", "이력 기록 · 영구 승격", "N번째 잠금이면 영구 잠금으로 승격합니다.", later="16단원")])

# ---------------------------------------------------------------- 3) 계정 단위
s3 = Scenario("account", "계정 단위 탐지 (분산 브루트포스)",
              "공격자가 IP를 여러 개로 나누면 IP당 실패는 5회를 못 넘길 수 있습니다. 그래서 'IP와 상관없이 이 계정이 총 몇 번 틀렸나'를 따로 세서, 8회를 넘으면 계정 자체를 잠급니다.")
s3.screen("IP 기준으로는 아직 정상", "IP 판정이 '아직 아님'이면 이어서 계정 기준 판정을 합니다.",
          fn=LOGIN, hl=("# IP 단위로는 아직 수상하지 않더라도", "account_suspicious, account_failure_count = detector.is_account_suspicious(username)"))
s3.step("① 이 계정이 합쳐서 몇 번 틀렸나? (판정)", "어느 IP에서 왔든 이 아이디의 최근 실패를 모두 합쳐 8회를 초과하면 수상합니다.",
        fn=LOGIN, hl=("account_suspicious, account_failure_count = detector.is_account_suspicious(username)", "if account_suspicious:"),
        calls=[call("detector.is_account_suspicious", "계정 기준 판정", "(수상한가?, 실패 횟수)를 돌려줍니다.",
                    then=[call("db.count_recent_failures_by_username", "이 아이디의 최근 실패 세기", "IP를 가리지 않고 아이디로만 셉니다.")]),
               call(snippet=("config.py", "ACCOUNT_FAILURE_THRESHOLD =", "ACCOUNT_FAILURE_THRESHOLD ="), title="계정 임계값 (8회)", plain="IP 임계값(5)보다 높게 잡아, 정상 사용자가 여러 기기에서 몇 번 틀려도 잠기지 않게 합니다.",
                    label="config.py 계정 임계값")])
s3.step("② 몇 개의 서로 다른 IP에서 왔나?", "알림에 '분산 공격 규모'를 보여주려고 서로 다른 IP 개수를 셉니다.",
        fn=LOGIN, hl=("distinct_ips = detector.count_distinct_ips_by_username(username)", "soar.enforce_account_lockout("),
        calls=[call("detector.count_distinct_ips_by_username", "서로 다른 IP 개수", "db가 센 값을 그대로 전달합니다.",
                    then=[call("db.count_recent_distinct_ips_by_username", "이 아이디를 시도한 IP 종류 세기", "최근 60초 동안 이 아이디를 시도한 IP의 종류 수.")])])
s3.step("③ 계정 잠금을 DB에 저장", "이후에는 어느 IP로 접속해도 이 아이디로는 로그인할 수 없습니다.",
        fn="soar.enforce_account_lockout", hl="db.create_account_lockout(username, failure_count)",
        calls=[call("db.create_account_lockout", "계정 잠금 저장", "account_lockouts 표에 저장합니다.")])
s3.step("④ Slack 알림", "계정 이름·실패 횟수·시도한 IP 개수를 담아 보냅니다.",
        fn="soar.enforce_account_lockout", hl=("alert.send_account_lockout_alert(", "distinct_ip_count"),
        calls=[call("notify/alert.py:send_account_lockout_alert", "계정 잠금 알림", "Slack으로 전송합니다.")])
s3.step("⑤ CRITICAL 이벤트 + 잠금 이력", "DISTRIBUTED_BRUTE_FORCE 로 기록하고, 계정 영구 승격 판단도 거칩니다.",
        fn="soar.enforce_account_lockout", hl=("_record_event(", '"DISTRIBUTED_BRUTE_FORCE", failure_count, triggering_ip=triggering_ip'),
        calls=[call("security/soar/_events.py:_record_event", "보안 이벤트 기록", "상관분석 훅까지 호출합니다.", later="8단원"),
               call("security/lockdown.py:after_temporary_lock", "이력 · 영구 승격", "계정 영구 잠금 판단(16단원).", later="16단원")])

SCENARIOS = [s1.build(), s2.build(), s3.build()]
