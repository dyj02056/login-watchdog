# 21단원 — 관리자 계정 단위 잠금 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "21-admin-account-lockout"
TITLE = "21. 관리자 계정 단위 잠금"
SUBTITLE = "IP를 나눠 쓰는 분산 브루트포스로부터 관리자 계정을 지키는 계정 단위 잠금의 코드 흐름도"

FILE_ROLES = {
    "routes/admin/login.py": "관리자 로그인(/admin/login) 입구 파일. 확인 → 기록 → 판정 → 집행 순서를 지휘한다.",
    "security/detector.py": "판사 파일. 관리자 아이디의 실패 횟수가 기준을 넘었는지 판정만 한다.",
    "security/soar/lockouts.py": "집행관 파일. 관리자 계정을 5분 잠그고 알림·기록을 남긴다(영구 승격은 안 함).",
    "security/lockdown.py": "허용 목록 IP 판단 등 영구 잠금 로직 파일. 관리자 계정 잠금에서는 허용 목록 확인에 쓰인다.",
    "db/admin.py": "관리자 계정과 관리자 로그인 기록(admin_login_log)을 다루는 저장소 파일.",
    "db/admin_lockouts.py": "관리자 계정 잠금 전용 표(admin_account_lockouts)를 다루는 저장소 파일. 회원 잠금과 분리되어 있다.",
    "routes/admin/locks.py": "잠금 해제 API 입구 파일. 관리자 계정 해제는 super_admin 만 가능하다.",
}

LOGIN = "routes/admin/login.py:admin_login_submit"

s1 = Scenario("lock", "관리자 계정이 잠기는 과정",
              "관리자 로그인은 IP 단위로만 잠겼습니다. IP 100개로 나눠 IP당 4회씩 시도하면 어느 IP도 기준을 넘지 않아 관리자 계정은 사실상 무제한으로 비밀번호를 시도당할 수 있었습니다. 회원 로그인에 이미 있던 계정 단위 잠금을 관리자에게도 적용했습니다.")
s1.screen("관리자 로그인 제출 (POST /admin/login)", "회원 로그인(/login)과 같은 화면 틀을 쓰지만 처리 경로·계정 표는 완전히 분리되어 있습니다.",
          fn=LOGIN, hl=('@admin_bp.route("/admin/login", methods=["POST"])', "def admin_login_submit"))
s1.step("① 이미 잠긴 관리자 아이디면 비밀번호 확인 없이 거절", "허용 목록 IP(관리자 PC)는 건너뜁니다 — 공격자가 일부러 틀려 관리자를 쫓아내도 관리자 PC 에서는 로그인해 대시보드에서 풀 수 있게 하기 위해서입니다.",
        fn=LOGIN, hl=("account_locked = detector.is_admin_account_locked(username)", "if account_locked and not lockdown.is_ip_allowlisted(ip):"), reject="잠긴 계정입니다. 잠시 후 다시 시도해주세요.",
        calls=[call("detector.is_admin_account_locked", "관리자 계정 잠금 여부", "admin_account_lockouts 에 유효한 잠금이 있는지.",
                    then=[call("db.get_active_admin_account_lockout", "유효한 잠금 찾기", "회원 잠금 표와 별개의 표를 봅니다.")]),
               call("security/lockdown.py:is_ip_allowlisted", "허용 목록 IP 인가?", "PERMANENT_LOCK_IP_ALLOWLIST 와 같은 단위로 비교합니다.", later="16단원")])
s1.step("② 비밀번호 확인 + 관리자 로그인 기록", "성공이든 실패든 기록합니다. 아이디가 없어도 더미 해시로 같은 시간이 걸립니다(15단원).",
        fn=LOGIN, hl=("success = db.verify_admin_credentials(username, password)", "db.log_admin_attempt(username, success, ip)"),
        calls=[call("db.verify_admin_credentials", "관리자 비밀번호 확인", "저장된 해시와 비교합니다."),
               call("db.log_admin_attempt", "관리자 로그인 기록", "admin_login_log 에 한 줄 남깁니다.")])
s1.step("③ IP 기준 판정이 먼저", "관리자 로그인 실패가 IP 기준을 넘으면 IP 를 잠급니다(5단원과 같은 lockouts 표 — /login 쪽에서도 함께 잠깁니다).",
        fn=LOGIN, hl=("suspicious, failure_count = detector.is_admin_suspicious(ip)", "return render_template"),
        calls=[call("detector.is_admin_suspicious", "관리자 IP 기준 판정", "admin_login_log 를 셉니다.", later="5단원"),
               call("soar.enforce_lockout", "IP 잠금 집행", "is_admin=True 로 ADMIN_BRUTE_FORCE 로 기록합니다.", later="5단원")])
s1.step("④ 아니면 아이디 기준 판정 (IP 와 무관, 15분 창)", "회원(60초 창)보다 긴 15분 창으로 세서 분당 몇 회씩 천천히 시도하는 공격도 잡습니다. 관리자는 몇 명뿐이라 오탐 여지가 작습니다. 이미 잠긴 계정(허용 목록 IP 로 들어온 경우)은 다시 잠그지 않아 알림이 반복되지 않습니다.",
        fn=LOGIN, hl=("if not account_locked:", "distinct_ips = db.count_recent_distinct_admin_ips_by_username(username)"),
        calls=[call("detector.is_admin_account_suspicious", "관리자 아이디 기준 판정", "15분 안에 8회를 '초과'하면 수상.",
                    then=[call("db.count_recent_admin_failures_by_username", "아이디 기준 실패 세기", "IP 를 가리지 않고 이 관리자 아이디의 실패만 셉니다.")]),
               call(snippet=("config.py", "ADMIN_ACCOUNT_FAILURE_THRESHOLD =", "ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS ="), title="임계값 (8회 / 15분)", plain="아이디가 실제로 있든 없든 같은 기준으로 잠가 존재 여부가 드러나지 않습니다.", label="config.py 관리자 임계값")])
s1.step("⑤ 잠금 집행 — 5분 잠금 + CRITICAL 알림, 영구 승격은 없음", "관리자 계정 전용 표에 잠그고 ADMIN_DISTRIBUTED_BRUTE_FORCE 이벤트를 남깁니다. 영구 잠금으로는 올리지 않습니다 — 관리자를 영구히 못 들어오게 만드는 것 자체가 공격자가 원하는 결과이기 때문입니다. 감사 추적을 위해 잠금 이력만 한 줄 남깁니다.",
        fn="soar.enforce_admin_account_lockout", hl=("db.create_admin_account_lockout(username, failure_count)", '"admin_account", username, "TEMPORARY"'),
        calls=[call("db.create_admin_account_lockout", "관리자 계정 잠금 저장", "회원 잠금과 분리된 표에 저장해 같은 이름의 회원과 서로 영향을 주지 않습니다."),
               call("notify/alert.py:send_account_lockout_alert", "Slack 알림", "is_admin=True 로 관리자 배지를 붙입니다.", later="5단원"),
               call("db.insert_lock_history", "잠금 이력 한 줄", "영구 승격 판단은 하지 않습니다.")])
s1.step("⑥ 잠긴 뒤 같은 문구로 거절", "아이디가 실제로 없어도 똑같이 잠그고 같은 문구로 거절합니다.",
        fn=LOGIN, hl=("soar.enforce_admin_account_lockout(username, account_failure_count, distinct_ips, ip)", 'flash("잠긴 계정입니다. 잠시 후 다시 시도해주세요.")'), reject="잠긴 계정입니다. 잠시 후 다시 시도해주세요.")

s2 = Scenario("unlock", "해제는 super_admin 만",
              "관리자 계정의 잠금을 푸는 것은 회원 계정보다 위험도가 높아서 일반 해제 권한(unlock_ip)과 따로 나눴습니다.")
s2.screen("'즉시 해제' 클릭 (POST /api/unlock-admin-account)", "super_admin 에게만 이 버튼이 보입니다.",
          fn="routes/admin/locks.py:api_unlock_admin_account", hl=('@admin_bp.route("/api/unlock-admin-account"', '@require_permission("unlock_admin_account")'))
s2.step("① unlock_admin_account 권한 확인 → 해제", "이 권한은 super_admin 만 가집니다(13단원).",
        fn="routes/admin/locks.py:api_unlock_admin_account", hl=('username = data.get("username")', "return jsonify({\"success\": soar.manual_release_admin_account(username)})"),
        calls=[call("soar.manual_release_admin_account", "관리자 계정 즉시 해제", "잠금을 풀고 이 아이디의 관련 CRITICAL 이벤트만 정리합니다(같은 이름의 회원 이벤트는 그대로).")])
s2.step("② 자동 해제도 같은 방식", "요청이 들어올 때마다 풀릴 시간이 지난 관리자 계정 잠금을 확인해 풉니다.",
        fn="soar.try_release_expired_admin_account_lockouts", hl="for lockout in db.list_expired_active_admin_account_lockouts():",
        calls=[call("db.list_expired_active_admin_account_lockouts", "만료된 관리자 잠금 목록", "풀릴 시각이 지난 active 잠금을 찾습니다.")])

SCENARIOS = [s1.build(), s2.build()]
