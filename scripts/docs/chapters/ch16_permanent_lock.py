# 16단원 — 영구 잠금 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "16-permanent-lock"
TITLE = "16. 영구 잠금"
SUBTITLE = "5분 임시 잠금이 반복되면 자동 만료 없는 '영구 잠금'으로 올라가고, 사람이 풀 때까지 유지되는 과정의 코드 흐름도"

FILE_ROLES = {
    "security/lockdown.py": "임시 잠금을 영구 잠금으로 올리고(승격), 영구 잠금을 푸는(관리자 해제·이메일 복구) 로직 본체.",
    "security/soar/lockouts.py": "임시 잠금 집행 파일. 잠금 직후 lockdown 에 '승격 여부 판단'을 맡긴다.",
    "security/correlate.py": "상관분석 파일. 사건 위험등급에 따라 영구 잠금 승격을 판단하도록 부른다.",
    "security/detector.py": "잠금 상태(없음/임시/영구)를 판정만 하는 판사 파일.",
    "db/lock_history.py": "잠금 이력(lock_history 표)을 '추가만' 하는 저장소 파일. 반복 횟수를 세는 근거.",
    "db/lockouts.py": "IP 잠금 표. 임시 → 영구 승격(조건부 UPDATE)과 영구 잠금 조회를 담당한다.",
    "db/account_lockouts.py": "계정 잠금 표. 영구 승격·해제를 담당한다.",
    "routes/admin/locks.py": "영구 잠금 수동 승격·해제 API 입구 파일. 해제는 super_admin 전용.",
    "routes/auth.py": "로그인·회원가입 입구 파일. 영구 잠긴 IP·계정을 막고 복구 링크를 보여준다.",
    "notify/alert.py": "Slack 알림 전송 파일.",
}

# ---------------------------------------------------------------- 1) 승격
s1 = Scenario("promote", "반복 잠금 → 영구 잠금 승격",
              "5분 잠금은 풀리면 같은 공격자가 또 시도할 수 있습니다. 그래서 같은 IP·계정이 최근 30일 안에 2번째로 잠기면 자동 만료가 없는 '영구 잠금'으로 올립니다.")
s1.screen("임시 잠금이 방금 걸린 직후", "5단원의 enforce_lockout() 마지막 단계가 lockdown 을 부릅니다.",
          fn="soar.enforce_lockout", hl='lockdown.after_temporary_lock("ip"')
s1.step("① 잠금 이력을 한 줄 남긴다", "횟수는 덮어쓰기(upsert)가 일어나는 lockouts 표가 아니라, '추가만 하는' lock_history 표에서 셉니다. 덮어쓰는 표로는 몇 번째인지 알 수 없기 때문입니다.",
        fn="security/lockdown.py:after_temporary_lock", hl='db.insert_lock_history(target_kind, target_value, "TEMPORARY", "THRESHOLD", source_event_type)',
        calls=[call("db.insert_lock_history", "잠금 이력 한 줄 추가", "lock_history 에 (대상·종류·사유·유형)을 추가합니다. 고치거나 지우지 않습니다(append-only).")])
s1.step("② 최근 30일 안에 몇 번째 잠금인가?", "회원 로그인 잠금(BRUTE_FORCE·PASSWORD_SPRAYING)끼리, 관리자 로그인 잠금(ADMIN_BRUTE_FORCE)끼리만 셉니다.",
        fn="security/lockdown.py:after_temporary_lock", hl=('if target_kind == "ip":', "return"),
        calls=[call("db.count_lock_history", "최근 N일 임시 잠금 횟수", "lock_history 에서 이 대상의 TEMPORARY 이력을 셉니다."),
               call(snippet=("config.py", "PERMANENT_LOCK_STRIKE_COUNT =", "PERMANENT_LOCK_STRIKE_WINDOW_DAYS ="), title="승격 기준 (2회 / 30일)", plain="IP 2회 · 계정 2회 · 집계 창 30일.", label="config.py 승격 기준")])
s1.step("③ 계정은 '보호관찰 중 재잠금'도 본다", "이메일 복구 직후 24시간 안에 다시 잠기면, 본인 인증 수단이 공격자에게 넘어갔을 수 있다고 보고 횟수와 무관하게 관리자 전용 영구 잠금으로 올립니다.",
        fn="security/lockdown.py:after_temporary_lock", hl=('strikes = db.count_lock_history("account"', "elif strikes >= config.PERMANENT_LOCK_ACCOUNT_STRIKE_COUNT:"),
        calls=[call("security/lockdown.py:_in_probation", "보호관찰 기간인가?", "probation_until 이 아직 미래인지 봅니다.")])
s1.step("④ 승격 실행 — 허용 목록은 절대 안 잠근다", "관리자 PC 같은 허용 목록 IP 는 영구 잠그지 않습니다(관리자 자충수 방지). 이미 영구면 False 라서 알림도 한 번만 나갑니다.",
        fn="security/lockdown.py:promote_ip", hl=("if is_ip_allowlisted(ip):", "if not db.promote_lockout_permanent"),
        reject="(허용 목록 IP / 이미 영구 잠금이면 아무것도 안 함)",
        calls=[call("security/lockdown.py:is_ip_allowlisted", "허용 목록인가?", "IPv6 는 /64 대역 단위로 비교합니다(29단원)."),
               call("db.promote_lockout_permanent", "임시 → 영구 (조건부 UPDATE)", "WHERE lock_type='TEMPORARY' AND active 일 때만 바꿔서, 동시에 두 요청이 와도 먼저 온 쪽만 승격됩니다.")])
s1.step("⑤ 이력 · 이벤트 · 알림", "PERMANENT 이력을 남기고 PERMANENT_LOCK(CRITICAL) 이벤트를 기록한 뒤 Slack 으로 알립니다. 이 이벤트는 사건에 기록되지만 다시 승격을 부르지는 않습니다(재귀 방지).",
        fn="security/lockdown.py:promote_ip", hl=('"ip", ip, "PERMANENT", reason', "alert.send_permanent_lock_alert"),
        calls=[call("notify/alert.py:send_permanent_lock_alert", "영구 잠금 Slack 알림", "대상·사유·복구 방식을 담아 보냅니다.")])
s1.step("⑥ 계정 승격은 가입된 아이디만", "가입되지 않은 아이디는 승격하지 않습니다. 공격자가 아무 아이디나 넣어 영구 잠금 행을 무한히 만들지 못하게 하기 위해서입니다.",
        fn="security/lockdown.py:promote_account", hl=("user = db.get_user_by_username(username)", "recoverable = \"ADMIN_ONLY\""),
        calls=[call("db.promote_account_lockout_permanent", "계정 임시 → 영구", "조건부 UPDATE 로 한 번만 승격합니다.")])

# ---------------------------------------------------------------- 2) 사건 기반 승격
s2 = Scenario("incident", "SIEM 사건 기반 승격",
              "개별 잠금 횟수가 아니라 '사건'의 위험등급으로도 영구 잠금을 겁니다. CRITICAL 이면 즉시, HIGH 면 관리자 승인을 거칩니다(사람이 최종 결정).")
s2.screen("사건이 열리거나 갱신된 직후", "상관분석이 마지막 단계에서 승격을 판단하도록 부릅니다.",
          fn="security/correlate.py:check_and_correlate", hl=("if event_type == lockdown.PERMANENT_LOCK_EVENT_TYPE:", "lockdown.consider_incident_promotion(ip, incident)"))
s2.step("① 영구 잠금 이벤트 자체는 다시 승격하지 않는다", "승격이 승격을 부르는 재귀를 막고, 설정이 켜져 있으면 그 사건을 자동으로 닫습니다.",
        fn="security/correlate.py:check_and_correlate", hl=("if event_type == lockdown.PERMANENT_LOCK_EVENT_TYPE:", "lockdown.close_incident_if_configured(incident)"),
        calls=[call("security/lockdown.py:close_incident_if_configured", "사건 자동 닫기(선택)", "기본은 꺼짐 — 관리자가 직접 '해결'을 누릅니다.")])
s2.step("② CRITICAL 사건은 즉시 영구 잠금", "허용 목록 IP 는 건너뜁니다.",
        fn="security/lockdown.py:consider_incident_promotion", hl=('severity = incident.get("severity_max")', 'promote_ip(ip, "SIEM_CRITICAL", "EXEMPTION", incident_id=incident.get("id"))'))
s2.step("③ HIGH 사건은 관리자 승인 대기", "자동 승격 설정이 꺼져 있으면(기본) 승인 대기 표에 올리고 Slack 으로 알립니다. 가입·글·댓글 도배처럼 오탐 여지가 있는 등급이라 사람이 확인합니다.",
        fn="security/lockdown.py:consider_incident_promotion", hl=("if config.PERMANENT_LOCK_AUTO_ON_HIGH:", "alert.send_pending_approval_alert("),
        calls=[call("db.insert_pending_request", "승인 대기 요청 저장", "11단원의 AI 조기 경보 승인 표를 그대로 재사용합니다.", later="11단원")])

# ---------------------------------------------------------------- 3) 영구 잠금 적용 · 해제
s3 = Scenario("effect", "영구 잠금이 걸린 뒤 · 해제",
              "영구 잠금은 로그인과 회원가입을 모두 막고, 풀 수 있는 방법은 이메일 본인 인증(17단원)이나 관리자 해제뿐입니다.")
s3.screen("영구 잠긴 IP 의 요청", "로그인 화면은 잠금 안내와 함께 복구 링크를 보여주고, 회원가입도 막습니다.",
          fn="routes/auth.py:login_submit", hl=("exemption = None", "# 예외가 있으면 IP 잠금 안내 없이"))
s3.step("① 잠금 상태가 '영구'로 판정된다", "영구 잠금은 풀릴 시각(unlock_at)이 비어 있습니다. '풀릴 시각이 미래인가'만 보면 안 잠긴 것으로 보이므로, 조회 쿼리가 영구 잠금을 따로 포함시킵니다.",
        fn="db.get_active_lockout", hl=('.or_(f"lock_type.eq.PERMANENT', "execute()"),
        calls=[call("detector.get_ip_lock_state", "NONE / TEMPORARY / PERMANENT", "lock_type 까지 보고 상태를 알려줍니다.")])
s3.step("② 영구 잠긴 IP 는 가입도 막는다", "공격자가 새 계정을 만들어 자기 IP 의 예외를 받아내는 우회로를 차단합니다.",
        fn="routes/auth.py:signup_submit", hl=("if detector.get_ip_lock_state(ip) == detector.LOCK_STATE_PERMANENT:", "return render_template"), reject="현재 이 네트워크에서는 회원가입을 할 수 없습니다.")
s3.step("③ 관리자 '영구 해제' — super_admin 전용, 사유 필수", "누가 언제 왜 풀었는지가 lock_history 에 남아야 해서 사유가 비어 있으면 거부합니다. 해제한 사람은 요청 본문이 아니라 로그인 세션에서 가져옵니다(본문은 위조 가능).",
        fn="routes/admin/locks.py:api_permanent_locks_release", hl=("note = (data.get(\"note\") or \"\").strip()", "released = lockdown.release("), reject="해제 사유(note)를 입력해야 합니다.",
        calls=[call("security/lockdown.py:release", "영구 잠금 해제", "해제자·사유를 이력에 남기고 Slack 으로 알립니다. 사건(SIEM)은 닫지 않습니다.",
                    then=[call("db.release_permanent_lockout", "영구 잠금 해제 저장", "lockouts 의 영구 행을 풀림 상태로 바꿉니다."),
                          call("db.mark_lock_released", "해제 이력 기록", "released_by·note 를 lock_history 에 남깁니다.")])])
s3.step("④ 관리자 '수동 영구 잠금'", "허용 목록 IP·가입되지 않은 아이디는 거부합니다. 수동 승격은 이메일 복구 대상이 아니라 관리자만 풀 수 있게(ADMIN_ONLY) 겁니다.",
        fn="routes/admin/locks.py:api_permanent_locks_promote", hl=("if kind == \"ip\":", "promoted = lockdown.promote_account("),
        calls=[call("security/lockdown.py:promote_ip", "IP 영구 잠금", "수동 승격에도 같은 함수를 씁니다.")])

SCENARIOS = [s1.build(), s2.build(), s3.build()]
