# 20단원 — 복구 코드 시도 제한 + 관리자 세션 검증 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "20-code-attempts-admin-session"
TITLE = "20. 복구 코드 시도 제한 + 관리자 세션 검증"
SUBTITLE = "'비교하기 전에 시도권부터 예약'하는 복구 코드 방어와, 요청마다 DB 계정과 대조하는 관리자 세션 검증의 코드 흐름도"

FILE_ROLES = {
    "routes/recovery.py": "복구 화면의 입구 파일. 6자리 코드는 비교하기 전에 시도권을 예약한다.",
    "db/recovery.py": "복구 요청 표를 다루는 저장소 파일. 시도권 예약을 조건부 UPDATE 로 처리한다.",
    "helpers/auth.py": "관리자 문지기. 세션이 지금도 존재하는 관리자 계정을 가리키는지 요청마다 확인한다.",
    "routes/admin/login.py": "관리자 로그인 입구 파일. 성공하면 세션에 아이디·기본키·로그인 시각을 넣는다.",
    "db/admin.py": "관리자 계정 표를 읽고 쓰는 저장소 파일.",
    "app.py": "Flask 앱 조립 파일. 복구 코드 제출에 좁은 요청 한도를 따로 건다.",
}

REC = "routes/recovery.py:recovery_verify_submit"

s1 = Scenario("code", "6자리 복구 코드: 비교 전에 시도권 예약",
              "6자리 코드는 경우의 수가 100만 개뿐이라 '5회까지만 틀릴 수 있다'가 유일한 방어선입니다. 그런데 코드를 비교한 '뒤에' 횟수를 올리면, 동시에 1000개를 보냈을 때 횟수가 오르기 전에 1000번 모두 비교가 끝나 버립니다.")
s1.screen("코드 입력 제출 (POST /recovery/verify)", "아이디 + 6자리 코드를 보냅니다.",
          fn=REC, hl=('@recovery_bp.route("/recovery/verify", methods=["POST"])', "def recovery_verify_submit"))
s1.step("① 요청한 기기가 아니면 공통 문구 (시도권 사용 안 함)", "아이디 없음·진행 중인 요청 없음·다른 기기를 같은 문구로 답하고 시도권도 쓰지 않습니다. 그래서 다른 기기에서 틀린 코드를 넣어 남의 복구를 취소시킬 수도 없습니다(22단원).",
        fn=REC, hl=("req = (", "return render_template(\"recovery_verify.html\", mode=\"code\", message=CODE_GENERIC_FAILURE_MESSAGE)"), reject="아이디 또는 코드가 올바르지 않거나 만료되었습니다.",
        calls=[call("db.get_latest_pending_recovery_for_username", "이 아이디의 진행 중 요청", "users 와 inner join 한 번으로 찾습니다."),
               call("routes/recovery.py:_device_matches", "요청한 기기인가?", "쿠키 해시와 저장된 해시를 타이밍 안전 비교합니다.")])
s1.step("② 비교 '전에' 시도권 1회를 예약", "먼저 시도권을 받아야만 비교할 수 있게 하면, 동시에 몇 개를 보내든 한도 이상은 비교조차 되지 않습니다. 예약에 실패하면 맞는 코드여도 통과시키지 않습니다(실패 쪽으로 닫힘).",
        fn=REC, hl=("attempt = db.reserve_recovery_code_attempt(", "return render_template(\"recovery_verify.html\", mode=\"code\", message=CODE_EXHAUSTED_MESSAGE)"), reject="코드가 올바르지 않습니다. 복구를 다시 요청해주세요.",
        calls=[call("db.reserve_recovery_code_attempt", "시도권 예약 (조건부 UPDATE)", "'읽은 횟수 그대로일 때만' +1 합니다. 경쟁에서 지면 다시 읽고 최대 3번 재시도, 한도에 닿으면 None.",
                    hl=('.eq("status", "PENDING")', '.gt("expires_at", db._now_iso())'))])
s1.step("③ 이제서야 코드 비교 — 틀렸고 마지막 기회였다면 요청 취소", "코드는 hmac.compare_digest 로 해시끼리 비교합니다. 마지막 시도권으로 맞게 입력한 사용자는 성공해야 해서, 한도에 닿아도 예약 단계에서 취소하지 않고 틀렸을 때만 취소합니다.",
        fn=REC, hl=("if not hmac.compare_digest(hash_secret(code), req[\"code_hash\"]):", "return _finish(req)"),
        calls=[call("db.revoke_recovery_request", "복구 요청 취소", "마지막 시도마저 틀리면 REVOKED 로 바꿉니다.")])
s1.step("④ 제출 자체에도 분당 한도 (2차 방어선)", "시도권 예약이 핵심 방어선이고, 이 한도는 그 앞단의 보조 방어선입니다. 전역 한도보다 훨씬 좁게 겁니다. 인메모리라 서버리스 인스턴스마다 따로 셉니다.",
        snippet=("app.py", 'app.view_functions["recovery.recovery_verify_submit"]', "re:^\\)\\(app.view_functions"), label="app.py 복구 제출 한도",
        calls=[call(snippet=("config.py", "RECOVERY_MAX_CODE_ATTEMPTS =", "RECOVERY_MAX_CODE_ATTEMPTS ="), title="코드 시도 한도", plain="한 요청당 틀릴 수 있는 횟수.", label="RECOVERY_MAX_CODE_ATTEMPTS")])

s2 = Scenario("session", "관리자 세션: 요청마다 DB 계정과 대조",
              "세션 쿠키는 서명만 되어 있을 뿐 서버가 따로 보관하지 않습니다. 예전처럼 '아이디가 들어 있는가'만 보면 삭제된 관리자도 남은 쿠키로 대시보드를 계속 볼 수 있었고, 같은 아이디로 계정을 다시 만들면 옛 쿠키가 되살아났습니다.")
s2.screen("관리자 로그인 성공 — 세션에 3가지를 넣는다", "아이디뿐 아니라 계정의 기본키(admin_id)와 로그인 시각까지 넣어 둡니다.",
          fn="routes/admin/login.py:admin_login_submit", hl=("admin_id = db.get_admin_id_by_username(username)", "start_admin_session(admin_id, username)"),
          calls=[call("helpers/auth.py:start_admin_session", "관리자 세션 시작", "admin_username · admin_id · admin_login_at 을 저장합니다.")])
s2.step("① 세션 값이 모두 있는가", "일부가 없으면(이 기능 이전에 만들어진 세션 포함) 무효입니다. 배포 직후 기존 관리자는 한 번 다시 로그인해야 합니다.",
        fn="helpers/auth.py:_load_current_admin", hl=('admin_id = session.get("admin_id")', "return None"), reject="무효 세션 → 다시 로그인")
s2.step("② 로그인한 지 8시간이 지났나", "수명은 '마지막 활동'이 아니라 '로그인 시각' 기준입니다. 대시보드가 5초마다 폴링해서 활동이 없는 상태가 생기지 않기 때문입니다.",
        fn="helpers/auth.py:_load_current_admin", hl=("if time.time() - login_at > config.ADMIN_SESSION_MAX_HOURS * 3600:", "return None"), reject="무효 세션 → 다시 로그인",
        calls=[call(snippet=("config.py", "ADMIN_SESSION_MAX_HOURS =", "ADMIN_SESSION_MAX_HOURS ="), title="세션 수명 (8시간)", plain="환경변수로 바꿀 수 있습니다.", label="ADMIN_SESSION_MAX_HOURS")])
s2.step("③ DB 에 그 계정이 지금도 있고 아이디가 같은가", "삭제됐거나 같은 아이디로 다시 만들어졌다면 기본키(id)가 달라 걸러집니다. 통과하면 계정(역할 포함)을 g.admin 에 담아 둡니다.",
        fn="helpers/auth.py:_load_current_admin", hl=("admin = db.get_admin_by_id(admin_id)", "g.admin = admin"), reject="무효 세션 → 다시 로그인",
        calls=[call("db.get_admin_by_id", "기본키로 관리자 찾기", "admin_users 에서 id 로 한 줄을 가져옵니다.")])
s2.step("④ 실패하면: '세션 없음'과 '무효 세션'을 구분", "세션이 아예 없음 = 공격일 수 있으므로 미인증 접근으로 기록(6단원). 세션은 있는데 무효 = 다시 로그인해야 할 관리자이므로 기록하지 않습니다(기록하면 삭제된 관리자의 폴링이 공격으로 오탐됩니다).",
        fn="helpers/auth.py:_reject_admin_request", hl=('if "admin_username" in session:', 'return redirect(url_for("admin.admin_login"))'),
        calls=[call("helpers/auth.py:clear_admin_session", "관리자 세션만 지우기", "같은 브라우저의 회원 세션은 그대로 둡니다.")])

SCENARIOS = [s1.build(), s2.build()]
