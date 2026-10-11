# 12단원 — 관리자 대시보드 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "12-admin-dashboard"
TITLE = "12. 관리자 대시보드"
SUBTITLE = "자동 대응 위에 '사람의 최종 판단'을 얹는 관리자 화면의 데이터 흐름과 처리 버튼의 코드 흐름도"

FILE_ROLES = {
    "routes/admin/status.py": "관리자 대시보드 화면과 5초마다 부르는 /api/status(전체 상태) · /api/stats(집계) 입구 파일.",
    "routes/admin/locks.py": "'즉시 해제'·영구 잠금·IP 예외·복구 요청 처리 버튼이 호출하는 API 입구 파일.",
    "helpers/auth.py": "관리자 문지기(login_required)와 권한 문지기(require_permission)가 있는 파일.",
    "helpers/request_utils.py": "시도 기록에 접속 위치(국가·도시)를 붙이는 공용 도구.",
    "security/soar/lockouts.py": "잠금 집행과 해제(자동 만료·관리자 수동)를 담당하는 집행관 파일.",
    "db/lockouts.py": "IP 잠금(lockouts 표)을 읽고 쓰는 저장소 파일.",
    "db/security_events.py": "위험등급 이벤트 표를 읽고 쓰는 저장소 파일.",
    "db/roles.py": "역할별 허용 액션(permissions 표)을 조회하는 저장소 파일. (13단원)",
}

# ---------------------------------------------------------------- 1) 5초 갱신
s1 = Scenario("poll", "5초마다 상태 갱신 (/api/status)",
              "화면은 뼈대만 받고, 실제 데이터는 브라우저가 5초마다 /api/status 를 불러 채웁니다(탭이 안 보이면 멈춤, 27단원). 서버는 서로 무관한 조회 17개를 '동시에' 보내서 가장 느린 조회 하나만큼만 기다립니다.")
s1.screen("대시보드 접속 (/admin/dashboard)", "화면 뼈대(HTML)만 렌더링하고, 몇 ms 마다 갱신할지(poll_interval_ms)를 config 에서 받아 내려줍니다. 이후 데이터는 아래 API 가 채웁니다.",
          fn="routes/admin/status.py:admin_dashboard", hl=('@admin_bp.route("/admin/dashboard"', "@login_required"),
          calls=[call(snippet=("config.py", "ADMIN_PAGE_SIZE =", "ADMIN_STATUS_CACHE_SECONDS ="), title="갱신 주기·표 크기·캐시 설정", plain="폴링 5초 · 표 한 쪽 10건 · 응답 캐시 3초.", label="config.py 관리자 화면 설정")])
s1.step("① 관리자 로그인 확인 (문지기)", "세션이 지금도 존재하는 관리자 계정을 가리키는지 확인합니다. 아니면 401 JSON 또는 로그인 화면으로 보냅니다.",
        fn="helpers/auth.py:login_required", hl=("if _load_current_admin() is None:", "return _reject_admin_request()"), reject="401(API) / 관리자 로그인 화면",
        calls=[call("helpers/auth.py:_load_current_admin", "세션 → 관리자 계정", "세션의 id·아이디가 실제 계정과 맞는지 DB 에서 확인합니다.")])
s1.step("② 잠깐 보관한 응답이 있으면 그대로", "탭이 여러 개여도 같은 조회를 나눠 쓰도록 3초 동안 응답을 보관합니다. 역할(role)에 따라 응답이 다르므로 역할·쪽 번호별로 따로 둡니다.",
        fn="routes/admin/status.py:api_status", hl=("ttl = config.ADMIN_STATUS_CACHE_SECONDS", "return jsonify(hit[1])"))
s1.step("③ 만료된 잠금 정리 (정해진 간격마다)", "별도 타이머 없이, 대시보드가 갱신될 때 '풀릴 시간이 지난 잠금'을 확인해 풀어줍니다(IP·회원 계정·관리자 계정 3종을 동시에).",
        fn="routes/admin/status.py:api_status", hl="_release_expired_locks_if_due()",
        calls=[call("routes/admin/status.py:_release_expired_locks_if_due", "만료 잠금 정리 3종", "정해진 간격마다만 동시에 돌립니다.",
                    then=[call("soar.try_release_expired_lockouts", "IP 잠금 만료 해제", "풀릴 시각이 지난 IP 잠금을 풀고 CRITICAL 이벤트를 정리합니다.")])])
s1.step("④ 조회 17개를 동시에 실행", "로그인 시도·잠긴 IP·회원·게시글·댓글·보안 이벤트·사건·AI 조기 경보 등을 한꺼번에 보냅니다. 순서대로 하면 2~3초, 동시에 하면 가장 느린 쿼리 하나 수준입니다(실측 약 5배 개선).",
        fn="routes/admin/status.py:api_status", hl=("with ThreadPoolExecutor(max_workers=17) as executor:", "admin_users_future = executor.submit(db.list_admin_users)"),
        calls=[call(refs=["db.list_recent_attempts", "db.list_active_lockouts", "db.list_users", "db.list_security_events", "db.list_security_incidents", "db.list_pending_requests"],
                    title="조회 17개 중 대표 6개", plain="각각 (이번 쪽 데이터, 전체 개수)를 한 번의 왕복으로 돌려줍니다. 나머지는 게시글·댓글·로그인 기록·복구 요청 등입니다.")])
s1.step("⑤ 시도 기록에 접속 위치 붙이기", "시도 목록이 도착하자마자, 다른 조회가 아직 도는 동안 함께 위치를 붙입니다.",
        fn="routes/admin/status.py:api_status", hl="recent_attempts = _attach_locations(attempts)",
        calls=[call("helpers._attach_locations", "기록에 위치 붙이기", "IP → 국가·도시(4단원).", later="4단원")])
s1.step("⑥ '관리자 계정 관리' 카드는 super_admin 에게만", "권한이 없으면 응답에 키 자체가 없어서 화면이 카드를 숨깁니다. 권한 확인과 목록 조회는 같은 배치로 미리 보내고, 권한이 없으면 목록은 버립니다.",
        fn="routes/admin/status.py:api_status", hl=("admin_users = admin_users_future.result() if can_manage_admins else None", 'response_data["admin_users"] = admin_users'),
        calls=[call("db.has_permission", "이 역할이 manage_admin_users 를 가졌나", "permissions 표를 매번 직접 조회합니다(13단원).", later="13단원")])
s1.step("⑦ 응답 보관 후 JSON 으로 응답", "다음 3초 안의 요청은 이 값을 재사용합니다. 보관 개수는 64개로 제한합니다.",
        fn="routes/admin/status.py:api_status", hl=("if ttl > 0:", "return jsonify(response_data)"))
s1.step("⑧ 처리 버튼(POST)이 끝나면 보관 응답을 비움", "방금 누른 버튼의 결과가 오래된 값에 가려지지 않게 합니다.",
        fn="routes/admin/status.py:_clear_status_cache_after_change", hl='if request.method == "POST":')

# ---------------------------------------------------------------- 2) 즉시 해제
s2 = Scenario("unlock", "'즉시 해제' 버튼",
              "잠긴 IP 카드의 '즉시 해제'를 누르면 /api/unlock 이 호출됩니다. 권한 확인은 라우트 문지기가 먼저 끝내고, 해제 함수는 '이미 권한이 확인된 요청'이라고 가정하고 실행에만 집중합니다.")
s2.screen("'즉시 해제' 클릭 (POST /api/unlock)", "브라우저가 {ip} 를 보냅니다.",
          fn="routes/admin/locks.py:api_unlock", hl=('@admin_bp.route("/api/unlock"', '@require_permission("unlock_ip")'))
s2.step("① 권한 확인 + 입력 확인", "unlock_ip 권한이 있는 로그인된 관리자만 이 함수까지 도달합니다. ip 값이 없으면 400.",
        fn="routes/admin/locks.py:api_unlock", hl=('data = request.get_json(silent=True) or {}', "released = soar.manual_release(ip)"), reject="ip 값이 필요합니다. (400)",
        calls=[call("helpers/auth.py:require_permission", "권한 문지기", "로그인 확인 → 역할별 권한 확인(13단원).", later="13단원")])
s2.step("② 지금 정말 잠겨 있는 IP 인가?", "활성 잠금 목록에 없으면 아무것도 하지 않고 False.",
        fn="soar.manual_release", hl=('active = {row["ip_address"]: row for row in db.list_active_lockouts()}', "return False"),
        calls=[call("db.list_active_lockouts", "현재 잠긴 IP 목록", "lockouts 표에서 active=True 인 줄을 가져옵니다.")])
s2.step("③ 영구 잠금은 이 버튼으로 못 푼다", "사유 기록과 권한 분리가 필요한 별도 경로('영구 해제', super_admin 전용)로만 풉니다.",
        fn="soar.manual_release", hl=('if active[ip].get("lock_type") == "PERMANENT":', "return False"), reject="영구 잠금은 '영구 해제'로만 풀 수 있습니다. (409)")
s2.step("④ 해제 + CRITICAL 이벤트 정리", "행을 지우지 않고 active=False 로만 바꿔 '언제 잠겼다 풀렸는지' 이력을 남깁니다. 연관 사건(SIEM)은 닫지 않습니다 — 관리자가 '해결'로 따로 판단합니다.",
        fn="soar.manual_release", hl=("db.release_lockout(ip)", "return True"),
        calls=[call("db.release_lockout", "잠금 해제 (active=False)", "해제됨 표시만 남깁니다."),
               call("db.resolve_security_events_for_ip", "CRITICAL 이벤트 자동 처리", "이 IP 의 미해결 CRITICAL 이벤트를 해결됨으로 표시합니다(8단원).")])

SCENARIOS = [s1.build(), s2.build()]
