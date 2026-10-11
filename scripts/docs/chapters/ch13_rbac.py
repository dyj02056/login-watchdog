# 13단원 — 관리자 RBAC 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "13-rbac"
TITLE = "13. 관리자 RBAC"
SUBTITLE = "관리자 요청이 '세션 확인 → 역할별 권한 확인'의 두 단계 문지기를 통과하는 코드 흐름도"

FILE_ROLES = {
    "helpers/auth.py": "관리자 문지기(login_required)와 권한 문지기(require_permission)를 만드는 파일.",
    "db/roles.py": "역할(roles)과 허용 액션(permissions) 표를 조회하는 저장소 파일. 캐싱하지 않는다.",
    "routes/admin/locks.py": "잠금 해제 등 권한이 필요한 처리 API 입구 파일.",
    "routes/admin/manage.py": "회원 삭제·가입 on/off·게시글 삭제·관리자 계정 생성/삭제 API 입구 파일.",
    "db/admin.py": "관리자 계정(admin_users 표)을 만들고 지우고 조회하는 저장소 파일.",
}

s1 = Scenario("guard", "권한 문지기 (require_permission)",
              "'로그인만 되면 뭐든 가능'은 위험합니다. 조회 담당자 계정이 털려도 회원 삭제까지 가능해지기 때문입니다. 그래서 요청마다 ① 세션이 아직 유효한가 ② 이 역할이 이 일을 해도 되는가를 차례로 확인합니다.")
s1.screen("보호된 API 호출 (예: /api/unlock)", "라우트 위에 @require_permission(\"unlock_ip\") 처럼 '필요한 액션'을 적어 둡니다.",
          fn="routes/admin/locks.py:api_unlock", hl=('@admin_bp.route("/api/unlock"', '@require_permission("unlock_ip")'))
s1.step("① 세션이 아직 유효한 관리자인가?", "세션의 관리자 번호·아이디가 실제 계정과 맞는지 매 요청마다 DB 에서 확인합니다. 삭제되거나 바뀐 계정이면 더 진행하지 않습니다.",
        fn="helpers/auth.py:require_permission", hl=("admin = _load_current_admin()", "return _reject_admin_request()"), reject="401(API) 또는 로그인 화면 / 무효 세션이면 다시 로그인",
        calls=[call("helpers/auth.py:_load_current_admin", "세션 → 관리자 계정", "id·아이디·수명을 확인하고 g.admin 에 담습니다."),
               call("helpers/auth.py:_reject_admin_request", "미인증 응답", "세션이 아예 없으면 미인증 접근으로 기록(6단원), 무효 세션이면 기록 없이 다시 로그인으로.", later="6단원")])
s1.step("② 이 역할이 이 액션을 해도 되나?", "로그인은 됐지만 역할에 그 액션이 없으면 403 JSON 을 돌려줍니다. 이미 로그인한 상태에서 걸리는 경우라 화면 이동이 아니라 항상 JSON 입니다.",
        fn="helpers/auth.py:require_permission", hl=('if not db.has_permission(admin["role"], action):', "403"), reject="이 작업을 수행할 권한이 없습니다. (403)",
        calls=[call("db.has_permission", "permissions 표 조회", "(role, action) 한 줄이 있는지 매번 직접 조회합니다. 캐싱하지 않습니다.")])
s1.step("③ 통과하면 실제 처리 함수 실행", "권한이 확인된 요청만 도달하므로, 처리 함수(예: soar.manual_release)는 권한을 다시 확인하지 않고 실행에만 집중합니다.",
        fn="helpers/auth.py:require_permission", hl="return view(*args, **kwargs)",
        calls=[call("soar.manual_release", "즉시 해제 실행", "12단원.", later="12단원")])

s2 = Scenario("cache", "권한은 캐싱하지 않는다 (즉시 회수)",
              "권한을 메모리에 담아 두면, super_admin 이 다른 관리자의 권한을 방금 바꿨는데도 그 관리자가 로그아웃하기 전까지 예전 권한이 유지됩니다. 그래서 요청마다 DB 를 직접 봅니다.")
s2.screen("권한 확인 요청 (매 요청마다)", "role 과 action 을 받아 permissions 표에 한 줄이 있는지만 봅니다.",
          fn="db.has_permission", hl="def has_permission(")
s2.step("① permissions 표에서 (역할, 액션) 조회", "있으면 허용, 없으면 거부입니다.",
        fn="db.has_permission", hl=('.table("permissions")', "return bool(res.data)"),
        calls=[call("db.list_role_permissions", "이 역할의 액션 전체 목록", "대시보드가 '어떤 버튼을 보여줄지' 정하려고 /api/status 에 실어 보내는 값입니다. 화면 표시용일 뿐 실제 검사는 서버가 따로 합니다.")])

s3 = Scenario("admins", "super_admin 은 이 화면에서 만들 수 없다",
              "'super_admin 은 1명만 둔다'는 운영 정책을 화면(select 옵션)뿐 아니라 서버에서도 강제합니다. fetch() 를 직접 조작해 우회하는 요청까지 막기 위해서입니다.")
s3.screen("관리자 계정 생성 (POST /api/admin-users/create)", "manage_admin_users 권한(= super_admin)이 있어야 호출할 수 있습니다.",
          fn="routes/admin/manage.py:api_admin_users_create", hl=('@admin_bp.route("/api/admin-users/create"', '@require_permission("manage_admin_users")'))
s3.step("① 입력 규칙 + 만들 수 있는 역할 제한", "아이디 형식·비밀번호 길이는 회원가입과 같은 규칙을 쓰고, 역할은 security_viewer / security_admin 두 가지만 허용합니다.",
        fn="routes/admin/manage.py:api_admin_users_create", hl=("if not config.USERNAME_PATTERN.match(username):", "role은 security_viewer 또는 security_admin만 가능합니다."), reject="규칙에 어긋난 항목 안내 (400)",
        calls=[call(snippet=("routes/admin/manage.py", "_CREATABLE_ADMIN_ROLES =", "_CREATABLE_ADMIN_ROLES ="), title="만들 수 있는 역할 (super_admin 없음)", plain="여기 super_admin 을 넣지 않은 것이 핵심 안전장치입니다.", label="_CREATABLE_ADMIN_ROLES")])
s3.step("② 계정 저장", "이미 있는 아이디면 거부합니다.",
        fn="routes/admin/manage.py:api_admin_users_create", hl="created = db.create_admin_user(username, password, role)", reject="이미 존재하는 아이디입니다.",
        calls=[call("db.create_admin_user", "관리자 계정 저장", "비밀번호를 해시로 바꿔 admin_users 표에 저장합니다.")])
s3.step("③ 삭제: super_admin 이면 거부", "삭제 대상의 역할을 먼저 조회해 super_admin 이면 막습니다. 이렇게 하지 않으면 마지막 super_admin 까지 지워질 수 있습니다.",
        fn="routes/admin/manage.py:api_admin_users_delete", hl=("target_role = db.get_admin_role_by_id(admin_id)", "return jsonify({\"success\": deleted})"), reject="super_admin 계정은 이 화면에서 삭제할 수 없습니다. (400)",
        calls=[call("db.get_admin_role_by_id", "대상의 역할 조회", "삭제 전에 역할을 확인합니다."),
               call("db.delete_admin_user", "관리자 계정 삭제", "super_admin 구분은 하지 않으므로 호출 전에 막아야 합니다.")])

SCENARIOS = [s1.build(), s2.build(), s3.build()]
