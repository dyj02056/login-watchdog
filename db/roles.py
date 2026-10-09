# ============================================================================
# db/roles.py — roles / permissions 표 관련 함수 (Track B guide26, RBAC 기본 구조)
#
# admin_users.role이 "이 관리자가 어떤 역할인지"를 말해준다면, 이 파일의
# has_permission()은 "그 역할이 지금 하려는 일을 해도 되는지"를 확인한다.
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

import db


def has_permission(role: str, action: str) -> bool:
    """이 role이 이 action을 해도 되는지 permissions 표를 조회해서 확인한다.

    db/settings.py의 get_signup_enabled()와 같은 이유로 캐싱하지 않고 매번
    Supabase를 직접 조회한다 — 역할별 권한(permissions 표)은 운영 중에 Supabase에서
    바뀔 수 있는 값이라(대시보드에는 권한 편집 화면이 없다), 한 번 메모리에 담아두면 다른 서버 인스턴스(로컬/Vercel)나
    이미 로그인된 세션에서 권한 변경이 즉시 반영되지 않는다.
    """
    res = (
        db.get_client()
        .table("permissions")
        .select("role")
        .eq("role", role)
        .eq("action", action)
        .limit(1)
        .execute()
    )
    return bool(res.data)


def list_role_permissions(role: str) -> list[str]:
    """이 role이 가진 action 목록 전체를 한 번의 조회로 가져온다.

    대시보드가 "이 관리자에게 어떤 버튼을 보여줄지" 정하려고 /api/status 응답에 싣는
    값이다(예: release_permanent_lock이 없으면 "영구 해제" 버튼을 숨긴다). 화면 표시용일
    뿐이고, 실제 권한 검사는 서버의 require_permission()이 요청마다 따로 한다.
    """
    res = db.get_client().table("permissions").select("action").eq("role", role).execute()
    return [row["action"] for row in res.data]
