# ============================================================================
# routes/admin/manage.py — 회원·회원가입 설정·게시판·관리자 계정 관리 API
#
# 예전 routes/admin.py(798줄)를 기능 묶음별로 나눈 조각 중 하나다. Blueprint(admin_bp)는
# routes/admin/__init__.py에서 하나만 만들고, 이 파일은 거기에 라우트를 붙이기만 한다
# — 그래서 엔드포인트 이름(url_for("admin.xxx"))은 나누기 전과 똑같다.
# 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

from flask import jsonify, request

import config
import db
from helpers import require_permission
from routes.admin import admin_bp


@admin_bp.route("/api/users/delete", methods=["POST"])
@require_permission("delete_user")
def api_users_delete():
    """대시보드의 회원 목록에서 "삭제" 버튼을 눌렀을 때 호출되는 API.

    /api/unlock과 똑같은 패턴이다 — require_permission이 이미 "권한 있는 관리자의
    요청"임을 보장해주므로, 이 함수는 삭제 실행에만 집중한다.
    """
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "user_id 값이 필요합니다."}), 400

    deleted = db.delete_user(user_id)
    return jsonify({"success": deleted})


@admin_bp.route("/api/settings/signup", methods=["POST"])
@require_permission("toggle_signup")
def api_settings_signup():
    """대시보드의 "회원가입 켜기/끄기" 토글을 눌렀을 때 호출되는 API.

    {"enabled": true} 또는 {"enabled": false}를 받아 db.set_signup_enabled()로
    Supabase에 반영한다. 이 값을 서버 메모리가 아니라 Supabase에 저장해두는
    이유는 db.get_signup_enabled() 설명(db/settings.py) 참고 — 로컬/Vercel 등 여러 곳에서
    서버가 동시에 돌아도 항상 같은 값을 보게 하기 위함이다.
    """
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"success": False, "error": "enabled(true/false) 값이 필요합니다."}), 400

    db.set_signup_enabled(enabled)
    return jsonify({"success": True, "signup_enabled": enabled})


@admin_bp.route("/api/board/posts/delete", methods=["POST"])
@require_permission("delete_post")
def api_board_posts_delete():
    """관리자 대시보드의 "게시글 관리" 섹션에서 임의 게시글을 삭제할 때 호출되는 API.

    /api/users/delete와 동일한 패턴 — require_permission이 이미 "권한 있는 관리자의
    요청"임을 보장해주므로, 회원 본인 글인지 여부와 무관하게 바로 삭제한다
    (docs/board-comment/02-design-decisions.md 결정 #2 — 삭제 권한: 본인 + 관리자).
    """
    data = request.get_json(silent=True) or {}
    post_id = data.get("post_id")
    if not post_id:
        return jsonify({"success": False, "error": "post_id 값이 필요합니다."}), 400

    deleted = db.delete_post(post_id)
    return jsonify({"success": deleted})


@admin_bp.route("/api/board/comments/delete", methods=["POST"])
@require_permission("delete_comment")
def api_board_comments_delete():
    """관리자 대시보드에서 임의 댓글을 삭제할 때 호출되는 API. 위 함수와 동일한 패턴."""
    data = request.get_json(silent=True) or {}
    comment_id = data.get("comment_id")
    if not comment_id:
        return jsonify({"success": False, "error": "comment_id 값이 필요합니다."}), 400

    deleted = db.delete_comment(comment_id)
    return jsonify({"success": deleted})


# super_admin만 만들 수 있는 역할. 여기 super_admin을 넣지 않은 게 핵심 안전장치다 —
# 이 화면(그리고 아래 삭제 API)으로는 super_admin 계정을 만들거나 지울 수 없게
# 만들어서, "super_admin은 1명만 둔다"는 운영 정책(login_watchdog_expansion_plan.md
# 논의)을 코드 수준에서도 지키게 한다.
_CREATABLE_ADMIN_ROLES = ("security_viewer", "security_admin")


@admin_bp.route("/api/admin-users/create", methods=["POST"])
@require_permission("manage_admin_users")
def api_admin_users_create():
    """대시보드 "관리자 계정 관리" 카드의 생성 폼이 호출하는 API.

    scripts/create_admin.py와 동일한 검증 규칙(아이디 형식, 비밀번호 길이)을
    쓰고, db.create_admin_user()도 그대로 재사용한다 — 다만 역할은
    _CREATABLE_ADMIN_ROLES 두 가지로만 제한한다. 화면(select 옵션)에서도
    super_admin을 아예 안 보여주지만, fetch()를 직접 조작해 super_admin을
    보내는 요청도 여기서 한 번 더 막아야 실질적인 방어가 된다.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    role = data.get("role", "")

    if not config.USERNAME_PATTERN.match(username):
        return jsonify({"success": False, "error": "아이디는 영문/숫자/밑줄 3~20자여야 합니다."}), 400
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return jsonify({"success": False, "error": f"비밀번호는 최소 {config.MIN_PASSWORD_LENGTH}자 이상이어야 합니다."}), 400
    if role not in _CREATABLE_ADMIN_ROLES:
        return jsonify({"success": False, "error": "role은 security_viewer 또는 security_admin만 가능합니다."}), 400

    created = db.create_admin_user(username, password, role)
    if not created:
        return jsonify({"success": False, "error": "이미 존재하는 아이디입니다."}), 400
    return jsonify({"success": True})


@admin_bp.route("/api/admin-users/delete", methods=["POST"])
@require_permission("manage_admin_users")
def api_admin_users_delete():
    """대시보드 "관리자 계정 관리" 카드의 "삭제" 버튼이 호출하는 API.

    삭제 전에 대상의 role을 먼저 조회해서 super_admin이면 거부한다 —
    db.delete_admin_user() 자체는 그 구분을 하지 않으므로(db/admin.py 설명 참고),
    여기서 막지 않으면 마지막 super_admin 계정까지 지워질 수 있다.
    """
    data = request.get_json(silent=True) or {}
    admin_id = data.get("admin_id")
    if not admin_id:
        return jsonify({"success": False, "error": "admin_id 값이 필요합니다."}), 400

    target_role = db.get_admin_role_by_id(admin_id)
    if target_role == "super_admin":
        return jsonify({"success": False, "error": "super_admin 계정은 이 화면에서 삭제할 수 없습니다."}), 400

    deleted = db.delete_admin_user(admin_id)
    return jsonify({"success": deleted})
