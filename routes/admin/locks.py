# ============================================================================
# routes/admin/locks.py — 잠금 해제·영구 잠금·IP 예외·복구 요청 관리 API
#
# 예전 routes/admin.py(798줄)를 기능 묶음별로 나눈 조각 중 하나다. Blueprint(admin_bp)는
# routes/admin/__init__.py에서 하나만 만들고, 이 파일은 거기에 라우트를 붙이기만 한다
# — 그래서 엔드포인트 이름(url_for("admin.xxx"))은 나누기 전과 똑같다.
# 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import ipaddress

from flask import jsonify, request, session

import db
from helpers import require_permission
from routes.admin import admin_bp
from security import lockdown, soar


# ============================================================================
# 임시 잠금 즉시 해제 API (IP / 회원 계정 / 관리자 계정)
# ============================================================================


@admin_bp.route("/api/unlock", methods=["POST"])
@require_permission("unlock_ip")
def api_unlock():
    """대시보드의 "즉시 해제" 버튼을 눌렀을 때 브라우저가 호출하는 API.

    이 라우트가 require_permission("unlock_ip")로 보호되어 있으므로, 이 함수가 실행되는
    시점엔 이미 "IP 잠금 해제 권한이 있는 로그인된 관리자의 요청"이라는 게 보장된 상태다
    — 그래서 soar.manual_release는 권한 확인을 다시 하지 않고 바로 실행에만 집중할 수
    있다(4단계 security/soar/ 설명 참고).
    """
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "ip 값이 필요합니다."}), 400

    released = soar.manual_release(ip)
    if not released and lockdown.is_permanent_ip(ip):
        return jsonify({"success": False, "error": "영구 잠금은 '영구 해제'로만 풀 수 있습니다."}), 409
    return jsonify({"success": released})


@admin_bp.route("/api/unlock-account", methods=["POST"])
@require_permission("unlock_ip")
def api_unlock_account():
    """대시보드 "현재 잠긴 IP / 계정" 카드에서 계정 잠금의 "즉시 해제" 버튼을
    눌렀을 때 호출되는 API. /api/unlock의 계정 버전이며, 별도 권한을 새로 만들지
    않고 같은 "잠금 해제" 권한(unlock_ip)을 그대로 쓴다.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    if not username:
        return jsonify({"success": False, "error": "username 값이 필요합니다."}), 400

    released = soar.manual_release_account(username)
    if not released and lockdown.is_permanent_account(username):
        return jsonify({"success": False, "error": "영구 잠금은 '영구 해제'로만 풀 수 있습니다."}), 409
    return jsonify({"success": released})


@admin_bp.route("/api/unlock-admin-account", methods=["POST"])
@require_permission("unlock_admin_account")
def api_unlock_admin_account():
    """잠긴 관리자 계정의 "즉시 해제" 버튼이 호출하는 API(guide38). super_admin만 가진
    unlock_admin_account 권한이 필요하다 — 관리자 계정의 잠금을 푸는 것은 회원 계정보다
    위험도가 높아서 /api/unlock-account(unlock_ip 권한)와 권한을 나눴다.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    if not username:
        return jsonify({"success": False, "error": "username 값이 필요합니다."}), 400

    return jsonify({"success": soar.manual_release_admin_account(username)})


# ============================================================================
# 영구 잠금 + 이메일 복구 관리 API (guide33) — 쓰기 API 하나당 권한 하나(1:1)
#
#   promote_permanent_lock   : security_admin, super_admin  (수동 영구 승격)
#   release_permanent_lock   : super_admin만               (영구 잠금 완전 해제 — 가장 신중해야 하는 조치)
#   revoke_ip_exemption      : security_admin, super_admin  (IP 예외 회수)
#   revoke_recovery_request  : security_admin, super_admin  (진행 중인 복구 요청 취소)
# ============================================================================

_PERMANENT_LOCK_KINDS = ("ip", "account")


def _int_field(data: dict, key: str) -> int | None:
    """JSON 본문에서 정수 id 하나를 꺼낸다. bool(True/False)은 파이썬에서 int의 하위 타입이라
    따로 걸러야 한다(api_security_incidents_resolve와 같은 이유)."""
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


@admin_bp.route("/api/permanent-locks/promote", methods=["POST"])
@require_permission("promote_permanent_lock")
def api_permanent_locks_promote():
    """대시보드 "영구 잠금 수동 승격" 폼이 호출하는 API — IP나 계정을 관리자가 직접 영구 잠금한다.

    수동 승격은 이메일 복구 대상이 아니라 관리자만 풀 수 있게(ADMIN_ONLY) 건다.
    허용 목록 IP(관리자 PC 등)와 가입되지 않은 아이디는 거부한다.
    """
    data = request.get_json(silent=True) or {}
    kind = data.get("target_kind")
    value = (data.get("target_value") or "").strip()
    reason = (data.get("reason") or "").strip()
    if kind not in _PERMANENT_LOCK_KINDS or not value or not reason:
        return jsonify({"success": False, "error": "target_kind(ip/account), target_value, reason이 필요합니다."}), 400

    note = f"{session['admin_username']}: {reason}"
    if kind == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return jsonify({"success": False, "error": "올바른 IP 주소가 아닙니다."}), 400
        if lockdown.is_ip_allowlisted(value):
            return jsonify({"success": False, "error": "허용 목록의 IP는 영구 잠금할 수 없습니다."}), 400
        promoted = lockdown.promote_ip(value, "ADMIN_MANUAL", "ADMIN_ONLY", note=note)
    else:
        if db.get_user_by_username(value) is None:
            return jsonify({"success": False, "error": "가입되지 않은 아이디입니다."}), 404
        promoted = lockdown.promote_account(value, "ADMIN_MANUAL", "ADMIN_ONLY", note=note)

    if not promoted:
        return jsonify({"success": False, "error": "이미 영구 잠금 상태입니다."}), 409
    return jsonify({"success": True})


@admin_bp.route("/api/permanent-locks/release", methods=["POST"])
@require_permission("release_permanent_lock")
def api_permanent_locks_release():
    """대시보드 영구 잠금 카드의 "영구 해제" 버튼이 호출하는 API(super_admin 전용).

    사유(note)가 비어 있으면 거부한다 — "누가 언제 왜 풀었는지"가 lock_history에 남아야 하기
    때문이다. 해제한 관리자는 요청 본문이 아니라 로그인 세션에서 가져온다(본문은 위조 가능).
    """
    data = request.get_json(silent=True) or {}
    kind = data.get("target_kind")
    value = (data.get("target_value") or "").strip()
    note = (data.get("note") or "").strip()
    if kind not in _PERMANENT_LOCK_KINDS or not value:
        return jsonify({"success": False, "error": "target_kind(ip/account)와 target_value가 필요합니다."}), 400
    if not note:
        return jsonify({"success": False, "error": "해제 사유(note)를 입력해야 합니다."}), 400

    released = lockdown.release(kind, value, f"admin:{session['admin_username']}", note)
    if not released:
        return jsonify({"success": False, "error": "영구 잠금 상태가 아닌 대상입니다."}), 404
    return jsonify({"success": True})


@admin_bp.route("/api/ip-exemptions/revoke", methods=["POST"])
@require_permission("revoke_ip_exemption")
def api_ip_exemptions_revoke():
    """IP 영구 잠금 예외(본인+본인 기기 출입증)를 관리자가 회수하는 API."""
    data = request.get_json(silent=True) or {}
    exemption_id = _int_field(data, "id")
    if exemption_id is None:
        return jsonify({"success": False, "error": "id 값이 필요합니다."}), 400
    reason = (data.get("reason") or "").strip() or f"관리자 회수 ({session['admin_username']})"

    if not db.revoke_ip_exemption(exemption_id, reason):
        return jsonify({"success": False, "error": "유효한 예외가 아닙니다."}), 404
    return jsonify({"success": True})


@admin_bp.route("/api/recovery-requests/revoke", methods=["POST"])
@require_permission("revoke_recovery_request")
def api_recovery_requests_revoke():
    """진행 중(PENDING)인 이메일 복구 요청을 관리자가 취소하는 API."""
    data = request.get_json(silent=True) or {}
    request_id = _int_field(data, "id")
    if request_id is None:
        return jsonify({"success": False, "error": "id 값이 필요합니다."}), 400

    if not db.revoke_recovery_request(request_id):
        return jsonify({"success": False, "error": "진행 중인 복구 요청이 아닙니다."}), 404
    return jsonify({"success": True})
