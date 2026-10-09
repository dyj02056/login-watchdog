# ============================================================================
# routes/admin/incidents.py — AI 조기 경보 승인/반려, 보안 이벤트·연관 사건 처리 API
#
# 예전 routes/admin.py(798줄)를 기능 묶음별로 나눈 조각 중 하나다. Blueprint(admin_bp)는
# routes/admin/__init__.py에서 하나만 만들고, 이 파일은 거기에 라우트를 붙이기만 한다
# — 그래서 엔드포인트 이름(url_for("admin.xxx"))은 나누기 전과 똑같다.
# 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

from flask import g, jsonify, request, session

import db
from helpers import require_permission
from routes.admin import admin_bp
from security import soar


@admin_bp.route("/api/access-requests/approve", methods=["POST"])
@require_permission("approve_pending_action")
def api_access_requests_approve():
    """대시보드 "AI 조기 경보" 표의 "승인" 버튼을 눌렀을 때 브라우저가 호출하는
    API (Track A, guide31). 같은 표에 올라오는 SIEM HIGH 사건의 영구 잠금 후보(guide33)도
    이 API로 승인한다.

    security_admin/super_admin 둘 다 가진다 — unlock_ip/resolve_security_event와
    같은 급의 "IP·계정 관련 보안 조치" 권한이라, 그 두 액션과 동일한 두 역할에게
    부여한다(login_watchdog_expansion_plan.md 논의 참고). session의
    문지기(require_permission)가 확인해 둔 g.admin의 id로 "누가 승인했는지"를
    access_requests에 함께 남긴다.
    """
    data = request.get_json(silent=True) or {}
    request_id = data.get("request_id")
    if not request_id:
        return jsonify({"success": False, "error": "request_id 값이 필요합니다."}), 400

    admin_id = g.admin["id"]
    executed = soar.execute_approved_request(request_id, admin_id)
    return jsonify({"success": executed})


@admin_bp.route("/api/access-requests/reject", methods=["POST"])
@require_permission("approve_pending_action")
def api_access_requests_reject():
    """"AI 조기 경보" 표의 "반려" 버튼을 눌렀을 때 호출되는 API. 승인과 동일한
    권한을 쓴다 — 승인/반려는 "같은 결정을 내릴 수 있는 권한"의 앞뒤 면일 뿐이다.
    """
    data = request.get_json(silent=True) or {}
    request_id = data.get("request_id")
    if not request_id:
        return jsonify({"success": False, "error": "request_id 값이 필요합니다."}), 400

    admin_id = g.admin["id"]
    rejected = soar.reject_pending_request(request_id, admin_id)
    return jsonify({"success": rejected})


@admin_bp.route("/api/security-events/resolve", methods=["POST"])
@require_permission("resolve_security_event")
def api_security_events_resolve():
    """대시보드의 "처리 완료" 버튼을 눌렀을 때 브라우저가 호출하는 API.

    /api/board/posts/delete와 동일한 패턴 — require_permission이 이미 "권한 있는 관리자의
    요청"임을 보장해주므로, db.resolve_security_event는 권한 확인 없이 바로 실행한다.
    CRITICAL(IP 잠금) 이벤트는 잠금이 풀릴 때 자동으로 처리되므로(security/soar/lockouts.py의
    해제 함수들이 부르는 db.resolve_security_events_for_ip 참고), 이 버튼은 HIGH/MEDIUM 이벤트에서만 쓰인다.
    """
    data = request.get_json(silent=True) or {}
    event_id = data.get("event_id")
    if not event_id:
        return jsonify({"success": False, "error": "event_id 값이 필요합니다."}), 400

    resolved = db.resolve_security_event(event_id)
    return jsonify({"success": resolved})


@admin_bp.route("/api/security-incidents/resolve", methods=["POST"])
@require_permission("resolve_incident")
def api_security_incidents_resolve():
    """대시보드 "연관 사건" 표의 "해결" 버튼을 눌렀을 때 브라우저가 호출하는 API.

    IP 잠금 해제(/api/unlock)와는 별개다 — 잠금을 푸는 것은 접속 차단을 거두는
    조치이고, 사건 해결은 "관리자가 내용을 확인하고 조사가 끝났다"는 판단이라
    사람이 사건을 CLOSED로 만드는 길은 이 API뿐이다(예외: PERMANENT_LOCK_AUTO_CLOSE_INCIDENT를
    켜면 영구 잠금이 걸린 사건을 시스템이 자동으로 닫는다, guide33). 누가 해결했는지는 요청 본문이 아니라
    로그인 세션(admin_username)에서 가져온다 — 본문 값은 위조할 수 있기 때문이다.
    """
    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    if isinstance(incident_id, bool) or not isinstance(incident_id, int):
        return jsonify({"success": False, "error": "incident_id 값이 필요합니다."}), 400

    resolved = db.resolve_incident(incident_id, session["admin_username"])
    return jsonify({"success": resolved})
