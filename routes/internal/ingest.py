# ============================================================================
# routes/internal/ingest.py — POST /api/internal/net-events: 센서 경보 접수 창구 (계약서 K4)
#
# 담당: 역할 B (B1-1에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# shipper만 부를 수 있다(보낸이 "shipper"). 서명이 없거나 틀리면 401, 서명이 맞아도
# 구현 전까지는 501로만 답한다 — 뼈대 단계에서 DB에 아무것도 쓰지 않기 위해서다.
# ============================================================================

from flask import jsonify

from routes.internal import internal_bp
from routes.internal._hmac import verify_request


@internal_bp.route("/net-events", methods=["POST"])
def net_events():
    """센서 경보 한 건을 받는다. B1-1에서 검증·저장을 구현한다."""
    if verify_request({"shipper"}) is None:
        return jsonify(error="unauthorized"), 401
    return jsonify(error="not_implemented"), 501


def rate_limit_key() -> str:
    """이 창구의 요청 한도를 셀 때 쓰는 이름표. B1-1에서 센서별로 나눈다."""
    return "net-ingest"
