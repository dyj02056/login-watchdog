# ============================================================================
# routes/internal/heartbeat.py — POST /api/internal/heartbeat: 장비 생존 신호 (계약서 K9 ③)
#
# 담당: 역할 C (C1-2에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# fw-agent와 shipper 둘 다 부른다. 서명이 없거나 틀리면 401, 구현 전까지는 501.
# ============================================================================

from flask import jsonify

from routes.internal import internal_bp
from routes.internal._hmac import verify_request


@internal_bp.route("/heartbeat", methods=["POST"])
def heartbeat():
    """fw-agent(10초)·shipper(30초)의 생존 신호. C1-2에서 구현한다."""
    if verify_request({"fw-agent", "shipper"}) is None:
        return jsonify(error="unauthorized"), 401
    return jsonify(error="not_implemented"), 501
