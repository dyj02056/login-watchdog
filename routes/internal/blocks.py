# ============================================================================
# routes/internal/blocks.py — fw-agent 전용 차단 목록 창구 (계약서 K9 ①②)
#   GET  /api/internal/blocks      — 지금 막아야 할 IP 목록(원하는 상태 전체)
#   POST /api/internal/blocks/ack  — fw-agent가 실제로 반영했다는 확인 보고
#
# 담당: 역할 C (C1-2에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# fw-agent만 부를 수 있다(보낸이 "fw-agent"). 서명이 없거나 틀리면 401, 구현 전까지는 501.
# ============================================================================

from flask import jsonify

from routes.internal import internal_bp
from routes.internal._hmac import verify_request


@internal_bp.route("/blocks", methods=["GET"])
def list_blocks():
    """fw-agent가 2초마다 가져가는 차단 목록. C1-2에서 구현한다."""
    if verify_request({"fw-agent"}) is None:
        return jsonify(error="unauthorized"), 401
    return jsonify(error="not_implemented"), 501


@internal_bp.route("/blocks/ack", methods=["POST"])
def ack_block():
    """fw-agent의 반영 확인(APPLIED·REMOVED·FAILED). C1-2에서 구현한다."""
    if verify_request({"fw-agent"}) is None:
        return jsonify(error="unauthorized"), 401
    return jsonify(error="not_implemented"), 501
