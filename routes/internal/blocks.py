# ============================================================================
# routes/internal/blocks.py — fw-agent 전용 차단 목록 창구 (계약서 K9 ①②)
#   GET  /api/internal/blocks      — 지금 막아야 할 IP 목록(원하는 상태 전체)
#   POST /api/internal/blocks/ack  — fw-agent가 실제로 반영했다는 확인 보고
#
# 담당: 역할 C (C1-2에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# fw-agent만 부를 수 있다(보낸이 "fw-agent"). 서명이 없거나 틀리면 401, 구현 전까지는 501.
# ============================================================================

from datetime import datetime, timezone
import ipaddress
import math

from flask import jsonify, request

import config
import db
from routes.internal import internal_bp
from routes.internal._hmac import verify_request
from security import net_ingest


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@internal_bp.route("/blocks", methods=["GET"])
def list_blocks():
    """fw-agent가 2초마다 가져가는 차단 목록. C1-2에서 구현한다."""
    if verify_request({"fw-agent"}) is None:
        return jsonify(error="unauthorized"), 401

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()

    # 1. 지연 만료 처리
    expired_rows = db.list_expired_network_blocks(now_iso)
    for row in expired_rows:
        ip = row["ip_address"]
        cur_status = row["status"]
        if db.update_network_block_if_status(ip, [cur_status], {"status": "REMOVED", "removed_at": now_iso}):
            net_ingest.resolve_net_blocked(ip)

    # 2. 원하는 차단 목록 조회 및 서브넷 필터링
    desired = db.list_desired_network_blocks()
    if config.NET_EDGE_SUBNET:
        try:
            subnet = ipaddress.ip_network(config.NET_EDGE_SUBNET, strict=False)
            desired = [r for r in desired if ipaddress.ip_address(r["ip_address"]) in subnet]
        except ValueError:
            print(f"[blocks] 잘못된 NET_EDGE_SUBNET 설정: '{config.NET_EDGE_SUBNET}'")

    # 3. 항목별 ttl_seconds 계산
    blocks_res = []
    for r in desired:
        ip = r["ip_address"]
        st = r["status"]
        exp_str = r.get("expires_at")

        ttl_sec = None
        if st in ("PENDING_APPLY", "APPLIED") and exp_str:
            exp_dt = _parse_iso(exp_str)
            if exp_dt:
                rem = (exp_dt - now_dt).total_seconds()
                if rem <= 0:
                    continue
                ttl_sec = math.ceil(rem)

        blocks_res.append({
            "ip": ip,
            "status": st,
            "ttl_seconds": ttl_sec
        })

    return jsonify({"generated_at": now_iso, "blocks": blocks_res})


@internal_bp.route("/blocks/ack", methods=["POST"])
def ack_block():
    """fw-agent의 반영 확인(APPLIED·REMOVED·FAILED). C1-2에서 구현한다."""
    if verify_request({"fw-agent"}) is None:
        return jsonify(error="unauthorized"), 401

    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    status = data.get("status")
    error = data.get("error")

    # 입력 검증
    if not ip or not isinstance(ip, str):
        return jsonify(error="invalid", field="ip"), 400
    try:
        parsed_ip = ipaddress.ip_address(ip)
        if parsed_ip.version == 6:
            return jsonify(error="invalid", field="ip"), 400
    except ValueError:
        return jsonify(error="invalid", field="ip"), 400

    if config.NET_EDGE_SUBNET:
        try:
            subnet = ipaddress.ip_network(config.NET_EDGE_SUBNET, strict=False)
            if parsed_ip not in subnet:
                return jsonify(error="invalid", field="ip"), 400
        except ValueError:
            pass

    if status not in ("APPLIED", "REMOVED", "FAILED"):
        return jsonify(error="invalid", field="status"), 400

    if error is not None:
        if not isinstance(error, str):
            error = str(error)
        error = error[:500]

    now_iso = datetime.now(timezone.utc).isoformat()
    changed = False

    if status == "APPLIED":
        changed = db.update_network_block_if_status(ip, ["PENDING_APPLY"], {"status": "APPLIED", "applied_at": now_iso})
        if changed:
            row = db.get_network_block(ip)
            reason = row.get("reason", "NET_FLOOD") if row else "NET_FLOOD"
            net_ingest.record_net_blocked(ip, reason)
    elif status == "REMOVED":
        changed = db.update_network_block_if_status(ip, ["PENDING_REMOVE"], {"status": "REMOVED", "removed_at": now_iso})
        if changed:
            net_ingest.resolve_net_blocked(ip)
    elif status == "FAILED":
        changed = db.update_network_block_if_status(ip, ["PENDING_APPLY", "PENDING_REMOVE"], {"status": "FAILED", "last_error": error})

    return jsonify({"changed": changed})