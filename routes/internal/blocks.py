# ============================================================================
# routes/internal/blocks.py — fw-agent 전용 차단 목록 창구 (계약서 K9 ①②)
#   GET  /api/internal/blocks      — 지금 막아야 할 IP 목록(원하는 상태 전체)
#   POST /api/internal/blocks/ack  — fw-agent가 실제로 반영했다는 확인 보고
#
# 담당: 역할 C (C1-2). fw-agent만 부를 수 있다(보낸이 "fw-agent"). 서명이 없거나 틀리면 401.
# 앱은 "원하는 상태"만 장부(network_blocks)에 적고, 실제 ipset 반영은 fw-agent가 한다(P6 —
# NET_ADMIN 권한 컨테이너에 DB 키를 주지 않기 위해). 그래서 이 창구가 장부와 agent를 잇는다.
# ============================================================================

from datetime import datetime, timezone
import ipaddress
import math

from flask import jsonify, request

import config
import db
from routes.internal import internal_bp
from routes.internal._hmac import verify_request
from security import correlate, net_ingest


def _parse_iso(value: str | None) -> datetime | None:
    """DB가 돌려준 시각 문자열을 UTC datetime으로 바꾼다. 해석할 수 없으면 None —
    잘못된 행 하나 때문에 목록 전체가 500이 되면 fw-agent가 모든 차단을 못 받기 때문이다."""
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
    """fw-agent가 2초마다 가져가는 차단 목록(계약서 K9 ①).

    응답 전에 만료된 차단을 REMOVED로 바꾼다(지연 만료). 앱에 별도 스케줄러가 없으므로
    agent가 묻는 이 순간이 만료를 정리하기 가장 확실한 시점이다."""
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
            # 공격이 아직 진행 중이면 바로 다시 막는다. 아래 2번 조회가 새 PENDING_APPLY를 같은 응답에
            # 싣기 때문에, 다음 분의 경보를 기다리지 않아도 된다(10/29 공백 보완). 관리자 수동 차단은 제외.
            if row.get("reason") == "NET_FLOOD":
                correlate.reblock_on_expiry(ip)

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

        item = {
            "ip": ip,
            "status": st,
            "ttl_seconds": ttl_sec
        }
        # 요청 번호(guide56). fw-agent가 ACK에 그대로 돌려줘 "어느 요청의 완료인지"를 구분한다.
        # version 칸이 없는 DB(guide56 실행 전)에서는 칸을 빼서 예전 응답 모양을 그대로 둔다.
        if "version" in r:
            item["version"] = r["version"]
        blocks_res.append(item)

    return jsonify({"generated_at": now_iso, "blocks": blocks_res})


@internal_bp.route("/blocks/ack", methods=["POST"])
def ack_block():
    """fw-agent의 반영 확인(APPLIED·REMOVED·FAILED, 계약서 K9 ②).

    상태 전이는 조건부 UPDATE로만 한다 — 같은 보고가 두 번 와도(재전송) 두 번째는
    changed=false가 되어 NET_BLOCKED가 중복 기록되지 않는다(멱등)."""
    if verify_request({"fw-agent"}) is None:
        return jsonify(error="unauthorized"), 401

    data = request.get_json(silent=True)
    # [C1-1·C1-2 보완] 본문이 JSON 객체가 아니면(목록·문자열 등) .get()에서 500이 나므로 400으로 거절한다.
    if not isinstance(data, dict):
        return jsonify(error="invalid", field="body"), 400
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

    # version이 있으면 그 요청 번호의 행일 때만 상태를 바꾼다(10/26 강사 피드백 4). 없으면(옛 agent) 예전처럼.
    version = data.get("version")
    if version is not None and (isinstance(version, bool) or not isinstance(version, int) or version < 0):
        return jsonify(error="invalid", field="version"), 400
    cond = {} if version is None else {"expected_version": version}

    now_iso = datetime.now(timezone.utc).isoformat()
    changed = False

    if status == "APPLIED":
        changed = db.update_network_block_if_status(ip, ["PENDING_APPLY"], {"status": "APPLIED", "applied_at": now_iso}, **cond)
        if changed:
            row = db.get_network_block(ip)
            reason = row.get("reason", "NET_FLOOD") if row else "NET_FLOOD"
            net_ingest.record_net_blocked(ip, reason)
    elif status == "REMOVED":
        changed = db.update_network_block_if_status(ip, ["PENDING_REMOVE"], {"status": "REMOVED", "removed_at": now_iso}, **cond)
        if changed:
            net_ingest.resolve_net_blocked(ip)
    elif status == "FAILED":
        changed = db.update_network_block_if_status(ip, ["PENDING_APPLY", "PENDING_REMOVE"], {"status": "FAILED", "last_error": error}, **cond)

    return jsonify({"changed": changed})