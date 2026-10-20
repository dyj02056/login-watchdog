# ============================================================================
# routes/internal/heartbeat.py — POST /api/internal/heartbeat: 장비 생존 신호 (계약서 K9 ③)
#
# 담당: 역할 C (C1-2에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
# fw-agent와 shipper 둘 다 부른다. 서명이 없거나 틀리면 401, 구현 전까지는 501.
# ============================================================================

from datetime import datetime, timezone
import json

from flask import jsonify, request

import config
import db
from notify import alert
from routes.internal import internal_bp
from routes.internal._hmac import verify_request


@internal_bp.route("/heartbeat", methods=["POST"])
def heartbeat():
    """fw-agent(10초)·shipper(30초)의 생존 신호. C1-2에서 구현한다."""
    sender = verify_request({"fw-agent", "shipper"})
    if sender is None:
        return jsonify(error="unauthorized"), 401

    if not config.LW_NODE_NAME:
        return jsonify(error="invalid", field="node"), 400

    data = request.get_json(silent=True) or {}
    agent = data.get("agent")
    detail = data.get("detail")

    if agent != sender:
        return jsonify(error="invalid", field="agent"), 400

    if not isinstance(detail, dict):
        return jsonify(error="invalid", field="detail"), 400

    try:
        detail_json = json.dumps(detail)
        if len(detail_json.encode("utf-8")) > 2048:
            return jsonify(error="invalid", field="detail"), 400
    except Exception:
        return jsonify(error="invalid", field="detail"), 400

    stalled = False
    if sender == "shipper":
        stalled = bool(data.get("stalled", False))
        detail["stalled"] = stalled

    # DB upsert
    db.upsert_agent_heartbeat(agent, config.LW_NODE_NAME, detail)

    # Stalled 알림 처리
    if stalled:
        cooldown_key = f"slack:stalled:{config.LW_NODE_NAME}:{agent}"
        if db.try_acquire_cooldown(cooldown_key, config.AGENT_ALERT_COOLDOWN_SECONDS):
            alert.send_component_alert(agent, f"센서 로그가 2분 넘게 늘지 않습니다 (PC: {config.LW_NODE_NAME})")

    # 상대 장비 정지 감시
    try:
        other_agent = "shipper" if agent == "fw-agent" else "fw-agent"
        other_stale_sec = config.SHIPPER_STALE_SECONDS if other_agent == "shipper" else config.FW_AGENT_STALE_SECONDS
        beats = db.get_agent_heartbeats(config.LW_NODE_NAME)
        if other_agent in beats:
            last_seen_str = beats[other_agent].get("last_seen_at")
            if last_seen_str:
                try:
                    last_seen_dt = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                    if last_seen_dt.tzinfo is None:
                        last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    diff_sec = (now_dt - last_seen_dt).total_seconds()
                    if diff_sec > other_stale_sec:
                        stale_key = f"slack:stale:{config.LW_NODE_NAME}:{other_agent}"
                        if db.try_acquire_cooldown(stale_key, config.AGENT_ALERT_COOLDOWN_SECONDS):
                            alert.send_component_alert(other_agent, f"{int(diff_sec)}초 넘게 생존 신호가 없습니다 (PC: {config.LW_NODE_NAME})")
                except Exception as e:
                    print(f"[heartbeat] 상대 장비 시각 해석 예외: {e}")
    except Exception as e:
        print(f"[heartbeat] 상대 장비 점검 예외: {e}")

    return jsonify({"ok": True})