# ============================================================================
# routes/internal/heartbeat.py — POST /api/internal/heartbeat: 장비 생존 신호 (계약서 K9 ③)
#
# 담당: 역할 C (C1-2). fw-agent와 shipper 둘 다 부른다. 서명이 없거나 틀리면 401.
# 생존 신호는 (agent, LW_NODE_NAME) 한 줄로 저장한다 — 세 PC가 같은 DB를 써도 서로 덮어쓰지
# 않게 하기 위해서다(계약서 K9 ③·K11).
# ============================================================================

from datetime import datetime, timezone
import json

from flask import jsonify, request

import config
import db
from notify import alert
from routes.internal import internal_bp
from routes.internal._hmac import verify_request


# 센서 파일 이름 → 알림에 쓸 사람용 이름(guide57).
_SENSOR_LABELS = {"eve": "eve.json(Suricata)", "l4": "l4.json(Scapy l4-detector)"}
# Suricata가 놓친 패킷 비율이 이보다 크면 알린다(guide57). 폭주 때 센서가 따라가지 못하면 탐지가 늦거나 빠진다.
_KERNEL_DROP_ALERT_RATIO = 0.05


def _alert_once(key: str, component: str, message: str) -> None:
    """쿨다운 안이면 보내지 않는다. 키는 PC(LW_NODE_NAME)별로 만들어 세 PC가 서로 막지 않게 한다."""
    if db.try_acquire_cooldown(key, config.AGENT_ALERT_COOLDOWN_SECONDS):
        alert.send_component_alert(component, message)


def _check_fw_agent_detail(detail: dict) -> None:
    """fw-agent가 보낸 상태값으로 "살아 있지만 제 일을 못 하는" 경우를 알린다(guide57, 계약서 K9 ③).

    - rules_ok·l3_ok가 false: 누가 iptables 규칙을 지웠다. ipset에는 IP가 남아 "막혀 있음"으로 보이지만
      실제로는 막지 않는다. fw-agent가 60초 안에 되살리지만, 되살리지 못하면 계속 알린다.
    - poll_failures가 기준 이상: heartbeat는 오므로 정지 감시로는 잡히지 않는데, 새 차단 목록을 못 받는다.
    옛 fw-agent는 이 칸을 보내지 않으므로, 값이 명시적으로 false일 때만 알린다.
    """
    node = config.LW_NODE_NAME
    missing = []
    if detail.get("rules_ok") is False:
        missing.append("INPUT lw_block DROP(L4 차단 전체)")
    if detail.get("l3_ok") is False:
        missing.append("LW_L3(ICMP 속도 제한)")
    if missing:
        _alert_once(
            f"slack:rules:{node}", "fw-agent",
            f"방화벽 규칙이 빠져 있습니다: {', '.join(missing)} (PC: {node}) — fw-agent 로그를 확인하세요",
        )
    poll_failures = detail.get("poll_failures")
    if isinstance(poll_failures, int) and poll_failures >= config.FW_AGENT_POLL_FAIL_ALERT_COUNT:
        _alert_once(
            f"slack:pollfail:{node}", "fw-agent",
            f"차단 목록을 {poll_failures}번 연속 받지 못했습니다(살아 있지만 새 차단이 걸리지 않음, PC: {node}). "
            "앱 응답·NET_EDGE_SUBNET 형식(503)을 확인하세요",
        )


def _check_shipper_detail(detail: dict, stalled: bool) -> None:
    """shipper가 보낸 파일별 정지·패킷 누락을 알린다(guide57).

    두 파일 모두 멈춘 경우(stalled)는 위에서 이미 알렸으므로, 같은 쿨다운 키를 써서 두 번 가지 않게 한다.
    """
    node = config.LW_NODE_NAME
    sensors = detail.get("stalled_sensors")
    if not stalled and isinstance(sensors, list) and sensors:
        names = ", ".join(_SENSOR_LABELS.get(str(name), str(name)) for name in sensors)
        _alert_once(
            f"slack:stalled:{node}:shipper", "shipper",
            f"센서 기록이 2분 넘게 늘지 않습니다: {names} (PC: {node}) — 그 센서 컨테이너를 확인하세요",
        )
    packets = detail.get("kernel_packets")
    drops = detail.get("kernel_drops")
    if isinstance(packets, int) and isinstance(drops, int) and packets > 0 and drops / packets > _KERNEL_DROP_ALERT_RATIO:
        _alert_once(
            f"slack:drops:{node}", "sensor",
            f"Suricata가 최근 패킷 {packets:,}개 중 {drops:,}개를 놓쳤습니다(PC: {node}) — 폭주 때 탐지가 늦거나 빠질 수 있습니다",
        )


@internal_bp.route("/heartbeat", methods=["POST"])
def heartbeat():
    """fw-agent(10초)·shipper(30초)의 생존 신호(계약서 K9 ③).

    받을 때마다 상대 장비(fw-agent ↔ shipper)의 마지막 신호도 확인한다 — 관리자 화면을
    아무도 열지 않아도 장비 정지를 Slack으로 알리기 위해서다."""
    sender = verify_request({"fw-agent", "shipper"})
    if sender is None:
        return jsonify(error="unauthorized"), 401

    if not config.LW_NODE_NAME:
        return jsonify(error="invalid", field="node"), 400

    data = request.get_json(silent=True)
    # [C1-1·C1-2 보완] 본문이 JSON 객체가 아니면 .get()에서 500이 나므로 400으로 거절한다.
    if not isinstance(data, dict):
        return jsonify(error="invalid", field="body"), 400
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

    # guide57: 살아 있지만 제 일을 못 하는 상태 알림. 실패해도 생존 신호 응답은 그대로 200이다.
    try:
        if sender == "fw-agent":
            _check_fw_agent_detail(detail)
        else:
            _check_shipper_detail(detail, stalled)
    except Exception as e:
        print(f"[heartbeat] 상태 점검 예외: {e}")

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