# ============================================================================
# routes/internal/ingest.py — POST /api/internal/net-events: 센서 경보 접수 창구 (계약서 K4)
#
# 원본 본문으로 서명을 검사한 뒤 K4의 칸만 저장해 내부 DB 필드를 덮어쓰지 못하게 한다.
# ============================================================================

import ipaddress
import re
from datetime import datetime

from flask import jsonify, request

import config
import db

from routes.internal import internal_bp
from routes.internal._hmac import verify_request
from security import net_ingest
from services.ip_utils import normalize_ip


_ENUMS = {
    "sensor": {"suricata", "scapy"},
    "layer": {"L3", "L4", "L7"},
    "proto": {"TCP", "UDP", "ICMP"},
    "category": {"SYN_FLOOD", "PORT_SCAN", "SCANNER_UA", "WEB_ATTACK", "LOGIN_BURST", "OTHER"},
}
_TIME_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z")


def _invalid_field(payload: dict) -> str | None:
    """입력 형이 섞여도 예외를 내지 않고 계약에서 처음 어긴 칸을 돌려준다."""
    event_id = payload.get("event_id")
    if not isinstance(event_id, str) or re.fullmatch(r"[0-9a-f]{64}", event_id) is None:
        return "event_id"
    for field in ("sensor", "layer", "src_ip", "dst_port", "proto", "category",
                  "signature_id", "signature", "sensor_severity", "packet_count",
                  "window_start", "observed_at"):
        value = payload.get(field)
        if field in {"dst_port", "proto", "sensor_severity"} and value is None:
            continue
        if field in _ENUMS:
            if not isinstance(value, str) or value not in _ENUMS[field]:
                return field
        elif field == "src_ip":
            if not isinstance(value, str):
                return field
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return field
        elif field in {"dst_port", "signature_id", "sensor_severity", "packet_count"}:
            # bool은 int의 하위 형이지만 계약서의 정수 입력에는 해당하지 않는다.
            if type(value) is not int:
                return field
            if field == "dst_port" and not 0 <= value <= 65535:
                return field
            if field == "signature_id" and value < 1:
                return field
            if field == "sensor_severity" and not 1 <= value <= 3:
                return field
            if field == "packet_count" and not 1 <= value <= 10_000_000:
                return field
        elif field == "signature":
            if not isinstance(value, str) or not 1 <= len(value) <= 200:
                return field
        else:
            if not isinstance(value, str) or _TIME_PATTERN.fullmatch(value) is None:
                return field
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return field
    return None


@internal_bp.route("/net-events", methods=["POST"])
def net_events():
    """크기·인증·형식 순서로 거절해 검증되지 않은 경보가 저장되지 않게 한다."""
    if request.content_length is not None and request.content_length > config.NET_INGEST_MAX_BODY_BYTES:
        return jsonify(error="too_large"), 413
    if verify_request({"shipper"}) is None:
        return jsonify(error="unauthorized"), 401
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="invalid", field="body"), 400
    field = _invalid_field(payload)
    if field is not None:
        return jsonify(error="invalid", field=field), 400

    # 클라이언트가 id·promoted·received_at 같은 서버 관리 칸을 지정하지 못하게 한다.
    fields = ("event_id", "sensor", "layer", "src_ip", "dst_port", "proto", "category",
              "signature_id", "signature", "sensor_severity", "packet_count", "window_start", "observed_at")
    row = {field: payload.get(field) for field in fields}
    row["src_ip"] = normalize_ip(row["src_ip"])
    row["last_seen_at"] = row["observed_at"]
    row["promoted"] = False
    if db.insert_network_event(row):
        promoted = net_ingest.promote(row)
        if promoted:
            db.mark_network_event_promoted(row["event_id"])
        return jsonify(status="stored", promoted=promoted)
    db.bump_network_event(row["event_id"], row["packet_count"], last_seen_at=row["observed_at"])
    return jsonify(status="updated", promoted=False)


def rate_limit_key() -> str:
    """서명 전 헤더는 인증 정보가 아닌 한도 계산용 이름표로만 사용한다."""
    return f"net-ingest:{request.headers.get('X-LW-Sender') or 'unknown'}"
