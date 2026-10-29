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
from notify import alert
from security import correlate, net_ingest, netblock


# fw-agent가 이 오류로 FAILED를 보고한 행은 다시 시도해도 결과가 같다(허용 목록·대역 밖 IP는 agent가
# 일부러 거부한 것이다). 그래서 적용 재시도(guide57)에서 뺀다.
_NO_RETRY_ERRORS = ("allowlisted", "out_of_subnet", "infrastructure")


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


def _edge_network():
    """NET_EDGE_SUBNET을 대역으로 바꾼다. 비었거나 형식이 틀리면 None."""
    if not config.NET_EDGE_SUBNET:
        return None
    try:
        return ipaddress.ip_network(config.NET_EDGE_SUBNET, strict=False)
    except ValueError:
        return None


def _cooldown_ok(key: str) -> bool:
    """알림 쿨다운을 잡는다. 쿨다운 표 조회가 실패해도 차단 목록 응답은 깨지지 않게 False로 넘긴다."""
    try:
        return db.try_acquire_cooldown(key, config.AGENT_ALERT_COOLDOWN_SECONDS)
    except Exception as error:
        print(f"[blocks] 알림 쿨다운 확인 실패: {type(error).__name__}")
        return False


def _notify_block_failed(ip: str, error: str | None, gave_up: bool) -> None:
    """적용 실패·재시도 포기를 Slack으로 알린다. 같은 IP의 반복 실패는 쿨다운으로 한 번만 보낸다.

    포기 알림은 쿨다운 키를 따로 둔다 — 첫 실패 알림의 쿨다운 안에 포기해도 "이제 사람이 봐야 한다"는
    마지막 알림은 반드시 가야 하기 때문이다."""
    kind = "block_gaveup" if gave_up else "block_failed"
    if not _cooldown_ok(f"slack:{kind}:{config.LW_NODE_NAME or '-'}:{ip}"):
        return
    try:
        row = db.get_network_block(ip)
        reason = (row or {}).get("reason", "NET_FLOOD")
        alert.send_block_failed_alert(ip, reason, error, gave_up=gave_up)
    except Exception as exc:
        print(f"[blocks] 적용 실패 알림 오류: {type(exc).__name__}")


def _retry_failed_applies(now_dt: datetime) -> None:
    """적용에 실패한 차단을 횟수 상한 안에서 다시 PENDING_APPLY로 돌린다(guide57, 계약서 K9 ①).

    예전에는 FAILED 행이 "원하는 상태" 목록에서 빠지고 플레이북 기록은 이미 OK라, 일시적인 ipset 오류
    한 번으로 영구 차단(CR-01)이 조용히 걸리지 않을 수 있었다. 앱에 별도 스케줄러가 없으므로 agent가
    2초마다 묻는 이 순간에 재시도도 처리한다. apply_attempts 칸이 없는 DB(guide57 실행 전)는 건너뛴다.
    횟수를 다 쓰면 failed_at을 비워 다음부터 후보에서 빼고, "포기" 알림을 한 번 보낸다.
    """
    for row in db.list_failed_apply_blocks():
        if "apply_attempts" not in row:
            continue
        ip = row["ip_address"]
        last_error = row.get("last_error") or ""
        if last_error.startswith(_NO_RETRY_ERRORS):
            continue
        expires_at = _parse_iso(row.get("expires_at"))
        if expires_at is not None and expires_at <= now_dt:
            continue  # 이미 끝났어야 할 TTL 차단은 다시 걸지 않는다.
        failed_at = _parse_iso(row.get("failed_at"))
        if failed_at is not None and (now_dt - failed_at).total_seconds() < config.NET_BLOCK_APPLY_RETRY_SECONDS:
            continue
        cond = {"expected_version": row["version"]} if "version" in row else {}
        attempts = int(row.get("apply_attempts") or 0)
        if attempts >= config.NET_BLOCK_APPLY_MAX_RETRIES:
            if db.update_network_block_if_status(ip, ["FAILED"], {"failed_at": None}, **cond):
                _notify_block_failed(ip, last_error, gave_up=True)
            continue
        fields = {"status": "PENDING_APPLY", "apply_attempts": attempts + 1, "failed_at": None}
        if "version" in row:
            fields["version"] = int(row.get("version") or 0) + 1
        if db.update_network_block_if_status(ip, ["FAILED"], fields, **cond):
            print(f"[blocks] 적용 재시도 {attempts + 1}/{config.NET_BLOCK_APPLY_MAX_RETRIES}: {ip}")


@internal_bp.route("/blocks", methods=["GET"])
def list_blocks():
    """fw-agent가 2초마다 가져가는 차단 목록(계약서 K9 ①).

    응답 전에 만료된 차단을 REMOVED로 바꾼다(지연 만료). 앱에 별도 스케줄러가 없으므로
    agent가 묻는 이 순간이 만료를 정리하기 가장 확실한 시점이다."""
    if verify_request({"fw-agent"}) is None:
        return jsonify(error="unauthorized"), 401

    # 0. 대역 값이 있는데 형식이 틀리면 아무것도 내보내지 않는다(guide57). 예전에는 경고만 찍고 거르지 않은
    #    목록을 내보내, 오타 하나로 다른 PC 대역의 차단까지 이 PC 정문에 걸렸다. fw-agent는 503을 오류로 보고
    #    마지막 상태를 유지하고, 그 사이 poll_failures 알림이 울린다.
    #    값이 아예 비어 있으면 예전처럼 거르지 않는다(계약서 K1) — 대신 아래 2번에서 인프라 주소는 항상 뺀다.
    edge = _edge_network()
    if config.NET_EDGE_SUBNET and edge is None:
        print(f"[blocks] 설정 오류: NET_EDGE_SUBNET 형식이 틀림 ('{config.NET_EDGE_SUBNET}')")
        return jsonify(error="misconfigured"), 503
    if config.LW_NODE_NAME and edge is None:
        print(f"[blocks] 경고: LW_NODE_NAME={config.LW_NODE_NAME}인데 NET_EDGE_SUBNET이 비어 대역으로 거르지 않습니다")

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

    # 1-2. 적용 실패 재시도(guide57). 어떤 오류도 목록 응답을 깨지 않게 삼킨다.
    try:
        _retry_failed_applies(now_dt)
    except Exception as error:
        print(f"[blocks] 적용 재시도 처리 오류: {type(error).__name__}")

    # 2. 원하는 차단 목록 조회 및 서브넷 필터링
    desired = db.list_desired_network_blocks()
    if edge is not None:
        desired = [r for r in desired if ipaddress.ip_address(r["ip_address"]) in edge]
    # request_block이 인프라 주소를 거절하지만, 예전에 들어간 행이나 손으로 넣은 행도 내보내지 않는다(guide57).
    desired = [r for r in desired if not netblock.is_infrastructure_ip(r["ip_address"])]

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
        # 적용 실패(PENDING_APPLY → FAILED)와 해제 실패(PENDING_REMOVE → FAILED)를 나눠서 바꾼다(guide57).
        # 적용 실패만 failed_at을 적어 재시도 후보로 삼고 Slack으로 알린다 — 해제 실패 행은 reconcile이
        # ipset에서 빼므로 다시 시도할 일이 없다. failed_at 칸이 없는 DB에서는 예전 칸만 쓴다.
        fields = {"status": "FAILED", "last_error": error}
        row = db.get_network_block(ip)
        apply_fields = dict(fields)
        if row is not None and "failed_at" in row:
            apply_fields["failed_at"] = now_iso
        changed = db.update_network_block_if_status(ip, ["PENDING_APPLY"], apply_fields, **cond)
        if changed:
            _notify_block_failed(ip, error, gave_up=False)
        else:
            changed = db.update_network_block_if_status(ip, ["PENDING_REMOVE"], fields, **cond)

    return jsonify({"changed": changed})