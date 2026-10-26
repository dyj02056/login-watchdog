# ============================================================================
# security/playbooks.py — Track D 대응 절차서(플레이북): 규칙이 맞으면 조치를 순서대로 실행한다
#
# 담당: 역할 B (B2-2). 단계와 기록의 실패를 격리해 다음 조치를 보장한다.
# 플레이북·단계 이름은 docs/track-d/contracts.md 계약서 K12, 넘겨받는 ctx 모양은 K8이 기준이다.
#
# 판단(B)과 실행(C)을 나눈다: 이 파일은 "어떤 조치를 어떤 순서로"만 정하고, 실제 차단·메일·알림은
# 역할 C의 조치 함수가 스스로 검증하며 실행한다.
# 기존 복합 공격 알림(security/correlate.py의 PLAYBOOKS["CRITICAL_MULTI_STAGE"])은 옮기지 않는다 —
# 이 파일은 Track D 플레이북만 담당한다(계약서 K12).
# ============================================================================


import importlib
from datetime import datetime, timezone

import db

ACTIONS = {
    "lock_ip_permanent": "security.lockdown.promote_ip",
    "lock_account_permanent": "security.lockdown.promote_account",
    "block_l4": "security.netblock.request_block",
    "block_l4_ttl": "security.netblock.request_block",
    "invalidate_sessions": "db.bump_session_version",
    "notify_owner_email": "notify.mailer.send_suspicious_login_notice",
    "notify_slack": "notify.alert.send_playbook_alert",
    "require_approval": "db.insert_pending_request",
    "llm_postmortem": "services.llm_client.summarize_incident",
}

PLAYBOOKS = {
    "NET_FLOOD_TTL": ["block_l4_ttl", "notify_slack"],
    "KILL_CHAIN": ["lock_ip_permanent", "block_l4", "notify_slack", "llm_postmortem"],
    "NET_FLOOD": ["block_l4_ttl", "notify_slack"],
    "SUSPICIOUS_SUCCESS_LOGIN": ["invalidate_sessions", "notify_owner_email", "notify_slack"],
    "SUBNET_REVIEW": ["require_approval", "notify_slack"],
    "ROTATION_EVASION": ["lock_account_permanent", "notify_owner_email", "notify_slack"],
    "WEB_ATTACK": ["lock_ip_permanent", "notify_slack"],
}


class _MissingContext(Exception):
    """필수 값을 추정해서 조치하지 않도록 건너뛰기 신호로 쓴다."""


def _required(ctx, key):
    value = ctx.get(key)
    if value is None or value == "":
        raise _MissingContext(key)
    return value


def _lock_ip_permanent(playbook, ctx, results):
    recoverable = {"KILL_CHAIN": "ADMIN_ONLY", "WEB_ATTACK": "EXEMPTION"}[playbook]
    return (_required(ctx, "ip"),), dict(
        reason="NETWORK_IDS", recoverable=recoverable, incident_id=ctx.get("incident_id")
    )


def _lock_account_permanent(playbook, ctx, results):
    return (_required(ctx, "username"),), dict(
        reason="NETWORK_IDS", recoverable="EXEMPTION", triggering_ip=_required(ctx, "ip")
    )


def _block_l4(playbook, ctx, results):
    if playbook != "KILL_CHAIN":
        raise ValueError("영구 L4 차단은 KILL_CHAIN 전용")
    return (_required(ctx, "ip"), "KILL_CHAIN"), dict(
        evidence="CONNECTED", ttl_seconds=None, requested_by="playbook:KILL_CHAIN"
    )


def _block_l4_ttl(playbook, ctx, results):
    # CONNECTED와 None의 조합은 영구 차단이므로 TTL 경로는 증거를 고정한다.
    return (_required(ctx, "ip"), "NET_FLOOD"), dict(
        evidence="SPOOFABLE", ttl_seconds=None, requested_by=f"playbook:{playbook}"
    )


def _invalidate_sessions(playbook, ctx, results):
    return (_required(ctx, "user_id"),), {}


def _notify_owner_email(playbook, ctx, results):
    return (
        _required(ctx, "user_email"), _required(ctx, "ip"),
        datetime.now(timezone.utc).isoformat(),
    ), {}


def _notify_slack(playbook, ctx, results):
    # 이후 결과가 알림에 소급해서 섞이지 않도록 이전 결과만 복사한다.
    return (
        playbook, _required(ctx, "ip"), list(ctx.get("matched_rules") or []),
        [dict(result) for result in results],
    ), {}


def _require_approval(playbook, ctx, results):
    # 선택 규칙의 대상·횟수는 판단 계층이 제공해야 하며 실행기가 만들어내지 않는다.
    kind = "subnet" if playbook == "SUBNET_REVIEW" else "ip"
    return (), dict(
        event_type="NET_SUBNET_ATTACK" if kind == "subnet" else "NET_REPEAT_FLOOD",
        pending_action="BLOCK_SUBNET" if kind == "subnet" else "BLOCK_L4_PERMANENT",
        target_kind=kind,
        target_value=_required(ctx, "subnet" if kind == "subnet" else "ip"),
        count=_required(ctx, "count"), threshold=_required(ctx, "threshold"),
        llm_reason=f"Track D {playbook} 관리자 승인 요청", context_ip=ctx.get("ip"),
    )


def _llm_postmortem(playbook, ctx, results):
    return (_required(ctx, "incident_id"),), {}


_ARGUMENTS = {name: globals()[f"_{name}"] for name in ACTIONS}


def run(playbook: str, trigger_ref: str, ctx: dict) -> list[dict]:
    """단계별 결과를 반환하고 기록 실패도 격리하여 이미 수행한 차단을 보존한다.

    조치 함수를 호출 시점에 찾아 monkeypatch를 지원하고, 실행 함수가 없는 단계(선택 과제 llm_postmortem)는 SKIPPED로 남긴다.
    예외 메시지에 비밀값이 섞일 수 있으므로 기록에는 예외 종류만 남긴다.
    """
    results = []
    for step in PLAYBOOKS.get(playbook, []):
        status, error = "OK", None
        try:
            args, kwargs = _ARGUMENTS[step](playbook, ctx, results)
            module_name, function_name = ACTIONS[step].rsplit(".", 1)
            try:
                module = importlib.import_module(module_name)
            except ModuleNotFoundError as exc:
                if exc.name != module_name and not module_name.startswith(f"{exc.name}."):
                    raise
                module = None
            function = getattr(module, function_name, None)
            if not callable(function):
                status, error = "SKIPPED", "조치 함수 없음"
            else:
                value = function(*args, **kwargs)
                # 멱등 차단의 False는 미실행이며 세션 무효화 False는 실패다.
                if value is False:
                    status = "FAILED" if step == "invalidate_sessions" else "SKIPPED"
                elif step == "notify_owner_email" and value in ("FAILED", "REFUSED", "SKIPPED"):
                    status = "FAILED" if value == "FAILED" else "SKIPPED"
                if status != "OK":
                    error = "조치 미완료" if status == "FAILED" else "조치 미실행"
        except _MissingContext as exc:
            status, error = "SKIPPED", f"필수 값 없음: {exc}"
        except Exception as exc:
            status, error = "FAILED", type(exc).__name__
        result = {"step": step, "status": status, "error": error}
        results.append(result)
        try:
            db.insert_playbook_run(playbook, trigger_ref, step, status, error)
        except Exception as exc:
            print(f"[playbook record failed] {type(exc).__name__}")
    return results
