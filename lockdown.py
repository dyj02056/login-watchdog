# ============================================================================
# lockdown.py — "영구 출입금지 담당 부서": 임시 잠금을 영구 잠금으로 올리고(승격),
# 영구 잠금을 풀어주는(관리자 해제 / 이메일 복구) 로직 본체 (guide33 / guide34-a)
#
# 왜 별도 모듈인가: soar.py가 이미 correlate.py를 import하고 있어서, correlate.py가
# soar.py의 승격 함수를 직접 부르면 순환 import가 된다. 그래서 승격·해제 로직을 이
# 파일 하나로 모으고, soar.py와 correlate.py가 둘 다 이 파일만 import하게 한다.
# 이 파일은 모듈 수준에서 db / alert / config만 import한다. 영구 잠금 이벤트를
# 상관분석(correlate)에 흘려보내는 부분만 함수 안에서 늦게 import한다(순환 방지).
#
# 설계 원칙 (docs의 permanent-lock 계획서 1.1 참고)
#   - "영구"는 시간이 아니라 해제 조건의 문제다: 자동 만료가 없고 이메일 인증이나
#     관리자 수동 해제로만 풀린다.
#   - IP 영구 잠금은 이메일로 "해제"하지 않고 본인+본인 기기에게만 "예외"를 발급한다.
#   - 허용 목록(PERMANENT_LOCK_IP_ALLOWLIST)의 IP는 절대 영구 잠그지 않는다(자충수 방지).
# ============================================================================

from datetime import datetime, timedelta, timezone

import alert
import config
import db

PERMANENT_LOCK_EVENT_TYPE = "PERMANENT_LOCK"

# T1은 BRUTE_FORCE / PASSWORD_SPRAYING 잠금끼리, T5는 ADMIN_BRUTE_FORCE 잠금끼리만 센다.
_USER_LOGIN_EVENT_TYPES = ["BRUTE_FORCE", "PASSWORD_SPRAYING"]
_ADMIN_LOGIN_EVENT_TYPES = ["ADMIN_BRUTE_FORCE"]


# ---------------------------------------------------------------------------
# 조회 헬퍼
# ---------------------------------------------------------------------------

def is_ip_allowlisted(ip: str) -> bool:
    """이 IP가 "절대 영구 잠그지 않는 목록"(관리자 PC 등)에 있는지."""
    return ip in config.PERMANENT_LOCK_IP_ALLOWLIST


def is_permanent_ip(ip: str) -> bool:
    """이 IP가 지금 영구 잠금 상태인지."""
    row = db.get_active_lockout(ip)
    return bool(row) and row.get("lock_type") == "PERMANENT"


def is_permanent_account(username: str) -> bool:
    """이 계정이 지금 영구 잠금 상태인지."""
    row = db.get_active_account_lockout(username)
    return bool(row) and row.get("lock_type") == "PERMANENT"


# ---------------------------------------------------------------------------
# 승격 (임시 잠금 → 영구 잠금)
# ---------------------------------------------------------------------------

def _record_permanent_lock_event(
    ip: str, count: int, username: str | None, correlate_event: bool
) -> None:
    """PERMANENT_LOCK(CRITICAL) 이벤트를 security_events에 기록하고, IP 단위이면
    상관분석에도 흘려보낸다.

    db.insert_security_event()를 직접 부르는 이유: soar._record_event()를 쓰면 soar가
    lockdown을, lockdown이 다시 soar를 import하는 순환이 생긴다. 상관분석 호출만
    함수 안에서 늦게 import한다(correlate는 모듈 수준에서 lockdown을 import한다).
    """
    if username is not None:
        db.insert_security_event(
            PERMANENT_LOCK_EVENT_TYPE, "CRITICAL", ip, None, count, "PERMANENT_LOCKED", username=username
        )
    else:
        db.insert_security_event(PERMANENT_LOCK_EVENT_TYPE, "CRITICAL", ip, None, count, "PERMANENT_LOCKED")
    if correlate_event:
        import correlate  # noqa: PLC0415  (순환 import 방지를 위한 지연 import)

        correlate.check_and_correlate(ip, PERMANENT_LOCK_EVENT_TYPE, "CRITICAL")


def promote_ip(
    ip: str,
    reason: str,
    recoverable: str,
    incident_id: int | None = None,
    strikes: int | None = None,
    note: str | None = None,
) -> bool:
    """이 IP를 영구 잠금으로 올린다. 실제로 바뀌었을 때만 True(알림·이벤트도 그때만 나간다).

    허용 목록 IP는 거부한다. 이미 영구 잠금인 IP도 False를 돌려준다 — 같은 IP에 대해
    사건 이벤트가 하나씩 더 붙을 때마다 알림이 반복되는 "알림 피로"를 막는다.
    """
    if is_ip_allowlisted(ip):
        return False
    if not db.promote_lockout_permanent(ip, reason, recoverable, failure_count=strikes or 0):
        return False

    db.insert_lock_history(
        "ip", ip, "PERMANENT", reason, incident_id=incident_id, trigger_note=note
    )
    _record_permanent_lock_event(ip, strikes or 1, None, correlate_event=True)
    alert.send_permanent_lock_alert("ip", ip, reason, recoverable, strikes)
    return True


def promote_account(
    username: str,
    reason: str,
    recoverable: str,
    triggering_ip: str = "-",
    strikes: int | None = None,
    note: str | None = None,
) -> bool:
    """이 계정을 영구 잠금으로 올린다. 실제로 바뀌었을 때만 True.

    - 가입되지 않은 아이디는 승격하지 않는다 — 공격자가 아무 아이디나 넣어서 영구 잠금
      행을 무한히 만들어내는 걸 막는다(임시 잠금까지만 걸린다).
    - 이메일을 신뢰할 수 없는 계정(email_status=UNDELIVERABLE)은 이메일로 풀 수 없게
      recoverable을 ADMIN_ONLY로 올린다.
    """
    user = db.get_user_by_username(username)
    if user is None:
        return False
    if user.get("email_status") == "UNDELIVERABLE":
        recoverable = "ADMIN_ONLY"

    if not db.promote_account_lockout_permanent(username, reason, recoverable, failure_count=strikes or 0):
        return False

    db.insert_lock_history("account", username, "PERMANENT", reason, trigger_note=note)
    # 계정 단위 이벤트는 특정 IP가 아니라 "이 계정이 공격받았다"는 뜻이라 상관분석에는
    # 보내지 않는다(요청 IP를 사건에 끌어들이면 무관한 IP가 사건에 섞인다).
    _record_permanent_lock_event(triggering_ip, strikes or 1, username, correlate_event=False)
    alert.send_permanent_lock_alert("account", username, reason, recoverable, strikes)
    return True


def after_temporary_lock(
    target_kind: str,
    target_value: str,
    source_event_type: str,
    failure_count: int = 0,
    triggering_ip: str = "-",
) -> None:
    """임시 잠금이 방금 걸린 직후 호출된다: 이력을 한 줄 남기고, 최근 기간 안의 잠금
    횟수가 기준 이상이면 영구 잠금으로 승격한다(T1/T2/T5).

    횟수는 lock_history에서 센다 — lockouts는 같은 IP를 upsert로 덮어써서 횟수를 셀 수 없다.
    """
    db.insert_lock_history(target_kind, target_value, "TEMPORARY", "THRESHOLD", source_event_type)
    window = config.PERMANENT_LOCK_STRIKE_WINDOW_DAYS

    if target_kind == "ip":
        event_types = (
            _ADMIN_LOGIN_EVENT_TYPES if source_event_type == "ADMIN_BRUTE_FORCE" else _USER_LOGIN_EVENT_TYPES
        )
        strikes = db.count_lock_history("ip", target_value, window, event_types)
        if strikes >= config.PERMANENT_LOCK_STRIKE_COUNT:
            # 관리자 로그인 무차별 대입(T5)은 위험도가 가장 높아 이메일 복구 대상이 아니다.
            recoverable = "ADMIN_ONLY" if source_event_type == "ADMIN_BRUTE_FORCE" else "EXEMPTION"
            promote_ip(target_value, "REPEAT_OFFENDER", recoverable, strikes=strikes)
        return

    strikes = db.count_lock_history("account", target_value, window)
    row = db.get_account_lockout_row(target_value) or {}
    # 이메일 복구 직후 보호관찰 기간(기본 24시간) 안에 다시 잠기면, 본인 인증 수단이
    # 공격자에게 넘어갔을 수 있다고 보고 횟수와 무관하게 관리자 전용 영구 잠금으로 올린다.
    if _in_probation(row):
        promote_account(
            target_value, "REPEAT_OFFENDER", "ADMIN_ONLY", triggering_ip=triggering_ip, strikes=strikes,
            note="이메일 복구 보호관찰 기간 중 재잠금",
        )
    elif strikes >= config.PERMANENT_LOCK_ACCOUNT_STRIKE_COUNT:
        promote_account(
            target_value, "REPEAT_OFFENDER", "SELF", triggering_ip=triggering_ip, strikes=strikes
        )


def _in_probation(account_lockout_row: dict) -> bool:
    until = account_lockout_row.get("probation_until")
    if not until:
        return False
    until_dt = datetime.fromisoformat(until)
    if until_dt.tzinfo is None:
        until_dt = until_dt.replace(tzinfo=timezone.utc)
    return until_dt > datetime.now(timezone.utc)


def consider_incident_promotion(ip: str, incident: dict) -> None:
    """상관분석 사건의 최고 위험등급에 따라 영구 잠금을 건다(T3/T4).

    CRITICAL → 즉시 승격. HIGH → PERMANENT_LOCK_AUTO_ON_HIGH가 true면 승격, 아니면
    관리자 승인 대기(access_requests)로 올린다(Human-in-the-loop). 이미 영구 잠금인
    IP나 허용 목록 IP는 건너뛴다.
    """
    severity = incident.get("severity_max")
    if severity not in ("CRITICAL", "HIGH") or is_ip_allowlisted(ip):
        return

    if severity == "CRITICAL":
        promote_ip(ip, "SIEM_CRITICAL", "EXEMPTION", incident_id=incident.get("id"))
        return

    if config.PERMANENT_LOCK_AUTO_ON_HIGH:
        promote_ip(ip, "SIEM_HIGH", "EXEMPTION", incident_id=incident.get("id"))
        return

    if is_permanent_ip(ip) or db.get_pending_request("SIEM_HIGH_INCIDENT", "ip", ip) is not None:
        return
    event_types = incident.get("event_types") or []
    reason = f"SIEM 상관분석 사건이 HIGH 등급에 도달 (관련 유형: {', '.join(event_types)})"
    db.insert_pending_request(
        "SIEM_HIGH_INCIDENT", "PERMANENT_LOCK_IP", "ip", ip, len(event_types), 2, reason
    )
    alert.send_pending_approval_alert(
        "SIEM HIGH 사건 → 영구 잠금 후보", "ip", ip, len(event_types), 2, reason
    )


def close_incident_if_configured(incident: dict) -> None:
    """PERMANENT_LOCK_AUTO_CLOSE_INCIDENT가 true일 때만, 영구 잠금 이벤트가 병합된 사건을
    시스템 계정으로 자동 CLOSED 처리한다(기본 false — 관리자가 직접 "해결"을 누른다)."""
    if config.PERMANENT_LOCK_AUTO_CLOSE_INCIDENT:
        db.close_incident_system(incident["id"], "system:permanent_lock")


# ---------------------------------------------------------------------------
# 해제 (관리자 / 이메일 복구)
# ---------------------------------------------------------------------------

def release(target_kind: str, target_value: str, actor: str, note: str) -> bool:
    """관리자(또는 운영 스크립트)가 영구 잠금을 완전히 푼다. 실제로 풀렸을 때만 True.

    actor는 호출부가 형식을 정해서 넘긴다 — 대시보드는 'admin:<관리자 아이디>',
    터미널 스크립트는 'script:unlock_ip' 같은 값이다(lock_history.released_by에 그대로 기록).

    영구 잠금이 아닌 대상(이미 풀렸거나 임시 잠금)이면 False — 호출부가 404/409로 응답한다.
    푼 사람과 사유를 lock_history에 'admin:<이름>' 형식으로 남기고 Slack에도 알린다.
    연관 보안 이벤트는 정리하지만, 연관 사건(security_incidents)은 닫지 않는다 —
    사건 해결은 관리자의 "검토 끝" 판단이라 별개다(guide32).
    """
    if target_kind == "ip":
        released = db.release_permanent_lockout(target_value)
        if released:
            db.resolve_security_events_for_ip(target_value)
    else:
        released = db.release_permanent_account_lockout(target_value)
        if released:
            db.resolve_security_events_for_username(target_value)
    if not released:
        return False

    db.mark_lock_released(target_kind, target_value, actor, note)
    alert.send_permanent_release_alert(target_kind, target_value, actor, note)
    return True


def apply_recovery(recovery_request: dict, username: str) -> bool:
    """이메일 인증이 끝난 복구 요청을 실제 조치로 반영한다. 실제로 반영됐을 때만 True.

    - account: SELF 복구 방식인 영구 계정 잠금을 풀고(ADMIN_ONLY는 풀지 않음), 보호관찰
      기간을 시작한다.
    - ip: 그 IP가 지금도 EXEMPTION 복구 방식의 영구 잠금일 때만, "요청한 사용자 + 요청한
      기기"에게 예외를 발급한다(IP 자체는 계속 잠긴 상태다).
    """
    target_kind = recovery_request["target_kind"]
    target_value = recovery_request["target_value"]

    if target_kind == "account":
        if not db.release_permanent_account_lockout(target_value, only_recoverable="SELF"):
            return False
        db.resolve_security_events_for_username(target_value)
        db.mark_lock_released("account", target_value, "EMAIL_RECOVERY", "이메일 인증으로 해제")
        probation_until = datetime.now(timezone.utc) + timedelta(hours=config.RECOVERY_PROBATION_HOURS)
        db.set_account_probation(target_value, probation_until.isoformat())
        alert.send_recovery_completed_alert("account", target_value, username)
        return True

    row = db.get_active_lockout(target_value)
    if not row or row.get("lock_type") != "PERMANENT" or row.get("recoverable") != "EXEMPTION":
        return False
    if not recovery_request.get("device_hash"):
        return False
    expires_at = datetime.now(timezone.utc) + timedelta(days=config.IP_EXEMPTION_DAYS)
    db.insert_ip_exemption(
        target_value,
        recovery_request["user_id"],
        recovery_request["device_hash"],
        "EMAIL_RECOVERY",
        expires_at.isoformat(),
    )
    alert.send_recovery_completed_alert("ip", target_value, username)
    return True
