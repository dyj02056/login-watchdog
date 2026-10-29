# ============================================================================
# security/correlate.py — "형사" 역할: 흩어진 개별 신고(security_events)들을 보고
# "이거 같은 출처가 벌인 하나의 사건 아니야?"를 판단한다 (Track C guide27, SIEM 상관분석)
#
# security/soar/가 security_events에 새 이벤트를 기록할 때마다 이 모듈의
# check_and_correlate()를 호출한다. security/detector.py와 동일한 원칙으로, 이 파일도
# "판단"만 하고(사건으로 묶어야 하는가?) 실제 저장/병합은 db 패키지(db/incidents.py)에
# 맡긴다 — security/soar/가 db에게 조치를 맡기는 것과 같은 구조다.
#
# PLAYBOOKS(Track C guide28, SOAR 플레이북)도 이 파일에 둔다. security/soar/가 이미
# security/correlate.py를 import하고 있어서, 플레이북 실행을 security/soar/ 쪽에 두고
# security/correlate.py가 그걸 호출하게 하면 반대 방향 import가 생겨 순환 참조가 된다.
# security/correlate.py는 사건이 얼마나 심각해졌는지 이미 알고 있는 유일한 곳이므로,
# 여기서 곧바로 notify/alert.py를 불러 실행하는 것이 security/soar/가 notify/alert.py를 직접
# 부르는 것과 같은 자연스러운 구조다.
#
# Track D 교차 규칙은 다음 위험을 따로 다룬다.
# NET-01: 출발지 위조가 가능한 SYN Flood는 영구 잠금 대신 TTL 차단만 요청한다.
# CR-01: 네트워크 정찰 뒤 앱 침투가 이어질 때 연결이 확인된 킬체인으로 본다.
# CR-02: SYN Flood와 전역 HTTP 폭주가 겹칠 때만 다계층 폭주로 묶는다.
# CR-03: 웹 공격·스캐너 기록(연결 완성 증거)이 있는 IP의 로그인 성공은 세션 전에 막는다 —
#        비밀번호를 이미 손에 넣은 공격자일 수 있고, SYN·포트 스캔은 위조 가능해 근거로 쓰지 않는다.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db
from notify import alert
from security import lockdown, playbooks


_SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# app.py의 라우트별 limiter.limit을 바꾸면 여기도 바꾼다.
CR02_EXCLUDED_FLOOD_PATHS = {
    "/recovery/verify",
    "/recovery/request",
    "/email/confirm",
    "/password/forgot",
    "/password/reset",
}

CROSS_LAYER_RULES = [
    {
        "id": "NET-01",
        "single": "NET_SYN_FLOOD",
        "priority": "HIGH",
        "playbook": "NET_FLOOD_TTL",
        "evidence": "SPOOFABLE",
    },
    {
        "id": "CR-01",
        "window_minutes": config.NET_CORRELATION_WINDOW_MINUTES,
        "first_any": {"NET_PORT_SCAN", "NET_SCANNER_UA"},
        "then_any": {"WEB_SCANNING", "BRUTE_FORCE", "PASSWORD_SPRAYING"},
        "ordered": True,
        "priority": "CRITICAL",
        "playbook": "KILL_CHAIN",
        "evidence": "CONNECTED",
    },
    {
        "id": "CR-02",
        "window_minutes": config.NET_FLOOD_WINDOW_MINUTES,
        "all": {"NET_SYN_FLOOD", "HTTP_FLOOD"},
        "priority": "CRITICAL",
        "playbook": "NET_FLOOD",
        "evidence": "SPOOFABLE",
    },
]

# "사건이 이 정도로 심각해지면 → 이런 대응을 한다"는 매뉴얼을 선언적으로
# 나열한다. 지금은 항목이 하나뿐이지만(에스컬레이션 알림), 나중에 대응이
# 늘어나도 이 리스트에 함수 이름만 추가하면 된다 — _maybe_escalate()의
# 호출부는 바뀌지 않는다.
#
# 함수 객체(alert.send_incident_escalation_alert) 자체가 아니라 이름(문자열)을
# 담아두는 이유: db/alert의 다른 모든 호출부와 마찬가지로 "함수를 부르는
# 순간"에 getattr(alert, ...)로 다시 찾아야 테스트에서 monkeypatch.setattr(alert,
# "send_incident_escalation_alert", ...)로 바꿔치기한 게 실제로 적용된다 —
# 모듈을 처음 읽어들일 때(import 시점) 함수 객체를 미리 꺼내서 담아두면, 그
# 뒤에 monkeypatch로 바꿔도 이 딕셔너리 안의 참조는 원래 함수를 그대로 가리킨다.
PLAYBOOKS = {
    "CRITICAL_MULTI_STAGE": ["send_incident_escalation_alert"],
}


def check_and_correlate(ip: str, event_type: str, severity: str, source: str = "APP") -> None:
    """방금 security_events에 기록된 이벤트를 계기로, 이 IP가 최근
    config.INCIDENT_CORRELATION_WINDOW_MINUTES분 안에 서로 다른 event_type을
    2개 이상 남겼는지 확인한다.

    2개 이상이면 기존 사건 상관분석을 수행한다. 교차 계층 규칙은 더 긴 자체 창을
    쓰고 NET-01은 단일 유형 규칙이므로, 기존 사건의 유형 수와 무관하게 따로 확인한다.
    """
    distinct_types = db.get_recent_distinct_event_types(
        ip, config.INCIDENT_CORRELATION_WINDOW_MINUTES
    )
    if len(distinct_types) >= 2:
        # 기본 APP 호출은 기존 모양을 유지하고 NET 출처는 사건 기록 계층까지 전달한다.
        if source == "APP":
            incident = db.record_incident(ip, distinct_types, severity)
        else:
            incident = db.record_incident(ip, distinct_types, severity, source=source)
        _maybe_escalate(ip, incident)

        # 영구 잠금 이벤트 자체는 사건의 결과이므로 재귀 승격 대신 선택적으로 닫는다.
        if event_type == lockdown.PERMANENT_LOCK_EVENT_TYPE:
            lockdown.close_incident_if_configured(incident)
        else:
            lockdown.consider_incident_promotion(ip, incident)

    if event_type != "NET_BLOCKED":
        try:
            check_cross_layer(ip, event_type)
        except Exception as error:
            # 교차 규칙 보조 경로가 원래 이벤트 기록과 기존 사건 처리를 깨면 안 된다.
            print(f"[교차 규칙 오류] {type(error).__name__}")


def check_cross_layer(ip: str, event_type: str) -> None:
    """NET-01·CR-01·CR-02를 자체 시간 창으로 평가하고 규칙별 한 번만 실행한다."""
    try:
        for rule in CROSS_LAYER_RULES:
            matched = _match_cross_layer_rule(ip, event_type, rule)
            if not matched:
                continue

            existing = db.get_open_incident(ip)
            # 오래 조용했던 사건은 record_incident가 IDLE로 넘기고 새 사건을 연다. 여기서 그 옛
            # 사건의 matched_rules를 보고 건너뛰면, 같은 IP의 SYN Flood가 TTL 차단이 끝난 몇 시간
            # 뒤에 다시 와도 NET-01이 영영 다시 돌지 않는다(유형이 하나뿐이라 다른 경로로는 IDLE이
            # 되지 않음). 그래서 IDLE 대상 사건은 "이미 실행함" 판단에서 뺀다.
            if (
                existing
                and not db.incidents._is_idle(existing)
                and rule["id"] in (existing.get("matched_rules") or [])
            ):
                # 규칙은 이미 기록됐다 — 대응을 처음부터 반복하지 않고, 실패로 남은 단계만 이어서 한다.
                _retry_failed_steps(
                    rule["playbook"], f"incident:{existing['id']}:{rule['id']}",
                    _rule_ctx(ip, existing, rule),
                )
                _reblock_if_ttl_expired(ip, existing, rule)
                continue

            event_types = sorted({row["event_type"] for row in matched})
            severity = max(
                (row.get("severity") or "MEDIUM" for row in matched),
                key=lambda value: _SEVERITY_RANK[value],
            )
            # 규칙 우선순위를 APP 등급으로 오인하지 않도록 교차 규칙 병합은 NET 출처로 기록한다.
            incident = db.record_incident(
                ip, event_types, severity, source="NET", rule_id=rule["id"]
            )
            if not incident.get("rule_added", True):
                # 동시에 들어온 다른 요청이 같은 사건에 이 규칙을 먼저 기록했다 — 그쪽이 실행한다.
                continue
            playbooks.run(
                rule["playbook"], f"incident:{incident['id']}:{rule['id']}", _rule_ctx(ip, incident, rule)
            )
    except Exception as error:
        print(f"[교차 규칙 오류] {type(error).__name__}")


def check_success_login(ip: str, username: str) -> bool:
    """연결이 확인된 NET 경보 뒤의 로그인 성공을 막고 CR-03을 사건당 한 번 실행한다.

    조회나 기록이 실패하면 검사 오류 때문에 정상 로그인을 막지 않는다.
    """
    try:
        evidence = db.list_recent_connected_net_events_for_login(
            ip, config.NET_SUCCESS_LOGIN_LOOKBACK_MINUTES
        )
        if not evidence:
            return False

        existing = db.get_open_incident(ip)
        if (
            existing
            and not db.incidents._is_idle(existing)
            and "CR-03" in (existing.get("matched_rules") or [])
        ):
            # 이번 로그인은 막는다. 다만 같은 IP에서 다른 계정이 들어왔다면 그 계정의 기존 세션도 끊어야
            # 하므로, 사건이 이미 처리됐어도 계정마다 세션 끊기는 따로 확인한다(강사 피드백 추가 상황).
            _invalidate_sessions_once_per_user(ip, existing, username)
            return True

        user = db.get_user_by_username(username)
        event = evidence[0]
        incident = db.record_incident(
            ip, [event["event_type"]], event.get("severity") or "MEDIUM",
            source="NET", rule_id="CR-03",
        )
        if incident.get("rule_added", True):
            ctx = {
                "ip": ip,
                "incident_id": incident["id"],
                "rule_id": "CR-03",
                "priority": "HIGH",
                "matched_rules": incident.get("matched_rules") or [],
                "evidence": "CONNECTED",
                "username": username,
                "user_id": user["id"],
                "user_email": user.get("email"),
            }
            playbooks.run(
                "SUSPICIOUS_SUCCESS_LOGIN", f"incident:{incident['id']}:CR-03", ctx
            )
        else:
            # 같은 순간 다른 요청이 CR-03을 먼저 기록했다 — 그쪽은 그 계정만 처리하므로 이 계정은 따로 확인한다.
            _invalidate_sessions_once_per_user(ip, incident, username)
        return True
    except Exception as error:
        print(f"[의심 로그인 검사 오류] {type(error).__name__}")
        return False


def _rule_ctx(ip: str, incident: dict, rule: dict) -> dict:
    """교차 규칙 플레이북에 넘길 공통 정보. 처음 실행과 실패 단계 재실행이 같은 값을 쓴다."""
    return {
        "ip": ip,
        "incident_id": incident["id"],
        "rule_id": rule["id"],
        "priority": rule["priority"],
        "matched_rules": incident.get("matched_rules") or [],
        "evidence": rule["evidence"],
        "username": None,
        "user_id": None,
        "user_email": None,
    }


def _retry_failed_steps(playbook: str, trigger_ref: str, ctx: dict) -> None:
    """같은 실행 근거에서 마지막 결과가 FAILED인 조치 단계만 다시 실행한다.

    matched_rules는 "규칙에 해당함"만 뜻하고 "조치 완료"는 playbook_runs에 남는다. 예전에는 규칙이
    기록돼 있으면 차단 요청이 일시적으로 실패했어도 다음 경보에서 건너뛰어, 오류가 풀린 뒤에도 차단이
    걸리지 않았다(10/26 강사 피드백 3). 이미 성공한 단계와 알림은 반복하지 않는다(RETRYABLE_STEPS).
    조회가 실패하면 아무것도 하지 않는다 — 확실하지 않을 때 조치를 반복하는 것보다 안전하다.
    """
    try:
        latest: dict[str, str] = {}
        for row in db.list_playbook_runs(trigger_ref):
            latest[row["step"]] = row["status"]
    except Exception as error:
        print(f"[실패 단계 재실행 조회 오류] {type(error).__name__}")
        return
    steps = [step for step, status in latest.items()
             if status == "FAILED" and step in playbooks.RETRYABLE_STEPS]
    if steps:
        playbooks.run(playbook, trigger_ref, ctx, only_steps=steps)


# TTL 차단(block_l4_ttl)을 쓰는 규칙. CR-01(킬체인)은 영구 차단이라 TTL로 끝나지 않으므로 빠진다.
_TTL_REBLOCK_RULES = {"NET-01", "CR-02"}


def _parse_utc(value: str | None) -> datetime | None:
    """DB 시각 문자열을 UTC datetime으로 바꾼다. 비었거나 해석할 수 없으면 None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ttl_block_expired(row: dict | None) -> bool:
    """network_blocks 행이 'TTL이 다 돼서' 풀렸는지(또는 이미 풀렸어야 하는지).

    - REMOVED이고 removed_at >= expires_at: 지연 만료(GET /blocks)가 정리한 행 → True.
    - REMOVED이고 removed_at < expires_at: 관리자가 만료 전에 푼 행 → False(관리자 판단 존중).
    - PENDING_APPLY/APPLIED인데 expires_at이 지남: fw-agent가 멈춰 정리만 안 됐고 커널은 이미 풀었다 → True.
    - 행이 없음: 처음부터 거절된 IP(허용 목록 등)일 수 있어 경보마다 같은 거절을 반복하지 않게 False.
    """
    if not row:
        return False
    expires_at = _parse_utc(row.get("expires_at"))
    if expires_at is None:
        return False  # 영구 차단(또는 깨진 값)은 TTL로 끝나지 않는다.
    status = row.get("status")
    if status == "REMOVED":
        removed_at = _parse_utc(row.get("removed_at"))
        return removed_at is not None and removed_at >= expires_at
    if status in ("PENDING_APPLY", "APPLIED"):
        return expires_at <= datetime.now(timezone.utc)
    return False


def _expire_block_row(ip: str, row: dict) -> bool:
    """만료 시각이 지났는데 아직 APPLIED인 행을 지연 만료(GET /blocks)와 똑같이 정리한다.

    다음 경보가 fw-agent 폴링(2초)보다 먼저 오면 행이 APPLIED인 채로 다시 막게 된다. 그러면 이전
    NET_BLOCKED가 해결되지 않아 새 NET_BLOCKED가 기록되지 않고(record_net_blocked의 멱등 규칙),
    request_block이 세는 '실제 적용 횟수'가 늘지 않아 TTL 2배가 한 번에서 멈춘다(10/29 Docker 실측:
    60→120→120초). 그래서 REMOVED로 바꾸고 NET_BLOCKED를 해결 처리한 뒤 다시 요청한다.
    조건부로만 바꾸므로, 그 사이 다른 요청이 행을 바꿨으면 다시 읽어 확실히 만료된 경우에만 True.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    cond = {"expected_version": row["version"]} if "version" in row else {}
    try:
        if db.update_network_block_if_status(
            ip, [row["status"]], {"status": "REMOVED", "removed_at": now_iso}, **cond
        ):
            db.resolve_net_blocked_events(ip)
            return True
        latest = db.get_network_block(ip)
    except Exception as error:
        print(f"[재차단 만료 정리 오류] {type(error).__name__}")
        return False
    # 지연 만료가 먼저 정리했으면(REMOVED, NET_BLOCKED 해결됨) 그대로 다시 막는다. 다른 요청이 이미
    # 다시 막았으면(PENDING_APPLY 등) 여기서 또 요청하지 않는다.
    return bool(latest) and latest.get("status") == "REMOVED" and _ttl_block_expired(latest)


def _reblock_if_ttl_expired(ip: str, incident: dict, rule: dict) -> None:
    """같은 사건 안에서 TTL 차단이 끝났는데 공격이 계속되면 차단 단계만 다시 실행한다.

    센서는 iptables보다 앞(AF_PACKET)에서 패킷을 보므로 차단 중에도 경보가 계속 들어오고, 그때마다
    사건의 last_event_at이 갱신돼 IDLE이 되지 않는다. 그러면 "이미 실행한 규칙"으로만 판단해 TTL이
    끝난 뒤 다시 막지 못한다(10/29 점검). 차단 단계만 다시 돌리고 알림은 반복하지 않는다 —
    RETRYABLE_STEPS와 같은 이유다. TTL을 2배로 늘리는 계산은 request_block이 그대로 맡는다.
    조회가 실패하면 아무것도 하지 않는다 — 확실하지 않을 때 조치를 반복하지 않는다.
    """
    if rule["id"] not in _TTL_REBLOCK_RULES:
        return
    try:
        row = db.get_network_block(ip)
    except Exception as error:
        print(f"[재차단 조회 오류] {type(error).__name__}")
        return
    if not _ttl_block_expired(row):
        return
    if row.get("status") in ("PENDING_APPLY", "APPLIED") and not _expire_block_row(ip, row):
        return
    playbooks.run(
        rule["playbook"], f"incident:{incident['id']}:{rule['id']}",
        _rule_ctx(ip, incident, rule), only_steps=["block_l4_ttl"],
    )


def reblock_on_expiry(ip: str) -> None:
    """TTL 차단이 만료 처리된 바로 그 순간, 공격이 아직 진행 중이면 차단 단계만 다시 실행한다.

    GET /blocks의 지연 만료가 행을 REMOVED로 바꾼 직후 부른다. shipper는 1분 창의 첫 경보만 바로 보내고
    같은 분의 추가분은 창이 끝난 뒤 보내므로(계약서 K4), 경보를 기다려 다시 막으면 TTL이 분 중간에
    끝날 때 다음 분까지 차단이 풀려 있었다(10/29 Docker 실측: 약 21~25초, 최대 약 1분). 그래서 만료
    시점에 이번 분이나 지난 분 창에 SYN Flood 경보가 있으면 공격이 계속되는 것으로 보고 바로 다시 요청한다.
    같은 응답의 차단 목록에 새 요청이 실리므로 공백은 fw-agent 폴링 간격(2초) 안쪽이 된다.
    공격이 만료 직전 1~2분 안에 멈췄다면 한 번 더 막힐 수 있지만, TTL 차단이라 시간이 지나면 풀린다.
    사건 기록·알림은 하지 않는다. 이미 실행된 TTL 규칙(NET-01·CR-02)이 있는 열린 사건에서만 동작한다.
    어떤 오류도 차단 목록 응답을 깨지 않게 여기서 삼킨다.
    """
    try:
        now = datetime.now(timezone.utc)
        since = (now.replace(second=0, microsecond=0) - timedelta(minutes=1)).isoformat()
        if not db.has_recent_network_event(ip, "SYN_FLOOD", since):
            return
        existing = db.get_open_incident(ip)
        if not existing or db.incidents._is_idle(existing):
            return
        matched = existing.get("matched_rules") or []
        for rule in CROSS_LAYER_RULES:
            if rule["id"] in _TTL_REBLOCK_RULES and rule["id"] in matched:
                # 둘 다 기록돼 있어도 첫 재요청 뒤 행이 PENDING_APPLY라 두 번째는 건너뛴다.
                _reblock_if_ttl_expired(ip, existing, rule)
    except Exception as error:
        print(f"[만료 시 재차단 확인 오류] {type(error).__name__}")


def _invalidate_sessions_once_per_user(ip: str, incident: dict, username: str) -> None:
    """CR-03 사건이 이미 처리된 IP에서 들어온 계정의 기존 세션을, 계정마다 한 번 끊는다.

    사건 단위로 "이미 처리함"을 판단하면 같은 IP의 두 번째 계정은 이번 로그인만 막히고, 이미 발급된
    세션은 그대로 남는다(10/26 강사 피드백 추가 상황). 그래서 계정별 실행 근거
    incident:<id>:CR-03:user:<user_id> 로 세션 끊기 단계만 따로 기록·확인한다. 메일·Slack은 사건당
    한 번이면 충분하므로 여기서는 보내지 않는다. 첫 계정도 다음 로그인 때 이 확인을 한 번 거치므로
    session_version이 한 번 더 오를 수 있지만, 이미 끊긴 세션이라 결과는 같다.
    어떤 오류도 로그인 차단 판정(True)을 바꾸지 않게 여기서 삼킨다.
    """
    try:
        user = db.get_user_by_username(username)
        if not user:
            return
        trigger_ref = f"incident:{incident['id']}:CR-03:user:{user['id']}"
        rows = db.list_playbook_runs(trigger_ref)
        if any(row["step"] == "invalidate_sessions" and row["status"] == "OK" for row in rows):
            return
        ctx = {
            "ip": ip,
            "incident_id": incident["id"],
            "rule_id": "CR-03",
            "priority": "HIGH",
            "matched_rules": incident.get("matched_rules") or [],
            "evidence": "CONNECTED",
            "username": username,
            "user_id": user["id"],
            "user_email": user.get("email"),
        }
        playbooks.run("SUSPICIOUS_SUCCESS_LOGIN", trigger_ref, ctx, only_steps=["invalidate_sessions"])
    except Exception as error:
        print(f"[계정별 세션 끊기 오류] {type(error).__name__}")


def _match_cross_layer_rule(ip: str, event_type: str, rule: dict) -> list[dict]:
    """현재 이벤트와 관련된 규칙만 조회해 매칭에 실제로 쓰인 행을 돌려준다."""
    if rule.get("single"):
        if event_type != rule["single"]:
            return []
        return [{"event_type": event_type, "severity": "HIGH"}]

    relevant_types = set(rule.get("first_any", set())) | set(rule.get("then_any", set()))
    relevant_types |= set(rule.get("all", set()))
    if event_type not in relevant_types:
        return []

    rows = db.list_recent_security_events_for_correlation(ip, rule["window_minutes"])
    if rule["id"] == "CR-01":
        return _match_ordered_rule(rows, rule["first_any"], rule["then_any"])
    if rule["id"] == "CR-02":
        usable = [
            row for row in rows
            if row.get("event_type") != "HTTP_FLOOD"
            or row.get("path") not in CR02_EXCLUDED_FLOOD_PATHS
        ]
        by_type = {row.get("event_type"): row for row in usable}
        if rule["all"].issubset(by_type):
            return [by_type[event] for event in sorted(rule["all"])]
    return []


def _match_ordered_rule(rows: list[dict], first_any: set[str], then_any: set[str]) -> list[dict]:
    """정찰 행보다 나중 시각의 앱 침투 행이 있을 때 그 두 행만 증거로 고른다."""
    ordered = sorted(rows, key=lambda row: row.get("detected_at") or "")
    for first_index, first in enumerate(ordered):
        if first.get("event_type") not in first_any:
            continue
        for later in ordered[first_index + 1:]:
            if (
                later.get("event_type") in then_any
                and (later.get("detected_at") or "") > (first.get("detected_at") or "")
            ):
                return [first, later]
    return []


def _maybe_escalate(ip: str, incident: dict) -> None:
    """사건이 SOAR 플레이북(CRITICAL_MULTI_STAGE) 조건 — CRITICAL이면서
    서로 다른 event_type이 config.INCIDENT_ESCALATION_MIN_EVENT_TYPES개
    이상 — 에 도달했고, 아직 이 사건으로 에스컬레이션 알림을 보낸 적이
    없다면 플레이북을 실행한다.

    이미 escalated된 사건이면 건너뛴다 — soar.enforce_lockout()이 "잠그는
    순간에 딱 한 번만" 알리는 것과 같은 이유로, 같은 사건에 이벤트가 하나씩
    더 붙을 때마다 매번 재알림하면 알림 피로가 생긴다.
    """
    if incident["escalated"]:
        return
    if incident["severity_max"] != "CRITICAL":
        return
    if len(incident["event_types"]) < config.INCIDENT_ESCALATION_MIN_EVENT_TYPES:
        return

    for action_name in PLAYBOOKS["CRITICAL_MULTI_STAGE"]:
        action = getattr(alert, action_name)
        action(ip, incident["event_types"], incident["severity_max"])
    db.mark_incident_escalated(incident["id"])
