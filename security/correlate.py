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
# ============================================================================

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
            ctx = {
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
            playbooks.run(
                rule["playbook"], f"incident:{incident['id']}:{rule['id']}", ctx
            )
    except Exception as error:
        print(f"[교차 규칙 오류] {type(error).__name__}")


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
