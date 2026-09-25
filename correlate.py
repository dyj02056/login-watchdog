# ============================================================================
# correlate.py — "형사" 역할: 흩어진 개별 신고(security_events)들을 보고
# "이거 같은 출처가 벌인 하나의 사건 아니야?"를 판단한다 (Track C guide27, SIEM 상관분석)
#
# soar.py가 security_events에 새 이벤트를 기록할 때마다 이 모듈의
# check_and_correlate()를 호출한다. detector.py와 동일한 원칙으로, 이 파일도
# "판단"만 하고(사건으로 묶어야 하는가?) 실제 저장/병합은 db.py(db/incidents.py)에
# 맡긴다 — soar.py가 db.py에게 조치를 맡기는 것과 같은 구조다.
#
# PLAYBOOKS(Track C guide28, SOAR 플레이북)도 이 파일에 둔다. soar.py가 이미
# correlate.py를 import하고 있어서, 플레이북 실행을 soar.py 쪽에 두고
# correlate.py가 그걸 호출하게 하면 반대 방향 import가 생겨 순환 참조가 된다.
# correlate.py는 사건이 얼마나 심각해졌는지 이미 알고 있는 유일한 곳이므로,
# 여기서 곧바로 alert.py를 불러 실행하는 것이 soar.py가 alert.py를 직접
# 부르는 것과 같은 자연스러운 구조다.
# ============================================================================

import alert
import config
import db

# "사건이 이 정도로 심각해지면 → 이런 대응을 한다"는 매뉴얼을 선언적으로
# 나열한다. 지금은 항목이 하나뿐이지만(에스컬레이션 알림), 나중에 대응이
# 늘어나도 이 리스트에 함수 이름만 추가하면 된다 — _maybe_escalate()의
# 호출부는 바뀌지 않는다.
#
# 함수 객체(alert.send_incident_escalation_alert) 자체가 아니라 이름(문자열)을
# 담아두는 이유: db.py/alert.py의 다른 모든 호출부와 마찬가지로 "함수를 부르는
# 순간"에 getattr(alert, ...)로 다시 찾아야 테스트에서 monkeypatch.setattr(alert,
# "send_incident_escalation_alert", ...)로 바꿔치기한 게 실제로 적용된다 —
# 모듈을 처음 읽어들일 때(import 시점) 함수 객체를 미리 꺼내서 담아두면, 그
# 뒤에 monkeypatch로 바꿔도 이 딕셔너리 안의 참조는 원래 함수를 그대로 가리킨다.
PLAYBOOKS = {
    "CRITICAL_MULTI_STAGE": ["send_incident_escalation_alert"],
}


def check_and_correlate(ip: str, event_type: str, severity: str) -> None:
    """방금 security_events에 기록된 이벤트를 계기로, 이 IP가 최근
    config.INCIDENT_CORRELATION_WINDOW_MINUTES분 안에 서로 다른 event_type을
    2개 이상 남겼는지 확인한다.

    2개 미만(=이 이벤트 하나뿐)이면 아무 것도 하지 않는다 — 단발성 이벤트까지
    전부 "사건"으로 묶으면 security_incidents가 security_events와 다를 바
    없어진다. 2개 이상이면 db.record_incident()로 사건을 열거나 갱신하고,
    그 결과가 에스컬레이션 조건을 넘는지 이어서 확인한다.
    """
    distinct_types = db.get_recent_distinct_event_types(
        ip, config.INCIDENT_CORRELATION_WINDOW_MINUTES
    )
    if len(distinct_types) < 2:
        return
    incident = db.record_incident(ip, distinct_types, severity)
    _maybe_escalate(ip, incident)


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
