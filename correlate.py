# ============================================================================
# correlate.py — "형사" 역할: 흩어진 개별 신고(security_events)들을 보고
# "이거 같은 출처가 벌인 하나의 사건 아니야?"를 판단한다 (Track C guide27, SIEM 상관분석)
#
# soar.py가 security_events에 새 이벤트를 기록할 때마다 이 모듈의
# check_and_correlate()를 호출한다. detector.py와 동일한 원칙으로, 이 파일도
# "판단"만 하고(사건으로 묶어야 하는가?) 실제 저장/병합은 db.py(db/incidents.py)에
# 맡긴다 — soar.py가 db.py에게 조치를 맡기는 것과 같은 구조다.
# ============================================================================

import config
import db


def check_and_correlate(ip: str, event_type: str, severity: str) -> None:
    """방금 security_events에 기록된 이벤트를 계기로, 이 IP가 최근
    config.INCIDENT_CORRELATION_WINDOW_MINUTES분 안에 서로 다른 event_type을
    2개 이상 남겼는지 확인한다.

    2개 미만(=이 이벤트 하나뿐)이면 아무 것도 하지 않는다 — 단발성 이벤트까지
    전부 "사건"으로 묶으면 security_incidents가 security_events와 다를 바
    없어진다. 2개 이상일 때만 db.record_incident()를 불러 사건을 열거나 갱신한다.
    """
    distinct_types = db.get_recent_distinct_event_types(
        ip, config.INCIDENT_CORRELATION_WINDOW_MINUTES
    )
    if len(distinct_types) < 2:
        return
    db.record_incident(ip, distinct_types, severity)
