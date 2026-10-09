# ============================================================================
# db/incidents.py — security_incidents 표 관련 함수 (Track C guide27, SIEM 상관분석)
#
# security_events가 개별 신고서 한 장 한 장이라면, 이 표는 "같은 IP가 짧은 시간
# 안에 서로 다른 event_type을 2개 이상 남겼을 때" 그 신고들을 하나로 묶어두는
# 사건철이다. security/correlate.py가 판단(묶어야 하는가?)만 하고, 실제 조회/삽입/병합은
# 전부 이 파일이 맡는다(security/detector.py·security/soar/와 동일한 판단·실행 분리 원칙).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

import config
import db

_SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def get_recent_distinct_event_types(ip: str, window_minutes: int) -> list[str]:
    """이 IP가 최근 window_minutes분 안에 security_events에 남긴 서로 다른
    event_type 목록을 정렬해서 돌려준다. 방금 기록된 이벤트도 포함된다
    (correlate.check_and_correlate가 db.insert_security_event 직후에 이 함수를
    부르기 때문).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    res = (
        db.get_client()
        .table("security_events")
        .select("event_type")
        .eq("ip_address", ip)
        .gte("detected_at", cutoff)
        .execute()
    )
    return sorted({row["event_type"] for row in res.data})


def list_security_incidents(page: int = 1, page_size: int = 20) -> tuple[list[dict], int]:
    """상관된 사건을 최신 활동순으로 `page`번째 페이지만 가져오고, 전체 건수도
    함께 돌려준다. db.list_security_events()와 동일한 페이지네이션 방식이다 —
    관리자 대시보드의 "연관 사건" 표에 쓰인다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("security_incidents")
        .select("*", count="exact")
        .order("last_event_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0


def get_open_incident(ip: str) -> dict | None:
    """이 IP에 지금 열려있는(status='OPEN') 사건이 있으면 그 행을 돌려준다.

    escalated도 함께 가져온다 — record_incident()가 병합할 때 "이미 에스컬레이션
    알림을 보낸 사건인지"를 판단해야 하기 때문이다(Track C guide28, SOAR 플레이북).
    last_event_at도 가져온다 — 마지막 이벤트로부터 너무 오래 지난 사건은 병합하지
    않고 IDLE로 옮겨야 하는지(_is_idle) 판단하는 데 쓰인다.
    """
    res = (
        db.get_client()
        .table("security_incidents")
        .select("id, event_types, severity_max, escalated, last_event_at")
        .eq("ip_address", ip)
        .eq("status", "OPEN")
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def _insert_incident(ip: str, event_types: list[str], severity_max: str) -> int:
    now = db._now_iso()
    res = (
        db.get_client()
        .table("security_incidents")
        .insert(
            {
                "ip_address": ip,
                "event_types": event_types,
                "severity_max": severity_max,
                "status": "OPEN",
                "escalated": False,
                "first_event_at": now,
                "last_event_at": now,
            }
        )
        .execute()
    )
    return res.data[0]["id"]


def _update_incident(incident_id: int, event_types: list[str], severity_max: str) -> None:
    db.get_client().table("security_incidents").update(
        {"event_types": event_types, "severity_max": severity_max, "last_event_at": db._now_iso()}
    ).eq("id", incident_id).execute()


def _merge_into_existing(existing: dict, event_types: list[str], severity: str) -> dict:
    merged_types = sorted(set(existing["event_types"]) | set(event_types))
    merged_severity = _higher_severity(existing["severity_max"], severity)
    _update_incident(existing["id"], merged_types, merged_severity)
    return {
        "id": existing["id"],
        "event_types": merged_types,
        "severity_max": merged_severity,
        "escalated": existing["escalated"],
    }


def record_incident(ip: str, event_types: list[str], severity: str) -> dict:
    """이 IP에 열린 사건이 있으면 event_types/최고 위험등급을 병합해서 갱신하고,
    없으면 새로 연다. 병합/생성된 사건의 최종 상태(id/event_types/severity_max/
    escalated)를 돌려준다 — security/correlate.py가 이 값을 보고 SOAR 플레이북(사건
    에스컬레이션 알림, Track C guide28)을 실행할지 판단한다.

    "열려있는지 확인" 후 "새로 연다" 사이의 아주 짧은 틈에 동시 요청 두 개가
    겹치면(드문 경쟁 조건), docs/schema.sql의 idx_security_incidents_open_ip
    부분 유니크 인덱스가 두 번째 삽입을 막아준다 — db.insert_security_event_or_bump()와
    같은 방식으로, 그 충돌(Postgres 오류 코드 23505)을 여기서 붙잡아 새로 여는
    대신 이미 삽입된 사건에 병합하는 것으로 대체한다.
    """
    existing = get_open_incident(ip)
    if existing and _is_idle(existing):
        # 마지막 이벤트로부터 config.INCIDENT_MERGE_IDLE_MINUTES 넘게 조용했던 옛
        # 사건 — 새 이벤트를 억지로 합치지 않고 IDLE(활동 없음, 아직 관리자
        # 미해결)로 옮긴 뒤 새 사건을 연다. idx_security_incidents_open_ip는
        # status='OPEN'에만 걸려 있으므로 옛 사건이 IDLE로 빠져야 새 OPEN 사건을
        # 만들 수 있다. 새 사건은 escalated=False로 시작하므로, 이미 escalated
        # 된 옛 사건이 새 공격의 에스컬레이션 알림을 삼키는 일이 없어진다.
        mark_incident_idle(existing["id"])
        existing = None
    if existing:
        return _merge_into_existing(existing, event_types, severity)
    try:
        incident_id = _insert_incident(ip, event_types, severity)
        return {"id": incident_id, "event_types": event_types, "severity_max": severity, "escalated": False}
    except APIError as e:
        if e.code != "23505":
            raise
        existing = get_open_incident(ip)
        return _merge_into_existing(existing, event_types, severity)


def mark_incident_escalated(incident_id: int) -> None:
    """이 사건에 에스컬레이션(SOAR 플레이북) 알림을 이미 보냈다고 표시한다.

    soar.enforce_lockout()이 "잠그는 순간에 딱 한 번만" Slack에 알리는 것과
    같은 이유 — 이 표시가 없으면 이미 CRITICAL·다유형에 도달한 사건에 이벤트가
    하나씩 더 붙을 때마다 매번 "복합 공격 발생" 알림이 반복돼서 알림 피로가 생긴다.
    """
    db.get_client().table("security_incidents").update({"escalated": True}).eq("id", incident_id).execute()


def mark_incident_idle(incident_id: int) -> None:
    """이 사건을 IDLE(활동 없음, 아직 관리자 미해결)로 옮긴다.

    record_incident()가 "마지막 이벤트로부터 너무 오래 지난 사건"을 만났을 때만
    부른다. OPEN인 행에만 적용되므로 이미 CLOSED/IDLE인 사건은 건드리지 않는다.
    """
    db.get_client().table("security_incidents").update({"status": "IDLE"}).eq(
        "id", incident_id
    ).eq("status", "OPEN").execute()


def resolve_incident(incident_id: int, admin_username: str) -> bool:
    """관리자가 대시보드에서 "해결"을 눌렀을 때, 이 사건을 CLOSED로 바꾸고 누가
    언제 해결했는지 기록한다.

    IP 잠금 해제와는 완전히 별개다 — 잠금을 푸는 것은 접속 차단을 거두는 조치이고,
    사건 해결은 "관리자가 내용을 확인하고 조사가 끝났다"는 판단이므로 오직 이
    함수(관리자 버튼)로만 사건이 CLOSED가 된다. OPEN 또는 IDLE인 사건에만 적용돼서,
    이미 해결된 사건을 다시 눌러도 안전하다(res.data가 비어있으면 False를 돌려줌
    — resolve_security_event()와 같은 방식).
    """
    res = (
        db.get_client()
        .table("security_incidents")
        .update({"status": "CLOSED", "resolved_at": db._now_iso(), "resolved_by": admin_username})
        .eq("id", incident_id)
        .in_("status", ["OPEN", "IDLE"])
        .execute()
    )
    return bool(res.data)


def close_incident_system(incident_id: int, actor: str) -> bool:
    """사건을 시스템이 자동으로 CLOSED 처리한다(PERMANENT_LOCK_AUTO_CLOSE_INCIDENT=true일 때만 쓰인다).

    resolve_incident()와 같은 조건(OPEN/IDLE만 대상)이지만, 사람이 눌렀을 때와
    구분되도록 resolved_by에 "system:permanent_lock" 같은 시스템 표식을 기록한다.
    """
    res = (
        db.get_client()
        .table("security_incidents")
        .update({"status": "CLOSED", "resolved_at": db._now_iso(), "resolved_by": actor})
        .eq("id", incident_id)
        .in_("status", ["OPEN", "IDLE"])
        .execute()
    )
    return bool(res.data)


def _is_idle(incident: dict) -> bool:
    """마지막 이벤트(last_event_at)로부터 config.INCIDENT_MERGE_IDLE_MINUTES가 지났는지.

    last_event_at이 없으면(조회 결과에 빠진 경우) 오래됐다고 단정할 근거가 없으므로
    False로 본다 — 기존처럼 병합하는 쪽이 안전하다.
    """
    last_event_at = incident.get("last_event_at")
    if not last_event_at:
        return False
    last = datetime.fromisoformat(last_event_at)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last > timedelta(minutes=config.INCIDENT_MERGE_IDLE_MINUTES)


def _higher_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b
