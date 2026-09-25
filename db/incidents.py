# ============================================================================
# db/incidents.py — security_incidents 표 관련 함수 (Track C guide27, SIEM 상관분석)
#
# security_events가 개별 신고서 한 장 한 장이라면, 이 표는 "같은 IP가 짧은 시간
# 안에 서로 다른 event_type을 2개 이상 남겼을 때" 그 신고들을 하나로 묶어두는
# 사건철이다. correlate.py가 판단(묶어야 하는가?)만 하고, 실제 조회/삽입/병합은
# 전부 이 파일이 맡는다(detector.py/soar.py와 동일한 판단·실행 분리 원칙).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

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
    """이 IP에 지금 열려있는(status='OPEN') 사건이 있으면 그 행을 돌려준다."""
    res = (
        db.get_client()
        .table("security_incidents")
        .select("id, event_types, severity_max")
        .eq("ip_address", ip)
        .eq("status", "OPEN")
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def _insert_incident(ip: str, event_types: list[str], severity_max: str) -> None:
    now = db._now_iso()
    db.get_client().table("security_incidents").insert(
        {
            "ip_address": ip,
            "event_types": event_types,
            "severity_max": severity_max,
            "status": "OPEN",
            "first_event_at": now,
            "last_event_at": now,
        }
    ).execute()


def _update_incident(incident_id: int, event_types: list[str], severity_max: str) -> None:
    db.get_client().table("security_incidents").update(
        {"event_types": event_types, "severity_max": severity_max, "last_event_at": db._now_iso()}
    ).eq("id", incident_id).execute()


def _merge_into_existing(existing: dict, event_types: list[str], severity: str) -> None:
    merged_types = sorted(set(existing["event_types"]) | set(event_types))
    merged_severity = _higher_severity(existing["severity_max"], severity)
    _update_incident(existing["id"], merged_types, merged_severity)


def record_incident(ip: str, event_types: list[str], severity: str) -> None:
    """이 IP에 열린 사건이 있으면 event_types/최고 위험등급을 병합해서 갱신하고,
    없으면 새로 연다.

    "열려있는지 확인" 후 "새로 연다" 사이의 아주 짧은 틈에 동시 요청 두 개가
    겹치면(드문 경쟁 조건), docs/schema.sql의 idx_security_incidents_open_ip
    부분 유니크 인덱스가 두 번째 삽입을 막아준다 — db.insert_security_event_or_bump()와
    같은 방식으로, 그 충돌(Postgres 오류 코드 23505)을 여기서 붙잡아 새로 여는
    대신 이미 삽입된 사건에 병합하는 것으로 대체한다.
    """
    existing = get_open_incident(ip)
    if existing:
        _merge_into_existing(existing, event_types, severity)
        return
    try:
        _insert_incident(ip, event_types, severity)
    except APIError as e:
        if e.code != "23505":
            raise
        existing = get_open_incident(ip)
        _merge_into_existing(existing, event_types, severity)


def close_open_incident_for_ip(ip: str) -> None:
    """이 IP의 열린 사건을 닫힘으로 표시한다.

    resolve_security_events_for_ip()와 짝을 이룬다 — 잠금이 풀리는 순간(자동
    만료든 수동 해제든) 그 IP를 둘러싼 사건도 함께 끝난 것으로 본다.
    """
    db.get_client().table("security_incidents").update({"status": "CLOSED"}).eq(
        "ip_address", ip
    ).eq("status", "OPEN").execute()


def _higher_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b
