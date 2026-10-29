# ============================================================================
# db/network_events.py — network_events 표: 센서 경보 원본 기록 (계약서 K4·K10·K11)
#
# 중복 event_id는 삽입 유니크 제약으로 처리하고 누적 수는 조건부 갱신으로 보호한다.
#
# 새 DB 함수는 이 파일에 만들고, 이름을 아래 __all__ 목록에 추가한다. 그러면
# db/__init__.py가 "from .network_events import *"로 자동으로 다시 내보내므로, 다른 파일에서
# 바로 db.함수이름(...)으로 쓸 수 있다 — 세 사람이 공용 파일(db/__init__.py)을 고치지
# 않아도 되게 하려는 장치다(team-plan 01 3.2).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고(import db 후 db.get_client()).
# ============================================================================

from collections import Counter
from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

import db

__all__ = [
    "insert_network_event",
    "bump_network_event",
    "list_recent_network_events",
    "count_network_events_by_category",
    "mark_network_event_promoted",
    "resolve_net_blocked_events",
    "is_network_event_unpromoted",
    "list_recent_security_events_for_correlation",
    "list_recent_connected_net_events_for_login",
    "has_recent_network_event",
]

_PAGE = 1000
_MAX_ROWS = 20000


def list_recent_security_events_for_correlation(ip: str, window_minutes: int) -> list[dict]:
    """같은 IP의 교차 규칙 판단에 필요한 이벤트만 UTC 창 안에서 오래된 순으로 읽는다.

    규칙 순서(CR-01)는 Python에서 판단하되, 창 밖 행은 DB가 먼저 거르게 해 오래된
    보안 기록이 많아져도 불필요한 전송을 만들지 않는다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    return (
        db.get_client().table("security_events")
        .select("event_type,severity,path,detected_at,source,layer")
        .eq("ip_address", ip)
        .gte("detected_at", cutoff)
        .order("detected_at")
        .execute().data
    )


def list_recent_connected_net_events_for_login(ip: str, window_minutes: int) -> list[dict]:
    """의심 로그인 판단에 쓸 연결 완성 NET 증거만 UTC 창 안에서 읽는다.

    SYN·포트 스캔은 출발지를 위조할 수 있으므로 DB 조회 단계부터 제외한다.
    창의 위쪽 끝(앱의 현재 시각)은 걸지 않는다 — detected_at은 DB 시계(now())로 찍히는데
    앱 컨테이너 시계가 DB보다 조금만 늦어도 방금 들어온 스캐너 경보가 "미래 기록"으로 빠져
    CR-03이 맞지 않기 때문이다(list_recent_security_events_for_correlation과 같은 방식).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    return (
        db.get_client().table("security_events")
        .select("event_type,severity,detected_at")
        .eq("ip_address", ip).eq("source", "NET")
        .in_("event_type", ["NET_WEB_ATTACK", "NET_SCANNER_UA"])
        .gte("detected_at", cutoff)
        .order("detected_at", desc=True).limit(1).execute().data
    )


def mark_network_event_promoted(event_id: str) -> None:
    """승격을 마친 원본 경보만 표시하고 반복 호출로 상태를 되돌리지 않는다."""
    db.get_client().table("network_events").update({"promoted": True}).eq(
        "event_id", event_id
    ).eq("promoted", False).execute()


def is_network_event_unpromoted(event_id: str) -> bool:
    """저장은 됐지만 승격이 끝나지 않은 경보인지 본다. 재전송 때 승격을 마저 할지 판단하는 데 쓴다.

    행이 없으면 False — 승격할 원본이 없으므로 아무것도 하지 않는 쪽이 안전하다.
    """
    rows = (
        db.get_client().table("network_events").select("promoted")
        .eq("event_id", event_id).limit(1).execute().data
    )
    return bool(rows) and rows[0].get("promoted") is False


def has_recent_network_event(ip: str, category: str, since_iso: str) -> bool:
    """이 IP의 해당 category 경보가 since_iso 이후 창(window_start)에 하나라도 있는지.

    shipper는 1분 창의 첫 경보를 바로 보내므로, 공격이 이어지는 동안에는 이번 분(또는 분이 막 바뀐
    때는 지난 분) 창의 행이 항상 있다. TTL 차단이 끝나는 순간 공격이 아직 진행 중인지 판단하는 데 쓴다.
    """
    rows = (
        db.get_client().table("network_events").select("event_id")
        .eq("src_ip", ip).eq("category", category).gte("window_start", since_iso)
        .limit(1).execute().data
    )
    return bool(rows)


def resolve_net_blocked_events(ip: str) -> None:
    """IP와 이벤트 유형 및 미해결 조건을 함께 걸어 다른 보안 기록을 보존한다."""
    db.get_client().table("security_events").update({"resolved_at": db._now_iso()}).eq(
        "ip_address", ip
    ).eq("event_type", "NET_BLOCKED").is_("resolved_at", "null").execute()


def insert_network_event(row: dict) -> bool:
    """유니크 제약이 동시 삽입을 중재하게 하고 다른 DB 오류는 호출자에게 전달한다."""
    try:
        db.get_client().table("network_events").insert(row).execute()
    except APIError as error:
        if error.code != "23505":
            raise
        return False
    return True


def bump_network_event(event_id: str, packet_count: int, last_seen_at: str) -> None:
    """재전송 순서가 뒤집혀도 누적 수와 마지막 관측 시각이 감소하지 않게 한다."""
    client = db.get_client()
    client.table("network_events").update({"packet_count": packet_count}).eq(
        "event_id", event_id
    ).lt("packet_count", packet_count).execute()
    # 누적 수가 같거나 작아도 더 늦은 관측 시각은 반영해야 하므로 따로 갱신한다.
    client.table("network_events").update({"last_seen_at": last_seen_at}).eq(
        "event_id", event_id
    ).lt("last_seen_at", last_seen_at).execute()


def list_recent_network_events(limit=50) -> list[dict]:
    """화면에 필요한 칸만 최신 관측 순으로 가져와 응답 크기를 제한한다."""
    return (
        db.get_client().table("network_events")
        .select("id,observed_at,src_ip,layer,category,signature,packet_count,promoted")
        .order("observed_at", desc=True).order("id", desc=True).limit(limit).execute().data
    )


def count_network_events_by_category(since_iso: str) -> list[dict]:
    """전체 PC의 경보 행을 최대 2만 건까지 세어 통계 조회 비용을 제한한다."""
    counts = Counter()
    for start in range(0, _MAX_ROWS, _PAGE):
        page = (
            db.get_client().table("network_events").select("category,layer")
            .gte("observed_at", since_iso).order("observed_at", desc=True).order("id", desc=True)
            .range(start, start + _PAGE - 1).execute().data
        )
        counts.update((row["category"], row["layer"]) for row in page)
        if len(page) < _PAGE:
            break
    return [
        {"category": category, "layer": layer, "count": count}
        for (category, layer), count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]
