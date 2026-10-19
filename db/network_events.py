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

from postgrest.exceptions import APIError

import db

__all__ = [
    "insert_network_event",
    "bump_network_event",
    "list_recent_network_events",
    "count_network_events_by_category",
]

_PAGE = 1000
_MAX_ROWS = 20000


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
