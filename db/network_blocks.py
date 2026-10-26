# ============================================================================
# db/network_blocks.py — network_blocks 표: L4 차단 요청·상태 전이 (계약서 K7·K9·K11)
#
# 담당: 역할 C. Track D 뼈대 PR(I0-1)이 빈 모듈로 만들고, C1-1~C2-1에서 함수를 채웠다.
#
# 새 DB 함수는 이 파일에 만들고, 이름을 아래 __all__ 목록에 추가한다. 그러면
# db/__init__.py가 "from .network_blocks import *"로 자동으로 다시 내보내므로, 다른 파일에서
# 바로 db.함수이름(...)으로 쓸 수 있다 — 세 사람이 공용 파일(db/__init__.py)을 고치지
# 않아도 되게 하려는 장치다(team-plan 01 3.2).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고(import db 후 db.get_client()).
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

import db

__all__ = [
    "get_network_block",
    "insert_network_block",
    "update_network_block_if_status",
    "count_recent_net_blocked_events",
    "list_desired_network_blocks",
    "list_expired_network_blocks",
    "list_network_blocks_for_dashboard",
]


def get_network_block(ip: str) -> dict | None:
    res = db.get_client().table("network_blocks").select("*").eq("ip_address", ip).limit(1).execute()
    return res.data[0] if res.data else None


def insert_network_block(row: dict) -> bool:
    try:
        db.get_client().table("network_blocks").insert(row).execute()
        return True
    except APIError as e:
        if getattr(e, "code", None) == "23505":
            return False
        raise


def update_network_block_if_status(
    ip: str, from_statuses: list[str], fields: dict, expected_version: int | None = None,
) -> bool:
    """상태가 from_statuses 중 하나일 때만 바꾼다. expected_version을 주면 version도 같아야 바꾼다.

    상태만으로는 "60초 차단 요청"과 그 사이 바뀐 "영구 차단 요청"이 둘 다 PENDING_APPLY라 구분되지
    않는다. 요청마다 올리는 version(guide56)을 함께 조건에 걸어, 늦게 온 옛 요청의 ACK가 새 요청을
    완료시키지 못하게 한다(10/26 강사 피드백 4).
    """
    query = (
        db.get_client()
        .table("network_blocks")
        .update(fields)
        .eq("ip_address", ip)
        .in_("status", from_statuses)
    )
    if expected_version is not None:
        query = query.eq("version", expected_version)
    res = query.execute()
    return bool(res.data)


def count_recent_net_blocked_events(ip: str, since_iso: str) -> int:
    res = (
        db.get_client()
        .table("security_events")
        .select("id", count="exact")
        .eq("event_type", "NET_BLOCKED")
        .eq("ip_address", ip)
        .gte("detected_at", since_iso)
        .execute()
    )
    return res.count or 0


def list_desired_network_blocks() -> list[dict]:
    res = (
        db.get_client()
        .table("network_blocks")
        .select("*")
        .in_("status", ["PENDING_APPLY", "APPLIED", "PENDING_REMOVE"])
        .execute()
    )
    return res.data or []


def list_expired_network_blocks(now_iso: str) -> list[dict]:
    res = (
        db.get_client()
        .table("network_blocks")
        .select("*")
        .in_("status", ["PENDING_APPLY", "APPLIED"])
        .not_.is_("expires_at", "null")
        .lte("expires_at", now_iso)
        .execute()
    )
    return res.data or []


def list_network_blocks_for_dashboard() -> list[dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    # REMOVED가 아니거나, removed_at이 최근 24시간 이내인 REMOVED 행
    query = f"status.neq.REMOVED,and(status.eq.REMOVED,removed_at.gte.{cutoff})"
    res = (
        db.get_client()
        .table("network_blocks")
        .select("*")
        .or_(query)
        .order("requested_at", desc=True)
        .limit(100)
        .execute()
    )
    return res.data or []