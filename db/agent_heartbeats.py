# ============================================================================
# db/agent_heartbeats.py — agent_heartbeats 표: fw-agent·shipper 생존 신호, PC별 저장 (계약서 K9·K11)
#
# 담당: 역할 C (C1-1부터). Track D 뼈대 PR(I0-1)이 만든 빈 모듈이다.
#
# 새 DB 함수는 이 파일에 만들고, 이름을 아래 __all__ 목록에 추가한다. 그러면
# db/__init__.py가 "from .agent_heartbeats import *"로 자동으로 다시 내보내므로, 다른 파일에서
# 바로 db.함수이름(...)으로 쓸 수 있다 — 세 사람이 공용 파일(db/__init__.py)을 고치지
# 않아도 되게 하려는 장치다(team-plan 01 3.2).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고(import db 후 db.get_client()).
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

import db

__all__ = [
    "upsert_agent_heartbeat",
    "get_agent_heartbeats",
    "try_acquire_cooldown",
]


def upsert_agent_heartbeat(agent: str, node: str, detail: dict) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    row = {
        "agent": agent,
        "node": node,
        "last_seen_at": now_iso,
        "detail": detail,
    }
    db.get_client().table("agent_heartbeats").upsert(row, on_conflict="agent,node").execute()


def get_agent_heartbeats(node: str) -> dict[str, dict]:
    res = (
        db.get_client()
        .table("agent_heartbeats")
        .select("*")
        .eq("node", node)
        .execute()
    )
    rows = res.data or []
    return {row["agent"]: row for row in rows}


def try_acquire_cooldown(key: str, seconds: int) -> bool:
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    cutoff_iso = (now_dt - timedelta(seconds=seconds)).isoformat()

    # 1. 조건부 update 시도 (last_sent_at < cutoff_iso)
    res = (
        db.get_client()
        .table("notification_cooldowns")
        .update({"last_sent_at": now_iso})
        .eq("key", key)
        .lt("last_sent_at", cutoff_iso)
        .execute()
    )
    if res.data:
        return True

    # 2. 행이 없는 경우 insert 시도
    try:
        db.get_client().table("notification_cooldowns").insert(
            {"key": key, "last_sent_at": now_iso}
        ).execute()
        return True
    except APIError as e:
        if getattr(e, "code", None) == "23505":
            return False
        raise