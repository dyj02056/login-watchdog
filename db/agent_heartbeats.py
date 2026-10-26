# ============================================================================
# db/agent_heartbeats.py — agent_heartbeats 표: fw-agent·shipper 생존 신호, PC별 저장 (계약서 K9·K11)
#
# 담당: 역할 C. Track D 뼈대 PR(I0-1)이 빈 모듈로 만들고, C1-1~C2-1에서 함수를 채웠다.
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
    "release_cooldown",
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


def release_cooldown(key: str) -> None:
    """try_acquire_cooldown()으로 잡은 쿨다운을 풀어, 다음 호출이 바로 True를 받게 한다.

    쿨다운은 "보내기 전에" 잡아야 여러 스레드·PC가 같은 알림을 동시에 보내지 않는다. 그런데
    그 뒤 실제 전송이 일시 장애로 실패하면, 아무것도 가지 않았는데 쿨다운 시간 내내 막힌다.
    그래서 전송이 실패했을 때 호출부가 이 함수로 기록을 지운다.

    행을 key로만 지우므로, 아주 드물게 그 사이 다른 쪽이 새로 잡은 쿨다운까지 지울 수 있다.
    그 결과는 알림이 한 번 더 가는 것뿐이라, 알림이 아예 안 가는 쪽보다 낫다고 보고 받아들인다.
    """
    db.get_client().table("notification_cooldowns").delete().eq("key", key).execute()