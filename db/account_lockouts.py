# ============================================================================
# db/account_lockouts.py — account_lockouts 표 관련 함수
# — "지금 어떤 계정(아이디)이 잠겨있고, 언제 풀리는지"라는 "현재 상태"를 관리한다.
#
# db/lockouts.py(IP 단위 잠금)와 짝을 이루는 계정 단위 잠금이다 — 공격자가 여러
# IP로 나눠서(또는 느린 속도로) 같은 계정만 노리면 IP당 실패 횟수는 임계값을
# 넘지 않아 lockouts로는 못 잡는다. 이 표는 IP와 무관하게 "이 계정이 총 몇 번
# 실패했는가"를 기준으로 잠근다 (L7 공격 보강 계획 Tier 1).
#
# db.get_client()를 통해 호출하는 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def create_account_lockout(
    username: str, failure_count: int, duration_seconds: int = config.LOCKOUT_DURATION_SECONDS
) -> None:
    """이 계정을 지금부터 `duration_seconds`(기본 300초=5분) 동안 잠근다.

    db.create_lockout()과 동일하게 upsert를 써서, 같은 계정이 두 번 잠기는
    것을 걱정하지 않고 그냥 호출하면 되도록 설계했다.
    """
    now = datetime.now(timezone.utc)
    unlock_at = now + timedelta(seconds=duration_seconds)
    db.get_client().table("account_lockouts").upsert(
        {
            "username": username,
            "locked_at": now.isoformat(),
            "unlock_at": unlock_at.isoformat(),
            "failure_count": failure_count,
            "active": True,
        },
        on_conflict="username",
    ).execute()


def get_active_account_lockout(username: str) -> dict | None:
    """이 계정이 "지금 이 순간" 실제로 잠겨있는지 확인하고, 잠겨있다면 그 잠금 정보를 돌려준다.

    db.get_active_lockout()과 동일한 두 조건(active=True, unlock_at이 미래)을 본다.
    """
    res = (
        db.get_client()
        .table("account_lockouts")
        .select("*")
        .eq("username", username)
        .eq("active", True)
        .gt("unlock_at", db._now_iso())
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def release_account_lockout(username: str) -> None:
    """이 계정의 잠금을 해제한다 (active 칸을 False로 바꿈).

    db.release_lockout()과 마찬가지로 줄을 지우지 않고 "해제됨" 표시만 남긴다.
    """
    db.get_client().table("account_lockouts").update({"active": False}).eq(
        "username", username
    ).execute()


def list_active_account_lockouts() -> list[dict]:
    """지금 잠겨있는(active=True) 계정 목록 전체를 가져온다."""
    res = (
        db.get_client()
        .table("account_lockouts")
        .select("*")
        .eq("active", True)
        .order("locked_at", desc=True)
        .execute()
    )
    return res.data


def list_expired_active_account_lockouts() -> list[dict]:
    """"5분이 지났는데도 아직 active=True로 남아있는" 계정 잠금 목록을 찾는다.

    db.list_expired_active_lockouts()와 마찬가지로 아무것도 풀지 않고 "풀어야
    할 목록"만 알려준다 — 실제로 푸는 실행은 soar.py의
    try_release_expired_account_lockouts()가 담당한다.
    """
    res = (
        db.get_client()
        .table("account_lockouts")
        .select("*")
        .eq("active", True)
        .lte("unlock_at", db._now_iso())
        .execute()
    )
    return res.data
