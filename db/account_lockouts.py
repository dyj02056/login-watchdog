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


def get_account_lockout_row(username: str) -> dict | None:
    """active 여부·잠금 종류와 무관하게 이 계정의 account_lockouts 행을 그대로 돌려준다
    (db.get_lockout_row()의 계정 버전 — 영구 잠금 보호와 보호관찰 확인에 쓰인다)."""
    res = (
        db.get_client()
        .table("account_lockouts")
        .select("*")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def create_account_lockout(
    username: str, failure_count: int, duration_seconds: int = config.LOCKOUT_DURATION_SECONDS
) -> None:
    """이 계정을 지금부터 `duration_seconds`(기본 300초=5분) 동안 잠근다.

    db.create_lockout()과 동일하게 upsert를 써서, 같은 계정이 두 번 잠기는
    것을 걱정하지 않고 그냥 호출하면 되도록 설계했다. 영구 잠금 보호 방식도 동일하다
    (active인 PERMANENT 행은 그대로 두고, 풀린 영구 행은 TEMPORARY 값으로 덮어쓴다).
    probation_until은 payload에 일부러 넣지 않는다 — 이메일 복구 직후 24시간 동안
    다시 잠겼는지 판단하는 값이라 임시 잠금 upsert가 지우면 안 된다.
    """
    existing = get_account_lockout_row(username)
    if existing and existing.get("active") and existing.get("lock_type") == "PERMANENT":
        return

    now = datetime.now(timezone.utc)
    unlock_at = now + timedelta(seconds=duration_seconds)
    db.get_client().table("account_lockouts").upsert(
        {
            "username": username,
            "locked_at": now.isoformat(),
            "unlock_at": unlock_at.isoformat(),
            "failure_count": failure_count,
            "active": True,
            "lock_type": "TEMPORARY",
            "recoverable": "SELF",
            "permanent_reason": None,
            "promoted_at": None,
        },
        on_conflict="username",
    ).execute()


def promote_account_lockout_permanent(
    username: str, reason: str, recoverable: str, failure_count: int = 0
) -> bool:
    """이 계정의 잠금을 영구 잠금으로 올린다. 실제로 바뀌었을 때만 True
    (db.promote_lockout_permanent()의 계정 버전)."""
    now_iso = db._now_iso()
    res = (
        db.get_client()
        .table("account_lockouts")
        .update(
            {
                "lock_type": "PERMANENT",
                "unlock_at": None,
                "recoverable": recoverable,
                "permanent_reason": reason,
                "promoted_at": now_iso,
            }
        )
        .eq("username", username)
        .eq("lock_type", "TEMPORARY")
        .eq("active", True)
        .execute()
    )
    if res.data:
        return True

    existing = get_account_lockout_row(username)
    if existing and existing.get("active") and existing.get("lock_type") == "PERMANENT":
        return False

    db.get_client().table("account_lockouts").upsert(
        {
            "username": username,
            "locked_at": now_iso,
            "unlock_at": None,
            "failure_count": (existing or {}).get("failure_count", failure_count),
            "active": True,
            "lock_type": "PERMANENT",
            "recoverable": recoverable,
            "permanent_reason": reason,
            "promoted_at": now_iso,
        },
        on_conflict="username",
    ).execute()
    return True


def release_permanent_account_lockout(username: str, only_recoverable: str | None = None) -> bool:
    """active인 영구 계정 잠금을 해제한다. 실제로 풀렸을 때만 True.

    only_recoverable을 주면 그 복구 방식(예: 'SELF')인 행만 푼다 — 이메일 복구
    (lockdown.apply_recovery)가 "관리자만 풀 수 있게 올려둔(ADMIN_ONLY) 잠금"을
    실수로 풀지 않도록, 조건을 UPDATE 문 안에 넣어 확인과 해제를 한 번에 한다.
    """
    query = (
        db.get_client()
        .table("account_lockouts")
        .update({"active": False})
        .eq("username", username)
        .eq("lock_type", "PERMANENT")
        .eq("active", True)
    )
    if only_recoverable is not None:
        query = query.eq("recoverable", only_recoverable)
    return bool(query.execute().data)


def set_account_lockout_recoverable(username: str, recoverable: str) -> None:
    """active인 계정 잠금의 복구 방식을 바꾼다(예: 이메일을 신뢰할 수 없다고 판단되면 ADMIN_ONLY)."""
    db.get_client().table("account_lockouts").update({"recoverable": recoverable}).eq(
        "username", username
    ).eq("active", True).execute()


def set_account_probation(username: str, until_iso: str) -> None:
    """이메일 복구로 풀린 계정에 보호관찰 종료 시각을 기록한다(그 전에 다시 잠기면 관리자 전용)."""
    db.get_client().table("account_lockouts").update({"probation_until": until_iso}).eq(
        "username", username
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
        .or_(f"lock_type.eq.PERMANENT,unlock_at.gt.{db._now_iso()}")
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
        .eq("lock_type", "TEMPORARY")  # 영구 잠금은 자동 만료 대상이 아니다(guide33)
        .lte("unlock_at", db._now_iso())
        .execute()
    )
    return res.data
