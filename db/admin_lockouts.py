# ============================================================================
# db/admin_lockouts.py — admin_account_lockouts 표 + 관리자 계정 단위 실패 집계 (guide38)
#
# db/account_lockouts.py(회원 계정 잠금)의 관리자 버전이다. 회원 표를 같이 쓰지 않는 이유:
# account_lockouts는 username이 기본키라 회원 "alice"와 관리자 "alice"가 같은 줄을 쓰게
# 되고(관리자가 공격당하면 같은 이름의 회원까지 잠김), 회원 잠금에는 이메일 복구·보호관찰·
# 영구 승격 흐름이 얽혀 있어서 관리자에게는 맞지 않는다. 관리자 계정 잠금은 항상 임시
# 잠금뿐이라 표 구조도 처음 account_lockouts와 같은 단순한 형태다.
#
# 실패 횟수는 admin_login_log에서 IP와 무관하게 "이 아이디가 몇 번 실패했는가"를 센다
# (db.count_recent_failures_by_username()의 관리자 버전). 아이디가 실제로 있든 없든 똑같이
# 세고 똑같이 잠근다 — 그래야 "잠겼다"는 응답으로 관리자 아이디 존재 여부가 드러나지 않는다.
#
# db.get_client()를 통해 호출하는 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def _cutoff_iso(window_seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()


def count_recent_admin_failures_by_username(
    username: str, window_seconds: int = config.ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS
) -> int:
    """최근 `window_seconds`(기본 15분) 동안 이 관리자 아이디로 실패한 로그인 횟수(IP 무관)."""
    res = (
        db.get_client()
        .table("admin_login_log")
        .select("id", count="exact")
        .eq("username", username)
        .eq("success", False)
        .gte("attempted_at", _cutoff_iso(window_seconds))
        .execute()
    )
    return res.count or 0


def count_recent_distinct_admin_ips_by_username(
    username: str, window_seconds: int = config.ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS
) -> int:
    """같은 창 안에서 이 관리자 아이디의 실패가 서로 다른 IP 몇 개에서 왔는지(Slack 알림 표시용)."""
    res = (
        db.get_client()
        .table("admin_login_log")
        .select("ip_address")
        .eq("username", username)
        .eq("success", False)
        .gte("attempted_at", _cutoff_iso(window_seconds))
        .execute()
    )
    return len({row["ip_address"] for row in res.data})


def create_admin_account_lockout(
    username: str, failure_count: int, duration_seconds: int = config.LOCKOUT_DURATION_SECONDS
) -> None:
    """이 관리자 아이디를 지금부터 `duration_seconds`(기본 5분) 동안 잠근다(upsert)."""
    now = datetime.now(timezone.utc)
    db.get_client().table("admin_account_lockouts").upsert(
        {
            "username": username,
            "locked_at": now.isoformat(),
            "unlock_at": (now + timedelta(seconds=duration_seconds)).isoformat(),
            "failure_count": failure_count,
            "active": True,
        },
        on_conflict="username",
    ).execute()


def get_active_admin_account_lockout(username: str) -> dict | None:
    """이 관리자 아이디가 지금 잠겨 있으면(active이고 unlock_at이 미래) 그 행을, 아니면 None."""
    res = (
        db.get_client()
        .table("admin_account_lockouts")
        .select("*")
        .eq("username", username)
        .eq("active", True)
        .gt("unlock_at", db._now_iso())
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def release_admin_account_lockout(username: str) -> bool:
    """이 관리자 아이디의 잠금을 해제한다(줄은 남기고 active만 False). 실제로 풀렸을 때만 True."""
    res = (
        db.get_client()
        .table("admin_account_lockouts")
        .update({"active": False})
        .eq("username", username)
        .eq("active", True)
        .execute()
    )
    return bool(res.data)


def list_active_admin_account_lockouts() -> list[dict]:
    """지금 잠겨 있는(active=True) 관리자 아이디 목록(대시보드 표시용)."""
    res = (
        db.get_client()
        .table("admin_account_lockouts")
        .select("*")
        .eq("active", True)
        .order("locked_at", desc=True)
        .execute()
    )
    return res.data


def list_expired_active_admin_account_lockouts() -> list[dict]:
    """잠금 시간이 지났는데 아직 active로 남아 있는 관리자 계정 잠금(자동 해제 대상)."""
    res = (
        db.get_client()
        .table("admin_account_lockouts")
        .select("*")
        .eq("active", True)
        .lte("unlock_at", db._now_iso())
        .execute()
    )
    return res.data
