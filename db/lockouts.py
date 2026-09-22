# ============================================================================
# db/lockouts.py — lockouts 표 관련 함수
# — "지금 어떤 IP가 잠겨있고, 언제 풀리는지"라는 "현재 상태"를 관리하는 기능
# (login_attempts가 "지나간 일의 기록"이라면, lockouts는 "지금 이 순간의 상태판")
#
# db.get_client()/db._now_iso()를 통해 호출하는 이유는 db/attempts.py 상단
# 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def create_lockout(
    ip: str, failure_count: int, duration_seconds: int = config.LOCKOUT_DURATION_SECONDS
) -> None:
    """이 IP를 지금부터 `duration_seconds`(기본 300초=5분) 동안 잠근다.

    upsert(업서트)란 "이미 그 IP의 잠금 기록이 있으면 덮어쓰고,
    없으면 새로 만든다"는 뜻의 합성어(update + insert)다.
    같은 IP가 두 번 잠기는 것을 걱정하지 않고 그냥 호출하면 되도록 설계했다.
    """
    now = datetime.now(timezone.utc)
    unlock_at = now + timedelta(seconds=duration_seconds)  # "풀려날 시각" = 지금 + 5분
    db.get_client().table("lockouts").upsert(
        {
            "ip_address": ip,
            "locked_at": now.isoformat(),
            "unlock_at": unlock_at.isoformat(),
            "failure_count": failure_count,  # 몇 번 실패해서 잠겼는지 같이 기록
            "active": True,                  # "지금 잠긴 상태다"라는 표시
        },
        on_conflict="ip_address",  # ip_address가 이미 표에 있으면 새로 만들지 않고 덮어씀
    ).execute()


def list_lockouts_since(hours: int = 24) -> list[dict]:
    """지난 `hours`시간 동안 새로 걸린 잠금 전체를 가져온다 (현재 풀렸는지와 무관하게).

    list_active_lockouts()는 "지금 이 순간 잠긴 것만" 보여주지만, 일일 리포트는
    "오늘 하루 동안 몇 번이나 잠금이 발생했는지"가 궁금한 것이므로 active 여부로
    거르지 않고 locked_at 기준으로만 걸러온다.

    (원래 db.py에서는 login_attempts 섹션 바로 옆에 있었지만, 조회 대상 표가
    lockouts이므로 분리 시 이 모듈로 옮겼다.)
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("lockouts")
        .select("*")
        .gte("locked_at", cutoff)
        .execute()
    )
    return res.data


def list_lockouts_between(start_time: str, end_time: str) -> list[dict]:
    """지정한 시작 시각(start_time)부터 종료 시각(end_time) 사이에 새로 걸린 잠금 전체를 가져온다.

    list_lockouts_since()가 "최근 N시간"만 지원하는 것과 달리, 특정 정적 기간
    (예: 2026-09-01T00:00:00 ~ 2026-09-01T12:00:00)을 지정해 정밀 조회할 때 쓴다.
    daily_report.py의 --start/--end 옵션이 이 함수를 사용해, 지정한 기간의
    로그인 시도(list_attempts_between)와 잠금 건수를 같은 기준으로 맞춰 보여준다.
    """
    res = (
        db.get_client()
        .table("lockouts")
        .select("*")
        .gte("locked_at", start_time)  # start_time 이상
        .lte("locked_at", end_time)    # end_time 이하
        .execute()
    )
    return res.data


def get_active_lockout(ip: str) -> dict | None:
    """이 IP가 "지금 이 순간" 실제로 잠겨있는지 확인하고, 잠겨있다면 그 잠금 정보를 돌려준다.

    조건이 두 가지 다 맞아야 "진짜로 잠긴 상태"로 인정한다:
    - active가 True (아직 해제되지 않았고)
    - unlock_at(풀리는 시각)이 지금보다 미래 (아직 시간이 안 지났고)

    두 조건을 만족하는 기록이 없으면 None(없음)을 돌려준다.
    """
    res = (
        db.get_client()
        .table("lockouts")
        .select("*")
        .eq("ip_address", ip)
        .eq("active", True)
        .gt("unlock_at", db._now_iso())  # gt = greater than = "~보다 미래"
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None  # 결과가 있으면 첫 번째 줄, 없으면 None


def release_lockout(ip: str) -> None:
    """이 IP의 잠금을 해제한다 (active 칸을 False로 바꿈).

    줄을 지우는 게 아니라 "해제됨" 표시만 남겨서, 나중에 "언제 잠겼다가 언제 풀렸는지"
    이력을 되짚어볼 수 있게 한다. 관리자가 수동으로 풀 때나, 5분이 지나 자동으로
    풀릴 때나 똑같이 이 함수 하나를 쓴다.
    """
    db.get_client().table("lockouts").update({"active": False}).eq("ip_address", ip).execute()


def list_active_lockouts() -> list[dict]:
    """지금 잠겨있는(active=True) IP 목록 전체를 가져온다.

    관리자 대시보드에서 "현재 잠긴 IP 카드" 목록을 보여줄 때 쓰인다.
    """
    res = (
        db.get_client()
        .table("lockouts")
        .select("*")
        .eq("active", True)
        .order("locked_at", desc=True)  # 가장 최근에 잠긴 것부터 보여줌
        .execute()
    )
    return res.data


def list_expired_active_lockouts() -> list[dict]:
    """"5분이 지났는데도 아직 active=True로 남아있는" 잠금 목록을 찾는다.

    이 목록이 바로 "지금 당장 자동으로 풀어줘야 할 IP들"이다.
    이 함수 자체는 아무것도 풀지 않고, "풀어야 할 목록"만 알려준다
    (실제로 푸는 실행은 soar.py의 try_release_expired_lockouts()가 담당).
    """
    res = (
        db.get_client()
        .table("lockouts")
        .select("*")
        .eq("active", True)
        .lte("unlock_at", db._now_iso())  # lte = less than or equal = "~보다 과거이거나 같음"
        .execute()
    )
    return res.data
