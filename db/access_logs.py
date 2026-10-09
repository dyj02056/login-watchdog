# ============================================================================
# db/access_logs.py — not_found_attempts / unauthorized_attempts /
# page_access_attempts 표 관련 함수 (요청 로그)
#
# 세 표는 각각 Web Scanning(21단계), Unauthorized Access, 반복 페이지 접근을
# 탐지하기 위한 요청 로그다(attack_response_state.md 구현 대상 #1/#2/#4).
# 그 중 임계값을 넘은 이상행위만 security_events(db/security_events.py)에
# 위험등급과 함께 따로 기록된다. 원래 db/security_events.py에 같이 있었는데
# 2026-10-09에 나눴다(docs/refactor/2026-10-09-module-plan.md).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def log_not_found_attempt(ip: str, path: str) -> None:
    """404가 발생한 요청 한 건을 not_found_attempts 표에 기록한다."""
    db.get_client().table("not_found_attempts").insert({"ip_address": ip, "path": path}).execute()


def count_recent_not_found_attempts(
    ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 번이나 404를 유발했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("not_found_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


def log_unauthorized_attempt(ip: str, path: str) -> None:
    """세션 없이 관리자 API에 접근한 요청 한 건을 unauthorized_attempts 표에 기록한다."""
    db.get_client().table("unauthorized_attempts").insert({"ip_address": ip, "path": path}).execute()


def count_recent_unauthorized_attempts(
    ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 번이나 세션 없이 관리자 API를 두드렸는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("unauthorized_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


def log_page_access_attempt(ip: str, path: str) -> None:
    """GET 페이지 요청 한 건을 page_access_attempts 표에 기록한다."""
    db.get_client().table("page_access_attempts").insert({"ip_address": ip, "path": path}).execute()


def count_recent_page_access_attempts(
    ip: str, path: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 이 경로를 몇 번이나 요청했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("page_access_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .eq("path", path)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0
