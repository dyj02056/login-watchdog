# ============================================================================
# db/api_access_log.py — api_access_log 표 관련 함수 (Track C guide29, 매크로/봇 탐지)
#
# not_found_attempts/unauthorized_attempts/page_access_attempts(db/security_events.py)와
# 같은 목적의 요청 로그다. 다만 이 표는 "/api/*" 요청 전체(POST 포함)를 메서드와
# 함께 기록해서, 같은 IP가 짧은 시간에 서로 다른 API 여러 개를 옮겨 다니는
# 패턴(매크로/봇 의심)을 잡는다.
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def log_api_access(ip: str, path: str, method: str) -> None:
    """API 요청 한 건을 api_access_log 표에 기록한다."""
    db.get_client().table("api_access_log").insert(
        {"ip_address": ip, "path": path, "method": method}
    ).execute()


def count_recent_distinct_api_paths(
    ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 서로 다른 API 경로를 몇 개나 호출했는지 센다.

    count_recent_distinct_usernames()(같은 IP가 시도한 서로 다른 아이디 개수)와
    동일한 발상을 "아이디" 대신 "API 경로"에 적용한 것이다 — 사람이 짧은 시간에
    손으로 여러 화면을 옮겨 다니며 API를 부르는 것과, 스크립트가 여러 API를
    기계적으로 훑는 것을 구분한다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("api_access_log")
        .select("path")
        .eq("ip_address", ip)
        .gte("requested_at", cutoff)
        .execute()
    )
    return len({row["path"] for row in res.data})
