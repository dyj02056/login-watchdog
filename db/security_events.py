# ============================================================================
# db/security_events.py — not_found_attempts / unauthorized_attempts /
# page_access_attempts / security_events 표 관련 함수
#
# 앞의 세 표는 각각 Web Scanning(21단계), Unauthorized Access, 반복 페이지
# 접근을 탐지하기 위한 요청 로그다(attack_response_state.md 구현 대상 #1/#2/#4).
# security_events는 그 중 MEDIUM/HIGH/CRITICAL 이상행위를 위험등급과 함께
# 기록하는 공통 표다(security-risk-response-summary.md 5절 참고). LOW는 여기
# 저장하지 않고 위 개별 테이블 조회로만 추세를 본다.
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

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


def insert_security_event(
    event_type: str, severity: str, ip: str, path: str | None, count: int, action: str
) -> None:
    """이상행위 이벤트 한 건을 security_events 표에 기록한다."""
    db.get_client().table("security_events").insert(
        {
            "event_type": event_type,
            "severity": severity,
            "ip_address": ip,
            "path": path,
            "count": count,
            "action": action,
        }
    ).execute()


def list_security_events(page: int = 1, page_size: int = 20) -> tuple[list[dict], int]:
    """보안 이벤트를 최신순으로 `page`번째 페이지만 가져오고, 전체 건수도 함께 돌려준다.

    관리자 대시보드의 "보안 이벤트" 표에 쓰인다. list_recent_attempts()와 동일하게
    select(..., count="exact") + range()로 목록과 개수를 한 번의 왕복으로 가져온다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("security_events")
        .select("*", count="exact")
        .order("detected_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0


def resolve_security_event(event_id: int) -> bool:
    """관리자가 대시보드에서 "처리 완료"를 눌렀을 때, 이 이벤트를 해결됨으로 표시한다.

    아직 미해결(resolved_at이 비어있음)인 경우에만 실제로 값이 바뀌므로, 이미
    처리된 이벤트를 다시 눌러도 안전하다(res.data가 비어있으면 False를 돌려줌).

    CRITICAL 이벤트는 이 함수로 처리하지 않는다 — CRITICAL은 잠금이 풀릴 때
    resolve_security_events_for_ip()가 자동으로 처리하는 것이 유일한 경로여야
    한다. 화면(dashboard.js)에서는 CRITICAL 행에 "처리 완료" 버튼 자체를 안
    보여주지만, 그건 화면 쪽 제약일 뿐이라 API를 직접 호출하면 우회할 수
    있었다 — .neq("severity", "CRITICAL")로 서버 쪽에서도 막는다(그러면 IP가
    아직 잠긴 채로 CRITICAL 이벤트만 "처리 완료"로 표시되는 상태가 생기지 않는다).
    """
    res = (
        db.get_client()
        .table("security_events")
        .update({"resolved_at": db._now_iso()})
        .eq("id", event_id)
        .neq("severity", "CRITICAL")
        .is_("resolved_at", "null")
        .execute()
    )
    return bool(res.data)


def resolve_security_events_for_ip(ip: str) -> None:
    """이 IP의 미해결 CRITICAL 이벤트를 전부 해결됨으로 표시한다.

    CRITICAL(로그인 잠금)은 관리자가 따로 처리 완료를 누르지 않아도, 잠금이
    풀리는 순간(자동 만료든 수동 해제든) 그 사건도 함께 끝난 것으로 본다
    (soar.try_release_expired_lockouts/manual_release가 release_lockout 직후 호출).
    """
    db.get_client().table("security_events").update({"resolved_at": db._now_iso()}).eq(
        "ip_address", ip
    ).eq("severity", "CRITICAL").is_("resolved_at", "null").execute()


def get_unresolved_security_event(ip: str, event_type: str) -> dict | None:
    """이 IP·이벤트 유형에 대해 아직 처리되지 않은 이벤트가 있으면 그 행을 돌려준다.

    HIGH(요청 거부) 탐지 함수들은 차단되는 동안 시도 자체를 로그에 남기지 않아
    count가 차단 기간 내내 고정된다 — MEDIUM처럼 "정확히 임계값+1일 때만"이라는
    신호가 없다. 그래서 매 거부마다 새 행을 만드는 대신, is_locked()와 같은
    방식으로 "이미 열린 사건이 있으면 그 사건의 count만 올린다"는 상태 기반
    중복 방지를 쓴다(soar.record_rejection 참고). id·count를 함께 돌려주는
    이유는 호출한 쪽이 바로 update_security_event_count()를 부를 수 있게 하기
    위해서다 — 있는지 확인하는 쿼리와 실제 값을 가져오는 쿼리를 따로 두 번
    보내지 않는다.
    """
    res = (
        db.get_client()
        .table("security_events")
        .select("id, count")
        .eq("ip_address", ip)
        .eq("event_type", event_type)
        .is_("resolved_at", "null")
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def update_security_event_count(event_id: int, count: int) -> None:
    """미해결 이벤트가 다시 한번 거부를 유발했을 때, 그 행의 count 칸을 갱신한다.

    같은 사건이 열려있는 동안 반복될 때마다 이 함수로 count를 1씩 올려서,
    "제한값을 살짝 넘긴 것"과 "봇이 수천 번 두드린 것"을 관리자 대시보드에서
    구분할 수 있게 한다(record_rejection이 새 값을 계산해 넘겨준다).
    """
    db.get_client().table("security_events").update({"count": count}).eq("id", event_id).execute()


def insert_security_event_or_bump(
    event_type: str, severity: str, ip: str, path: str | None, count: int, action: str
) -> None:
    """HIGH 이벤트를 새로 기록하되, 아주 드물게 동시 요청 두 개가 거의 같은
    순간에 "미해결 이벤트 없음"을 확인하고 둘 다 새로 삽입을 시도하는 경쟁
    조건이 발생하면 — docs/schema.sql의 idx_security_events_high_open_incident
    (같은 IP·유형·HIGH·미해결은 최대 1건) 부분 유니크 인덱스가 두 번째 삽입을
    막아준다. 그 충돌(Postgres 오류 코드 23505 unique_violation)을 여기서
    붙잡아서, 새로 만드는 대신 먼저 삽입된 행의 count를 올리는 것으로 대체한다
    — soar.record_rejection()이 미리 하는 확인(get_unresolved_security_event)이
    "보통 경우"를 처리하고, 이 함수는 그 확인과 삽입 사이의 아주 짧은 틈에
    실제로 겹친 "드문 경우"만 뒤에서 조용히 정리하는 안전망이다.
    """
    try:
        insert_security_event(event_type, severity, ip, path, count, action)
    except APIError as e:
        if e.code != "23505":
            raise
        existing = get_unresolved_security_event(ip, event_type)
        if existing:
            update_security_event_count(existing["id"], existing["count"] + 1)
