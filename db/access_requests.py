# ============================================================================
# db/access_requests.py — access_requests 표 관련 함수 (Track A, guide31)
#
# security_incidents가 "여러 이벤트를 하나의 사건으로 묶는" 표라면, 이 표는
# "규칙이 아직 발동하지 않은 임계값 코앞 구간에서 LLM이 위험하다고 판단한
# 건들을 관리자 승인 대기 목록으로 쌓아두는" 표다. soar.consider_early_warning()이
# 판단(위험한가?) 결과를 여기 등록하고, 실제 승인/반려 실행은 soar.py의
# execute_approved_request()/reject_pending_request()가 이 파일의 함수를
# 통해서만 상태를 바꾼다 (detector.py/soar.py와 동일한 판단·실행 분리 원칙).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

import db


def count_recent_requests_for_target(
    event_type: str, target_kind: str, target_value: str, hours: int = 24
) -> int:
    """이 대상이 최근 `hours`시간(기본 24시간) 동안 이미 몇 번이나 조기 경보
    대상(PENDING/APPROVED/REJECTED 상태 전부 포함)이 됐는지 센다.

    judge_early_warning()에게 "지금 이 순간의 숫자 하나"만 보여주면 "일부러
    기준치를 피해 가려는 반복 패턴인지"를 판단할 근거가 없다는 문제
    (login_watchdog_expansion_plan.md 논의)를 메우려고 추가했다.

    다만 이 표는 LLM이 risky=True로 판단했을 때만 행이 생긴다
    (soar.consider_early_warning 참고) — risky=False로 넘어간 근처 구간
    진입은 어디에도 기록되지 않으므로, 이 값은 "완전한 이력"이 아니라
    "과거에 이미 위험하다고 판단된 적이 있는 횟수"까지만 알려주는 부분적인
    신호라는 한계가 있다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("access_requests")
        .select("request_id", count="exact")
        .eq("event_type", event_type)
        .eq("target_kind", target_kind)
        .eq("target_value", target_value)
        .gte("requested_at", cutoff)
        .execute()
    )
    return res.count or 0


def get_pending_request(event_type: str, target_kind: str, target_value: str) -> dict | None:
    """이 유형·대상에 이미 PENDING 상태인 요청이 있으면 그 행을 돌려준다.

    soar.consider_early_warning()이 매 요청마다 LLM을 새로 부르지 않도록
    막아주는 중복 방지 확인이다 — db.get_unresolved_security_event()와 같은
    목적의 함수다. 이미 하나가 대기 중이면, 관리자가 그걸 처리하기 전까지는
    같은 건에 대해 Groq를 또 호출하거나 Slack을 또 보낼 필요가 없다.
    """
    res = (
        db.get_client()
        .table("access_requests")
        .select("request_id")
        .eq("event_type", event_type)
        .eq("target_kind", target_kind)
        .eq("target_value", target_value)
        .eq("status", "PENDING")
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def insert_pending_request(
    event_type: str,
    pending_action: str,
    target_kind: str,
    target_value: str,
    count: int,
    threshold: int,
    llm_reason: str,
    path: str | None = None,
    context_count: int | None = None,
    context_ip: str | None = None,
) -> None:
    """LLM이 "지켜볼 필요가 있다"고 판단한 건을 PENDING 요청으로 새로 등록한다.

    idx_access_requests_open_target 부분 유니크 인덱스(docs/schema.sql)가
    "같은 유형·대상에는 PENDING이 동시에 2개 있을 수 없음"을 DB가 직접
    강제한다 — get_pending_request()로 미리 확인한 순간과 이 삽입 순간 사이의
    아주 짧은 틈에 동시 요청이 겹치는 경쟁 조건을, db.record_incident()와
    동일한 방식(23505 충돌을 붙잡아 조용히 무시)으로 막는다. 이미 같은 건이
    있다는 뜻이므로 새로 만들지 않고 그냥 넘어가도 안전하다.
    """
    try:
        db.get_client().table("access_requests").insert(
            {
                "event_type": event_type,
                "pending_action": pending_action,
                "target_kind": target_kind,
                "target_value": target_value,
                "path": path,
                "count": count,
                "threshold": threshold,
                "context_count": context_count,
                "context_ip": context_ip,
                "llm_reason": llm_reason,
                "status": "PENDING",
            }
        ).execute()
    except APIError as e:
        if e.code != "23505":
            raise


def list_pending_requests(page: int = 1, page_size: int = 20) -> tuple[list[dict], int]:
    """대시보드 "AI 조기 경보" 표에 보여줄 PENDING 요청을 최신순으로 가져온다.

    db.list_security_events() 등과 동일한 페이지네이션 방식이다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("access_requests")
        .select("*", count="exact")
        .eq("status", "PENDING")
        .order("requested_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0


def get_request(request_id: int) -> dict | None:
    """승인/반려를 실행하기 전에, 이 요청이 실제로 존재하고 지금 무슨 상태인지 확인한다."""
    res = (
        db.get_client()
        .table("access_requests")
        .select("*")
        .eq("request_id", request_id)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def decide_request(request_id: int, decision: str, admin_id: int) -> bool:
    """이 요청을 APPROVED/REJECTED로 확정하고, 누가 언제 결정했는지 기록한다.

    resolve_security_event()와 동일한 이유로 .eq("status", "PENDING") 조건을
    함께 걸어둔다 — 이미 처리된 요청이거나(관리자 두 명이 거의 동시에 같은
    버튼을 눌렀거나, 화면이 새로고침되지 않아 이미 없어진 요청을 다시 누른
    경우) 존재하지 않는 request_id면 res.data가 비어있으므로 False를 돌려주고,
    호출한 쪽(soar.py)이 실제 조치를 실행하지 않도록 막는다.
    """
    res = (
        db.get_client()
        .table("access_requests")
        .update({"status": decision, "decided_by_admin_id": admin_id, "decided_at": db._now_iso()})
        .eq("request_id", request_id)
        .eq("status", "PENDING")
        .execute()
    )
    return bool(res.data)
