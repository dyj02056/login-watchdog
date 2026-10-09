# ============================================================================
# db/lock_history.py — lock_history 표 관련 함수 (guide33, 영구 잠금)
#
# lockouts/account_lockouts는 같은 IP·계정이 다시 잠기면 같은 행에 덮어쓰는(upsert)
# "현재 상태판"이라서 "최근 30일 안에 몇 번 잠겼는가"를 셀 수 없다. 이 표는 잠금이
# 걸릴 때마다 한 줄씩 추가만 하는(append-only) 이력이라 그 횟수를 센다.
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import db


def insert_lock_history(
    target_kind: str,
    target_value: str,
    lock_type: str,
    trigger_reason: str,
    source_event_type: str | None = None,
    incident_id: int | None = None,
    trigger_note: str | None = None,
) -> None:
    """잠금이 걸린 사실을 이력에 한 줄 추가한다.

    target_kind는 'ip' / 'account' / 'admin_account'(관리자 계정, guide38), lock_type은 'TEMPORARY'/'PERMANENT',
    trigger_reason은 THRESHOLD / REPEAT_OFFENDER / SIEM_CRITICAL / SIEM_HIGH /
    NETWORK_IDS / ADMIN_MANUAL 중 하나다(docs/schema.sql의 CHECK 제약과 같다).
    """
    db.get_client().table("lock_history").insert(
        {
            "target_kind": target_kind,
            "target_value": target_value,
            "lock_type": lock_type,
            "trigger_reason": trigger_reason,
            "source_event_type": source_event_type,
            "incident_id": incident_id,
            "trigger_note": trigger_note,
        }
    ).execute()


def count_lock_history(
    target_kind: str,
    target_value: str,
    days: int,
    source_event_types: list[str] | None = None,
) -> int:
    """이 대상이 최근 `days`일 안에 "임시 잠금"으로 몇 번 잠겼는지 센다.

    TEMPORARY 이력만 센다 — 영구 승격 기록(PERMANENT)까지 세면 한 번의 승격이
    "잠금 1회 추가"로 이중 계산된다. source_event_types를 주면 그 유형(예:
    ADMIN_BRUTE_FORCE)으로 잠긴 횟수만 센다(T5는 관리자 로그인 잠금끼리만 센다).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    query = (
        db.get_client()
        .table("lock_history")
        .select("id", count="exact")
        .eq("target_kind", target_kind)
        .eq("target_value", target_value)
        .eq("lock_type", "TEMPORARY")
        .gte("locked_at", cutoff)
    )
    if source_event_types:
        query = query.in_("source_event_type", source_event_types)
    return query.execute().count or 0


def mark_lock_released(
    target_kind: str,
    target_value: str,
    released_by: str,
    release_note: str | None = None,
    lock_type: str = "PERMANENT",
) -> None:
    """이 대상의 아직 해제 기록이 없는 `lock_type` 이력에 해제 시각·해제자를 기록한다.

    released_by는 'EMAIL_RECOVERY' / 'admin:<이름>' / 'script:<이름>' 형식이다. 줄을 지우지
    않고 "누가 언제 풀었는가"만 덧붙여서 감사 추적에 쓴다. 기본적으로 영구 잠금 이력만
    대상으로 한다 — 같은 대상의 지난 5분 임시 잠금 이력까지 같이 찍으면 "관리자가 임시
    잠금을 풀었다"는 잘못된 기록이 된다(실제 E2E 테스트에서 발견).
    """
    db.get_client().table("lock_history").update(
        {"released_at": db._now_iso(), "released_by": released_by, "release_note": release_note}
    ).eq("target_kind", target_kind).eq("target_value", target_value).eq(
        "lock_type", lock_type
    ).is_("released_at", "null").execute()
