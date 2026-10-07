# ============================================================================
# db/recovery.py — recovery_requests / ip_lock_exemptions 표 + users.email_status
# 관련 함수 (guide34-a, 이메일 인증 복구)
#
# recovery_requests는 "이메일로 보낸 1회용 복구 링크/코드" 한 건 한 건이다. 토큰과
# 코드는 원문이 아니라 SHA-256 해시만 저장한다(DB가 유출돼도 진짜 토큰은 못 얻도록).
# ip_lock_exemptions는 IP 영구 잠금에서 "본인 + 본인 기기"만 통과시키는 출입증이다.
#
# Supabase REST에서는 파이썬이 BEGIN/COMMIT을 쓸 수 없으므로, 동시에 같은 토큰이
# 두 번 들어와도 한 번만 처리되게 "조건부 UPDATE(WHERE status='PENDING')"를 쓴다 —
# db.decide_request()와 같은 방식이다.
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

import db


def _flatten_username(row: dict) -> dict:
    """PostgREST가 FK로 붙여준 {"users": {"username": ...}}를 대시보드가 쓰기 쉽게
    row["username"] 한 칸으로 펼친다(사용자가 삭제돼 연결이 없으면 None)."""
    user = row.pop("users", None) or {}
    row["username"] = user.get("username")
    return row


# ---------------------------------------------------------------------------
# recovery_requests
# ---------------------------------------------------------------------------

def create_recovery_request(
    user_id: int,
    target_kind: str,
    target_value: str,
    token_hash: str,
    code_hash: str,
    device_hash: str | None,
    requested_ip: str,
    expires_at_iso: str,
) -> dict | None:
    """복구 요청 한 건을 새로 만든다. 같은 (사용자, 대상)의 기존 PENDING 요청은 먼저
    REVOKED로 바꾼다 — idx_recovery_requests_one_pending(부분 유니크 인덱스)가 "같은
    대상에 PENDING은 1건"을 DB 차원에서 강제하기 때문이다. 두 요청이 거의 동시에 들어와
    인덱스가 두 번째 삽입을 막으면(23505) None을 돌려준다."""
    db.get_client().table("recovery_requests").update({"status": "REVOKED"}).eq(
        "user_id", user_id
    ).eq("target_kind", target_kind).eq("target_value", target_value).eq("status", "PENDING").execute()
    try:
        res = (
            db.get_client()
            .table("recovery_requests")
            .insert(
                {
                    "user_id": user_id,
                    "target_kind": target_kind,
                    "target_value": target_value,
                    "token_hash": token_hash,
                    "code_hash": code_hash,
                    "device_hash": device_hash,
                    "requested_ip": requested_ip,
                    "expires_at": expires_at_iso,
                }
            )
            .execute()
        )
    except APIError as e:
        if e.code != "23505":
            raise
        return None
    return res.data[0] if res.data else None


def get_pending_recovery_by_token_hash(token_hash: str) -> dict | None:
    """토큰 해시로 "아직 유효한(PENDING + 만료 전)" 복구 요청을 찾는다. 소비하지 않는다
    (메일 보안 스캐너가 링크를 미리 GET으로 열어도 토큰이 닳지 않게 하려는 조회 전용)."""
    res = (
        db.get_client()
        .table("recovery_requests")
        .select("*")
        .eq("token_hash", token_hash)
        .eq("status", "PENDING")
        .gt("expires_at", db._now_iso())
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def get_latest_pending_recovery_for_user(user_id: int) -> dict | None:
    """이 사용자의 가장 최근 유효 복구 요청 하나(6자리 코드 입력 경로에서 쓴다)."""
    res = (
        db.get_client()
        .table("recovery_requests")
        .select("*")
        .eq("user_id", user_id)
        .eq("status", "PENDING")
        .gt("expires_at", db._now_iso())
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def consume_recovery_request(request_id: int) -> dict | None:
    """복구 요청을 VERIFIED로 바꿔 "소비"한다 — 원자적 1회용 소비.

    같은 요청이 거의 동시에 두 번 들어와도 DB가 한 행을 한 번에 하나씩만 고치므로,
    먼저 온 쪽만 PENDING→VERIFIED로 바꾸고 늦게 온 쪽은 조건(status='PENDING')에 맞는
    행이 없어 None(0행)을 받는다. 만료된 요청도 expires_at 조건으로 걸러진다.
    """
    res = (
        db.get_client()
        .table("recovery_requests")
        .update({"status": "VERIFIED", "verified_at": db._now_iso()})
        .eq("id", request_id)
        .eq("status", "PENDING")
        .gt("expires_at", db._now_iso())
        .execute()
    )
    return res.data[0] if res.data else None


_RESERVE_RETRIES = 3


def reserve_recovery_code_attempt(request_id: int, current_attempts: int, max_attempts: int) -> int | None:
    """6자리 코드를 비교하기 "전에" 시도권 1회를 원자적으로 예약하고, 예약된 시도 번호(1부터)를
    돌려준다. 한도에 도달했거나, 요청이 더 이상 PENDING이 아니거나, 경쟁이 계속돼 예약하지
    못하면 None — 호출부는 None이면 코드를 비교하지 않는다(실패 쪽으로 닫힌다).

    왜 비교 전에 예약하나: 코드는 경우의 수가 100만 개뿐이라 횟수 제한이 유일한 방어선이다.
    "비교 → 틀리면 +1" 순서면 동시에 보낸 요청 1000개가 횟수가 오르기 전에 전부 비교를
    마쳐버린다. 먼저 시도권을 받아야만 비교할 수 있게 하면, 동시에 몇 개를 보내든 한도
    이상은 비교되지 않는다.

    예약은 "읽은 횟수 그대로일 때만" 올리는 조건부 UPDATE다(db.update_user_password와 같은
    방식). 경쟁에서 지면(0행) 다시 읽고 재시도한다. 한도에 닿아도 여기서 REVOKED로 바꾸지
    않는다 — 마지막 시도권으로 맞는 코드를 넣은 사용자는 성공해야 하기 때문이다. 마지막
    시도마저 틀렸을 때의 취소는 호출부가 revoke_recovery_request()로 한다.
    """
    current = current_attempts
    for _ in range(_RESERVE_RETRIES):
        if current >= max_attempts:
            return None
        res = (
            db.get_client()
            .table("recovery_requests")
            .update({"code_attempts": current + 1})
            .eq("id", request_id)
            .eq("status", "PENDING")
            .eq("code_attempts", current)
            .gt("expires_at", db._now_iso())
            .execute()
        )
        if res.data:
            return current + 1

        latest = (
            db.get_client()
            .table("recovery_requests")
            .select("code_attempts, status")
            .eq("id", request_id)
            .limit(1)
            .execute()
        )
        if not latest.data or latest.data[0]["status"] != "PENDING":
            return None
        current = latest.data[0]["code_attempts"]
    return None


def revoke_recovery_request(request_id: int) -> bool:
    """진행 중(PENDING)인 복구 요청을 취소한다(관리자 또는 메일 발송 실패 시). 실제로 취소됐을 때만 True."""
    res = (
        db.get_client()
        .table("recovery_requests")
        .update({"status": "REVOKED"})
        .eq("id", request_id)
        .eq("status", "PENDING")
        .execute()
    )
    return bool(res.data)


def expire_old_recovery_requests() -> None:
    """만료 시각이 지났는데 아직 PENDING인 요청을 EXPIRED로 정리한다(요청 시점에 함께 실행)."""
    db.get_client().table("recovery_requests").update({"status": "EXPIRED"}).eq(
        "status", "PENDING"
    ).lte("expires_at", db._now_iso()).execute()


def count_recovery_requests_by_ip(ip: str, hours: int = 1) -> int:
    """이 IP가 최근 `hours`시간 안에 만든 복구 요청 수(메일 폭탄 방지용 빈도 제한)."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("recovery_requests")
        .select("id", count="exact")
        .eq("requested_ip", ip)
        .gte("created_at", cutoff)
        .execute()
    )
    return res.count or 0


def count_recovery_requests_by_user(user_id: int, hours: int = 24) -> int:
    """이 사용자(계정)가 최근 `hours`시간 안에 받은 복구 요청 수."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("recovery_requests")
        .select("id", count="exact")
        .eq("user_id", user_id)
        .gte("created_at", cutoff)
        .execute()
    )
    return res.count or 0


def get_latest_recovery_request_time(user_id: int) -> str | None:
    """이 사용자의 가장 최근 복구 요청 시각(쿨다운 판단용)."""
    res = (
        db.get_client()
        .table("recovery_requests")
        .select("created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0]["created_at"] if res.data else None


def get_recovery_activity(user_id: int, hours: int = 24) -> tuple[int, str | None]:
    """이 사용자의 최근 `hours`시간 복구 요청 (건수, 가장 최근 요청 시각)을 한 번의 조회로 가져온다.

    하루 요청 한도와 쿨다운 판단에 쓴다. 예전에는 건수 조회와 최근 시각 조회를 따로 했는데,
    원격 Supabase는 쿼리 하나에 수백 ms가 걸리고 복구 요청 응답은 시간이 정해진 안에 끝나야
    해서(Vercel 함수 제한 + 응답 시간 고정) 왕복 횟수를 줄였다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("recovery_requests")
        .select("created_at")
        .eq("user_id", user_id)
        .gte("created_at", cutoff)
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    )
    rows = res.data
    return len(rows), (rows[0]["created_at"] if rows else None)


def list_recent_recovery_requests(limit: int = 20) -> list[dict]:
    """관리자 대시보드 "복구 요청" 카드용 — 최근 요청 `limit`건(토큰/코드 해시는 빼고 가져온다)."""
    res = (
        db.get_client()
        .table("recovery_requests")
        .select(
            "id, user_id, target_kind, target_value, requested_ip, status, "
            "code_attempts, expires_at, created_at, verified_at, users(username)"
        )
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return [_flatten_username(row) for row in res.data]


# ---------------------------------------------------------------------------
# ip_lock_exemptions
# ---------------------------------------------------------------------------

def insert_ip_exemption(
    ip: str, user_id: int, device_hash: str, granted_via: str, expires_at_iso: str
) -> None:
    """IP 영구 잠금 예외(출입증)를 발급한다. 같은 (ip, 사용자, 기기)의 ACTIVE 예외가 이미
    있으면 새로 만들지 않고 만료 시각만 연장한다(부분 유니크 인덱스 idx_ip_lock_exemptions_active)."""
    res = (
        db.get_client()
        .table("ip_lock_exemptions")
        .update({"expires_at": expires_at_iso})
        .eq("ip_address", ip)
        .eq("user_id", user_id)
        .eq("device_hash", device_hash)
        .eq("status", "ACTIVE")
        .execute()
    )
    if res.data:
        return
    try:
        db.get_client().table("ip_lock_exemptions").insert(
            {
                "ip_address": ip,
                "user_id": user_id,
                "device_hash": device_hash,
                "granted_via": granted_via,
                "expires_at": expires_at_iso,
            }
        ).execute()
    except APIError as e:
        if e.code != "23505":
            raise


def get_active_ip_exemption(ip: str, user_id: int, device_hash: str | None) -> dict | None:
    """이 IP·사용자·기기에 유효한(ACTIVE + 만료 전) 예외가 있으면 그 행을 돌려준다.
    기기 쿠키가 없으면(device_hash=None) 항상 없음 — 공격자는 이 쿠키를 갖고 있지 않다."""
    if not device_hash:
        return None
    res = (
        db.get_client()
        .table("ip_lock_exemptions")
        .select("*")
        .eq("ip_address", ip)
        .eq("user_id", user_id)
        .eq("device_hash", device_hash)
        .eq("status", "ACTIVE")
        .gt("expires_at", db._now_iso())
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def revoke_ip_exemption(exemption_id: int, reason: str) -> bool:
    """예외를 회수한다(관리자 회수 또는 예외 통과 사용자의 연속 로그인 실패). 실제로 회수됐을 때만 True."""
    res = (
        db.get_client()
        .table("ip_lock_exemptions")
        .update({"status": "REVOKED", "revoked_reason": reason})
        .eq("id", exemption_id)
        .eq("status", "ACTIVE")
        .execute()
    )
    return bool(res.data)


def list_active_ip_exemptions(limit: int = 20) -> list[dict]:
    """관리자 대시보드 "IP 예외" 카드용 — 유효한 예외 목록(최근 발급순)."""
    res = (
        db.get_client()
        .table("ip_lock_exemptions")
        .select("id, ip_address, user_id, granted_via, status, granted_at, expires_at, users(username)")
        .eq("status", "ACTIVE")
        .gt("expires_at", db._now_iso())
        .order("granted_at", desc=True)
        .limit(limit)
        .execute()
    )
    return [_flatten_username(row) for row in res.data]


# ---------------------------------------------------------------------------
# users.email_status — 메일 서버가 수신자를 거부(존재하지 않는 이메일)했는지
# ---------------------------------------------------------------------------

def set_user_email_status(user_id: int, status: str) -> None:
    """이 사용자의 이메일 상태를 UNKNOWN / UNDELIVERABLE로 기록한다(확인 시각도 함께)."""
    db.get_client().table("users").update(
        {"email_status": status, "email_status_checked_at": db._now_iso()}
    ).eq("id", user_id).execute()


def get_email_statuses(usernames: list[str]) -> dict[str, str]:
    """여러 계정의 email_status를 한 번의 조회로 가져온다 → {username: status}.
    대시보드 영구 잠금 카드의 "이메일 확인 불가" 배지용이다."""
    if not usernames:
        return {}
    res = (
        db.get_client()
        .table("users")
        .select("username, email_status")
        .in_("username", usernames)
        .execute()
    )
    return {row["username"]: row["email_status"] for row in res.data}
