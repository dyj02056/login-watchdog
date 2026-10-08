# ============================================================================
# db/email_tokens.py — email_tokens 표 (guide40, 이메일 인증 / 이메일 변경 확인 / 비밀번호 재설정)
#
# 메일로 보내는 1회용 링크 한 건 한 건이다. 영구 잠금 복구(recovery_requests)와 같은 원칙을
# 따르지만 표는 나눴다 — 복구의 하루 한도·대시보드 카드·기기 쿠키·6자리 코드 흐름과 섞이지
# 않게 하기 위해서다.
#   - 토큰은 원문이 아니라 SHA-256 해시만 저장한다(DB가 유출돼도 링크는 못 만든다).
#   - 같은 (회원, 용도)에 PENDING은 1건만(idx_email_tokens_one_pending) — 새로 만들면 이전 것은 REVOKED.
#   - 소비는 조건부 UPDATE(WHERE status='PENDING' AND 만료 전)로 딱 한 번만 일어난다.
#
# db.get_client()를 통해 호출하는 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

from postgrest.exceptions import APIError

import db

PURPOSE_EMAIL_VERIFY = "EMAIL_VERIFY"
PURPOSE_EMAIL_CHANGE = "EMAIL_CHANGE"
PURPOSE_PASSWORD_RESET = "PASSWORD_RESET"


def create_email_token(
    user_id: int, purpose: str, email: str, token_hash: str, requested_ip: str, expires_at_iso: str
) -> dict | None:
    """토큰 한 건을 새로 만든다. 같은 (회원, 용도)의 기존 PENDING은 먼저 REVOKED로 바꾼다.
    두 요청이 거의 동시에 들어와 부분 유니크 인덱스가 두 번째 삽입을 막으면(23505) None."""
    db.get_client().table("email_tokens").update({"status": "REVOKED"}).eq("user_id", user_id).eq(
        "purpose", purpose
    ).eq("status", "PENDING").execute()
    try:
        res = (
            db.get_client()
            .table("email_tokens")
            .insert(
                {
                    "user_id": user_id,
                    "purpose": purpose,
                    "email": email,
                    "token_hash": token_hash,
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


def get_pending_email_token(token_hash: str) -> dict | None:
    """토큰 해시로 아직 유효한(PENDING + 만료 전) 토큰을 찾는다. 소비하지 않는다 — 메일 보안
    스캐너가 링크를 미리 GET으로 열어도 토큰이 닳지 않게 하려는 조회 전용이다."""
    res = (
        db.get_client()
        .table("email_tokens")
        .select("*")
        .eq("token_hash", token_hash)
        .eq("status", "PENDING")
        .gt("expires_at", db._now_iso())
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def get_pending_email_token_for_user(user_id: int, purpose: str) -> dict | None:
    """이 회원의 진행 중인 토큰(프로필의 "확인 대기 중: new@…" 표시용)."""
    res = (
        db.get_client()
        .table("email_tokens")
        .select("email, expires_at")
        .eq("user_id", user_id)
        .eq("purpose", purpose)
        .eq("status", "PENDING")
        .gt("expires_at", db._now_iso())
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def consume_email_token(token_id: int) -> dict | None:
    """토큰을 USED로 바꿔 소비한다 — 원자적 1회용. 동시에 두 번 들어와도 먼저 온 쪽만
    PENDING→USED로 바꾸고, 늦게 온 쪽(또는 만료된 토큰)은 0행이라 None을 받는다."""
    res = (
        db.get_client()
        .table("email_tokens")
        .update({"status": "USED", "used_at": db._now_iso()})
        .eq("id", token_id)
        .eq("status", "PENDING")
        .gt("expires_at", db._now_iso())
        .execute()
    )
    return res.data[0] if res.data else None


def revoke_email_token(token_id: int) -> None:
    """메일을 보내지 못했거나 보내지 않기로 한 토큰을 취소한다(PENDING일 때만)."""
    db.get_client().table("email_tokens").update({"status": "REVOKED"}).eq("id", token_id).eq(
        "status", "PENDING"
    ).execute()


def get_email_token_activity(user_id: int, purpose: str, hours: int = 24) -> tuple[int, str | None]:
    """이 회원·용도의 최근 `hours`시간 토큰 (건수, 가장 최근 생성 시각)을 한 번의 조회로 가져온다.
    상태와 무관하게 센다 — 취소된 요청도 메일 발송 시도였으므로 하루 한도와 쿨다운에 들어간다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("email_tokens")
        .select("created_at")
        .eq("user_id", user_id)
        .eq("purpose", purpose)
        .gte("created_at", cutoff)
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    )
    rows = res.data
    return len(rows), (rows[0]["created_at"] if rows else None)


def count_email_tokens_by_ip(ip: str, purpose: str, hours: int = 1) -> int:
    """이 IP가 최근 `hours`시간 안에 만든 이 용도의 토큰 수(비밀번호 재설정 요청의 IP 빈도 제한, guide41).
    아이디를 바꿔가며 여러 계정에 재설정 메일을 뿌리는 것을 막는다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("email_tokens")
        .select("id", count="exact")
        .eq("requested_ip", ip)
        .eq("purpose", purpose)
        .gte("created_at", cutoff)
        .execute()
    )
    return res.count or 0
