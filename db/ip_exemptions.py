# ============================================================================
# db/ip_exemptions.py — ip_lock_exemptions 표 관련 함수 (guide34-a)
#
# ip_lock_exemptions는 IP 영구 잠금에서 "본인 + 본인 기기"만 통과시키는 출입증이다.
# 이메일 인증 복구가 IP 복구를 끝낼 때(security/lockdown.py의 apply_recovery) 여기에 발급한다. 원래
# db/recovery.py에 같이 있었는데 2026-10-09에 나눴다(docs/refactor/2026-10-09-module-plan.md).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from postgrest.exceptions import APIError

import db
from db.recovery import _flatten_username


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
