# ============================================================================
# db/settings.py — app_settings / signup_attempts 표 관련 함수
# — app_settings: 서버 전체가 공유하는 설정값 (지금은 회원가입 On/Off 하나)
# — signup_attempts: 회원가입 요청 빈도 제한 (18단계 보안 점검 보완). login_attempts와
#   별도 표를 쓰는 이유: 회원가입은 성공/아이디 값과 무관하게 "이 IP가 얼마나
#   자주 두드렸는가"만 세면 되므로, 더 가벼운 구조로 분리했다.
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def get_signup_enabled() -> bool:
    """지금 회원가입을 받고 있는지(True) 막아뒀는지(False) 확인한다.

    이 값을 파이썬 변수(메모리)에만 저장해두면 안 되는 이유: 이 프로젝트는
    로컬 컴퓨터, Vercel 등 여러 곳에서 서버가 동시에 돌아갈 수 있는데, 메모리는
    각 서버(프로세스)마다 따로따로 존재한다. 관리자가 한 곳에서 "회원가입 끄기"를
    눌러도 다른 곳에서 돌고 있는 서버는 그 사실을 전혀 모른다. 그래서 모두가
    공유해서 보는 단 하나의 장소인 Supabase에 이 값을 저장해둔다.
    """
    res = db.get_client().table("app_settings").select("signup_enabled").eq("id", 1).limit(1).execute()
    if not res.data:
        return True  # 설정 행이 아직 없다면(예외 상황) 기본값은 "허용"으로 안전하게 처리
    return res.data[0]["signup_enabled"]


def set_signup_enabled(enabled: bool) -> None:
    """회원가입 허용 여부를 켜거나 끈다 (관리자가 대시보드에서 호출)."""
    db.get_client().table("app_settings").update({"signup_enabled": enabled}).eq("id", 1).execute()


def log_signup_attempt(ip: str) -> None:
    """회원가입 POST 요청 한 건을 signup_attempts 표에 기록한다 (성공/실패 무관)."""
    db.get_client().table("signup_attempts").insert({"ip_address": ip}).execute()


def count_recent_signup_attempts(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 회원가입을 몇 번이나 시도했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("signup_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0
