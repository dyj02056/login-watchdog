# ============================================================================
# db/attempts.py — login_attempts 표 관련 함수
# — "누가 언제 어떤 IP에서 로그인에 성공/실패했는지"를 기록하고 조회하는 기능
#
# 원래 db.py의 같은 이름 섹션을 그대로 옮겨왔다. 이 모듈은 내부에서 `import db`로
# 패키지 최상위(db/__init__.py)를 다시 참조해서 db.get_client()를 호출한다 —
# db.attempts.get_client가 아니라 이렇게 해야, 테스트가
# monkeypatch.setattr(db, "get_client", ...)로 db 패키지의 get_client를 바꿔치기
# 했을 때 이 파일의 함수들도 그 가짜 버전을 그대로 쓰게 된다(값을 미리 복사해서
# 이 파일 안에 별도 이름으로 묶어두면 그 바꿔치기가 안 먹는다).
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def log_attempt(ip: str, username: str, success: bool) -> None:
    """로그인 시도 한 건을 login_attempts 표에 새 줄로 저장한다.

    CCTV처럼 "누가 지나갔다"는 기록을 계속 쌓기만 하고, 절대 지우거나 덮어쓰지 않는다.
    """
    db.get_client().table("login_attempts").insert(
        {"ip_address": ip, "username": username, "success": success}
    ).execute()


def count_recent_failures(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 번이나 로그인에 실패했는지 센다.

    동작 순서:
    1. "지금 시각 - 60초"를 계산해서 "이 시각 이후의 기록만 보겠다"는 기준선을 만든다.
    2. login_attempts 표에서 "이 IP" + "실패(success=False)" + "기준선 이후"인 줄만 골라
       개수를 센다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("login_attempts")
        .select("id", count="exact")   # 실제 내용은 필요없고 "개수"만 알면 되므로 id만 요청
        .eq("ip_address", ip)          # 조건 1: IP가 일치하는 것만
        .eq("success", False)          # 조건 2: 실패한 시도만
        .gte("attempted_at", cutoff)   # 조건 3: 기준 시각 이후에 일어난 것만
        .execute()
    )
    return res.count or 0  # 만약 count가 없으면(None) 0으로 처리


def count_recent_distinct_usernames(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 몇 개의 서로 다른 아이디로 로그인
    실패를 시도했는지 센다.

    count_recent_failures()는 "몇 번" 두드렸는지만 알려주지만, 이 값은 "몇 개의
    서로 다른 문(아이디)"을 두드렸는지를 알려준다 — 1개면 계정 하나를 노린
    전형적인 Brute Force, 2개 이상이면 여러 계정을 돌아가며 시도하는 Password
    Spraying으로 의심할 수 있다 (soar.enforce_lockout이 Slack 알림에 이 값을
    함께 표시해서 두 패턴을 구분해준다).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("login_attempts")
        .select("username")
        .eq("ip_address", ip)
        .eq("success", False)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return len({row["username"] for row in res.data})


def count_recent_failures_by_username(
    username: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 아이디가 최근 몇 초(기본 60초) 안에 (어느 IP에서 왔든) 몇 번이나
    로그인에 실패했는지 센다.

    count_recent_failures()는 IP 기준이라, 공격자가 IP를 여러 개 돌려가며
    같은 계정만 노리면 IP 하나당 실패 횟수는 임계값을 넘지 않아 탐지를
    피해간다. 이 함수는 IP와 무관하게 "이 계정이 총 몇 번 공격당했는가"를
    세서 그 빈틈을 메운다 (config.ACCOUNT_FAILURE_THRESHOLD와 함께 쓰임).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("login_attempts")
        .select("id", count="exact")
        .eq("username", username)
        .eq("success", False)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


def count_recent_distinct_ips_by_username(
    username: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS
) -> int:
    """이 아이디에 대한 최근 로그인 실패 시도가 몇 개의 서로 다른 IP에서
    왔는지 센다.

    count_recent_distinct_usernames()(한 IP가 몇 개의 아이디를 시도했는지)의
    반대 방향이다 — 한 계정에 몰리는 IP가 많을수록 분산 브루트포스(봇넷/
    프록시 로테이션) 의심이 커진다는 걸 alert.py가 메시지에 보여줄 수 있게
    한다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("login_attempts")
        .select("ip_address")
        .eq("username", username)
        .eq("success", False)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return len({row["ip_address"] for row in res.data})


def list_recent_attempts(page: int = 1, page_size: int = 50) -> tuple[list[dict], int]:
    """로그인 시도 기록을 최신순으로 `page`번째 페이지만 가져오고, 전체 건수도 함께 돌려준다.

    관리자 대시보드 화면의 "최근 로그인 시도" 표에 쓰인다. select(..., count="exact")에
    range()를 함께 쓰면 PostgREST가 "이번 페이지 데이터"와 "range와 무관한 전체 개수"를
    한 번의 요청으로 같이 돌려준다 — 예전에는 목록 조회와 개수 조회를 별도 쿼리 두 번으로
    나눠서 했는데, 페이지네이션을 표 5개에 다 붙이고 나니 /api/status 한 번에 왕복이
    10번(표마다 목록+개수)까지 늘어나 관리자 대시보드 응답이 눈에 띄게 느려졌다. 이렇게
    합치면 표 하나당 왕복이 1번으로 줄어든다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("login_attempts")
        .select("*", count="exact")       # 이 줄의 모든 칸(id, ip, username 등) 전부 요청
        .order("attempted_at", desc=True) # 시각 기준으로 내림차순(최신이 맨 위) 정렬
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0


def list_attempts_since(hours: int = 24) -> list[dict]:
    """지난 `hours`시간(기본 24시간) 동안의 로그인 시도 전체를 가져온다.

    count_recent_failures()와 비슷한 "기준 시각 이후만" 패턴을 쓰지만, 특정
    IP나 성공/실패로 좁히지 않고 전체를 가져온다는 점이 다르다 — scripts/
    daily_report.py가 "오늘 하루 전체 통계"를 계산할 때 쓴다.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("login_attempts")
        .select("*")
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.data


def list_attempts_by_username(username: str, limit: int = 20) -> list[dict]:
    """특정 아이디의 로그인 시도 기록만 최신순으로 가져온다.

    list_recent_attempts()와 거의 똑같지만, 관리자용(전체 IP/전체 사용자)이 아니라
    회원 본인이 "내가 언제 로그인을 시도했는지"만 볼 수 있게 아이디로 걸러낸다는
    점이 다르다. 회원 대시보드의 "최근 로그인 기록" 화면에서 쓰인다.
    """
    res = (
        db.get_client()
        .table("login_attempts")
        .select("*")
        .eq("username", username)
        .order("attempted_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data
