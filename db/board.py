# ============================================================================
# db/board.py — posts / comments / post_attempts / comment_attempts 표 관련 함수
# — 게시판 글·댓글과, 그 도배(스팸) 방지용 요청 빈도 제한 로그
# (docs/board-comment/plan_board.md 참고)
# — login_attempts와 동일한 관례로 users와 FK를 걸지 않고 author_username을
#   텍스트로만 저장한다 (회원 탈퇴 후에도 글은 흔적만 남기고 유지, 결정 #4).
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from datetime import datetime, timedelta, timezone

import config
import db


def create_post(author_username: str, title: str, body: str) -> dict:
    """새 게시글을 만든다. 생성된 행(id 포함)을 그대로 돌려준다.

    상세 화면으로 바로 이동시키려면(app.py의 post_new_submit) 새로 생긴 글의
    id가 필요하므로, insert 결과를 그대로 반환한다.
    """
    res = (
        db.get_client()
        .table("posts")
        .insert({"author_username": author_username, "title": title, "body": body})
        .execute()
    )
    return res.data[0]


def get_post(post_id: int) -> dict | None:
    """글 번호(id)로 게시글 한 건을 찾는다. 없으면 None을 돌려준다."""
    res = db.get_client().table("posts").select("*").eq("id", post_id).limit(1).execute()
    return res.data[0] if res.data else None


def list_posts(page: int, page_size: int) -> tuple[list[dict], int]:
    """게시글 목록을 최신순으로 `page`번째 페이지만 가져오고, 전체 게시글 개수도
    함께 돌려준다 (1부터 시작).

    supabase-py의 .range(start, end)는 PostgREST의 offset 기반 페이지네이션을
    그대로 감싼 것이라, 별도 페이지네이션 라이브러리 없이 이 한 줄로 구현된다
    (docs/board-comment/plan_board.md 7절 "기술 스택 선택과 이유" 참고). select()에
    count="exact"를 함께 주면 range()와 무관하게 전체 개수도 같은 응답에 실려 오므로,
    목록 조회와 개수 조회를 쿼리 두 번으로 나눌 필요가 없다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("posts")
        .select("*", count="exact")
        .order("created_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0


def update_post(post_id: int, title: str, body: str) -> None:
    """게시글의 제목/본문을 수정한다. updated_at도 지금 시각으로 함께 갱신한다."""
    db.get_client().table("posts").update(
        {"title": title, "body": body, "updated_at": db._now_iso()}
    ).eq("id", post_id).execute()


def delete_post(post_id: int) -> bool:
    """게시글을 삭제한다. comments 표가 on delete cascade로 걸려있으므로,
    이 글에 달린 댓글도 Supabase가 알아서 함께 지운다 (docs/schema.sql 참고).

    반환값: 실제로 삭제된 행이 있었으면 True, 애초에 그런 id가 없었으면 False.
    """
    res = db.get_client().table("posts").delete().eq("id", post_id).execute()
    return len(res.data) > 0


def create_comment(post_id: int, author_username: str, body: str) -> None:
    """게시글 하나에 댓글 한 건을 새로 단다."""
    db.get_client().table("comments").insert(
        {"post_id": post_id, "author_username": author_username, "body": body}
    ).execute()


def get_comment(comment_id: int) -> dict | None:
    """댓글 번호(id)로 댓글 한 건을 찾는다. 없으면 None을 돌려준다.

    댓글 삭제 라우트(app.py의 board_comment_delete)가 "이 댓글이 정말 본인
    것인지" 확인할 때 쓴다 — get_post()와 대칭되는 함수.
    """
    res = db.get_client().table("comments").select("*").eq("id", comment_id).limit(1).execute()
    return res.data[0] if res.data else None


def list_comments_by_post(post_id: int) -> list[dict]:
    """특정 게시글에 달린 댓글 전체를 오래된 순(등록 순서대로)으로 가져온다."""
    res = (
        db.get_client()
        .table("comments")
        .select("*")
        .eq("post_id", post_id)
        .order("created_at", desc=False)
        .execute()
    )
    return res.data


def delete_comment(comment_id: int) -> bool:
    """댓글을 하나 삭제한다.

    반환값: 실제로 삭제된 행이 있었으면 True, 애초에 그런 id가 없었으면 False.
    """
    res = db.get_client().table("comments").delete().eq("id", comment_id).execute()
    return len(res.data) > 0


def get_latest_comment_info(post_id: int) -> dict:
    """이 글에 지금까지 달린 댓글 개수와, 가장 최근 댓글이 달린 시각을 돌려준다.

    board.js의 "새로운 댓글이 추가되었습니다" 배너가 15초마다 이 함수를 통해
    받은 값을 페이지 로드 시점 값과 비교한다 — 값이 달라졌을 때만 배너를
    띄우면 되므로, 댓글 내용 전체가 아니라 이 두 값만 가볍게 돌려준다.
    """
    res = (
        db.get_client()
        .table("comments")
        .select("id, created_at", count="exact")
        .eq("post_id", post_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    latest_at = res.data[0]["created_at"] if res.data else None
    return {"count": res.count or 0, "latest_at": latest_at}


def list_comments_admin(page: int, page_size: int) -> tuple[list[dict], int]:
    """관리자 대시보드 "게시글 관리" 표시용 — 게시글 구분 없이 전체 댓글을 최신순으로
    `page`번째 페이지만 가져오고, 전체 댓글 수도 함께 돌려준다. list_comments_by_post()는
    특정 글 하나에 달린 댓글만 보므로(회원용 게시글 상세 화면), 관리자용은 별도 함수로
    분리했다. select(..., count="exact") + range()로 목록/개수를 한 번에 가져온다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("comments")
        .select("*", count="exact")
        .order("created_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0


def log_post_attempt(ip: str) -> None:
    """게시글 작성 POST 요청 한 건을 post_attempts 표에 기록한다 (성공/실패 무관)."""
    db.get_client().table("post_attempts").insert({"ip_address": ip}).execute()


def count_recent_post_attempts(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 게시글을 몇 번이나 작성 시도했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("post_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0


def log_comment_attempt(ip: str) -> None:
    """댓글 작성 POST 요청 한 건을 comment_attempts 표에 기록한다 (성공/실패 무관)."""
    db.get_client().table("comment_attempts").insert({"ip_address": ip}).execute()


def count_recent_comment_attempts(ip: str, window_seconds: int = config.DETECTION_WINDOW_SECONDS) -> int:
    """이 IP가 최근 몇 초(기본 60초) 안에 댓글을 몇 번이나 작성 시도했는지 센다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        db.get_client()
        .table("comment_attempts")
        .select("id", count="exact")
        .eq("ip_address", ip)
        .gte("attempted_at", cutoff)
        .execute()
    )
    return res.count or 0
