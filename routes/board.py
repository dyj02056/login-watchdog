# ============================================================================
# routes/board.py — 게시판 (/board) — 전부 member_login_required로 보호됨 (회원 전용, 결정 #1)
#
# login_required/member_login_required는 "로그인 여부"만 확인하고 "이 글/댓글이
# 내 것인지"는 확인하지 않으므로, 수정/삭제 라우트마다 _is_post_owner() 등으로
# 직접 소유권을 검사한다 — 관리자는 routes/admin.py의 /api/board/*/delete를 통해
# 별도로 전체 글/댓글을 삭제할 수 있다(docs/board-comment/plan_board.md 5-3절 참고).
#
# 원래 app.py의 "게시판" 섹션을 그대로 옮겨왔다. 배경은
# docs/refactor/2026-09-15-file-split.md 참고.
# ============================================================================

import math

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

import config
import db
import detector
import soar
from helpers import get_request_ip, is_bot_submission, member_login_required

board_bp = Blueprint("board", __name__)

# 게시판 입력 길이 제한 (docs/board-comment/plan_board.md 참고). 아이디/이메일과
# 달리 제목·본문은 임의의 문자를 허용해야 하므로(한글, 문장부호 등) 정규식
# 화이트리스트 대신 "길이만" 제한한다 — 내용 자체의 안전성은 Jinja2 auto-escape가
# 출력 시점에 보장한다(결정 #5).
POST_TITLE_MAX_LENGTH = 100
POST_BODY_MAX_LENGTH = 5000
COMMENT_BODY_MAX_LENGTH = 1000


def _is_post_owner(post: dict) -> bool:
    """지금 로그인한 회원이 이 글의 작성자인지 확인한다."""
    return post["author_username"] == session.get("username")


@board_bp.route("/board", methods=["GET"])
@member_login_required
def board_list():
    """게시글 목록. 페이지 번호는 쿼리 파라미터 ?page=로 받는다 (결정 #9 — 페이지 번호 방식).

    page의 type=int 변환이 실패하면(예: ?page=abc) Flask가 자동으로 기본값 1을
    쓰므로, 잘못된 값이 와도 에러 없이 1페이지를 보여준다.
    """
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    posts, total_count = db.list_posts(page, config.BOARD_PAGE_SIZE)
    total_pages = max(1, math.ceil(total_count / config.BOARD_PAGE_SIZE))
    return render_template("board_list.html", posts=posts, page=page, total_pages=total_pages)


@board_bp.route("/board/new", methods=["GET"])
@member_login_required
def board_new():
    """글쓰기 폼 화면. board_form.html은 board_edit()과 화면을 공유한다
    (login_form.html이 /login과 /admin/login을 공유하는 것과 동일한 패턴) —
    post=None이면 "새 글쓰기", post가 있으면 "수정"으로 폼이 스스로 판단한다.
    """
    return render_template("board_form.html", form_action=url_for("board.board_new_submit"), post=None)


@board_bp.route("/board/new", methods=["POST"])
@member_login_required
def board_new_submit():
    """글쓰기 폼 제출을 처리한다."""
    ip = get_request_ip()

    # 허니팟 필드가 채워져 있으면 사람이 아니라 자동화 스크립트라고 보고,
    # 시도 기록조차 남기지 않고 즉시 거부한다 (L7 공격 보강 계획 Tier 3).
    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        flash("일시적인 오류가 발생했습니다. 다시 시도해주세요.")
        return render_template("board_form.html", form_action=url_for("board.board_new_submit"), post=None)

    # 같은 IP가 짧은 시간에 너무 많이 글을 올리면 거부한다 (signup_submit()과 동일한
    # "먼저 판정 → 성공/실패 무관하게 시도 자체를 기록" 순서, 결정 #7).
    if detector.is_post_rate_limited(ip):
        soar.record_rejection("POST_RATE_LIMIT", ip, request.path, config.POST_RATE_LIMIT)
        flash("너무 많은 게시글 작성 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return render_template("board_form.html", form_action=url_for("board.board_new_submit"), post=None)
    db.log_post_attempt(ip)

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()

    if not title or not body:
        flash("제목과 내용을 모두 입력해주세요.")
        return render_template("board_form.html", form_action=url_for("board.board_new_submit"), post=None)

    if len(title) > POST_TITLE_MAX_LENGTH or len(body) > POST_BODY_MAX_LENGTH:
        flash(
            f"제목은 최대 {POST_TITLE_MAX_LENGTH}자, 내용은 최대 {POST_BODY_MAX_LENGTH}자까지 "
            "입력할 수 있습니다."
        )
        return render_template("board_form.html", form_action=url_for("board.board_new_submit"), post=None)

    post = db.create_post(session["username"], title, body)
    flash("게시글이 등록되었습니다.")
    return redirect(url_for("board.board_detail", post_id=post["id"]))


@board_bp.route("/board/<int:post_id>", methods=["GET"])
@member_login_required
def board_detail(post_id):
    """게시글 상세 + 댓글 목록 + 댓글 작성 폼 + "새 댓글" 알림 배너 자리."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board.board_list"))

    comments = db.list_comments_by_post(post_id)
    return render_template(
        "board_detail.html",
        post=post,
        comments=comments,
        is_owner=_is_post_owner(post),
        # board.js가 "새 댓글" 배너를 몇 밀리초마다 확인할지. admin_dashboard()와
        # 동일한 이유로 config.py에서 값을 받아 템플릿에 내려준다.
        poll_interval_ms=config.BOARD_COMMENT_POLL_MS,
    )


@board_bp.route("/board/<int:post_id>/edit", methods=["GET"])
@member_login_required
def board_edit(post_id):
    """게시글 수정 폼. 본인 글이 아니면 폼을 아예 보여주지 않고 상세 화면으로 돌려보낸다."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board.board_list"))
    if not _is_post_owner(post):
        flash("본인이 작성한 글만 수정할 수 있습니다.")
        return redirect(url_for("board.board_detail", post_id=post_id))

    return render_template(
        "board_form.html", form_action=url_for("board.board_edit_submit", post_id=post_id), post=post
    )


@board_bp.route("/board/<int:post_id>/edit", methods=["POST"])
@member_login_required
def board_edit_submit(post_id):
    """게시글 수정 폼 제출을 처리한다.

    화면에서 수정 버튼을 감췄더라도, 여기서도 다시 한번 소유권을 확인한다
    (signup_submit()의 이중 검증 원칙과 동일 — 개발자 도구로 우회한 요청까지 방어).
    """
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board.board_list"))
    if not _is_post_owner(post):
        flash("본인이 작성한 글만 수정할 수 있습니다.")
        return redirect(url_for("board.board_detail", post_id=post_id))

    form_action = url_for("board.board_edit_submit", post_id=post_id)
    ip = get_request_ip()

    # 허니팟 필드가 채워져 있으면 사람이 아니라 자동화 스크립트라고 보고 즉시 거부한다
    # (L7 공격 보강 계획 Tier 3).
    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        flash("일시적인 오류가 발생했습니다. 다시 시도해주세요.")
        return render_template("board_form.html", form_action=form_action, post=post)

    # board_new_submit()과 동일한 빈도 제한 — 글 수정도 도배 대상이 될 수 있으므로
    # 새 글 작성과 같은 post_attempts 카운트를 공유한다 (원래 이 검사가 빠져있던
    # 공백을 보완, attack_response_state.md 구현 대상 #3).
    if detector.is_post_rate_limited(ip):
        soar.record_rejection("POST_RATE_LIMIT", ip, request.path, config.POST_RATE_LIMIT)
        flash("너무 많은 게시글 작성 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return render_template("board_form.html", form_action=form_action, post=post)
    db.log_post_attempt(ip)

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()

    if not title or not body:
        flash("제목과 내용을 모두 입력해주세요.")
        return render_template("board_form.html", form_action=form_action, post=post)

    if len(title) > POST_TITLE_MAX_LENGTH or len(body) > POST_BODY_MAX_LENGTH:
        flash(
            f"제목은 최대 {POST_TITLE_MAX_LENGTH}자, 내용은 최대 {POST_BODY_MAX_LENGTH}자까지 "
            "입력할 수 있습니다."
        )
        return render_template("board_form.html", form_action=form_action, post=post)

    db.update_post(post_id, title, body)
    flash("게시글이 수정되었습니다.")
    return redirect(url_for("board.board_detail", post_id=post_id))


@board_bp.route("/board/<int:post_id>/delete", methods=["POST"])
@member_login_required
def board_delete(post_id):
    """본인 글 삭제 (결정 #2 — 삭제 권한: 본인 + 관리자. 관리자는 /api/board/posts/delete 사용)."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board.board_list"))
    if not _is_post_owner(post):
        flash("본인이 작성한 글만 삭제할 수 있습니다.")
        return redirect(url_for("board.board_detail", post_id=post_id))

    db.delete_post(post_id)
    flash("게시글이 삭제되었습니다.")
    return redirect(url_for("board.board_list"))


@board_bp.route("/board/<int:post_id>/comments", methods=["POST"])
@member_login_required
def board_comment_submit(post_id):
    """댓글 작성. Post-Redirect-Get 패턴으로 처리 후 항상 상세 화면으로 돌아간다."""
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board.board_list"))

    ip = get_request_ip()

    # 허니팟 필드가 채워져 있으면 사람이 아니라 자동화 스크립트라고 보고 즉시 거부한다
    # (L7 공격 보강 계획 Tier 3).
    if is_bot_submission():
        soar.notify_bot_detected(ip, request.path)
        return redirect(url_for("board.board_detail", post_id=post_id))

    if detector.is_comment_rate_limited(ip):
        soar.record_rejection("COMMENT_RATE_LIMIT", ip, request.path, config.COMMENT_RATE_LIMIT)
        flash("너무 많은 댓글 작성 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
        return redirect(url_for("board.board_detail", post_id=post_id))
    db.log_comment_attempt(ip)

    body = request.form.get("body", "").strip()
    if not body:
        flash("댓글 내용을 입력해주세요.")
        return redirect(url_for("board.board_detail", post_id=post_id))
    if len(body) > COMMENT_BODY_MAX_LENGTH:
        flash(f"댓글은 최대 {COMMENT_BODY_MAX_LENGTH}자까지 입력할 수 있습니다.")
        return redirect(url_for("board.board_detail", post_id=post_id))

    db.create_comment(post_id, session["username"], body)
    return redirect(url_for("board.board_detail", post_id=post_id))


@board_bp.route("/board/<int:post_id>/comments/<int:comment_id>/delete", methods=["POST"])
@member_login_required
def board_comment_delete(post_id, comment_id):
    """본인 댓글 삭제."""
    comment = db.get_comment(comment_id)
    if comment is None:
        flash("존재하지 않는 댓글입니다.")
        return redirect(url_for("board.board_detail", post_id=post_id))
    if comment["author_username"] != session.get("username"):
        flash("본인이 작성한 댓글만 삭제할 수 있습니다.")
        return redirect(url_for("board.board_detail", post_id=post_id))

    db.delete_comment(comment_id)
    return redirect(url_for("board.board_detail", post_id=post_id))


@board_bp.route("/api/board/<int:post_id>/comments/latest", methods=["GET"])
@member_login_required
def api_board_comments_latest(post_id):
    """board.js가 짧은 주기(15초)로 폴링하는 API. 댓글 개수/최신 시각만 가볍게
    돌려준다 — 표 전체를 다시 그리는 관리자 대시보드(/api/status)와 달리,
    "값이 바뀌었으니 배너를 띄워라"는 신호로만 쓰인다(결정 #6).
    """
    return jsonify(db.get_latest_comment_info(post_id))
