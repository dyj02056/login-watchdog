# ============================================================================
# comment_spam_sim.py — 로그인한 계정이 댓글을 짧은 시간에 반복 등록하는 "댓글 도배(COMMENT_RATE_LIMIT)"를
# 흉내 내서, 댓글 작성 한도가 정말로 막아주는지 확인하는 검증 스크립트 (spam_sim.py의 댓글 버전)
#
# 서버는 같은 IP가 1분 안에 댓글을 COMMENT_RATE_LIMIT번(기본 10번) 쓰면 그다음부터 거부하고
# COMMENT_RATE_LIMIT(HIGH) 이벤트로 남긴다.
#
# 동작 요약:
#   1) 테스트 계정으로 로그인한다(--username/--password 또는 SPAM_TEST_USERNAME/SPAM_TEST_PASSWORD).
#   2) 댓글을 달 게시글이 필요하다. --post-id를 주면 그 글을 쓰고, 생략하면 "[COMMENT-SPAM-TEST]" 글을 하나 만든다.
#   3) 댓글을 --attempts번(기본 12번) 연속 작성한다. 한도를 넘긴 요청은 "너무 많은 댓글 작성 시도" 안내와
#      함께 거부되므로 그 문구가 나오면 성공.
#
# 안전 원칙: 로컬 서버만 대상. 테스트 글과 댓글은 제목/본문에 "[COMMENT-SPAM-TEST]"가 붙어 있어서 관리자
# 화면에서 쉽게 찾아 지울 수 있다. 실제 회원 계정이 아니라 테스트 계정으로만 실행한다.
# ============================================================================

import argparse
import getpass
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import (  # noqa: E402
    REQUEST_TIMEOUT, extract_csrf_token, fetch_csrf, new_session, post_form, require_local_or_exit,
)

REJECT_MESSAGE = "너무 많은 댓글 작성 시도"


def login(session, base_url: str, username: str, password: str) -> bool:
    token = fetch_csrf(session, base_url, "/login")
    response = post_form(session, base_url, "/login",
                         {"username": username, "password": password, "website": ""}, token)
    return response.status_code in (301, 302, 303) and "/dashboard" in response.headers.get("Location", "")


def create_post(session, base_url: str) -> int | None:
    token = fetch_csrf(session, base_url, "/board/new")
    response = post_form(session, base_url, "/board/new",
                         {"title": "[COMMENT-SPAM-TEST] 댓글 도배 시험용 글",
                          "body": "댓글 도배 시뮬레이션이 만든 시험용 글입니다. 관리자 화면에서 지워도 됩니다.",
                          "website": ""}, token)
    match = re.search(r"/board/(\d+)", response.headers.get("Location", ""))
    return int(match.group(1)) if match else None


def run(base_url: str, username: str, password: str, post_id: int | None, attempts: int, interval: float) -> bool:
    session = new_session()
    print(f"[*] 테스트 계정 '{username}'으로 로그인합니다.")
    if not login(session, base_url, username, password):
        print("[FAIL] 로그인에 실패했습니다. 테스트 계정 아이디/비밀번호를 확인하세요.", file=sys.stderr)
        return False

    if post_id is None:
        post_id = create_post(session, base_url)
        if post_id is None:
            print("[FAIL] 시험용 게시글을 만들지 못했습니다(글쓰기 한도에 걸렸을 수 있습니다).", file=sys.stderr)
            return False
        print(f"[*] 시험용 게시글 #{post_id}을 만들었습니다.")

    detail = session.get(f"{base_url}/board/{post_id}", timeout=REQUEST_TIMEOUT)
    token = extract_csrf_token(detail.text, page_name=f"/board/{post_id}")
    posted = rejected = 0
    print(f"[*] 게시글 #{post_id}에 댓글 {attempts}회 연속 작성")
    for i in range(1, attempts + 1):
        response = post_form(session, base_url, f"/board/{post_id}/comments",
                             {"body": f"[COMMENT-SPAM-TEST] 자동 댓글 {i}", "website": ""}, token,
                             referer_path=f"/board/{post_id}", follow=True)
        rejected_now = REJECT_MESSAGE in response.text
        posted, rejected = posted + (not rejected_now), rejected + rejected_now
        print(f"    댓글 {i:>2}/{attempts} | 상태 {response.status_code} | {'거부' if rejected_now else '등록'}")
        time.sleep(interval)

    print(f"[*] 등록 {posted}개 | 거부 {rejected}개")
    if rejected:
        print("[OK] 댓글 작성 한도가 정상 동작합니다.")
        print("  확인 위치: 대시보드 security_events의 event_type=COMMENT_RATE_LIMIT, severity=HIGH")
        return True
    print("[FAIL] 거부된 댓글이 없습니다. --attempts가 COMMENT_RATE_LIMIT(기본 10)보다 적었거나 한도가 꺼져 있습니다.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="댓글 도배(COMMENT_RATE_LIMIT) 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--username", default=os.environ.get("SPAM_TEST_USERNAME"), help="테스트 계정 아이디")
    parser.add_argument("--password", default=os.environ.get("SPAM_TEST_PASSWORD"), help="테스트 계정 비밀번호(생략하면 입력받음)")
    parser.add_argument("--post-id", type=int, default=None, help="댓글을 달 게시글 번호 (생략하면 시험용 글을 만든다)")
    parser.add_argument("--attempts", type=int, default=12, help="댓글 시도 횟수 (기본 12 = 한도 10 + 2)")
    parser.add_argument("--interval", type=float, default=0.1, help="요청 사이 간격(초), 기본 0.1")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    username = args.username or input("테스트 계정 아이디: ").strip()
    password = args.password or getpass.getpass("테스트 계정 비밀번호: ")
    ok = run(args.host.rstrip("/"), username, password, args.post_id, args.attempts, args.interval)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
