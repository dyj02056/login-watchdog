# ============================================================================
# macro_bot_sim.py — 짧은 시간 안에 서로 다른 관리자 API 여러 개를 옮겨 다니며
# 호출하는 "매크로/봇" 패턴을 흉내내서, 매크로/봇 탐지 로직(Track C guide29)이
# 실제로 알림을 울리는지 확인하는 검증 스크립트
#
# 매크로/봇 패턴이란? 사람이 화면을 눌러가며 기능을 하나씩 쓰는 것과 달리,
# 스크립트가 짧은 시간 안에 여러 API를 기계적으로 순서대로 호출하는 행위다.
# 이 스크립트는 이미 만들어져 있는 관리자 계정으로 로그인한 뒤, 서로 다른
# 관리자 API 6개를 순서대로 호출해서 그 패턴을 재현한다
# (config.MACRO_DISTINCT_API_THRESHOLD 기본값 5를 "초과"하려면 최소 6개가 필요하다).
#
# 안전 원칙: 실제로 뭔가를 삭제/변경하지 않는 것을 목표로 한다. --username/--password로
# security_viewer 역할 계정(대시보드 조회 말고는 아무 권한도 없음, guide26 참고)을
# 넘기면 서버가 6번의 호출을 전부 403(권한 없음)으로 거절한다 — before_request
# 훅(app.py의 track_api_access())은 실제 뷰 함수가 실행되기 훨씬 전에 먼저
# 실행되므로, 403으로 거절되는 요청도 매크로/봇 탐지 로그에는 정상적으로
# 기록된다. 계정이 없다면 먼저 다음처럼 만든다:
#   python scripts/create_admin.py --username macro_test --password <비밀번호> --role security_viewer
#
# bruteforce_sim.py/web_scanning_sim.py와 동일한 원칙으로, 팀이 소유한 로컬
# 서버(기본값 http://127.0.0.1:5000)만 대상으로 한다.
# ============================================================================

import argparse
import sys
from urllib.parse import urlparse

import requests

# 매크로/봇 탐지 대상인 /api/* 경로 중, 아무 권한도 없는 계정으로 호출해도
# 안전하게 403으로 거절되는 관리자 API 6개. admin.api_status는 대시보드가
# 스스로 반복 호출하는 폴링 API라 매크로/봇 탐지 대상에서 제외되므로
# (app.py의 _PAGE_ACCESS_EXCLUDED_ENDPOINTS) 이 목록에는 넣지 않는다.
TARGET_ENDPOINTS = [
    ("/api/unlock", {"ip": "203.0.113.1"}),  # 203.0.113.0/24는 예시 전용 대역(RFC 5737) — 실재 접속자와 무관
    ("/api/security-events/resolve", {"event_id": 999999999}),
    ("/api/users/delete", {"user_id": 999999999}),
    ("/api/settings/signup", {"enabled": True}),
    ("/api/board/posts/delete", {"post_id": 999999999}),
    ("/api/board/comments/delete", {"comment_id": 999999999}),
]


def is_local_host(host: str) -> bool:
    """--host로 받은 주소가 로컬(내 컴퓨터) 서버인지 확인한다."""
    hostname = urlparse(host).hostname or ""
    return hostname in ("127.0.0.1", "localhost", "::1")


def fetch_csrf_token(html: str) -> str:
    """HTML 응답 안의 hidden input 또는 meta 태그에서 csrf_token 값을 뽑아온다.

    로그인 폼(login_form.html)은 hidden input을, 대시보드(admin_dashboard.html)는
    <meta name="csrf-token"> 태그를 쓰므로 둘 다 찾아본다(tests/test_app.py의
    get_csrf_token()과 동일한 방식).
    """
    for marker in ('name="csrf_token" value="', 'name="csrf-token" content="'):
        if marker in html:
            start = html.index(marker) + len(marker)
            end = html.index('"', start)
            return html[start:end]
    raise RuntimeError("응답에서 csrf_token을 찾지 못했습니다.")


def log_in(session: requests.Session, base_url: str, username: str, password: str) -> str:
    """관리자 계정으로 로그인하고, 로그인 후 대시보드 HTML(다음 CSRF 토큰을
    뽑아낼 재료)을 돌려준다. 실패하면 예외를 던진다.
    """
    login_page = session.get(f"{base_url}/admin/login", timeout=5)
    csrf_token = fetch_csrf_token(login_page.text)

    response = session.post(
        f"{base_url}/admin/login",
        data={"username": username, "password": password, "csrf_token": csrf_token},
        timeout=5,
    )
    if "관리자 대시보드" not in response.text:
        raise RuntimeError(
            f"'{username}' 계정으로 로그인하지 못했습니다. 아이디/비밀번호를 확인하거나, "
            "먼저 scripts/create_admin.py로 계정을 만들어주세요."
        )
    print(f"[*] '{username}' 계정으로 로그인 성공")
    return response.text


def call_target_endpoints(session: requests.Session, base_url: str, csrf_token: str) -> None:
    """TARGET_ENDPOINTS를 순서대로, 최대한 짧은 간격으로 호출한다."""
    for path, payload in TARGET_ENDPOINTS:
        response = session.post(
            f"{base_url}{path}",
            json=payload,
            headers={"X-CSRFToken": csrf_token},
            timeout=5,
        )
        print(f"    POST {path} -> 상태 코드 {response.status_code}")


def run(base_url: str, username: str, password: str) -> None:
    print(f"[*] {base_url}에서 매크로/봇 패턴(서로 다른 API {len(TARGET_ENDPOINTS)}개 연속 호출)을 재현합니다")

    session = requests.Session()
    dashboard_html = log_in(session, base_url, username, password)
    csrf_token = fetch_csrf_token(dashboard_html)

    call_target_endpoints(session, base_url, csrf_token)

    print(
        "[VERIFY] 서버가 6번의 호출을 전부 403(권한 없음)으로 거절했다면 정상입니다"
        "(security_viewer 등 권한 없는 계정으로 호출했을 때) — 아무것도 실제로 삭제/변경되지 않았습니다.\n"
        "  Slack/콘솔 로그: [MEDIUM] '매크로/봇 의심' 확인\n"
        "  관리자 대시보드 또는 로그인된 GET /api/status로 security_events 확인\n"
        "  event_type=API_MACRO_PATTERN, severity=MEDIUM 확인"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="로그인 워치독의 매크로/봇 탐지가 실제로 알림을 울리는지 확인하는 시뮬레이션 스크립트."
    )
    parser.add_argument(
        "--host", default="http://127.0.0.1:5000",
        help="테스트 대상 서버 주소 (기본값: 로컬 개발 서버 http://127.0.0.1:5000)",
    )
    parser.add_argument("--username", required=True, help="이미 만들어져 있는 관리자 계정 아이디")
    parser.add_argument("--password", required=True, help="그 계정의 비밀번호")
    parser.add_argument(
        "--i-know-what-im-doing", action="store_true",
        help="localhost가 아닌 --host를 대상으로 실행하려면 반드시 이 플래그를 함께 줘야 한다.",
    )
    args = parser.parse_args()

    if not is_local_host(args.host) and not args.i_know_what_im_doing:
        print(
            "[FAIL] 이 스크립트는 팀이 소유한 로컬 서버만 대상으로 실행하도록 만들어졌습니다.\n"
            f"    '{args.host}'는 로컬 주소가 아닙니다. 실제 서비스나 타인의 서버에는 "
            "절대 실행하지 마세요.\n"
            "    정말 이 주소가 본인 소유의 서버라면 --i-know-what-im-doing 플래그를 추가하세요.",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        run(args.host, args.username, args.password)
    except RuntimeError as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
