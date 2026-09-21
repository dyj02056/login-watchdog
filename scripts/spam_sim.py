# ============================================================================
# spam_sim.py
#
# 목적:
#   테스트 계정으로 로그인한 뒤 짧은 시간 동안 게시글을 반복 등록하여
#   스팸성 데이터 대량 유입 패턴을 발생시키는 시뮬레이션 프로그램이다.
#
# 담당 범위:
#   이 프로그램은 스팸 게시글 작성 요청을 발생시키는 역할만 담당한다.
#   서버의 탐지·기록·차단 여부는 탐지 프로그램에서 처리한다.
#
# 기본 동작:
#   1. GET /login 요청으로 CSRF 토큰과 세션 쿠키 획득
#   2. POST /login 요청으로 테스트 계정 로그인
#   3. GET /board/new 요청으로 게시글 작성용 CSRF 토큰 획득
#   4. POST /board/new 요청을 짧은 간격으로 반복 전송
#
# 주의:
#   실제 게시글 데이터가 생성되므로 반드시 로컬 서버와 테스트 계정을 사용한다.
#   테스트 후 생성된 게시글은 관리자 화면에서 삭제한다.
#
# 허니팟:
#   이 프로젝트는 website 필드가 채워져 있으면 봇으로 판단한다.
#   게시글 스팸 시나리오에서는 website를 빈 문자열로 전송한다.
#   USERNAME: bot09211242321
#   PASSWORD 설정: True
# ============================================================================

import argparse
import getpass
import os
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


load_dotenv()


DEFAULT_HOST = "http://127.0.0.1:5000"
DEFAULT_ATTEMPTS = 6
DEFAULT_INTERVAL = 0.2
REQUEST_TIMEOUT = 5


class CsrfTokenParser(HTMLParser):
    """HTML의 hidden input에서 CSRF 토큰을 추출한다."""

    def __init__(self) -> None:
        super().__init__()
        self.token: str | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag != "input":
            return

        attributes = dict(attrs)

        if attributes.get("name") == "csrf_token":
            self.token = attributes.get("value")


def extract_csrf_token(html: str) -> str:
    """HTML 문서에서 csrf_token 값을 찾아 반환한다."""
    parser = CsrfTokenParser()
    parser.feed(html)

    if not parser.token:
        raise RuntimeError(
            "HTML 화면에서 CSRF 토큰을 찾지 못했습니다."
        )

    return parser.token


def is_local_host(host: str) -> bool:
    """대상 서버가 로컬 주소인지 확인한다."""
    hostname = urlparse(host).hostname or ""

    return hostname in ("127.0.0.1", "localhost", "::1")


def login(
    session: requests.Session,
    base_url: str,
    username: str,
    password: str,
) -> bool:
    """테스트 계정으로 로그인하고 세션 쿠키를 유지한다.

    먼저 GET /login으로 CSRF 토큰을 받은 다음, 같은 Session을 사용하여
    POST /login 요청을 보낸다.

    로그인 성공 시 서버가 /dashboard로 리다이렉트하므로 302 응답을
    성공 기준으로 사용한다.
    """
    base_url = base_url.rstrip("/")
    login_url = f"{base_url}/login"

    # 1. 로그인 화면에서 CSRF 토큰과 세션 쿠키 획득
    login_page = session.get(
        login_url,
        timeout=REQUEST_TIMEOUT,
    )
    login_page.raise_for_status()

    csrf_token = extract_csrf_token(login_page.text)

    # HTTPS 환경의 Flask-WTF CSRF 검사를 고려한 Referer 설정
    session.headers["Referer"] = login_url

    # 2. 로그인 폼 제출
    response = session.post(
        login_url,
        data={
            "username": username,
            "password": password,
            "csrf_token": csrf_token,

            # 봇 탐지용 허니팟 필드는 반드시 비워둔다.
            "website": "",
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )

    location = response.headers.get("Location", "")

    if response.status_code in (301, 302, 303) and "/dashboard" in location:
        print(f"[OK] 테스트 계정 '{username}'으로 로그인했습니다.")
        return True

    print(
        "[FAIL] 로그인에 실패했습니다.\n"
        f"       상태 코드: {response.status_code}\n"
        f"       이동 경로: {location or '없음'}",
        file=sys.stderr,
    )
    return False



def fetch_board_csrf_token(
    session: requests.Session,
    base_url: str,
) -> str:
    """게시글 작성 화면에서 CSRF 토큰을 가져온다."""
    base_url = base_url.rstrip("/")
    board_new_url = f"{base_url}/board/new"

    response = session.get(
        board_new_url,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    # 로그인이 풀렸다면 /login으로 이동할 수 있다.
    if "/login" in response.url:
        raise RuntimeError(
            "게시글 작성 화면에 접근하지 못했습니다. "
            "로그인 상태를 확인하세요."
        )

    return extract_csrf_token(response.text)


def create_spam_post_data(
    attempt_number: int,
    csrf_token: str,
) -> dict[str, str]:
    """요청마다 구분 가능한 스팸 게시글 데이터를 생성한다."""
    timestamp = int(time.time())

    return {
        "title": f"[SPAM-TEST] 자동 게시글 {timestamp}-{attempt_number}",
        "body": (
            "자동화된 게시글 반복 등록 시뮬레이션입니다.\n"
            f"요청 번호: {attempt_number}\n"
            "본 데이터는 로컬 보안 프로젝트 테스트 목적으로 생성되었습니다."
        ),
        "csrf_token": csrf_token,

        # 이 필드에 값이 있으면 게시글 스팸이 아닌 허니팟 봇 탐지에 걸린다.
        "website": "",
    }


def attempt_create_post(
    session: requests.Session,
    base_url: str,
    post_data: dict[str, str],
) -> requests.Response:
    """게시글 작성 요청 한 건을 전송한다."""
    base_url = base_url.rstrip("/")
    board_new_url = f"{base_url}/board/new"

    return session.post(
        board_new_url,
        data=post_data,
        timeout=REQUEST_TIMEOUT,

        # 성공 시 게시글 상세 화면으로 이동한다.
        # 302를 직접 확인하기 위해 자동 이동은 막는다.
        allow_redirects=False,
    )


def run(
    base_url: str,
    username: str,
    password: str,
    attempts: int,
    interval: float,
) -> bool:
    """로그인 후 게시글 작성 요청을 반복 전송한다."""
    base_url = base_url.rstrip("/")
    board_new_url = f"{base_url}/board/new"

    session = requests.Session()
    session.headers["User-Agent"] = (
        "Login-Watchdog-Post-Spam-Simulator/1.0"
    )

    print("=" * 60)
    print("게시글 스팸 시뮬레이션")
    print("=" * 60)
    print(f"[*] 대상 주소 : {board_new_url}")
    print(f"[*] 사용 계정 : {username}")
    print(f"[*] 요청 횟수 : {attempts}회")
    print(f"[*] 요청 간격 : {interval}초")

    if not login(
        session=session,
        base_url=base_url,
        username=username,
        password=password,
    ):
        return False

    # 게시글 작성 화면에서 CSRF 토큰을 받는다.
    session.headers["Referer"] = board_new_url

    csrf_token = fetch_board_csrf_token(
        session=session,
        base_url=base_url,
    )

    created_count = 0
    rejected_count = 0
    created_locations: list[str] = []

    print("-" * 60)

    for attempt_number in range(1, attempts + 1):
        post_data = create_spam_post_data(
            attempt_number=attempt_number,
            csrf_token=csrf_token,
        )

        response = attempt_create_post(
            session=session,
            base_url=base_url,
            post_data=post_data,
        )

        location = response.headers.get("Location", "")

        # 게시글 작성 성공 시 /board/숫자 형태로 리다이렉트된다.
        created = (
            response.status_code in (301, 302, 303)
            and "/board/" in location
        )

        if created:
            created_count += 1
            created_locations.append(location)
            result = "게시글 생성"
        else:
            rejected_count += 1
            result = "작성 거부"

        print(
            f"    요청 {attempt_number:>2}/{attempts}"
            f" | 상태 {response.status_code}"
            f" | {result}"
            f" | {post_data['title']}"
        )

        if attempt_number < attempts:
            time.sleep(interval)

    print("-" * 60)
    print(f"[*] 생성된 게시글: {created_count}개")
    print(f"[*] 거부된 요청  : {rejected_count}개")

    if created_locations:
        print("[*] 생성된 게시글 경로")

        for location in created_locations:
            print(f"    - {location}")

    print(f"[OK] 총 {attempts}회의 게시글 작성 요청을 전송했습니다.")

    return True


def main() -> None:
    """명령행 옵션을 읽고 게시글 스팸 시뮬레이션을 실행한다."""
    parser = argparse.ArgumentParser(
        description=(
            "테스트 계정으로 로그인하여 게시글 작성 요청을 "
            "반복 전송하는 스팸 시뮬레이터"
        )
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"테스트 대상 서버 주소 (기본값: {DEFAULT_HOST})",
    )

    parser.add_argument(
        "--username",
        default=os.environ.get("SPAM_TEST_USERNAME"),
        help=(
            "게시글 작성에 사용할 테스트 계정 아이디. "
            "생략하면 실행 중 입력받는다."
        ),
    )

    parser.add_argument(
        "--password",
        default=os.environ.get("SPAM_TEST_PASSWORD"),
        help=(
            "테스트 계정 비밀번호. 생략하면 화면에 표시하지 않고 입력받는다. "
            "명령행에 직접 입력하면 기록에 남을 수 있으므로 입력 방식을 권장한다."
        ),
    )

    parser.add_argument(
        "--attempts",
        type=int,
        default=DEFAULT_ATTEMPTS,
        help=f"게시글 작성 요청 횟수 (기본값: {DEFAULT_ATTEMPTS})",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"각 요청 사이의 대기 시간(초) (기본값: {DEFAULT_INTERVAL})",
    )

    parser.add_argument(
        "--i-know-what-im-doing",
        action="store_true",
        help="로컬이 아닌 팀 소유 테스트 서버에 실행할 때 필요한 확인 옵션",
    )

    args = parser.parse_args()

    if not is_local_host(args.host) and not args.i_know_what_im_doing:
        print(
            "[FAIL] 기본적으로 로컬 서버에서만 실행할 수 있습니다.",
            file=sys.stderr,
        )
        sys.exit(2)

    if args.attempts <= 0:
        print(
            "[FAIL] --attempts는 1 이상이어야 합니다.",
            file=sys.stderr,
        )
        sys.exit(2)

    if args.interval < 0:
        print(
            "[FAIL] --interval은 0 이상이어야 합니다.",
            file=sys.stderr,
        )
        sys.exit(2)

    username = args.username

    if not username:
        username = input("테스트 계정 아이디: ").strip()

    password = args.password

    if not password:
        password = getpass.getpass("테스트 계정 비밀번호: ")

    try:
        success = run(
            base_url=args.host,
            username=username,
            password=password,
            attempts=args.attempts,
            interval=args.interval,
        )

    except requests.ConnectionError:
        print(
            "[FAIL] Flask 서버에 연결할 수 없습니다.",
            file=sys.stderr,
        )
        sys.exit(1)

    except requests.Timeout:
        print(
            "[FAIL] 서버 응답 시간이 초과되었습니다.",
            file=sys.stderr,
        )
        sys.exit(1)

    except requests.RequestException as error:
        print(
            f"[FAIL] 요청 중 오류가 발생했습니다: {error}",
            file=sys.stderr,
        )
        sys.exit(1)

    except RuntimeError as error:
        print(
            f"[FAIL] {error}",
            file=sys.stderr,
        )
        sys.exit(1)

    except KeyboardInterrupt:
        print(
            "\n[중단] 사용자가 시뮬레이션을 중단했습니다.",
            file=sys.stderr,
        )
        sys.exit(130)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()