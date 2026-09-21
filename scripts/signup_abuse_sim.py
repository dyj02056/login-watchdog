# ============================================================================
# signup_abuse_sim.py
#
# 목적:
#   짧은 시간 동안 서로 다른 계정의 회원가입 요청을 반복하여
#   자동화된 계정 생성 남용(Signup Flooding) 패턴을 발생시킨다.
#
# 담당 범위:
#   이 프로그램은 비정상적인 회원가입 요청을 발생시키는 역할만 담당한다.
#   탐지, 기록, 경고 및 차단은 서버의 탐지 프로그램에서 처리한다.
#
# 기본 시나리오:
#   1. GET /signup으로 CSRF 토큰과 세션 쿠키 획득
#   2. 고유한 아이디와 이메일을 생성
#   3. POST /signup 요청을 짧은 간격으로 6회 전송
#
# 예상 흐름:
#   - 1~5번째 요청: 테스트 계정 생성
#   - 6번째 요청: 회원가입 빈도 제한으로 거부
#
# 안전 원칙:
#   실제 테스트 계정이 DB에 생성되므로 로컬 또는 팀 소유 테스트 서버에서만
#   사용해야 한다. 테스트 후 생성된 계정은 관리자 화면에서 삭제한다.
#
# 허니팟:
#   website 필드가 채워지면 서버가 즉시 봇으로 판단한다.
#   이번 시나리오는 회원가입 빈도 제한을 시험하므로 website는 비워둔다.
# ============================================================================

import argparse
import sys
import time
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


load_dotenv()


DEFAULT_HOST = "http://127.0.0.1:5000"
DEFAULT_ATTEMPTS = 3
DEFAULT_INTERVAL = 0.2
DEFAULT_PASSWORD = "TestPass123!"
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
    """HTML 문서에서 csrf_token 값을 추출한다."""
    parser = CsrfTokenParser()
    parser.feed(html)

    if not parser.token:
        raise RuntimeError(
            "회원가입 화면에서 CSRF 토큰을 찾지 못했습니다."
        )

    return parser.token


def is_local_host(host: str) -> bool:
    """대상 서버가 로컬 주소인지 확인한다."""
    hostname = urlparse(host).hostname or ""

    return hostname in ("127.0.0.1", "localhost", "::1")


def create_account_data(index: int) -> dict[str, str]:
    """요청마다 중복되지 않는 테스트 계정 정보를 생성한다.

    현재 시각을 아이디와 이메일에 포함하여 스크립트를 다시 실행해도
    기존 계정과 최대한 중복되지 않도록 한다.
    """
    timestamp = datetime.now().strftime("%m%d%H%M%S")

    username = f"bot{timestamp}{index}"
    email = f"{username}@example.com"

    return {
        "username": username,
        "email": email,
        "password": DEFAULT_PASSWORD,
        "password_confirm": DEFAULT_PASSWORD,

        # 비어 있지 않으면 별도의 봇 탐지에 걸리므로 빈 값으로 유지한다.
        "website": "",
    }

def fetch_signup_csrf_token(
    session: requests.Session,
    base_url: str,
) -> str:
    """회원가입 화면에서 CSRF 토큰과 세션 쿠키를 획득한다."""
    base_url = base_url.rstrip("/")
    signup_url = f"{base_url}/signup"

    response = session.get(
        signup_url,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    return extract_csrf_token(response.text)


def attempt_signup(
    session: requests.Session,
    base_url: str,
    account_data: dict[str, str],
    csrf_token: str,
) -> requests.Response:
    """테스트 계정 한 개의 회원가입 요청을 전송한다."""
    base_url = base_url.rstrip("/")
    signup_url = f"{base_url}/signup"

    form_data = {
        **account_data,
        "csrf_token": csrf_token,
    }

    return session.post(
        signup_url,
        data=form_data,
        timeout=REQUEST_TIMEOUT,

        # 성공 시 /login으로 이동하지만 자동으로 따라가지 않는다.
        # 그래야 302를 기준으로 가입 성공 여부를 구분할 수 있다.
        allow_redirects=False,
    )


def run(
    base_url: str,
    attempts: int,
    interval: float,
    ip: str | None = None,
) -> bool:
    """서로 다른 테스트 계정의 회원가입 요청을 반복 전송한다."""
    base_url = base_url.rstrip("/")
    signup_url = f"{base_url}/signup"

    session = requests.Session()

    session.headers["Referer"] = signup_url
    session.headers["User-Agent"] = (
        "Login-Watchdog-Signup-Abuse-Simulator/1.0"
    )

    if ip:
        session.headers["X-Forwarded-For"] = ip

    print("=" * 60)
    print("자동화 계정 생성 남용 시뮬레이션")
    print("=" * 60)
    print(f"[*] 대상 주소   : {signup_url}")
    print(f"[*] 요청 횟수   : {attempts}회")
    print(f"[*] 요청 간격   : {interval}초")

    if ip:
        print(f"[*] 시뮬레이션 IP: {ip}")
        print(
            "    서버의 TRUST_FORWARDED_FOR=true 설정에서만 "
            "실제 요청 IP로 반영됩니다."
        )

    # 같은 세션 쿠키와 연결된 CSRF 토큰을 먼저 획득한다.
    csrf_token = fetch_signup_csrf_token(
        session=session,
        base_url=base_url,
    )

    successful_accounts: list[str] = []
    rejected_attempts = 0

    print("-" * 60)

    for attempt_number in range(1, attempts + 1):
        account_data = create_account_data(attempt_number)

        response = attempt_signup(
            session=session,
            base_url=base_url,
            account_data=account_data,
            csrf_token=csrf_token,
        )

        location = response.headers.get("Location", "")

        # 회원가입 성공 시 서버가 /login으로 리다이렉트한다.
        created = (
            response.status_code in (301, 302, 303)
            and "/login" in location
        )

        if created:
            successful_accounts.append(account_data["username"])
            result = "계정 생성"
        else:
            rejected_attempts += 1
            result = "생성 거부"

        print(
            f"    요청 {attempt_number:>2}/{attempts}"
            f" | {account_data['username']}"
            f" | 상태 {response.status_code}"
            f" | {result}"
        )

        if attempt_number < attempts:
            time.sleep(interval)

    print("-" * 60)
    print(f"[*] 생성된 계정: {len(successful_accounts)}개")
    print(f"[*] 거부된 요청: {rejected_attempts}개")

    if successful_accounts:
        print("[*] 생성 계정 목록")

        for username in successful_accounts:
            print(f"    - {username}")

    print(f"[OK] 총 {attempts}회의 자동 회원가입 요청을 전송했습니다.")

    return True


if __name__ == "__main__":
    try:
        success = run(
            base_url=DEFAULT_HOST,
            attempts=DEFAULT_ATTEMPTS,
            interval=DEFAULT_INTERVAL,
        )

        sys.exit(0 if success else 1)

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