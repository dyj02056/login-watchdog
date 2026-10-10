# ============================================================================
# scripts/simulation/_sim_common.py — 공격 시뮬레이션 스크립트(*_sim.py)가 같이 쓰는 작은 도우미
#
# bruteforce_sim / macro_bot_sim / repeated_access_sim / spam_sim이 똑같은
# is_local_host()를, signup_abuse_sim / spam_sim이 똑같은 CSRF 토큰 추출기를 각자
# 복사해 들고 있어서 한 곳으로 모았다(docs/refactor/2026-10-09-module-plan.md 5단계).
#
# 시뮬레이션 스크립트는 `python scripts/xxx_sim.py`로 실행하므로 scripts/ 폴더가
# sys.path 맨 앞에 들어가 `from _sim_common import ...`로 바로 가져올 수 있다.
# 파일 이름 앞의 밑줄(_)은 "직접 실행하는 스크립트가 아니라 부품"이라는 표시다.
#
# 다른 시뮬레이션(password_spraying_sim / web_scanning_sim / unauthorized_access_sim)은
# 루프백 판정·응답 검증을 더 엄격하게 따로 구현하고 있어서 여기로 합치지 않았다.
# ============================================================================

from html.parser import HTMLParser
from urllib.parse import urlparse


def is_local_host(host: str) -> bool:
    """--host로 받은 주소가 로컬(내 컴퓨터) 서버인지 확인한다.

    urlparse().hostname으로 "http://127.0.0.1:5000" 같은 문자열에서 호스트
    부분만 뽑아내, localhost/127.0.0.1 계열인지만 확인한다.
    """
    hostname = urlparse(host).hostname or ""
    return hostname in ("127.0.0.1", "localhost", "::1")


class CsrfTokenParser(HTMLParser):
    """HTML의 hidden input에서 CSRF 토큰을 추출한다.

    로그인/회원가입/글쓰기 화면 HTML 안에는 눈에 보이지 않는
    <input type="hidden" name="csrf_token" value="..."> 태그가 있는데,
    이 클래스가 HTML을 한 줄씩 읽어가며 그 값을 뽑아낸다. 사람이 직접
    화면 소스보기로 찾는 일을 프로그램이 대신 해주는 셈이다.
    """

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


def extract_csrf_token(html: str, page_name: str = "HTML 화면") -> str:
    """HTML 문서에서 csrf_token 값을 찾아 반환한다. 없으면 page_name을 넣은 안내와 함께 실패한다."""
    parser = CsrfTokenParser()
    parser.feed(html)

    if not parser.token:
        raise RuntimeError(
            f"{page_name}에서 CSRF 토큰을 찾지 못했습니다."
        )

    return parser.token


# ---------------------------------------------------------------------------
# 아래는 새로 만든 시뮬레이션들(분산/관리자 브루트포스, 영구 잠금, 사건 상관분석, HTTP 도배,
# 댓글 도배, 복구 요청 폭주, 허니팟)이 같이 쓰는 부품이다. 기존 시뮬레이션은 쓰지 않는다.
# ---------------------------------------------------------------------------

import random
import sys

import requests

# 서버가 로그인 실패 화면에 띄우는 문구의 일부 — 응답 본문에 들어 있는지로 서버의 반응을 판단한다.
LOCK_MESSAGE = "잠긴 계정입니다"
# 계정 단위 잠금에만 붙는 안내(routes/auth.py의 ACCOUNT_LOCKED_MESSAGE 뒷부분). IP 잠금과 구분하는 데 쓴다.
ACCOUNT_LOCK_MARKER = "계속 로그인할 수 없다면"
PERMANENT_BLOCK_MESSAGE = "이 네트워크는 차단되어 있습니다"

REQUEST_TIMEOUT = 5

# 문서용 예약 대역(RFC 5737) — 실제 누구의 주소도 아니므로 "가짜 공격자 IP"로 안전하게 쓴다.
_TEST_NET_PREFIXES = ("203.0.113.", "198.51.100.", "192.0.2.")


def random_test_ip() -> str:
    """실행할 때마다 다른 가짜 공격자 IP 하나를 고른다(이전 실행의 잠금과 겹치지 않게)."""
    return random.choice(_TEST_NET_PREFIXES) + str(random.randint(1, 254))


def require_local_or_exit(host: str, allow_remote: bool) -> None:
    """로컬 서버가 아닌데 --i-know-what-im-doing도 없으면 실행을 거부한다(종료 코드 2)."""
    if is_local_host(host) or allow_remote:
        return
    print(
        "[FAIL] 이 스크립트는 팀이 소유한 로컬 서버만 대상으로 실행하도록 만들어졌습니다.\n"
        f"    '{host}'는 로컬 주소가 아닙니다. 실제 서비스나 타인의 서버에는 절대 실행하지 마세요.\n"
        "    정말 본인 소유의 서버라면 --i-know-what-im-doing 플래그를 추가하세요.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def new_session(ip: str | None = None) -> requests.Session:
    """공격자 한 명(= 쿠키 항아리 하나)을 흉내 내는 세션. ip를 주면 X-Forwarded-For로 가짜 IP를 실어 보낸다.

    서버의 TRUST_FORWARDED_FOR=true일 때만 이 헤더가 반영된다(운영 기본값 false에서는 무시된다).
    """
    session = requests.Session()
    session.headers["User-Agent"] = "Login-Watchdog-Attack-Simulator/1.0"
    if ip:
        session.headers["X-Forwarded-For"] = ip
    return session


def fetch_csrf(session: requests.Session, base_url: str, path: str) -> str:
    """path 화면을 GET으로 열어 csrf_token을 뽑는다. 같은 세션 쿠키로 이어서 POST해야 유효하다."""
    response = session.get(f"{base_url}{path}", timeout=REQUEST_TIMEOUT)
    return extract_csrf_token(response.text, page_name=path)


def post_form(
    session: requests.Session, base_url: str, path: str, data: dict, csrf_token: str,
    referer_path: str | None = None, follow: bool = False,
) -> requests.Response:
    """폼 한 건을 제출한다. HTTPS 서버의 Referer 검사를 위해 Referer도 함께 보낸다."""
    session.headers["Referer"] = f"{base_url}{referer_path or path}"
    return session.post(
        f"{base_url}{path}", data={**data, "csrf_token": csrf_token},
        timeout=REQUEST_TIMEOUT, allow_redirects=follow,
    )
