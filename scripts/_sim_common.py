# ============================================================================
# scripts/_sim_common.py — 공격 시뮬레이션 스크립트(*_sim.py)가 같이 쓰는 작은 도우미
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
