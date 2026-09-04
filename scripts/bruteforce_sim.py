# ============================================================================
# bruteforce_sim.py — /login에 대한 브루트포스 공격을 흉내내서, IP 잠금이
# 정말로 6번째 시도에서 걸리는지 자동으로 확인하는 검증 스크립트
#
# research.md(공격 시뮬레이션 절)와 plan.md(검증 절차)에 적힌 스펙:
#   1) 일부러 틀린 비밀번호로 /login에 POST 요청을 5회 순차 전송한다
#      (config.FAILURE_THRESHOLD 기본값 5회 = "60초 안에 5번 틀리면 잠금").
#   2) 6번째 요청을 한 번 더 보내서, 응답 본문에 "잠긴 계정" 문구가
#      포함되는지 확인한다 — 포함되면 잠금이 정상 동작한 것이다.
#
# 안전 원칙(research.md에 명시): 이 스크립트는 팀이 소유한 로컬 서버(기본값
# http://127.0.0.1:5000)만 대상으로 한다. 실제 서비스나 타인의 서버에 이
# 스크립트를 실행하는 것은 절대 금지된다 — 그래서 --host로 localhost/127.0.0.1이
# 아닌 주소를 지정하면 --i-know-what-im-doing 플래그 없이는 실행을 거부한다.
# ============================================================================

import argparse
import sys
from urllib.parse import urlparse

import requests

LOCKED_MESSAGE = "잠긴 계정입니다"


def is_local_host(host: str) -> bool:
    """--host로 받은 주소가 로컬(내 컴퓨터) 서버인지 확인한다.

    urlparse().hostname으로 "http://127.0.0.1:5000" 같은 문자열에서 호스트
    부분만 뽑아내, localhost/127.0.0.1 계열인지만 확인한다.
    """
    hostname = urlparse(host).hostname or ""
    return hostname in ("127.0.0.1", "localhost", "::1")


def fetch_csrf_token(session: requests.Session, base_url: str) -> str:
    """/login 화면을 한 번 GET으로 받아와서, 폼에 숨겨진 csrf_token 값을 뽑아온다.

    app.py에 CSRFProtect가 적용된 뒤로는(2번째 보안 수정), 이 토큰 없이 POST를
    보내면 로그인 로직이 실행되기도 전에 400(Bad Request)으로 거부된다. 브라우저는
    화면을 먼저 열어서 이 토큰을 자동으로 받아두므로, 이 스크립트도 실제 로그인
    시도를 흉내내려면 똑같이 먼저 화면을 한 번 열어봐야 한다.
    """
    response = session.get(f"{base_url}/login", timeout=5)
    marker = 'name="csrf_token" value="'
    start = response.text.index(marker) + len(marker)
    end = response.text.index('"', start)
    return response.text[start:end]


def attempt_login(
    session: requests.Session, base_url: str, username: str, password: str, csrf_token: str
) -> requests.Response:
    """/login에 아이디/비밀번호를 폼(form) 형식으로 제출하는 요청 한 건을 보낸다.

    app.py의 login_submit()이 request.form.get(...)으로 값을 읽으므로, JSON이
    아니라 브라우저 폼 제출과 똑같은 방식(data=... 로 보내면 requests가 자동으로
    application/x-www-form-urlencoded 형식을 써준다)으로 보내야 한다. csrf_token도
    폼 필드 중 하나이므로 같은 data 딕셔너리에 함께 실어 보낸다.

    session(requests.Session)을 매번 새로 만들지 않고 재사용하는 이유: 이 토큰은
    서버가 발급한 세션 쿠키와 짝을 이뤄야 유효하다고 검증되므로, GET에서 받은
    쿠키를 POST에도 그대로 이어서 보내야 한다(브라우저가 쿠키를 자동으로 유지하는
    것과 같은 원리) — requests.Session이 쿠키를 요청 사이에 자동으로 이어준다.
    """
    return session.post(
        f"{base_url}/login",
        data={"username": username, "password": password, "csrf_token": csrf_token},
        timeout=5,
    )


def run(base_url: str, username: str, attempts: int) -> bool:
    """실패 요청을 `attempts`번 순차로 보낸 뒤, 마지막(6번째) 요청의 응답에
    잠금 문구가 포함돼 있는지 확인한다.

    반환값: 검증 통과 여부(True/False). main()에서 이 값을 프로세스 종료
    코드로 변환해서, CI 등 다른 도구가 성공/실패를 스크립트 실행만으로
    판단할 수 있게 한다.
    """
    print(f"[*] {base_url}/login 에 틀린 비밀번호로 {attempts}회 연속 로그인 시도")

    session = requests.Session()
    csrf_token = fetch_csrf_token(session, base_url)

    response = None
    for i in range(1, attempts + 1):
        response = attempt_login(session, base_url, username, "wrong-password-on-purpose", csrf_token)
        locked = LOCKED_MESSAGE in response.text
        print(f"    시도 {i}/{attempts} - 상태 코드 {response.status_code}"
              f"{' - 이미 잠김' if locked else ''}")

    if response is not None and LOCKED_MESSAGE in response.text:
        print(f"[OK] {attempts}번째 시도에서 '{LOCKED_MESSAGE}' 문구를 확인했습니다. 잠금 정상 동작.")
        return True

    print(f"[FAIL] {attempts}번을 시도했지만 '{LOCKED_MESSAGE}' 문구를 찾지 못했습니다. 잠금이 걸리지 않았습니다.")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="로그인 워치독의 IP 브루트포스 잠금이 정상 동작하는지 확인하는 시뮬레이션 스크립트."
    )
    parser.add_argument(
        "--host", default="http://127.0.0.1:5000",
        help="테스트 대상 서버 주소 (기본값: 로컬 개발 서버 http://127.0.0.1:5000)",
    )
    parser.add_argument(
        "--username", default="nonexistent-user",
        help="시도에 사용할 아이디 (실제로 존재하지 않아도 된다 - 어차피 비밀번호부터 틀리게 보낸다)",
    )
    parser.add_argument(
        "--attempts", type=int, default=6,
        help="총 몇 번 요청을 보낼지 (기본값 6 = config.FAILURE_THRESHOLD 기본값 5 + 잠금 확인용 1회)",
    )
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

    success = run(args.host, args.username, args.attempts)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
