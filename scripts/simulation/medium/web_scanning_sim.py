# ============================================================================
# web_scanning_sim.py — "웹 스캐닝(Web Scanning)" 공격을 흉내 내서, 우리 서버의
# 탐지 로직이 실제로 알림을 울리는지 확인하는 검증 스크립트
#
# 웹 스캐닝이란? 공격자가 로그인도 하지 않은 채 "/admin.php", "/.env",
# "/wp-login.php" 같은, 흔히 취약한 서버에 존재하는 경로들을 무작위로 여러 번
# 두드려보며 "혹시 이 서버에 뚫을 수 있는 부분이 있나?"를 탐색하는 행위다.
# 이 스크립트는 그런 행동을 안전하게 재현해서, 우리 서버가 "누군가 스캐닝
# 중이다"라고 알아채는지 눈으로 확인하기 위해 만들어졌다.
#
# 동작 요약:
#   1) 로그인이나 쿠키 없이, 존재하지 않는 경로로 GET 요청을 11번 순서대로 보낸다.
#   2) 경로는 실제 스캐너들이 즐겨 찾는 이름들(TARGETS 목록)을 뒤에 무작위 값을
#      붙여서 절대 진짜로 존재하지 않게 만든다 — 그래서 항상 404(없음) 응답을
#      기대한다.
#   3) 11번 모두 404가 나오고, 전체 소요 시간이 서버의 탐지 시간창(기본 60초)
#      안에 들어오면 "탐지 조건을 재현했다"고 보고, 이후 실제로 서버가 알림을
#      울렸는지는 사람이 직접 로그/Slack/대시보드를 보고 확인해야 한다.
#
# 안전 원칙: 표준 라이브러리만 사용하며(외부 패키지 설치 불필요), 기본 대상은
# 로컬 서버(http://127.0.0.1:5000)다. 남의 서버나 실제 운영 중인 서비스에는
# 절대 실행하면 안 된다 — 소유하고 있거나 테스트 허락을 받은 서버에서만 쓴다.
# ============================================================================

import argparse
import math
import random
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


# 실제 공격자/스캐너들이 자주 찔러보는 "약점이 있을 법한" 경로 이름 모음.
# 예: .env(비밀 설정 파일), wp-login.php(워드프레스 로그인), backup.sql(DB 백업)
# 이 중 11개를 무작위로 골라서 요청을 보낸다(TARGETS 자체가 11개라 전부 사용됨).
TARGETS = (
    "admin.php", ".env", "wp-login.php", "wp-admin", "phpmyadmin",
    ".git/config", "backup.sql", "config.php", "xmlrpc.php", "server-status",
    "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
)


class NoRedirect(HTTPRedirectHandler):
    """서버가 "다른 주소로 가라"고 응답해도 그 말을 듣지 않게 막는 장치.

    브라우저처럼 자동으로 리다이렉트를 따라가 버리면, 원래 보내려던 11번의
    GET 요청보다 실제로는 더 많은 요청이 전송되어 "정확히 11회"라는 테스트
    조건이 깨질 수 있다. 그래서 리다이렉트를 받아도 그냥 무시하고 멈춘다.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 리다이렉트가 추가 GET을 만들어 11회 조건을 깨뜨리지 않게 한다.
        return None


def normalize_host(value):
    """사용자가 --host로 입력한 주소가 올바른 형태인지 검사하고 다듬는다.

    "http://127.0.0.1:5000" 처럼 스킴(http/https)과 호스트만 있는 깔끔한
    주소만 허용한다. 아이디/비밀번호가 박혀있거나("http://user:pw@..."),
    경로나 쿼리가 붙어있거나("http://host/foo?x=1"), 중간에 공백이 있는
    등 이상한 입력은 실행 전에 미리 걸러내서 엉뚱한 곳에 요청이 나가는
    사고를 막는다. 문제가 있으면 사람이 이해할 수 있는 에러 메시지로
    바로 알려준다.
    """
    try:
        parsed = urlsplit(value)
        parsed.port  # 잘못된 포트도 요청 전에 거부한다.
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in ("", "/")
                or any(char.isspace() for char in value)):
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("http(s)://호스트[:포트] 형식으로 입력하세요.") from None
    return value.rstrip("/")


def positive_seconds(value):
    """--timeout, --window로 입력한 값이 "0보다 큰 정상적인 초 단위 숫자"인지 검사한다.

    "abc" 같은 숫자가 아닌 값, 0이나 음수, 무한대(inf) 같은 값이 들어오면
    타이머 계산이 이상해지거나 프로그램이 영원히 멈출 수 있으므로 미리 막는다.
    """
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("양수인 초 단위 숫자가 필요합니다.") from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("유한한 양수가 필요합니다.")
    return number


def run(base_url, timeout=5.0, window=60.0):
    """실제로 GET 요청 11번을 순서대로 쏘고, 결과를 사람이 읽기 쉬운 로그로 출력한다."""
    # run_id: 이번 실행을 다른 실행과 구분하는 고유한 임의 문자열.
    # 나중에 서버 로그에서 "이 run_id가 들어간 요청이 정말 11번 찍혔는지"를
    # 찾아 대조할 수 있게 해주는 표식이다.
    run_id = uuid.uuid4().hex
    # TARGETS 중 11개를 무작위 순서로 뽑고, 각 경로 끝에 run_id를 붙여
    # "절대 실제로 존재하지 않는 경로"로 만든다 → 항상 404가 나와야 정상.
    paths = [f"/{target}/__scan_{run_id}" for target in random.sample(TARGETS, 11)]
    # 시스템 프록시/인증/쿠키 없이 같은 대상에 직접 순차 요청한다.
    # (프록시를 끄는 이유: 회사/개인 PC에 설정된 프록시를 거치면 요청이
    #  엉뚱한 경로로 새거나 로그가 뒤섞일 수 있기 때문)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    print(f"[START] {datetime.now(timezone.utc).isoformat()} run_id={run_id}")
    print(f"[TARGET] {base_url} | GET 11회 | 로그인 불필요", flush=True)
    started = time.monotonic()
    statuses = []  # 각 요청마다 받은 HTTP 상태 코드(예: 404)를 순서대로 쌓아둔다.
    for index, path in enumerate(paths, 1):
        # User-Agent를 지정해 "이건 사람이 브라우저로 접속한 게 아니라
        # 이 테스트 스크립트가 보낸 요청"이라는 걸 서버 로그에서 구분할 수 있게 한다.
        request = Request(base_url + path, headers={"User-Agent": "Watchdog-WebScanning-Test/1.0"})
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
        except HTTPError as error:
            status = error.code  # urllib은 정상적인 테스트 응답인 404도 예외로 반환한다.
            error.close()
        except (URLError, OSError) as error:
            # 서버가 꺼져있거나 네트워크 문제로 아예 연결이 안 된 경우.
            # 이런 경우는 "탐지 실패"가 아니라 "테스트를 아예 못 돌린 것"이므로
            # 재시도 없이 바로 중단하고 사람이 원인을 확인하게 한다.
            print(f"[ERROR] {index:02d}/11 GET {path}: {error}", flush=True)
            print("[INCOMPLETE] 자동 재시도 없이 중단했습니다. 서버 도달 여부는 로그로 확인하세요.")
            return 1
        statuses.append(status)
        print(f"[{index:02d}/11] GET {path} -> {status}", flush=True)

    elapsed = time.monotonic() - started
    print(f"[SUMMARY] 404={statuses.count(404)}/11, elapsed={elapsed:.2f}s")
    # 성공 조건: 11번 모두 404(없음)이었고, 전체 걸린 시간이 탐지 시간창보다 짧아야
    # "서버 입장에서 짧은 시간 안에 11번의 스캐닝성 요청이 몰렸다"는 상황이 재현된 것.
    valid = all(status == 404 for status in statuses) and elapsed < window
    if not valid:
        print("[INCOMPLETE] 404 11회 또는 지정한 탐지 시간창 조건을 충족하지 못했습니다.")
    # 이 스크립트는 요청을 보내는 것까지만 확인할 뿐, 서버가 실제로 "알림을
    # 울렸는지"는 알 수 없다. 그래서 아래처럼 사람이 직접 확인해야 할 항목을
    # 안내 문구로 남긴다.
    print("[VERIFY] 404만으로 탐지 성공을 확정할 수 없습니다.")
    print("  Slack/서버 로그: [MEDIUM] 및 'Web Scanning 의심' 확인")
    print("  관리자 대시보드 또는 로그인된 GET /api/status의 security_events 확인")
    print(f"  event_type=WEB_SCANNING, severity=MEDIUM, count=11, path에 {run_id} 포함")
    return 0 if valid else 1


def main():
    """커맨드라인 인자(--host, --timeout, --window)를 읽어서 run()을 실행한다."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=normalize_host, default="http://127.0.0.1:5000",
                        help="본인 소유 또는 테스트 허가를 받은 서버의 기본 URL")
    parser.add_argument("--timeout", type=positive_seconds, default=5.0,
                        help="요청별 소켓 타임아웃(초), 기본 5")
    parser.add_argument("--window", type=positive_seconds, default=60.0,
                        help="서버 DETECTION_WINDOW_SECONDS에 맞춘 검증 시간창, 기본 60")
    args = parser.parse_args()
    return run(args.host, args.timeout, args.window)


if __name__ == "__main__":
    # 터미널에서 "python web_scanning_sim.py"로 직접 실행했을 때만 동작하고,
    # 다른 파일에서 import만 했을 때는 자동으로 실행되지 않게 하는 관용적인 표현이다.
    raise SystemExit(main())
