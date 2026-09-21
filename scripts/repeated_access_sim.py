# ============================================================================
# repeated_access_sim.py
#
# 목적:
#   동일한 IP에서 같은 페이지로 짧은 시간 동안 GET 요청을 반복하여
#   비정상적인 고빈도 페이지 접근 패턴을 발생시키는 시뮬레이션 프로그램이다.
#
# 담당 범위:
#   이 프로그램은 반복 접근 요청을 발생시키는 역할만 담당한다.
#   탐지, 기록, 경고, 차단 여부는 서버의 탐지 프로그램에서 처리한다.
#
# 기본 동작:
#   - 대상 서버: http://127.0.0.1:5000
#   - 대상 경로: /
#   - 요청 횟수: 21회
#   - 요청 간격: 0.1초
#   - 동일한 requests.Session을 사용하여 같은 사용자의 반복 접근을 표현한다.
#
# 안전 원칙:
#   기본적으로 localhost, 127.0.0.1, ::1만 실행할 수 있다.
#   팀이 소유한 외부 테스트 서버에 실행하려면
#   --i-know-what-im-doing 옵션을 명시적으로 추가해야 한다.
#
# --------------------------------------------------------------------------
# 사용법
# --------------------------------------------------------------------------
#
# 1. 기본 실행
#    python .\scripts\repeated_access_sim.py
#
# 2. /login 페이지에 30회 반복 요청
#    python .\scripts\repeated_access_sim.py --path /login --attempts 30
#
# 3. 요청 사이에 0.5초 간격 적용
#    python .\scripts\repeated_access_sim.py --interval 0.5
#
# 4. 대기 시간 없이 50회 요청
#    python .\scripts\repeated_access_sim.py --attempts 50 --interval 0
#
# 5. 가짜 공격자 IP를 X-Forwarded-For 헤더에 포함
#    python .\scripts\repeated_access_sim.py --ip 192.0.2.10
#
#    주의:
#    --ip 옵션은 대상 Flask 서버의 TRUST_FORWARDED_FOR=true 설정이
#    활성화된 로컬 데모 환경에서만 실제 접속 IP처럼 반영된다.
#
# 6. 팀이 소유한 외부 테스트 서버에 실행
#    python .\scripts\repeated_access_sim.py `
#        --host https://test.example.com `
#        --path /login `
#        --attempts 21 `
#        --i-know-what-im-doing
#
# 실제 서비스나 허가받지 않은 타인의 서버에는 절대 실행하지 않는다.
# ============================================================================

import argparse
import sys
import time
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


load_dotenv()


# 기본 실행 설정
DEFAULT_HOST = "http://127.0.0.1:5000"
DEFAULT_PATH = "/"
DEFAULT_ATTEMPTS = 21
DEFAULT_INTERVAL = 0.1
REQUEST_TIMEOUT = 5


def is_local_host(host: str) -> bool:
    """입력받은 서버 주소가 로컬 주소인지 확인한다.

    urlparse()를 사용하여 전체 URL에서 호스트 부분만 추출한다.

    허용되는 로컬 주소:
        - 127.0.0.1
        - localhost
        - ::1
    """
    hostname = urlparse(host).hostname or ""

    return hostname in ("127.0.0.1", "localhost", "::1")


def normalize_path(path: str) -> str:
    """페이지 경로가 항상 슬래시(/)로 시작하도록 정리한다."""
    if not path.startswith("/"):
        return f"/{path}"

    return path


def request_page(
    session: requests.Session,
    base_url: str,
    path: str,
) -> requests.Response:
    """지정된 페이지에 GET 요청 한 건을 전송한다.

    allow_redirects=False를 사용한 이유:
    / 요청이 /login으로 이동하는 것처럼 리다이렉트가 발생하더라도,
    추가 요청을 자동으로 보내지 않도록 하기 위해서다.

    이렇게 해야 반복 횟수와 실제 전송 요청 수가 일치한다.
    """
    base_url = base_url.rstrip("/")
    path = normalize_path(path)
    url = f"{base_url}{path}"

    return session.get(
        url,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )


def run(
    base_url: str,
    path: str,
    attempts: int,
    interval: float,
    ip: str | None = None,
) -> bool:
    """같은 페이지에 지정된 횟수만큼 GET 요청을 반복 전송한다.

    같은 requests.Session 객체를 계속 사용하므로 서버가 발급한 쿠키가
    요청 사이에 유지된다. 따라서 같은 IP뿐만 아니라 같은 브라우저 또는
    같은 사용자가 페이지를 반복해서 접근하는 상황도 표현할 수 있다.

    ip 값이 지정되면 모든 요청에 X-Forwarded-For 헤더를 포함한다.
    단, 서버가 해당 헤더를 신뢰하도록 설정된 로컬 데모 환경에서만
    실제 접속 IP 판정에 반영된다.

    반환값:
        모든 요청 전송 완료: True
        요청 도중 통신 오류: 상위 main()으로 예외 전달
    """
    base_url = base_url.rstrip("/")
    path = normalize_path(path)
    target_url = f"{base_url}{path}"

    print("=" * 60)
    print("반복 페이지 접근 시뮬레이션")
    print("=" * 60)
    print(f"[*] 대상 페이지 : {target_url}")
    print(f"[*] 요청 횟수   : {attempts}회")
    print(f"[*] 요청 간격   : {interval}초")

    session = requests.Session()

    # 일반적인 브라우저 요청처럼 User-Agent를 지정한다.
    session.headers["User-Agent"] = (
        "Login-Watchdog-Repeated-Access-Simulator/1.0"
    )

    if ip:
        session.headers["X-Forwarded-For"] = ip
        print(f"[*] 시뮬레이션 IP: {ip}")
        print(
            "    서버의 TRUST_FORWARDED_FOR=true 설정에서만 "
            "실제 요청 IP처럼 반영됩니다."
        )

    print("-" * 60)

    status_counts: dict[int, int] = {}

    for attempt_number in range(1, attempts + 1):
        response = request_page(
            session=session,
            base_url=base_url,
            path=path,
        )

        status_code = response.status_code
        elapsed_ms = response.elapsed.total_seconds() * 1000

        status_counts[status_code] = (
            status_counts.get(status_code, 0) + 1
        )

        print(
            f"    요청 {attempt_number:>3}/{attempts}"
            f" | 상태 코드: {status_code}"
            f" | 응답 시간: {elapsed_ms:.1f}ms"
        )

        # 마지막 요청 이후에는 기다릴 필요가 없다.
        if attempt_number < attempts:
            time.sleep(interval)

    print("-" * 60)
    print(f"[OK] 동일 페이지에 총 {attempts}회 요청을 전송했습니다.")

    print("[*] 상태 코드 집계")

    for status_code, count in sorted(status_counts.items()):
        print(f"    {status_code}: {count}회")

    return True


def main() -> None:
    """명령행 옵션을 읽고 반복 접근 시뮬레이션을 실행한다."""
    parser = argparse.ArgumentParser(
        description=(
            "동일한 IP 또는 세션에서 같은 페이지를 반복 요청하는 "
            "고빈도 페이지 접근 시뮬레이터"
        )
    )

    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=(
            "테스트 대상 서버 주소 "
            f"(기본값: {DEFAULT_HOST})"
        ),
    )

    parser.add_argument(
        "--path",
        default=DEFAULT_PATH,
        help=(
            "반복 접근할 페이지 경로 "
            f"(기본값: {DEFAULT_PATH})"
        ),
    )

    parser.add_argument(
        "--attempts",
        type=int,
        default=DEFAULT_ATTEMPTS,
        help=(
            "전송할 총 요청 횟수 "
            f"(기본값: {DEFAULT_ATTEMPTS})"
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=(
            "각 요청 사이의 대기 시간(초) "
            f"(기본값: {DEFAULT_INTERVAL})"
        ),
    )

    parser.add_argument(
        "--ip",
        help=(
            "X-Forwarded-For 헤더에 포함할 가짜 공격자 IP. "
            "서버의 TRUST_FORWARDED_FOR=true 설정에서만 반영된다."
        ),
    )

    parser.add_argument(
        "--i-know-what-im-doing",
        action="store_true",
        help=(
            "localhost가 아닌 팀 소유 테스트 서버에 실행할 때 "
            "필요한 확인 옵션"
        ),
    )

    args = parser.parse_args()

    # 실수로 외부 서비스에 반복 요청을 보내는 상황을 방지한다.
    if not is_local_host(args.host) and not args.i_know_what_im_doing:
        print(
            "[FAIL] 이 프로그램은 기본적으로 로컬 서버만 대상으로 합니다.\n"
            f"       입력된 주소: {args.host}\n"
            "       팀이 소유한 테스트 서버가 확실하다면 "
            "--i-know-what-im-doing 옵션을 추가하세요.",
            file=sys.stderr,
        )
        sys.exit(2)

    # 잘못된 요청 횟수 방지
    if args.attempts <= 0:
        print(
            "[FAIL] --attempts 값은 1 이상이어야 합니다.",
            file=sys.stderr,
        )
        sys.exit(2)

    # 음수 대기 시간 방지
    if args.interval < 0:
        print(
            "[FAIL] --interval 값은 0 이상이어야 합니다.",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        success = run(
            base_url=args.host,
            path=args.path,
            attempts=args.attempts,
            interval=args.interval,
            ip=args.ip,
        )

    except requests.ConnectionError:
        print(
            f"[FAIL] {args.host} 서버에 연결할 수 없습니다.\n"
            "       Flask 서버가 실행 중인지 확인하세요.",
            file=sys.stderr,
        )
        sys.exit(1)

    except requests.Timeout:
        print(
            "[FAIL] 서버가 제한 시간 안에 응답하지 않았습니다.",
            file=sys.stderr,
        )
        sys.exit(1)

    except requests.RequestException as error:
        print(
            f"[FAIL] 요청 중 오류가 발생했습니다: {error}",
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