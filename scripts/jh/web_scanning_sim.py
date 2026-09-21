"""로그인 없이 GET 11회로 Web Scanning 탐지를 재현한다 (표준 라이브러리만 사용)."""

import argparse
import math
import random
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


TARGETS = (
    "admin.php", ".env", "wp-login.php", "wp-admin", "phpmyadmin",
    ".git/config", "backup.sql", "config.php", "xmlrpc.php", "server-status",
    "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 리다이렉트가 추가 GET을 만들어 11회 조건을 깨뜨리지 않게 한다.
        return None


def normalize_host(value):
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
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("양수인 초 단위 숫자가 필요합니다.") from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("유한한 양수가 필요합니다.")
    return number


def run(base_url, timeout=5.0, window=60.0):
    run_id = uuid.uuid4().hex
    paths = [f"/{target}/__scan_{run_id}" for target in random.sample(TARGETS, 11)]
    # 시스템 프록시/인증/쿠키 없이 같은 대상에 직접 순차 요청한다.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    print(f"[START] {datetime.now(timezone.utc).isoformat()} run_id={run_id}")
    print(f"[TARGET] {base_url} | GET 11회 | 로그인 불필요", flush=True)
    started = time.monotonic()
    statuses = []
    for index, path in enumerate(paths, 1):
        request = Request(base_url + path, headers={"User-Agent": "Watchdog-WebScanning-Test/1.0"})
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
        except HTTPError as error:
            status = error.code  # urllib은 정상적인 테스트 응답인 404도 예외로 반환한다.
            error.close()
        except (URLError, OSError) as error:
            print(f"[ERROR] {index:02d}/11 GET {path}: {error}", flush=True)
            print("[INCOMPLETE] 자동 재시도 없이 중단했습니다. 서버 도달 여부는 로그로 확인하세요.")
            return 1
        statuses.append(status)
        print(f"[{index:02d}/11] GET {path} -> {status}", flush=True)

    elapsed = time.monotonic() - started
    print(f"[SUMMARY] 404={statuses.count(404)}/11, elapsed={elapsed:.2f}s")
    valid = all(status == 404 for status in statuses) and elapsed < window
    if not valid:
        print("[INCOMPLETE] 404 11회 또는 지정한 탐지 시간창 조건을 충족하지 못했습니다.")
    print("[VERIFY] 404만으로 탐지 성공을 확정할 수 없습니다.")
    print("  Slack/서버 로그: [MEDIUM] 및 'Web Scanning 의심' 확인")
    print("  관리자 대시보드 또는 로그인된 GET /api/status의 security_events 확인")
    print(f"  event_type=WEB_SCANNING, severity=MEDIUM, count=11, path에 {run_id} 포함")
    return 0 if valid else 1


def main():
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
    raise SystemExit(main())
