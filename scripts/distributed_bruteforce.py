"""로컬 로그인 워치독의 계정 단위 분산 브루트포스 잠금을 검증한다.

사용법:
    python scripts/distributed_bruteforce_sim.py --username test_user

로컬 서버에서 TRUST_FORWARDED_FOR=true일 때만 각 요청의 가상 IP가 반영된다.
테스트 계정의 실제 비밀번호는 입력하지 않는다. 60초 안에 같은 계정으로
서로 다른 IP 9개가 한 번씩 실패한 뒤, 10번째 IP에서 잠금 안내를 확인한다.
테스트가 끝나면 관리 화면에서 계정 잠금을 해제하거나 만료를 기다린다.
"""

import argparse
import re
import sys
import uuid
from urllib.parse import urlparse

import requests


LOCKED_MESSAGE = "잠긴 계정입니다"
ACCOUNT_THRESHOLD = 8  # 문서상 ACCOUNT_FAILURE_THRESHOLD 기본값
IP_PREFIX = "192.0.2."  # 문서/테스트용 주소 범위


def local_base_url(value: str) -> str:
    parsed = urlparse(value)
    if (parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise argparse.ArgumentTypeError("--host에는 로컬 HTTP 서버의 기본 주소만 지정하세요.")
    return value.rstrip("/")


def run(base_url: str, username: str) -> bool:
    session = requests.Session()  # CSRF 토큰과 쿠키를 함께 유지
    session.headers["X-Forwarded-For"] = IP_PREFIX + "1"
    login_url = base_url + "/login"

    page = session.get(login_url, timeout=5)
    page.raise_for_status()
    match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)', page.text)
    if not match:
        print("[FAIL] 로그인 폼의 CSRF 토큰을 찾지 못했습니다.")
        return False
    csrf_token = match.group(1)
    wrong_password = "intentionally-wrong-" + uuid.uuid4().hex

    # 1~9번째: IP마다 한 번씩 실패. IP 잠금 기준(한 IP에서 5회 초과)을 넘지 않는다.
    for number in range(1, ACCOUNT_THRESHOLD + 2):
        ip = IP_PREFIX + str(number)
        session.headers["X-Forwarded-For"] = ip
        response = session.post(
            login_url,
            data={"username": username, "password": wrong_password,
                  "csrf_token": csrf_token},
            timeout=5,
        )
        print(f"[{number}/9] 가상 IP {ip}: HTTP {response.status_code}")
        if response.status_code >= 400:
            print("[FAIL] 로그인 로직에 도달하지 못했습니다. CSRF와 서버 로그를 확인하세요.")
            return False
        if number <= ACCOUNT_THRESHOLD and LOCKED_MESSAGE in response.text:
            print("[FAIL] 9회 이전에 잠겼습니다. 기존 잠금/실패 기록 또는 X-Forwarded-For 설정을 확인하세요.")
            return False

    # 9번째 실패가 계정 잠금을 만들면, 10번째 IP의 요청은 사전 잠금 검사에서 거절된다.
    probe_ip = IP_PREFIX + str(ACCOUNT_THRESHOLD + 2)
    session.headers["X-Forwarded-For"] = probe_ip
    probe = session.post(
        login_url,
        data={"username": username, "password": wrong_password,
              "csrf_token": csrf_token},
        timeout=5,
    )
    print(f"[확인] 가상 IP {probe_ip}: HTTP {probe.status_code}")
    if probe.status_code < 400 and LOCKED_MESSAGE in probe.text:
        print("[OK] 9개 IP에서 계정별 실패가 8회를 초과했고, 새 IP에서도 계정 잠금을 확인했습니다.")
        return True
    print("[FAIL] 계정 잠금 문구가 없습니다. TRUST_FORWARDED_FOR와 계정별 실패 기록을 확인하세요.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=local_base_url, default="http://127.0.0.1:5000")
    parser.add_argument("--username", required=True, help="실제로 존재하는 전용 테스트 계정의 아이디")
    args = parser.parse_args()
    try:
        return 0 if run(args.host, args.username) else 1
    except requests.RequestException as exc:
        print(f"[FAIL] 서버 요청 오류: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
