"""허가된 테스트 서버에 미인증 GET을 보내 Unauthorized Access 탐지를 검증한다."""

import json
import time
from urllib.parse import urlsplit

import requests


# 테스트 설정: 로컬 또는 사용자가 명시적으로 지정한 허가된 서버 하나만 사용한다.
BASE_URL = "http://127.0.0.1:5000"
TARGET_PATH = "/api/status"
REQUEST_COUNT = 11
REQUEST_INTERVAL = 0.5
ALERT_THRESHOLD = 10
DETECTION_WINDOW_SECONDS = 60
REQUEST_TIMEOUT = (3, 5)  # 연결 / 응답 읽기 타임아웃(초)


def create_unauthenticated_session():
    """새 세션을 만들고 환경변수 프록시 및 .netrc 자동 인증을 사용하지 않는다."""
    session = requests.Session()
    session.trust_env = False
    session.auth = None
    session.cookies.clear()
    session.headers.clear()
    session.headers.update({
        "Accept": "application/json",
        "User-Agent": "Watchdog-UnauthorizedAccess-Test/1.0",
    })
    return session


def send_unauthorized_request(session, url):
    """쿠키를 버리고 실제 전송할 요청을 검사한다. 재시도와 리다이렉트는 없다."""
    session.cookies.clear()
    prepared = session.prepare_request(requests.Request("GET", url))
    allowed_headers = {"accept", "user-agent"}
    # Cookie, Authorization, API key 등 허용 목록 밖의 헤더가 있으면 전송하지 않는다.
    auth_free = (
        session.auth is None
        and not session.trust_env
        and {key.lower() for key in prepared.headers} <= allowed_headers
        and prepared.body is None
    )
    if not auth_free:
        return validate_response(error="인증 정보 또는 허용하지 않은 요청 설정 감지; 전송 중단",
                                 auth_free=False)
    try:
        with session.send(prepared, timeout=REQUEST_TIMEOUT, allow_redirects=False,
                          proxies={}, verify=True, cert=None) as response:
            return validate_response(response)
    except requests.RequestException as error:
        return validate_response(error=f"{type(error).__name__}: {error}")
    finally:
        # 서버가 Set-Cookie를 보내도 다음 요청에서 재사용하지 않는다.
        session.cookies.clear()


def validate_response(response=None, error=None, auth_free=True):
    """401, JSON 형식, 차단 의심 징후를 각각 판정한다. JSON 필드는 강제하지 않는다."""
    status = None
    content_type = "(없음)"
    json_ok = False
    body = error or "응답 없음"
    possible_block = False
    if response is not None:  # requests의 401 응답은 bool(response)가 False다.
        status = response.status_code
        content_type = response.headers.get("Content-Type", "(없음)")
        media_type = content_type.split(";", 1)[0].strip().lower()
        json_type = media_type == "application/json" or (
            media_type.startswith("application/") and media_type.endswith("+json")
        )
        try:
            body = json.dumps(response.json(), ensure_ascii=False)
            json_ok = json_type
        except ValueError:
            body = response.text
        markers = ("ip blocked", "ip is blocked", "ip has been blocked",
                   "ip 차단", "차단된 ip", "ip 잠금", "잠긴 ip")
        possible_block = status in (403, 429) or any(
            marker in body.lower() for marker in markers
        )
    elif error and auth_free:
        # 연결 실패는 서버 미실행 등도 원인일 수 있어 IP 차단이라고 단정하지 않는다.
        possible_block = True
    return {
        "status": status,
        "content_type": content_type,
        "json_ok": json_ok,
        "body": body,
        "auth_free": auth_free,
        "possible_block": possible_block,
    }


def print_request_result(index, result):
    """상태 코드 기준 PASS/FAIL과 JSON 검사 결과를 별도로 출력한다."""
    print(f"\n[{index:02d}/{REQUEST_COUNT:02d}] GET {TARGET_PATH}")
    print(f"Status      : {result['status'] if result['status'] is not None else 'NO RESPONSE'}")
    print(f"Content-Type: {result['content_type']}")
    print(f"Result      : {'PASS' if result['status'] == 401 else 'FAIL'} (HTTP 401 기준)")
    print(f"JSON Check  : {'PASS' if result['json_ok'] else 'FAIL'}")
    print(f"Response    : {result['body']}")
    if result["possible_block"]:
        print("POSSIBLE IP BLOCK - SERVER LOG 확인 필요")
    if index == ALERT_THRESHOLD + 1:
        print("[MANUAL CHECK] 임계값 초과 요청: 서버 이벤트와 Slack/콘솔 알림 확인")
        print("  UNAUTHORIZED_ACCESS 이벤트가 생성되고 count가 10을 초과했는가?")
    print(flush=True)


def print_summary(results, elapsed):
    """HTTP 검증 결과와 수동 확인 항목을 구분하며 IP 잠금 부재를 단정하지 않는다."""
    count_401 = sum(item["status"] == 401 for item in results)
    auth_free = bool(results) and all(item["auth_free"] for item in results)
    attempted = sum(item["auth_free"] for item in results)
    completed = len(results) == REQUEST_COUNT and attempted == REQUEST_COUNT
    passed = completed and all(
        item["status"] == 401 and item["json_ok"] and not item["possible_block"]
        for item in results
    )
    print("\n--- Test Summary ---")
    print(f"Target            : {TARGET_PATH}")
    print(f"Requests          : {attempted} (planned: {REQUEST_COUNT})")
    print(f"401 Responses     : {count_401}")
    print(f"Unexpected        : {attempted - count_401}")
    print(f"JSON Failures     : {sum(not item['json_ok'] for item in results)}")
    print(f"Authentication    : {'NONE' if auth_free else 'CHECK FAILED / NOT TESTED'}")
    print(f"Alert Threshold   : {ALERT_THRESHOLD}")
    print(f"Alert Check       : request #{ALERT_THRESHOLD + 1}")
    print("IP Lock Expected  : NO")
    print(f"Elapsed           : {elapsed:.2f}s (window: {DETECTION_WINDOW_SECONDS}s)")
    print(f"HTTP/JSON Result  : {'PASS' if passed else 'FAIL'}")
    if any(item["possible_block"] for item in results):
        print("IP Lock Check     : POSSIBLE IP BLOCK - SERVER LOG 확인 필요")
    else:
        print("IP Lock Check     : MANUAL CHECK (HTTP 응답만으로 잠금 부재 확정 불가)")
    if attempted <= ALERT_THRESHOLD or elapsed >= DETECTION_WINDOW_SECONDS:
        print("[INCOMPLETE] 요청 수 또는 시간창 조건 미충족; 11번째 알림 재현을 보장할 수 없음")
    print("Alert Result      : MANUAL CHECK")
    print("  서버 로그/Slack: [MEDIUM], Unauthorized Access 의심, count=11 확인")
    print("  별도 관리자 브라우저: 보안 이벤트 및 active_lockouts 확인")
    return passed and attempted > ALERT_THRESHOLD and elapsed < DETECTION_WINDOW_SECONDS


def main():
    """단일 API에 순차 요청하며 로그인·병렬 실행·Slack 직접 호출을 하지 않는다."""
    try:
        base = urlsplit(BASE_URL)
        path = urlsplit(TARGET_PATH)
        base.port  # 잘못된 포트를 요청 전에 검출한다.
        if (base.scheme not in ("http", "https") or not base.hostname
                or base.username is not None or base.password is not None
                or base.path not in ("", "/") or base.query or base.fragment
                or path.scheme or path.netloc or path.query or path.fragment
                or not TARGET_PATH.startswith("/api/")
                or any(char.isspace() for char in BASE_URL + TARGET_PATH)):
            raise ValueError("BASE_URL은 인증 정보 없는 기본 URL, TARGET_PATH는 /api/ 경로여야 합니다.")
        if (type(REQUEST_COUNT) is not int or REQUEST_COUNT < 1
                or not 0.3 <= REQUEST_INTERVAL <= 1.0):
            raise ValueError("REQUEST_COUNT는 양의 정수, REQUEST_INTERVAL은 0.3~1초여야 합니다.")
    except (ValueError, TypeError) as error:
        print(f"[CONFIG ERROR] {error}")
        return 2

    url = BASE_URL.rstrip("/") + TARGET_PATH
    print(f"Target URL: {url}")
    print(f"Started   : {time.strftime('%Y-%m-%d %H:%M:%S %z')}")
    print("같은 IP의 기존 미인가 요청이 시간창에서 빠진 후 실행하세요(기본 60초 초과 대기).")
    results = []
    started = time.monotonic()
    with create_unauthenticated_session() as session:
        try:
            for index in range(1, REQUEST_COUNT + 1):
                result = send_unauthorized_request(session, url)
                results.append(result)
                print_request_result(index, result)
                if not result["auth_free"]:
                    break
                if index < REQUEST_COUNT:
                    time.sleep(REQUEST_INTERVAL)
        except KeyboardInterrupt:
            print("\n[INTERRUPTED] 사용자에 의해 중단됨; 서버 도달 횟수는 로그로 확인하세요.")
            print_summary(results, time.monotonic() - started)
            return 130
    return 0 if print_summary(results, time.monotonic() - started) else 1


if __name__ == "__main__":
    raise SystemExit(main())
