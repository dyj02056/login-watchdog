# ============================================================================
# unauthorized_access_sim.py — 로그인하지 않은 사람이 관리자 전용 API를
# 계속 두드려볼 때, 우리 서버가 "인가되지 않은 접근(Unauthorized Access)"으로
# 탐지하는지 확인하는 검증 스크립트
#
# 인가되지 않은 접근이란? 로그인 세션(쿠키)도, 어떤 인증 정보도 없는 상태로
# 원래 로그인한 사람만 볼 수 있어야 할 API(예: /api/status)를 반복해서
# 요청하는 행위다. 정상적인 사용자라면 이런 요청을 보낼 이유가 없으므로,
# 짧은 시간 안에 여러 번 발생하면 공격 시도로 의심할 수 있다.
#
# 동작 요약:
#   1) 로그인 쿠키가 전혀 없는 "새 세션"을 만든다(진짜 브라우저로 한 번도
#      로그인하지 않은 사람인 척한다).
#   2) 그 세션으로 /api/status에 GET 요청을 11번 순서대로 보낸다.
#   3) 서버가 매번 401(인증 안 됨)로 제대로 거절하는지 확인하고, 11번째
#      요청(=임계값 10회를 초과한 시점)에서 서버가 "의심스럽다"고 판단해
#      알림을 울렸는지는 사람이 직접 로그/Slack/대시보드로 확인해야 한다.
#
# 안전 원칙: 기본 대상은 로컬 서버(http://127.0.0.1:5000)이며, 본인이
# 소유했거나 테스트 허락을 받은 서버에서만 실행해야 한다. 인증 정보(쿠키,
# Authorization 헤더 등)를 절대 함께 보내지 않도록 전송 직전에 다시 한번
# 검사한다.
# ============================================================================

import json
import time
from urllib.parse import urlsplit

import requests


# 테스트 설정: 로컬 또는 사용자가 명시적으로 지정한 허가된 서버 하나만 사용한다.
BASE_URL = "http://127.0.0.1:5000"       # 테스트 대상 서버 주소 (기본: 내 컴퓨터)
TARGET_PATH = "/api/status"              # 로그인해야만 볼 수 있어야 하는 관리자용 API 경로
REQUEST_COUNT = 11                       # 총 몇 번 요청을 보낼지 (11번 = 임계값 10을 넘기는 지점까지)
REQUEST_INTERVAL = 0.5                   # 요청 사이 대기 시간(초) — 너무 빠르면 서버가 놓칠 수 있어 살짝 간격을 둠
ALERT_THRESHOLD = 10                     # 서버가 "의심스럽다"고 판단하기 시작하는 요청 횟수 기준
DETECTION_WINDOW_SECONDS = 60            # 서버가 "짧은 시간 안에 일어난 일"로 묶어서 보는 시간창(초)
REQUEST_TIMEOUT = (3, 5)  # 연결 / 응답 읽기 타임아웃(초)


def create_unauthenticated_session():
    """"한 번도 로그인한 적 없는 방문자"를 흉내 내는 깨끗한 세션을 만든다.

    requests.Session()은 원래 쿠키나 인증 정보를 자동으로 기억하고 재사용하는
    기능이 있는데, 여기서는 일부러 그 기능을 전부 끈다:
      - trust_env = False  → 컴퓨터에 설정된 프록시나 인증서 설정을 쓰지 않는다.
      - auth = None          → 아이디/비밀번호 같은 인증 정보를 붙이지 않는다.
      - cookies.clear()      → 남아있을 수 있는 로그인 쿠키를 모두 지운다.
      - headers.clear()      → 기본으로 붙는 헤더까지 지우고 최소한만 새로 넣는다.
    이렇게 해야 "정말로 아무 인증 정보도 없는 상태"에서 서버가 어떻게
    반응하는지를 정확하게 테스트할 수 있다.
    """
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
    """요청을 실제로 보내기 전에 "정말 인증 정보가 하나도 없는지" 한번 더 검사한 뒤 전송한다."""
    session.cookies.clear()
    # 요청을 "미리 조립"만 해보고, 그 안에 인증과 관련된 흔적이 있는지 점검한다.
    prepared = session.prepare_request(requests.Request("GET", url))
    allowed_headers = {"accept", "user-agent"}
    # Cookie, Authorization, API key 등 허용 목록 밖의 헤더가 있으면 전송하지 않는다.
    # (실수로 requests 라이브러리나 환경설정이 쿠키/인증 헤더를 몰래 끼워넣는 것을 방지)
    auth_free = (
        session.auth is None
        and not session.trust_env
        and {key.lower() for key in prepared.headers} <= allowed_headers
        and prepared.body is None
    )
    if not auth_free:
        # 조립된 요청에 인증 흔적이 하나라도 있으면, 진짜로 전송하지 않고
        # "테스트 조건이 깨졌다"고 바로 알린다 — 잘못된 결과로 안심하지 않기 위함.
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
        # (서버가 실수로라도 쿠키를 내려주면, 다음 요청부터 "로그인된 것처럼"
        #  보일 수 있으므로 매번 강제로 비워서 "비로그인 상태"를 계속 유지한다)
        session.cookies.clear()


def validate_response(response=None, error=None, auth_free=True):
    """서버 응답 하나를 분석해서 "정상적으로 거절했는지"와 "차단된 것 같은지"를 판단한다.

    확인하는 것들:
      - status: HTTP 상태 코드 (401이면 "로그인 안 했으니 거절"이라는 뜻으로 기대되는 정상 반응)
      - content_type / json_ok: 응답이 JSON 형식인지 (API 응답 형식이 맞는지 확인용)
      - possible_block: 403/429 같은 코드나 "IP 차단됨" 류의 문구가 있으면 "혹시 IP가
        차단된 건 아닐까?"라는 의심 표시를 남긴다 (이 스크립트가 직접 판단을 확정하진 않는다)
    """
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
    """요청 한 건의 결과를 사람이 읽기 쉬운 형태로 화면에 출력한다."""
    print(f"\n[{index:02d}/{REQUEST_COUNT:02d}] GET {TARGET_PATH}")
    print(f"Status      : {result['status'] if result['status'] is not None else 'NO RESPONSE'}")
    print(f"Content-Type: {result['content_type']}")
    # 기대하는 정상 반응은 401(로그인 안 됨)이다. 다른 코드가 나오면 FAIL로 표시해
    # "뭔가 예상과 다르다"는 걸 바로 알아볼 수 있게 한다.
    print(f"Result      : {'PASS' if result['status'] == 401 else 'FAIL'} (HTTP 401 기준)")
    print(f"JSON Check  : {'PASS' if result['json_ok'] else 'FAIL'}")
    print(f"Response    : {result['body']}")
    if result["possible_block"]:
        print("POSSIBLE IP BLOCK - SERVER LOG 확인 필요")
    if index == ALERT_THRESHOLD + 1:
        # 11번째 요청 = 임계값(10)을 넘긴 첫 요청. 이 시점에 서버가 이벤트를
        # 만들었어야 정상이므로, 사람이 직접 확인해야 할 체크포인트임을 알려준다.
        print("[MANUAL CHECK] 임계값 초과 요청: 서버 이벤트와 Slack/콘솔 알림 확인")
        print("  UNAUTHORIZED_ACCESS 이벤트가 생성되고 count가 10을 초과했는가?")
    print(flush=True)


def print_summary(results, elapsed):
    """전체 11번 요청이 끝난 뒤, 결과를 종합해서 요약 리포트를 출력한다."""
    count_401 = sum(item["status"] == 401 for item in results)
    auth_free = bool(results) and all(item["auth_free"] for item in results)
    attempted = sum(item["auth_free"] for item in results)
    completed = len(results) == REQUEST_COUNT and attempted == REQUEST_COUNT
    # passed: 11번 모두 정상적으로 진행됐고, 매번 401을 받았고, JSON 형식이었고,
    # 차단 의심 징후도 없었을 때만 클라이언트(이 스크립트) 입장에서 "성공"으로 판정한다.
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
    # 이 스크립트는 HTTP 응답만 확인할 뿐, 서버가 실제로 보안 이벤트를 만들고
    # 알림을 울렸는지는 알 수 없다. 그래서 항상 "사람이 직접 확인"하라고 안내한다.
    print("Alert Result      : MANUAL CHECK")
    print("  서버 로그/Slack: [MEDIUM], Unauthorized Access 의심, count=11 확인")
    print("  별도 관리자 브라우저: 보안 이벤트 및 active_lockouts 확인")
    return passed and attempted > ALERT_THRESHOLD and elapsed < DETECTION_WINDOW_SECONDS


def main():
    """단일 API에 순차 요청하며 로그인·병렬 실행·Slack 직접 호출을 하지 않는다."""
    try:
        # 실행 전에 설정값(BASE_URL, TARGET_PATH 등)이 이상하지 않은지 미리 검사한다.
        # 예를 들어 주소에 아이디/비밀번호가 박혀있거나, 대상 경로가 /api/로
        # 시작하지 않으면 엉뚱한 곳을 테스트하게 될 수 있으므로 여기서 막는다.
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
    # with 문으로 세션을 감싸서, 테스트가 끝나면(에러가 나도) 세션이 자동으로
    # 정리되도록 한다 — 뒤에 테스트를 또 돌릴 때 이전 흔적이 남지 않게 하기 위함.
    with create_unauthenticated_session() as session:
        try:
            for index in range(1, REQUEST_COUNT + 1):
                result = send_unauthorized_request(session, url)
                results.append(result)
                print_request_result(index, result)
                if not result["auth_free"]:
                    # 인증 흔적이 감지되면 더 이상 진행하지 않고 즉시 멈춘다
                    # (테스트 전제 조건이 깨졌으므로 계속해봐야 의미가 없음).
                    break
                if index < REQUEST_COUNT:
                    time.sleep(REQUEST_INTERVAL)
        except KeyboardInterrupt:
            # 사용자가 Ctrl+C로 중간에 멈춘 경우, 지금까지의 결과라도
            # 요약해서 보여준 뒤 종료한다.
            print("\n[INTERRUPTED] 사용자에 의해 중단됨; 서버 도달 횟수는 로그로 확인하세요.")
            print_summary(results, time.monotonic() - started)
            return 130
    return 0 if print_summary(results, time.monotonic() - started) else 1


if __name__ == "__main__":
    # 터미널에서 "python unauthorized_access_sim.py"로 직접 실행했을 때만 동작하고,
    # 다른 파일에서 import만 했을 때는 자동으로 실행되지 않게 하는 관용적인 표현이다.
    raise SystemExit(main())
