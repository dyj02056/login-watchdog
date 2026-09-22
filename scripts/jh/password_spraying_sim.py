"""단일 허가 서버에서 저속 로그인 실패 패턴을 만들고 탐지 결과를 관찰한다."""

import argparse
import ipaddress
import json
import re
import socket
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import requests


DEFAULT_HOST = "http://127.0.0.1:5000"
LOGIN_PATH = "/login"
DEFAULT_COUNT = 6
DEFAULT_INTERVAL = 0.5
REQUEST_TIMEOUT = 5
FAILURE_THRESHOLD = 5
USERNAME_FIELD = "username"
PASSWORD_FIELD = "password"
CSRF_FIELD = "csrf_token"
DEFAULT_TEST_PASSWORD = "wrong_test_password"
MAX_RESPONSE_PREVIEW = 300
LOCK_MARKERS = ("잠긴 계정", "계정 잠금", "account locked", "locked account")
SUCCESS_MARKERS = ("로그인 성공", "로그인에 성공", "login successful",
                   "successfully logged in", "logged in successfully")


class ConfigParser(argparse.ArgumentParser):
    """CLI 입력 오류를 traceback 없이 설정 오류로 표시한다."""

    def error(self, message):
        """argparse의 오류 종료 코드를 2로 유지한다."""
        self.exit(2, f"[CONFIG ERROR] {message}\n")


class LoginHTML(HTMLParser):
    """숨겨진 CSRF 토큰과 화면에 보이는 문장을 각각 추출한다."""

    def __init__(self):
        """토큰은 출력용 본문에 넣지 않는다."""
        super().__init__(convert_charrefs=True)
        self.tokens = []
        self.text = []
        self.ignored = None

    def handle_starttag(self, tag, attrs):
        """input 속성 순서나 따옴표 형태에 의존하지 않고 토큰을 찾는다."""
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == CSRF_FIELD and attrs.get("value"):
            self.tokens.append(attrs["value"])
        if tag in ("script", "style"):
            self.ignored = tag

    def handle_endtag(self, tag):
        """스크립트와 스타일 내용은 응답 미리보기에서 제외한다."""
        if tag == self.ignored:
            self.ignored = None

    def handle_data(self, data):
        """HTML 텍스트만 모아 hidden input 값의 노출을 피한다."""
        if self.ignored is None:
            self.text.append(data)


class PossibleLoginSuccess(RuntimeError):
    """로그인 성공이 의심되면 다음 요청을 막기 위한 예외다."""


def validate_host(url):
    """기본 URL의 형식, 포트, 인증정보, 경로, query와 fragment를 검사한다."""
    if not url or any(c.isspace() or ord(c) < 32 for c in url) or "\\" in url:
        raise ValueError("잘못된 URL입니다.")
    parsed = urlsplit(url)
    port = parsed.port
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or "?" in url or "#" in url
            or "%" in parsed.netloc or parsed.netloc.endswith(":") or port == 0):
        raise ValueError("인증정보·경로·query·fragment 없는 http(s)://호스트[:포트]가 필요합니다.")
    return parsed


def is_loopback_address(hostname):
    """문자열 IP를 파싱하여 loopback 여부를 판단한다."""
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def is_local_host(url):
    """IP는 loopback만, localhost는 DNS 결과가 모두 loopback일 때만 허용한다."""
    parsed = validate_host(url)
    if parsed.hostname != "localhost":
        return is_loopback_address(parsed.hostname)
    try:
        addresses = socket.getaddrinfo(
            "localhost", parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except OSError:
        return False
    return bool(addresses) and all(is_loopback_address(row[4][0]) for row in addresses)


def create_test_session():
    """테스트 전체에서 한 번 만들며 CSRF용 쿠키를 같은 Session에 유지한다."""
    session = requests.Session()
    session.trust_env = False
    session.auth = None
    session.headers.update({"User-Agent": "Watchdog-PasswordSpraying-Test/1.0"})
    return session


def parse_usernames(args):
    """고유 테스트 아이디를 준비하고 중복과 최소 개수를 검사한다."""
    if args.count < 1:
        raise ValueError("count는 1 이상의 정수여야 합니다.")
    if args.usernames is not None:
        names = [name.strip() for name in args.usernames.split(",") if name.strip()]
    else:
        prefix = (args.username_prefix if args.username_prefix is not None else "spray_user").strip()
        if not prefix:
            raise ValueError("username-prefix는 비어 있을 수 없습니다.")
        names = [f"{prefix}{index}" for index in range(1, args.count + 1)]
    seen, duplicates = set(), set()
    for name in names:
        if any(ord(char) < 32 or ord(char) == 127 for char in name):
            raise ValueError("username에 제어 문자를 사용할 수 없습니다.")
        if name in seen:
            duplicates.add(name)
        seen.add(name)
    if duplicates:
        raise ValueError("Password Spraying 검증에는 서로 다른 username이 필요합니다.\n"
                         "중복 username: " + ", ".join(sorted(duplicates)))
    if len(names) < FAILURE_THRESHOLD + 1:
        raise ValueError(f"서로 다른 username이 최소 {FAILURE_THRESHOLD + 1}개 필요합니다.")
    return names


def get_csrf_token(session, url):
    """매 POST 직전 같은 Session으로 GET한다. GET은 로그인 실패로 세지 않는 전제다."""
    with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False) as response:
        result = validate_response(response)
        if result["possible_login_success"]:
            raise PossibleLoginSuccess()
        if response.status_code != 200:
            raise RuntimeError(f"CSRF GET 응답이 예상과 다릅니다: HTTP {response.status_code}")
        parser = LoginHTML()
        parser.feed(response.text)
        tokens = set(parser.tokens)
        if len(tokens) != 1:
            raise RuntimeError("CSRF token을 찾지 못했습니다.\n"
                               "      서버가 CSRF를 사용하지 않는 경우 --no-csrf를 확인하세요.")
        return tokens.pop()


def send_login_attempt(session, url, username, password, use_json, csrf_token):
    """같은 비밀번호로 POST 한 번만 전송하며 모든 리다이렉트를 관찰만 한다."""
    payload = {USERNAME_FIELD: username, PASSWORD_FIELD: password}
    headers = {"Referer": url}  # HTTPS Flask-WTF의 동일 출처 검사에 필요한 정상 헤더.
    if csrf_token:
        payload[CSRF_FIELD] = csrf_token
        if use_json:
            headers["X-CSRFToken"] = csrf_token
    body = {"json": payload} if use_json else {"data": payload}
    return session.post(url, headers=headers, timeout=REQUEST_TIMEOUT,
                        allow_redirects=False, **body)


def redact_json(value):
    """JSON 응답의 비밀번호, 토큰, 쿠키 관련 필드를 출력 전에 가린다."""
    if isinstance(value, dict):
        return {key: "<REDACTED>" if re.search(
            r"password|token|cookie|secret|authorization|api.?key", key, re.I
        ) else redact_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


def safe_location(location):
    """Location의 인증정보, query, fragment는 표시하지 않는다."""
    try:
        parsed = urlsplit(location)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parsed.port:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))[:MAX_RESPONSE_PREVIEW]
    except ValueError:
        return "<INVALID LOCATION>"


def validate_response(response):
    """HTTP·본문의 잠금 신호와 로그인 성공 가능성을 분석하며 이벤트는 확정하지 않는다."""
    status = response.status_code
    content_type = response.headers.get("Content-Type", "")
    location = response.headers.get("Location", "")
    html = LoginHTML()
    html.feed(response.text)
    visible = " ".join(" ".join(html.text).split())
    data = None
    is_json = False
    try:
        data = response.json()
        is_json = True
    except ValueError:
        pass
    analysis_text = json.dumps(data, ensure_ascii=False) if is_json else visible
    preview = json.dumps(redact_json(data), ensure_ascii=False) if is_json else visible
    # 반환된 HTML/문자열이 전송 비밀번호를 되풀이하더라도 출력하지 않는다.
    request = response.request
    if request is not None and request.body:
        body = request.body.decode("utf-8", errors="replace") if isinstance(request.body, bytes) else request.body
        try:
            submitted = json.loads(body) if "application/json" in request.headers.get("Content-Type", "") else parse_qs(body)
            for key in (PASSWORD_FIELD, CSRF_FIELD):
                values = submitted.get(key, [])
                for value in values if isinstance(values, list) else [values]:
                    if isinstance(value, str) and value:
                        variants = {value, json.dumps(value, ensure_ascii=False)[1:-1]}
                        for secret in sorted(variants, key=len, reverse=True):
                            preview = preview.replace(secret, "<REDACTED>")
        except (ValueError, AttributeError):
            pass
    preview = re.sub(r"(?i)(?:set-cookie|cookie|authorization)\s*:.*", "<REDACTED>", preview)
    lock_message = any(marker in analysis_text.lower() for marker in LOCK_MARKERS)
    possible_login = any(marker in analysis_text.lower() for marker in SUCCESS_MARKERS)
    if isinstance(data, dict):
        possible_login |= any(data.get(key) is True for key in ("success", "authenticated", "logged_in"))
        possible_login |= bool(data.get("access_token"))
    error = None
    try:
        target_path = unquote(urlsplit(location).path).lower().rstrip("/")
        if location and any(target_path == path or target_path.startswith(path + "/")
                            for path in ("/dashboard", "/admin/dashboard", "/account", "/profile", "/member")):
            possible_login = True
    except ValueError:
        target_path = ""
        error = "잘못된 Location 응답입니다."
    if status in (301, 302, 303, 307, 308):
        if not location or target_path != LOGIN_PATH:
            error = error or "예상하지 못한 리다이렉트입니다. 이동하지 않았습니다."
    elif status not in (200, 401, 423):
        error = f"예상하지 못한 HTTP {status}; CSRF/제한/서버 로그를 확인하세요."
    if "csrf" in analysis_text.lower() and status >= 400:
        error = "CSRF 오류 응답입니다. 서버의 CSRF 설정을 확인하세요."
    return {
        "status": status, "content_type": content_type, "location": safe_location(location),
        "body_preview": preview[:MAX_RESPONSE_PREVIEW], "is_json": is_json,
        "lock_detected": lock_message or status == 423, "lock_message": lock_message,
        "possible_lock": status in (403, 429), "possible_login_success": bool(possible_login),
        "error": error,
    }


def print_attempt_result(index, total, username, result):
    """POST 응답과 임계값 확인 시점을 출력한다. Cookie 헤더는 출력하지 않는다."""
    print(f"\n[{index:02d}/{total:02d}] POST {LOGIN_PATH}\nUsername     : {username}")
    for label, value in (("Status", result["status"]), ("Content-Type", result["content_type"]),
                         ("Location", result["location"] or "-")):
        print(f"{label:13}: {value}")
    print(f"Lock Message : {'DETECTED' if result['lock_message'] else 'NOT DETECTED'}")
    print(f"Lock Status  : {'DETECTED' if result['lock_detected'] else 'POSSIBLE' if result['possible_lock'] else 'NORMAL'}")
    print(f"Result       : {result['error'] or 'LOGIN FAILURE TEST SENT'}")
    print(f"Response     : {result['body_preview']}")
    if result["possible_lock"]:
        print("POSSIBLE LOCK / RATE LIMIT - SERVER LOG CHECK REQUIRED")
    if index == FAILURE_THRESHOLD + 1:
        print(f"[THRESHOLD EXCEEDED]\nFAILURE_THRESHOLD={FAILURE_THRESHOLD} 초과 확인 시점입니다.")
        print("각 POST가 같은 시간창에서 로그인 실패로 기록되었다는 전제입니다.")
        print("[MANUAL CHECK] security_events에서 event_type=PASSWORD_SPRAYING 확인")
    print(flush=True)


def print_plan(args, usernames, url):
    """실행 계획을 출력하되 비밀번호는 가리고 네트워크는 사용하지 않는다."""
    print("Password Spraying Simulation" + (" - DRY RUN" if args.dry_run else ""))
    for label, value in (("Target", url), ("Planned Requests", len(usernames)),
                         ("Distinct Usernames", len(set(usernames))), ("Attack Pattern", "PASSWORD SPRAYING"),
                         ("Password", "********"), ("Password Strategy", "SAME PASSWORD"),
                         ("Session Strategy", "SAME SESSION"), ("IP Strategy", "UNCHANGED"),
                         ("Interval", f"{args.interval}s"), ("Payload", "JSON" if args.use_json else "FORM"),
                         ("CSRF", "DISABLED" if args.no_csrf else "ENABLED")):
        print(f"{label:20}: {value}")
    print("Usernames:\n  " + "\n  ".join(usernames))
    if args.use_json:
        print("[CHECK REQUIRED] 현재 프로젝트 /login은 FORM만 지원합니다. JSON 지원 서버에서만 --json을 쓰세요.")


def print_summary(results, usernames, args, elapsed, stop_reason="", possible_login=False):
    """요청 완료와 탐지 징후를 구분하고 서버 이벤트는 수동 확인으로 남긴다."""
    possible_login = possible_login or any(row["possible_login_success"] for row in results)
    passed = len(results) == len(usernames) and not stop_reason and not possible_login
    passed = passed and all(not row["error"] for row in results)
    print("\n--- Test Summary ---")
    fields = (("Target", LOGIN_PATH), ("Planned Requests", len(usernames)),
              ("Completed Requests", len(results)), ("Distinct Usernames", len(set(usernames))),
              ("Failure Threshold", FAILURE_THRESHOLD), ("Threshold Check", f"request #{FAILURE_THRESHOLD + 1}"),
              ("Attack Pattern", "PASSWORD SPRAYING"), ("Session Strategy", "SAME SESSION"),
              ("IP Strategy", "UNCHANGED"), ("Password Strategy", "SAME PASSWORD"),
              ("Payload Type", "JSON" if args.use_json else "FORM"), ("CSRF", "DISABLED" if args.no_csrf else "ENABLED"),
              ("Lock Message", "DETECTED" if any(r["lock_message"] for r in results) else "NOT DETECTED"),
              ("Detection Indicator", "YES" if any(r["lock_detected"] for r in results) else "NO"),
              ("Possible Lock", "YES" if any(r["possible_lock"] for r in results) else "NO"),
              ("Possible Login", "YES" if possible_login else "NO"), ("Elapsed", f"{elapsed:.2f}s"),
              ("Client Result", "PASS" if passed else "FAIL / CHECK REQUIRED"),
              ("Event Result", "MANUAL CHECK"), ("Expected Event", "PASSWORD_SPRAYING"))
    for label, value in fields:
        print(f"{label:20}: {value}")
    if stop_reason:
        print(f"[FAIL] {stop_reason}")
    print("[MANUAL CHECK] 관리자 대시보드 또는 security_events에서")
    print("event_type=PASSWORD_SPRAYING, source IP, failure count, 발생 시간을 확인하세요.")
    print("서로 다른 아이디 수와 탐지 시간창/임계값은 서버 로그·Slack·login_attempts로 확인하세요.")
    return passed


def main(argv=None):
    """설정 검증 뒤 Session 하나로 순차 실행하고 종료 코드로 클라이언트 결과를 알린다."""
    parser = ConfigParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--usernames", help="쉼표로 구분한 고유 테스트 아이디; 목록 길이가 요청 수")
    group.add_argument("--username-prefix", help="자동 생성 접두사, 기본 spray_user")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help="자동 생성 개수, 기본 6")
    parser.add_argument("--password", default=DEFAULT_TEST_PASSWORD, help="모든 요청에 쓰는 하나의 잘못된 테스트 비밀번호")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    parser.add_argument("--json", dest="use_json", action="store_true")
    parser.add_argument("--no-csrf", action="store_true")
    parser.add_argument("--i-know-what-im-doing", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        host = validate_host(args.host)
        usernames = parse_usernames(args)
        if not 0.3 <= args.interval <= 1.0 or not args.password:
            raise ValueError("interval은 0.3~1.0초이며 테스트 비밀번호는 비어 있을 수 없습니다.")
        # dry-run은 DNS 조회도 하지 않는다. localhost DNS 안전 검사는 실제 실행 때 한다.
        local = (host.hostname == "localhost" or is_loopback_address(host.hostname)) if args.dry_run else is_local_host(args.host)
        if not local and not args.i_know_what_im_doing:
            raise ValueError("loopback 외의 허가된 테스트 서버는 --i-know-what-im-doing이 필요합니다.")
    except (ValueError, OSError) as error:
        print(f"[CONFIG ERROR] {error}")
        return 2
    url = args.host.rstrip("/") + LOGIN_PATH
    print_plan(args, usernames, url)
    if args.dry_run:
        print("[DRY RUN] HTTP·DNS 요청을 전송하지 않았습니다. localhost DNS 검사는 실제 실행 시 수행합니다.")
        return 0
    print("기존 IP/계정 잠금이 없고 같은 IP의 이전 실패가 탐지 시간창(기본 60초)에서 빠진 상태여야 합니다.")
    print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S %z')}")
    results, stop_reason, possible_login = [], "", False
    started = time.monotonic()
    try:
        with create_test_session() as session:
            for index, username in enumerate(usernames, 1):
                token = None if args.no_csrf else get_csrf_token(session, url)
                with send_login_attempt(session, url, username, args.password, args.use_json, token) as response:
                    result = validate_response(response)
                results.append(result)
                print_attempt_result(index, len(usernames), username, result)
                if result["possible_login_success"]:
                    raise PossibleLoginSuccess()
                if index <= FAILURE_THRESHOLD and (result["lock_detected"] or result["possible_lock"]):
                    raise RuntimeError("6번째 이전에 잠금/제한 징후가 있습니다. 기존 기록과 서버 로그를 확인하세요.")
                if result["error"]:
                    raise RuntimeError(result["error"])
                if index < len(usernames):
                    time.sleep(args.interval)
    except PossibleLoginSuccess:
        possible_login = True
        stop_reason = "로그인 성공 가능성이 감지되어 중단했습니다."
        print("[POSSIBLE LOGIN SUCCESS]\n테스트용 비밀번호가 실제 계정과 일치했을 가능성이 있습니다.\n안전을 위해 테스트를 중단합니다.")
    except requests.exceptions.Timeout:
        stop_reason = "서버가 제한 시간 안에 응답하지 않았습니다."
    except requests.exceptions.ConnectionError:
        stop_reason = "테스트 서버에 연결할 수 없습니다.\n      서버가 실행 중이고 주소와 포트가 올바른지 확인하세요."
    except requests.exceptions.RequestException:
        # InvalidHeader 등의 예외 원문에는 CSRF 토큰이 들어갈 수 있어 출력하지 않는다.
        stop_reason = "HTTP 요청 처리에 실패했습니다. URL·요청 형식·CSRF 설정을 확인하세요."
    except RuntimeError as error:
        stop_reason = str(error)
    except KeyboardInterrupt:
        print("[INTERRUPTED] 사용자가 Password Spraying 테스트를 중단했습니다.")
        print_summary(results, usernames, args, time.monotonic() - started, "사용자 중단")
        return 130
    return 0 if print_summary(results, usernames, args, time.monotonic() - started,
                             stop_reason, possible_login) else 1


if __name__ == "__main__":
    raise SystemExit(main())
