# ============================================================================
# password_spraying_sim.py — "패스워드 스프레이(Password Spraying)" 공격을
# 흉내 내서, 우리 서버가 이를 탐지하는지 확인하는 검증 스크립트
#
# 패스워드 스프레이란? 브루트포스(한 계정에 비밀번호를 수십 번 바꿔가며
# 시도)와 반대로, "같은 비밀번호 하나"를 "서로 다른 여러 아이디"에 돌아가며
# 시도하는 공격이다. 계정 하나만 노리지 않으므로 "한 계정에 5번 틀리면
# 잠금" 같은 단순한 규칙은 피해갈 수 있는데, 대신 "같은 IP·같은 세션에서
# 짧은 시간에 서로 다른 아이디로 여러 번 실패"라는 패턴이 남는다. 이
# 스크립트는 바로 그 패턴을 재현해서 서버가 알아채는지 확인한다.
#
# 동작 요약:
#   1) 하나의 세션(=하나의 접속)을 계속 유지한 채, /login에 POST로 로그인을
#      시도한다.
#   2) 매 요청마다 "아이디"는 바꾸지만 "비밀번호"는 항상 똑같은(일부러 틀린)
#      값을 쓴다 — IP와 세션도 고정한다.
#   3) 기본 6번 시도하며, FAILURE_THRESHOLD(5)를 넘는 6번째 요청이
#      "이쯤이면 서버가 의심해야 하는 시점"이다.
#   4) 실제로 로그인 페이지가 CSRF 토큰(위조 방지용 1회용 값)을 요구하므로,
#      매번 로그인 폼을 먼저 GET으로 열어서 토큰을 받아온 뒤 그 토큰을
#      포함해 POST를 보낸다 — 실제 브라우저 사용자와 똑같은 절차를 따른다.
#
# 안전 원칙: 기본적으로 로컬 서버(loopback: 127.0.0.1/localhost)만 대상으로
# 허용하며, 그 외 주소는 --i-know-what-im-doing 플래그 없이는 거부한다.
# 비밀번호나 CSRF 토큰 같은 민감한 값은 화면에 그대로 출력하지 않고
# <REDACTED>(가림 처리)로 바꿔서 보여준다.
# ============================================================================

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
DEFAULT_COUNT = 6                # 기본 시도 횟수 (임계값 5를 넘기는 6번째까지 포함)
DEFAULT_INTERVAL = 0.5           # 요청 사이 대기 시간(초)
REQUEST_TIMEOUT = 5
FAILURE_THRESHOLD = 5            # 서버가 "이 횟수를 넘으면 의심"이라고 보는 실패 기준
USERNAME_FIELD = "username"
PASSWORD_FIELD = "password"
CSRF_FIELD = "csrf_token"        # 위조 방지용 1회용 토큰 필드 이름
DEFAULT_TEST_PASSWORD = "wrong_test_password"  # 항상 틀리도록 고정해 둔 테스트용 비밀번호
MAX_RESPONSE_PREVIEW = 300
LOCK_MARKERS = ("잠긴 계정", "계정 잠금", "account locked", "locked account")
SUCCESS_MARKERS = ("로그인 성공", "로그인에 성공", "login successful",
                   "successfully logged in", "logged in successfully")


class ConfigParser(argparse.ArgumentParser):
    """CLI 입력 오류를 traceback 없이 설정 오류로 표시한다.

    보통 argparse가 잘못된 입력을 받으면 프로그래머용 긴 에러 메시지(traceback)를
    쏟아내는데, 여기서는 그 대신 "[CONFIG ERROR] ..." 처럼 짧고 이해하기 쉬운
    한 줄 메시지만 보여주도록 바꿨다.
    """

    def error(self, message):
        """argparse의 오류 종료 코드를 2로 유지한다."""
        self.exit(2, f"[CONFIG ERROR] {message}\n")


class LoginHTML(HTMLParser):
    """로그인 페이지 HTML에서 "숨겨진 CSRF 토큰"과 "화면에 보이는 글자"를 따로 뽑아낸다.

    로그인 폼에는 사용자 눈에 보이지 않는 <input type="hidden" name="csrf_token"
    value="...">라는 위조 방지용 값이 숨어있다. 이 클래스는 HTML을 한 줄씩
    읽어가며 그 값만 따로 모으고(self.tokens), 동시에 눈에 보이는 문구들도
    따로 모아서(self.text) 나중에 "로그인 성공/실패 메시지가 있는지" 등을
    분석할 때 쓴다.
    """

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
    """혹시 진짜로 로그인에 성공한 것 같으면, 이 예외를 던져서 즉시 테스트를 멈춘다.

    이 스크립트는 "일부러 틀린 비밀번호"만 써야 하는데, 만약 우연히 실제
    계정 정보와 일치해서 로그인이 성공해버리면 위험하다(진짜 계정에
    영향을 줄 수 있음). 그래서 응답에서 "로그인 성공" 같은 신호가
    보이면 곧바로 멈추고 사용자에게 경고한다.
    """


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
    """문자열 IP를 파싱하여 loopback 여부를 판단한다.

    "loopback"이란 127.0.0.1처럼 "내 컴퓨터 자신"을 가리키는 특수 주소를 뜻한다.
    """
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def is_local_host(url):
    """이 URL이 정말로 "내 컴퓨터(로컬)"를 가리키는지 확인한다.

    IP 주소로 입력했다면 loopback 주소인지만 보면 되지만, "localhost"라는
    이름으로 입력했다면 실제로 DNS가 그 이름을 어떤 IP로 해석하는지까지
    확인해서, 전부 loopback일 때만 "로컬이다"라고 인정한다 — 누군가 DNS
    설정을 조작해 localhost를 다른 서버로 돌려놓는 상황까지 대비한 것이다.
    """
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
    """테스트 전체에서 딱 하나만 만들어서 계속 재사용하는 세션(=같은 접속)을 만든다.

    패스워드 스프레이 공격의 핵심 특징 중 하나가 "같은 세션/같은 IP에서
    여러 아이디를 시도한다"는 것이므로, 이 스크립트도 매 요청마다 새
    세션을 만들지 않고 하나의 세션을 끝까지 재사용해서 그 상황을
    그대로 재현한다.
    """
    session = requests.Session()
    session.trust_env = False
    session.auth = None
    session.headers.update({"User-Agent": "Watchdog-PasswordSpraying-Test/1.0"})
    return session


def parse_usernames(args):
    """이번 테스트에 사용할 "서로 다른 아이디 목록"을 준비하고 유효성을 검사한다.

    --usernames로 직접 콤마(,)로 구분해 지정하거나, --username-prefix로
    접두사를 주면 spray_user1, spray_user2 ... 식으로 자동 생성한다.
    아이디가 서로 겹치면(중복) 스프레이 공격의 "여러 계정을 노린다"는
    전제가 깨지므로 에러로 막고, 최소 개수(임계값+1개)도 검사한다.
    """
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
    """로그인 폼을 먼저 GET으로 열어서, 그 안에 숨어있는 CSRF 토큰을 꺼내온다.

    실제 브라우저 사용자는 로그인 페이지를 먼저 연 뒤 아이디/비밀번호를
    입력해 제출한다. 이 GET 요청은 "로그인 실패 시도"로 세지 않는다는
    전제 하에, 매 POST 직전 새로 토큰을 받아온다(토큰은 보통 세션마다
    한 번만 유효하거나 시간이 지나면 바뀔 수 있기 때문).
    """
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
    """실제 로그인 폼 제출과 똑같은 방식으로 아이디/비밀번호 POST 요청 한 건을 보낸다."""
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
    """응답 JSON을 화면에 출력하기 전에, 비밀번호·토큰 등 민감한 값은 가려서 보여준다.

    key 이름에 password, token, cookie, secret, authorization, api key
    같은 단어가 들어있으면 그 값은 <REDACTED>(가림 처리)로 바꾼다. 딕셔너리와
    리스트는 안쪽까지 재귀적으로(반복해서) 들어가며 검사한다.
    """
    if isinstance(value, dict):
        return {key: "<REDACTED>" if re.search(
            r"password|token|cookie|secret|authorization|api.?key", key, re.I
        ) else redact_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


def safe_location(location):
    """서버가 응답에 담아 보낸 "이동할 주소"(Location 헤더)에서 민감한 부분을 지우고 보여준다.

    Location 안에 아이디/비밀번호나 쿼리 파라미터, 해시(#) 값이 섞여 있을 수
    있으므로, 그런 부분은 다 빼고 "스킴+호스트+경로"만 남긴 안전한 형태로
    화면에 출력한다.
    """
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
    """서버가 보낸 응답 하나를 자세히 뜯어보고, "잠금 신호"나 "로그인 성공 가능성"을 찾아낸다.

    확인 항목:
      - lock_detected / lock_message: "계정 잠금" 같은 문구가 있는지
      - possible_login_success: "로그인 성공" 문구나, success/authenticated 같은
        JSON 필드가 true인 경우, 또는 /dashboard·/account 같은 로그인 후 이동하는
        페이지로 리다이렉트되는 경우 — 이런 신호가 보이면 "진짜로 로그인이
        성공했을 수도 있다"고 판단한다(그러면 즉시 멈춰야 함).
      - error: 예상하지 못한 상태 코드나 CSRF 오류 등 "테스트가 원래 의도대로
        진행되지 않았다"는 신호.
    비밀번호나 CSRF 토큰이 응답에 그대로 노출되지 않도록, 우리가 실제로 보낸
    값과 일치하는 문자열은 화면 출력 전에 <REDACTED>로 가린다.
    """
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
    """로그인 시도 한 건의 결과를 사람이 읽기 쉬운 형태로 화면에 출력한다."""
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
        # 6번째 시도 = 임계값(5)을 넘긴 첫 시도. 이 시점에서 서버가 패스워드
        # 스프레이로 인식했어야 정상이므로, 사람이 직접 확인해야 할 체크포인트다.
        print(f"[THRESHOLD EXCEEDED]\nFAILURE_THRESHOLD={FAILURE_THRESHOLD} 초과 확인 시점입니다.")
        print("각 POST가 같은 시간창에서 로그인 실패로 기록되었다는 전제입니다.")
        print("[MANUAL CHECK] security_events에서 event_type=PASSWORD_SPRAYING 확인")
    print(flush=True)


def print_plan(args, usernames, url):
    """실제 요청을 보내기 전에, 이번 테스트가 어떤 계획으로 진행될지 미리 보여준다.

    비밀번호는 절대 화면에 그대로 노출하지 않고 "********"로만 표시하며,
    --dry-run(연습 실행) 모드일 때는 이 계획만 보여주고 실제 네트워크
    요청은 전혀 보내지 않는다.
    """
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
    """전체 시도가 끝난 뒤(또는 중간에 멈췄을 때), 결과를 종합해서 요약 리포트를 출력한다."""
    possible_login = possible_login or any(row["possible_login_success"] for row in results)
    # passed: 계획한 모든 요청이 끝까지 진행됐고, 중간에 중단 사유가 없었고,
    # 실수로 로그인 성공한 것도 아니고, 개별 요청에서 에러도 없었을 때만 성공으로 본다.
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
    # 이 스크립트는 요청을 보내고 응답을 확인할 뿐, 서버가 실제로 보안 이벤트를
    # 만들고 알림을 울렸는지는 알 수 없다. 그래서 항상 사람이 직접 확인하라고 안내한다.
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
            # 로컬(내 컴퓨터)이 아닌 서버를 대상으로 하려면, 실수로 남의
            # 서버를 공격하는 사고를 막기 위해 일부러 이 플래그를 요구한다.
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
        # with 문으로 세션을 감싸서, 테스트가 끝나면(에러가 나도) 세션이
        # 자동으로 정리되도록 한다.
        with create_test_session() as session:
            for index, username in enumerate(usernames, 1):
                token = None if args.no_csrf else get_csrf_token(session, url)
                with send_login_attempt(session, url, username, args.password, args.use_json, token) as response:
                    result = validate_response(response)
                results.append(result)
                print_attempt_result(index, len(usernames), username, result)
                if result["possible_login_success"]:
                    # 진짜로 로그인이 성공한 것처럼 보이면 안전을 위해 즉시 중단한다.
                    raise PossibleLoginSuccess()
                if index <= FAILURE_THRESHOLD and (result["lock_detected"] or result["possible_lock"]):
                    # 아직 임계값(5)도 넘기기 전인데 벌써 잠금/제한 신호가 보이면,
                    # 이전 테스트의 흔적이 남아있는 등 테스트 전제가 깨진 것이므로 중단한다.
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
    # 터미널에서 "python password_spraying_sim.py"로 직접 실행했을 때만 동작하고,
    # 다른 파일에서 import만 했을 때는 자동으로 실행되지 않게 하는 관용적인 표현이다.
    raise SystemExit(main())
