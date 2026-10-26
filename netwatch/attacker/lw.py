"""로컬 Docker 실습망 전용 공격 재현 CLI.

SCANNER_USER_AGENTS는 Suricata local.rules의 sid 9000004 pcre 목록
(sqlmap|nikto|nmap|masscan|dirbuster|gobuster)과 같아야 한다.

사용자가 임의의 대상을 지정하지 못하게 CLI에는 --host가 없다.
대상은 실행 환경의 TARGET_URL만 사용하며, 172.28.0.0/16 대역의
gateway .10:8080 주소만 허용한다.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Callable, Mapping, TextIO
from urllib.parse import urlparse


APP_ROOT = PurePosixPath("/app")
SIMULATION_ROOT = APP_ROOT / "scripts" / "simulation"

WEBSCAN_SCRIPT = (
    SIMULATION_ROOT / "medium" / "web_scanning_sim.py"
)
BRUTE_SCRIPT = (
    SIMULATION_ROOT / "critical" / "bruteforce_sim.py"
)
HTTP_FLOOD_SCRIPT = (
    SIMULATION_ROOT / "high" / "http_flood_sim.py"
)

# 로그인 성공 시 앱이 보내는 회원 대시보드 경로(routes/member.py의 member_dashboard).
# 앱에서 이 경로가 바뀌면 여기도 함께 바꿔야 S6 판정(success)이 맞게 나온다.
MEMBER_DASHBOARD_PATH = "/dashboard"

# 앱에 Next.js 정적 화면(spa/)이 들어 있으면 GET /login은 csrf_token 입력칸이 없는 화면 껍데기를
# 돌려준다(helpers/spa.py). 브라우저처럼 이 헤더를 붙여 다시 요청하면 같은 라우트가 JSON 봉투
# {"csrf": ..., "page": ...}로 답하므로, 껍데기에서 토큰을 못 찾았을 때 이 경로로 받는다.
# 앱의 helpers/spa.py SPA_HEADER·SPA_HEADER_VALUE가 바뀌면 여기도 함께 바꾼다.
SPA_HEADER = "X-Requested-With"
SPA_HEADER_VALUE = "login-watchdog-spa"

SCANNER_USER_AGENTS = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "dirbuster",
    "gobuster",
)

ALLOWED_TARGET_NETWORK = ipaddress.ip_network("172.28.0.0/16")
TARGET_GATEWAY_HOST_NUMBER = 10
TARGET_PORT = 8080

MAX_SYN_COUNT = 5000
MAX_BRUTE_ATTEMPTS = 20
MAX_SCANNER_REQUESTS = 10
MAX_HTTP_REQUESTS = 500


class CsrfTokenParser(HTMLParser):
    """로그인 폼의 hidden csrf_token 값을 찾는다."""

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


def extract_csrf_token(html: str) -> str:
    """HTML 로그인 폼에서 CSRF 토큰을 추출한다."""
    parser = CsrfTokenParser()
    parser.feed(html)

    if not parser.token:
        raise ValueError("로그인 폼에서 CSRF 토큰을 찾지 못했습니다.")

    return parser.token


def fetch_login_csrf(session, login_url: str) -> str:
    """로그인 화면을 열어 CSRF 토큰을 받는다. 같은 세션 쿠키로 이어서 POST해야 유효하다.

    먼저 옛 Jinja 폼(hidden csrf_token)에서 찾고, 없으면 SPA 헤더로 다시 요청해 JSON의 csrf를 쓴다.
    Docker 단지처럼 spa/ 빌드가 있는 앱은 껍데기만 주므로, 이 대체 경로가 없으면 로그인 POST를
    보내지도 못하고 끝난다(10/26 C3-1 S6 FAIL의 원인).
    """
    response = session.get(login_url, timeout=5)
    response.raise_for_status()
    try:
        return extract_csrf_token(response.text)
    except ValueError:
        pass

    spa_response = session.get(
        login_url,
        headers={SPA_HEADER: SPA_HEADER_VALUE},
        timeout=5,
    )
    spa_response.raise_for_status()
    try:
        token = json.loads(spa_response.text).get("csrf")
    except (ValueError, AttributeError):
        token = None
    if not token:
        raise ValueError("로그인 화면(HTML·SPA JSON)에서 CSRF 토큰을 찾지 못했습니다.")
    return token


def bounded_int(
    minimum: int,
    maximum: int,
) -> Callable[[str], int]:
    """argparse에서 사용할 제한된 정수 변환기를 만든다."""

    def convert(raw_value: str) -> int:
        try:
            value = int(raw_value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                "정수를 입력해야 합니다."
            ) from error

        if not minimum <= value <= maximum:
            raise argparse.ArgumentTypeError(
                f"{minimum} 이상 {maximum} 이하만 허용합니다."
            )

        return value

    return convert


def parse_target_url(target_url: str) -> tuple[str, int, str]:
    """TARGET_URL이 로컬 실습망 gateway인지 검증한다."""
    normalized = target_url.rstrip("/")
    parsed = urlparse(normalized)

    if parsed.scheme != "http":
        raise ValueError("TARGET_URL은 http 주소여야 합니다.")

    if not parsed.hostname:
        raise ValueError("TARGET_URL에 호스트가 없습니다.")

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            "TARGET_URL 포트가 올바르지 않습니다."
        ) from error

    if port != TARGET_PORT:
        raise ValueError(
            f"TARGET_URL은 {TARGET_PORT} 포트만 허용합니다."
        )

    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise ValueError(
            "TARGET_URL은 실습망 IPv4 주소여야 합니다."
        ) from error

    if (
        address not in ALLOWED_TARGET_NETWORK
        or int(str(address).split(".")[-1])
        != TARGET_GATEWAY_HOST_NUMBER
    ):
        raise ValueError(
            "TARGET_URL은 172.28.x.10 gateway만 허용합니다."
        )

    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError(
            "TARGET_URL에는 추가 경로나 쿼리를 넣을 수 없습니다."
        )

    return str(address), port, normalized


def emit_json(result: dict, stdout: TextIO) -> None:
    """자동화 스크립트가 읽을 결과를 JSON 한 줄로 출력한다."""
    stdout.write(
        json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    stdout.write("\n")
    stdout.flush()


def write_subprocess_output(
    completed: object,
    stderr: TextIO,
) -> None:
    """하위 프로그램 출력을 JSON stdout과 섞이지 않게 stderr로 보낸다."""
    standard_output = getattr(completed, "stdout", "") or ""
    standard_error = getattr(completed, "stderr", "") or ""

    if standard_output:
        stderr.write(standard_output)

        if not standard_output.endswith("\n"):
            stderr.write("\n")

    if standard_error:
        stderr.write(standard_error)

        if not standard_error.endswith("\n"):
            stderr.write("\n")

    stderr.flush()


def run_process(
    command: list[str],
    runner: Callable[..., object],
    stderr: TextIO,
) -> object:
    """외부 명령을 실행하고 사람용 출력을 stderr로 전달한다."""
    completed = runner(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    write_subprocess_output(completed, stderr)
    return completed


def base_result(step: str, target_url: str) -> dict:
    """모든 명령에 공통으로 들어갈 JSON 칸을 만든다."""
    return {
        "step": step,
        "target": target_url,
        "ok": False,
    }


def command_scan(
    target_host: str,
    target_url: str,
    runner: Callable[..., object],
    stderr: TextIO,
) -> tuple[dict, int]:
    """제한된 포트 범위를 nmap SYN scan으로 확인한다."""
    command = [
        "nmap",
        "-sS",
        "-p",
        "8000-8090",
        "--max-rate",
        "100",
        "--open",
        "-oG",
        "-",
        target_host,
    ]
    completed = run_process(command, runner, stderr)
    exit_code = int(getattr(completed, "returncode", 1))
    output = getattr(completed, "stdout", "") or ""

    open_ports = sorted(
        {
            int(port)
            for port in re.findall(r"(\d+)/open/tcp", output)
        }
    )

    result = base_result("scan", target_url)
    result.update(
        {
            "ok": exit_code == 0,
            "open_ports": open_ports,
        }
    )
    return result, 0 if result["ok"] else 1


def run_simulator(
    *,
    step: str,
    script_path: PurePosixPath,
    arguments: list[str],
    target_url: str,
    runner: Callable[..., object],
    stderr: TextIO,
    allow_remote_flag: bool = True,
) -> tuple[dict, int, str]:
    """기존 시뮬레이터를 현재 Python으로 실행한다.

    allow_remote_flag: bruteforce·http_flood 시뮬레이터는 로컬이 아닌 --host를
    --i-know-what-im-doing 없이는 거부하므로 붙인다. web_scanning_sim은 그 인자
    자체가 없어서(붙이면 argparse가 exit 2로 끝남) webscan에서는 False로 넘긴다.
    """
    command = [
        sys.executable,
        str(script_path),
        "--host",
        target_url,
    ]

    if allow_remote_flag:
        command.append("--i-know-what-im-doing")

    command.extend(arguments)
    completed = run_process(command, runner, stderr)
    exit_code = int(getattr(completed, "returncode", 1))
    output = getattr(completed, "stdout", "") or ""

    result = base_result(step, target_url)
    result.update(
        {
            "ok": exit_code == 0,
            "exit_code": exit_code,
        }
    )
    return result, 0 if result["ok"] else 1, output


def command_webscan(
    target_url: str,
    runner: Callable[..., object],
    stderr: TextIO,
) -> tuple[dict, int]:
    """기존 웹 스캐닝 시뮬레이터를 실행한다."""
    result, exit_code, _ = run_simulator(
        step="webscan",
        script_path=WEBSCAN_SCRIPT,
        arguments=[],
        target_url=target_url,
        runner=runner,
        stderr=stderr,
        allow_remote_flag=False,
    )
    return result, exit_code


def command_brute(
    target_url: str,
    username: str,
    attempts: int,
    runner: Callable[..., object],
    stderr: TextIO,
) -> tuple[dict, int]:
    """기존 Brute Force 시뮬레이터를 제한된 횟수로 실행한다."""
    result, exit_code, output = run_simulator(
        step="brute",
        script_path=BRUTE_SCRIPT,
        arguments=[
            "--username",
            username,
            "--attempts",
            str(attempts),
        ],
        target_url=target_url,
        runner=runner,
        stderr=stderr,
    )

    lowered_output = output.lower()
    result["locked"] = (
        "잠긴 계정입니다" in output
        or "이미 잠김" in output
        or "locked" in lowered_output
    )
    return result, exit_code


def command_scanner_ua(
    target_url: str,
    ua: str,
    request_count: int,
    *,
    request_get: Callable[..., object] | None = None,
) -> tuple[dict, int]:
    """스캐너 User-Agent로 제한된 횟수의 GET 요청을 보낸다."""
    if request_get is None:
        import requests

        request_get = requests.get

    statuses: list[int] = []
    error_name: str | None = None

    for _ in range(request_count):
        try:
            response = request_get(
                f"{target_url}/",
                headers={"User-Agent": ua},
                timeout=5,
                allow_redirects=False,
            )
            statuses.append(int(response.status_code))
        except Exception as error:  # 네트워크 예외 종류는 requests가 결정한다.
            error_name = type(error).__name__
            break

    ok = error_name is None and len(statuses) == request_count
    result = base_result("scanner-ua", target_url)
    result.update(
        {
            "ok": ok,
            "ua": ua,
            "statuses": statuses,
        }
    )

    if error_name:
        result["error"] = error_name

    return result, 0 if ok else 1


def command_login(
    target_url: str,
    username: str,
    password: str | None,
    *,
    session_factory: Callable[[], object] | None = None,
) -> tuple[dict, int]:
    """환경변수의 비밀번호로 로그인 요청을 한 번 보낸다."""
    result = base_result("login", target_url)

    if not password:
        result.update(
            {
                "error": "no_password",
                "success": False,
                "status": None,
                "redirect": None,
            }
        )
        # 비밀번호 없음은 자동화가 JSON으로 판정하므로 프로세스 오류로 만들지 않는다.
        return result, 0

    if session_factory is None:
        import requests

        session_factory = requests.Session

    try:
        session = session_factory()
        login_url = f"{target_url}/login"

        csrf_token = fetch_login_csrf(session, login_url)

        # POST에는 SPA 헤더를 붙이지 않는다 — 그래야 앱이 JSON이 아니라 평소처럼 302(성공)·200(실패)으로
        # 답하고, 아래 성공 판정을 그대로 쓸 수 있다.
        post_response = session.post(
            login_url,
            data={
                "username": username,
                "password": password,
                "csrf_token": csrf_token,
            },
            timeout=5,
            allow_redirects=False,
        )

        status = int(post_response.status_code)
        redirect = post_response.headers.get("Location")
        # Location은 상대 경로("/dashboard")나 절대 URL로 올 수 있어 경로만 비교한다.
        # "/login"으로 되돌아가는 302(잠금 안내 등)와, 로그인 화면을 다시 주는 200(비밀번호 틀림·CR-03 차단 —
        # 둘은 일부러 같은 화면이다)은 성공이 아니다.
        redirect_path = (
            urlparse(redirect).path.rstrip("/") if redirect else ""
        )
        success = (
            status == 302
            and redirect_path == MEMBER_DASHBOARD_PATH
        )

        result.update(
            {
                "ok": True,
                "success": success,
                "status": status,
                "redirect": redirect,
            }
        )
        return result, 0

    except Exception as error:
        result.update(
            {
                "error": type(error).__name__,
                "success": False,
                "status": None,
                "redirect": None,
            }
        )
        return result, 1


def command_synflood(
    target_host: str,
    target_port: int,
    target_url: str,
    count: int,
    runner: Callable[..., object],
    stderr: TextIO,
) -> tuple[dict, int]:
    """속도와 개수를 제한한 SYN 패킷을 전송한다."""
    command = [
        "hping3",
        "-S",
        "-p",
        str(target_port),
        "-i",
        "u2000",
        "-c",
        str(count),
        target_host,
    ]
    completed = run_process(command, runner, stderr)
    exit_code = int(getattr(completed, "returncode", 1))

    result = base_result("synflood", target_url)
    result.update(
        {
            "ok": exit_code == 0,
            "sent": count,
        }
    )
    return result, 0 if result["ok"] else 1


def command_httpflood(
    target_url: str,
    path: str,
    request_count: int,
    runner: Callable[..., object],
    stderr: TextIO,
) -> tuple[dict, int]:
    """기존 HTTP Flood 시뮬레이터를 제한된 횟수로 실행한다."""
    if not path.startswith("/") or "://" in path:
        result = base_result("httpflood", target_url)
        result.update(
            {
                "error": "invalid_path",
                "exit_code": 2,
            }
        )
        return result, 2

    result, exit_code, _ = run_simulator(
        step="httpflood",
        script_path=HTTP_FLOOD_SCRIPT,
        arguments=[
            "--path",
            path,
            "--requests",
            str(request_count),
        ],
        target_url=target_url,
        runner=runner,
        stderr=stderr,
    )
    return result, exit_code


def create_parser() -> argparse.ArgumentParser:
    """공격 재현 명령행 인자를 정의한다."""
    parser = argparse.ArgumentParser(
        description="login-watchdog 로컬 실습망 공격 재현 도구"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser("scan")
    subparsers.add_parser("webscan")

    brute = subparsers.add_parser("brute")
    brute.add_argument(
        "--username",
        default="nonexistent-user",
    )
    brute.add_argument(
        "--attempts",
        type=bounded_int(1, MAX_BRUTE_ATTEMPTS),
        default=6,
    )

    scanner_ua = subparsers.add_parser("scanner-ua")
    scanner_ua.add_argument(
        "--ua",
        choices=SCANNER_USER_AGENTS,
        default="sqlmap",
    )
    scanner_ua.add_argument(
        "--requests",
        type=bounded_int(1, MAX_SCANNER_REQUESTS),
        default=3,
    )

    login = subparsers.add_parser("login")
    login.add_argument("--username", required=True)

    synflood = subparsers.add_parser("synflood")
    synflood.add_argument(
        "--count",
        type=bounded_int(1, MAX_SYN_COUNT),
        default=3000,
    )

    httpflood = subparsers.add_parser("httpflood")
    httpflood.add_argument("--path", default="/")
    httpflood.add_argument(
        "--requests",
        type=bounded_int(1, MAX_HTTP_REQUESTS),
        default=120,
    )

    return parser


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    runner: Callable[..., object] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    request_get: Callable[..., object] | None = None,
    session_factory: Callable[[], object] | None = None,
) -> int:
    """대상을 환경변수에서 읽고 선택한 재현 명령을 실행한다."""
    parser = create_parser()
    args = parser.parse_args(argv)

    active_environ = os.environ if environ is None else environ
    active_runner = subprocess.run if runner is None else runner
    active_stdout = sys.stdout if stdout is None else stdout
    active_stderr = sys.stderr if stderr is None else stderr

    target_value = active_environ.get("TARGET_URL", "").strip()

    if not target_value:
        active_stderr.write(
            "[FAIL] TARGET_URL이 없어 실행을 거부합니다.\n"
        )
        return 2

    try:
        target_host, target_port, target_url = parse_target_url(
            target_value
        )
    except ValueError as error:
        active_stderr.write(f"[FAIL] {error}\n")
        return 2

    if args.command == "scan":
        result, exit_code = command_scan(
            target_host,
            target_url,
            active_runner,
            active_stderr,
        )
    elif args.command == "webscan":
        result, exit_code = command_webscan(
            target_url,
            active_runner,
            active_stderr,
        )
    elif args.command == "brute":
        result, exit_code = command_brute(
            target_url,
            args.username,
            args.attempts,
            active_runner,
            active_stderr,
        )
    elif args.command == "scanner-ua":
        result, exit_code = command_scanner_ua(
            target_url,
            args.ua,
            args.requests,
            request_get=request_get,
        )
    elif args.command == "login":
        result, exit_code = command_login(
            target_url,
            args.username,
            active_environ.get("LW_VICTIM_PASSWORD"),
            session_factory=session_factory,
        )
    elif args.command == "synflood":
        result, exit_code = command_synflood(
            target_host,
            target_port,
            target_url,
            args.count,
            active_runner,
            active_stderr,
        )
    elif args.command == "httpflood":
        result, exit_code = command_httpflood(
            target_url,
            args.path,
            args.requests,
            active_runner,
            active_stderr,
        )
    else:  # argparse의 required=True 때문에 도달하지 않는다.
        parser.error("알 수 없는 명령입니다.")

    emit_json(result, active_stdout)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())