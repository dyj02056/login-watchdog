"""Docker 없이 연습용 공격 상자 CLI의 안전장치를 검사한다."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LW_PATH = PROJECT_ROOT / "netwatch" / "attacker" / "lw.py"
TARGET_URL = "http://172.28.11.10:8080"


def load_lw_module():
    """패키지가 아닌 lw.py를 파일 경로로 불러온다."""
    spec = importlib.util.spec_from_file_location(
        "test_attacker_lw",
        LW_PATH,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lw = load_lw_module()


class FakeRunner:
    """실제 nmap·hping3·시뮬레이터 대신 명령만 기록한다."""

    def __init__(
        self,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.returncode = returncode
        self.standard_output = stdout
        self.standard_error = stderr
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs):
        self.commands.append(command)

        return SimpleNamespace(
            returncode=self.returncode,
            stdout=self.standard_output,
            stderr=self.standard_error,
        )


class FakeResponse:
    """로그인 및 User-Agent 요청에 사용할 가짜 HTTP 응답."""

    def __init__(
        self,
        status_code: int,
        *,
        text: str = "",
        location: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = {}

        if location is not None:
            self.headers["Location"] = location

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("fake http error")


class FakeSession:
    """GET 로그인 폼과 POST 로그인 결과를 순서대로 반환한다."""

    def __init__(self, post_response: FakeResponse) -> None:
        self.post_response = post_response
        self.posted_data: dict | None = None

    def get(self, url: str, **kwargs) -> FakeResponse:
        return FakeResponse(
            200,
            text=(
                '<form><input type="hidden" '
                'name="csrf_token" value="test-csrf"></form>'
            ),
        )

    def post(
        self,
        url: str,
        *,
        data: dict,
        **kwargs,
    ) -> FakeResponse:
        self.posted_data = data
        return self.post_response


def run_cli(
    argv: list[str],
    *,
    environ: dict[str, str] | None = None,
    runner=None,
    request_get=None,
    session_factory=None,
):
    """lw.main을 실행하고 출력 JSON과 stderr를 반환한다."""
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = lw.main(
        argv,
        environ={} if environ is None else environ,
        runner=runner,
        stdout=stdout,
        stderr=stderr,
        request_get=request_get,
        session_factory=session_factory,
    )

    lines = [
        line
        for line in stdout.getvalue().splitlines()
        if line.strip()
    ]
    result = json.loads(lines[-1]) if lines else None

    return exit_code, result, stdout.getvalue(), stderr.getvalue()


def test_target_url_is_required() -> None:
    """TARGET_URL이 없으면 어떤 공격 명령도 실행하지 않는다."""
    runner = FakeRunner()

    exit_code, result, _, stderr = run_cli(
        ["scan"],
        environ={},
        runner=runner,
    )

    assert exit_code == 2
    assert result is None
    assert runner.commands == []
    assert "TARGET_URL" in stderr


def test_external_target_is_rejected() -> None:
    """환경변수라도 우리 실습망 gateway가 아니면 거부한다."""
    runner = FakeRunner()

    exit_code, result, _, _ = run_cli(
        ["scan"],
        environ={"TARGET_URL": "https://example.com"},
        runner=runner,
    )

    assert exit_code == 2
    assert result is None
    assert runner.commands == []


def test_host_argument_is_not_accepted() -> None:
    """사용자가 CLI에서 별도 공격 대상을 지정할 수 없다."""
    with pytest.raises(SystemExit) as error:
        lw.main(
            ["scan", "--host", "http://example.com"],
            environ={"TARGET_URL": TARGET_URL},
        )

    assert error.value.code == 2


def test_synflood_limit_rejects_more_than_5000() -> None:
    """SYN 전송 상한을 넘는 요청은 argparse 단계에서 거부한다."""
    with pytest.raises(SystemExit) as error:
        lw.main(
            ["synflood", "--count", "5001"],
            environ={"TARGET_URL": TARGET_URL},
        )

    assert error.value.code == 2


def test_synflood_builds_bounded_hping3_command() -> None:
    """hping3 명령에 대상·포트·속도·개수 제한이 들어간다."""
    runner = FakeRunner()

    exit_code, result, _, _ = run_cli(
        ["synflood", "--count", "100"],
        environ={"TARGET_URL": TARGET_URL},
        runner=runner,
    )

    assert exit_code == 0
    assert result["sent"] == 100

    command = runner.commands[0]

    assert command[0] == "hping3"
    assert "-S" in command
    assert ["-p", "8080"] == command[
        command.index("-p"):command.index("-p") + 2
    ]
    assert ["-i", "u2000"] == command[
        command.index("-i"):command.index("-i") + 2
    ]
    assert ["-c", "100"] == command[
        command.index("-c"):command.index("-c") + 2
    ]
    assert command[-1] == "172.28.11.10"


def test_scanner_ua_uses_sid_9000004_name() -> None:
    """스캐너 UA가 계약서에 명시된 pcre 목록 안에 있다."""
    calls: list[dict] = []

    def fake_get(url: str, **kwargs):
        calls.append({"url": url, **kwargs})
        return FakeResponse(200)

    exit_code, result, _, _ = run_cli(
        ["scanner-ua", "--ua", "sqlmap", "--requests", "3"],
        environ={"TARGET_URL": TARGET_URL},
        request_get=fake_get,
    )

    assert exit_code == 0
    assert result["ua"] in lw.SCANNER_USER_AGENTS
    assert result["statuses"] == [200, 200, 200]
    assert len(calls) == 3

    for call in calls:
        assert call["headers"]["User-Agent"] == "sqlmap"


def test_login_without_password_returns_json_error() -> None:
    """비밀번호가 없으면 값을 묻거나 출력하지 않고 JSON으로 끝낸다."""
    exit_code, result, stdout, stderr = run_cli(
        ["login", "--username", "victim_a"],
        environ={"TARGET_URL": TARGET_URL},
    )

    assert exit_code == 0
    assert result["ok"] is False
    assert result["error"] == "no_password"
    assert result["success"] is False
    assert "LW_VICTIM_PASSWORD" not in stdout.lower()
    assert "LW_VICTIM_PASSWORD" not in stderr.lower()


@pytest.mark.parametrize(
    ("status_code", "location", "expected_success"),
    [
        (302, "/dashboard", True),
        (302, "http://172.28.11.10:8080/dashboard", True),
        (302, "/login", False),
        (200, None, False),
    ],
)
def test_login_success_judgment(
    status_code: int,
    location: str | None,
    expected_success: bool,
) -> None:
    """302로 회원 대시보드(/dashboard)에 갈 때만 로그인 성공으로 판단한다."""
    password = "test-victim-pw"
    session = FakeSession(
        FakeResponse(
            status_code,
            location=location,
        )
    )

    exit_code, result, stdout, stderr = run_cli(
        ["login", "--username", "victim_a"],
        environ={
            "TARGET_URL": TARGET_URL,
            "LW_VICTIM_PASSWORD": password,
        },
        session_factory=lambda: session,
    )

    assert exit_code == 0
    assert result["success"] is expected_success
    assert result["status"] == status_code
    assert password not in stdout
    assert password not in stderr
    assert session.posted_data["password"] == password


@pytest.mark.parametrize(
    ("argv", "expected_step"),
    [
        (["scan"], "scan"),
        (["webscan"], "webscan"),
        (
            ["brute", "--username", "test-user", "--attempts", "3"],
            "brute",
        ),
        (["synflood", "--count", "10"], "synflood"),
        (
            ["httpflood", "--path", "/", "--requests", "10"],
            "httpflood",
        ),
    ],
)
def test_command_stdout_ends_with_json(
    argv: list[str],
    expected_step: str,
) -> None:
    """외부 명령을 쓰는 각 단계가 마지막에 공통 JSON을 출력한다."""
    runner = FakeRunner(
        stdout="Ports: 8080/open/tcp//http///\n",
    )

    exit_code, result, stdout, _ = run_cli(
        argv,
        environ={"TARGET_URL": TARGET_URL},
        runner=runner,
    )

    assert exit_code == 0
    assert result["step"] == expected_step
    assert result["target"] == TARGET_URL
    assert result["ok"] is True
    assert json.loads(stdout.splitlines()[-1]) == result


@pytest.mark.parametrize(
    ("argv", "expected_path", "expects_remote_flag"),
    [
        (
            ["webscan"],
            "/app/scripts/simulation/medium/"
            "web_scanning_sim.py",
            # web_scanning_sim에는 --i-know-what-im-doing 인자가 없다(붙이면 exit 2).
            False,
        ),
        (
            ["brute", "--username", "u", "--attempts", "3"],
            "/app/scripts/simulation/critical/"
            "bruteforce_sim.py",
            True,
        ),
        (
            ["httpflood", "--path", "/", "--requests", "10"],
            "/app/scripts/simulation/high/"
            "http_flood_sim.py",
            True,
        ),
    ],
)
def test_simulators_use_python_and_image_paths(
    argv: list[str],
    expected_path: str,
    expects_remote_flag: bool,
) -> None:
    """기존 시뮬레이터를 이미지 안의 고정 경로로 실행한다."""
    runner = FakeRunner()

    run_cli(
        argv,
        environ={"TARGET_URL": TARGET_URL},
        runner=runner,
    )

    command = runner.commands[0]

    assert command[0] == sys.executable
    assert command[1] == expected_path
    assert command[
        command.index("--host") + 1
    ] == TARGET_URL
    assert ("--i-know-what-im-doing" in command) is expects_remote_flag


def test_simulators_accept_the_flags_lw_passes() -> None:
    """lw가 넘기는 --i-know-what-im-doing을 실제 시뮬레이터가 받는지 원본에서 확인한다."""
    simulation = PROJECT_ROOT / "scripts" / "simulation"
    flag = '"--i-know-what-im-doing"'

    assert flag not in (
        simulation / "medium" / "web_scanning_sim.py"
    ).read_text(encoding="utf-8")
    assert flag in (
        simulation / "critical" / "bruteforce_sim.py"
    ).read_text(encoding="utf-8")
    assert flag in (
        simulation / "high" / "http_flood_sim.py"
    ).read_text(encoding="utf-8")


def test_member_dashboard_path_matches_app_route() -> None:
    """login 성공 판정 경로가 앱의 회원 대시보드 라우트와 같다."""
    member_routes = (PROJECT_ROOT / "routes" / "member.py").read_text(
        encoding="utf-8"
    )

    assert '@member_bp.route("/dashboard"' in member_routes
    assert lw.MEMBER_DASHBOARD_PATH == "/dashboard"


def test_app_trusts_gateway_forwarded_for() -> None:
    """공격 상자마다 다른 출발지 IP가 앱에 보이도록 app이 gateway의 XFF를 믿는다.

    TRUST_FORWARDED_FOR가 없으면 모든 요청이 gateway core 주소로 보여 brute가
    gateway 주소를 잠그고(모두 차단) S4·S6을 확인할 수 없다.
    """
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"
    )

    assert 'TRUST_FORWARDED_FOR: "true"' in compose


def test_compose_defines_fixed_attacker_network() -> None:
    """공격 상자가 고정된 lw_edge 네트워크만 사용하게 한다."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"
    )

    assert "name: lw_edge" in compose
    assert compose.count("image: lw-attacker:latest") == 3
    assert compose.count("profiles:\n      - attack") == 3
    assert compose.count("TARGET_URL:") == 3
    assert compose.count('ipv4_address: "${LW_EDGE_PREFIX}.101"') == 1
    assert compose.count('ipv4_address: "${LW_EDGE_PREFIX}.102"') == 1
    assert compose.count('ipv4_address: "${LW_EDGE_PREFIX}.103"') == 1


def test_compose_gives_attackers_only_net_raw() -> None:
    """공격 상자에는 패킷 생성에 필요한 NET_RAW만 부여한다."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"
    )

    attacker_section = compose.split("  attacker-1:", 1)[1].split(
        "\nnetworks:",
        1,
    )[0]

    assert attacker_section.count("- NET_RAW") == 3
    assert "NET_ADMIN" not in attacker_section
    assert "LW_VICTIM_PASSWORD" not in attacker_section


def test_attacker_dockerfile_and_requirements() -> None:
    """공격 이미지가 필요한 도구만 설치하고 비밀값을 포함하지 않게 한다."""
    dockerfile = (
        PROJECT_ROOT / "netwatch" / "attacker" / "Dockerfile"
    ).read_text(encoding="utf-8")
    requirements = (
        PROJECT_ROOT / "netwatch" / "attacker" / "requirements.txt"
    ).read_text(encoding="utf-8")

    assert "FROM python:3.12-slim" in dockerfile
    assert "nmap" in dockerfile
    assert "hping3" in dockerfile
    assert "iproute2" in dockerfile
    assert "COPY scripts/simulation" in dockerfile
    assert 'ENTRYPOINT ["python", "/app/netwatch/attacker/lw.py"]' in dockerfile

    assert "requests==2.34.2" in requirements
    assert "python-dotenv==1.2.3" in requirements
    assert "LW_VICTIM_PASSWORD" not in dockerfile