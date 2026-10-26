"""spa/ 빌드가 있는 앱에서도 공격 상자·시뮬레이터가 CSRF 토큰을 받아 로그인 POST를 보내는지 검사한다.

10/26 C3-1 첫 실행에서 Docker 앱의 GET /login이 Next.js 껍데기(csrf_token 입력칸 없음)를 돌려줘
lw.py login·brute가 POST를 한 번도 보내지 못했고, check_s6는 그 오류를 "메일 단계 기록 없음"으로 잘못 보고했다.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SIM_DIR = PROJECT_ROOT / "scripts" / "simulation"
TARGET_URL = "http://172.28.11.10:8080"
SPA_SHELL = '<html><body><div id="__next"><form class="form-stack"><input id="username"></form></div></body></html>'
SPA_JSON = json.dumps({"messages": [], "csrf": "spa-csrf", "page": "login_form.html", "status": 200})
HTML_FORM = '<form><input type="hidden" name="csrf_token" value="html-csrf"></form>'


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lw = _load("test_spa_lw", PROJECT_ROOT / "netwatch" / "attacker" / "lw.py")
sys.path.insert(0, str(SIM_DIR))
import _sim_common  # noqa: E402
bruteforce_sim = _load("test_spa_bruteforce_sim", SIM_DIR / "critical" / "bruteforce_sim.py")


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", location: str | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = {"Location": location} if location else {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("fake http error")

    def json(self):
        return json.loads(self.text)


class SpaSession:
    """헤더 없는 GET에는 껍데기를, SPA 헤더 GET에는 JSON 봉투를 주는 가짜 앱."""

    def __init__(self, spa_body: str = SPA_JSON, html_body: str = SPA_SHELL,
                 post_response: FakeResponse | None = None) -> None:
        self.spa_body = spa_body
        self.html_body = html_body
        self.post_response = post_response or FakeResponse(302, location="/dashboard")
        self.get_headers: list[dict] = []
        self.post_kwargs: dict | None = None
        self.headers: dict = {}

    def get(self, url: str, headers: dict | None = None, **kwargs) -> FakeResponse:
        self.get_headers.append(headers or {})
        if (headers or {}).get("X-Requested-With") == "login-watchdog-spa":
            return FakeResponse(200, self.spa_body)
        return FakeResponse(200, self.html_body)

    def post(self, url: str, **kwargs) -> FakeResponse:
        self.post_kwargs = kwargs
        return self.post_response


def _run_login(session) -> dict:
    stdout = io.StringIO()
    lw.main(
        ["login", "--username", "victim_a"],
        environ={"TARGET_URL": TARGET_URL, "LW_VICTIM_PASSWORD": "test-victim-pw"},
        stdout=stdout, stderr=io.StringIO(), session_factory=lambda: session,
    )
    return json.loads(stdout.getvalue().strip().splitlines()[-1])


def test_lw_login_falls_back_to_spa_csrf_and_posts_plain_form() -> None:
    session = SpaSession()
    result = _run_login(session)
    assert result["ok"] is True and result["success"] is True
    assert session.post_kwargs["data"]["csrf_token"] == "spa-csrf"
    # 두 번째 GET만 SPA 헤더, POST는 헤더 없이 폼으로(302·200 판정을 그대로 쓰기 위해)
    assert session.get_headers == [{}, {"X-Requested-With": "login-watchdog-spa"}]
    assert "headers" not in session.post_kwargs


def test_lw_login_uses_html_token_without_extra_request() -> None:
    session = SpaSession(html_body=HTML_FORM)
    result = _run_login(session)
    assert result["success"] is True
    assert session.post_kwargs["data"]["csrf_token"] == "html-csrf"
    assert len(session.get_headers) == 1


def test_lw_login_reports_error_when_no_token_anywhere() -> None:
    session = SpaSession(spa_body="not json")
    result = _run_login(session)
    assert result["success"] is False
    assert result["error"] == "ValueError"
    assert result.get("ok") is not True
    assert session.post_kwargs is None


def test_sim_common_fetch_csrf_falls_back_to_spa() -> None:
    session = SpaSession()
    assert _sim_common.fetch_csrf(session, TARGET_URL, "/login") == "spa-csrf"
    session = SpaSession(html_body=HTML_FORM)
    assert _sim_common.fetch_csrf(session, TARGET_URL, "/login") == "html-csrf"
    assert len(session.get_headers) == 1


def test_sim_common_fetch_csrf_fails_with_path_when_no_token() -> None:
    session = SpaSession(spa_body=json.dumps({"messages": []}))
    try:
        _sim_common.fetch_csrf(session, TARGET_URL, "/board/new")
    except RuntimeError as error:
        assert "/board/new" in str(error)
    else:
        raise AssertionError("토큰이 없으면 RuntimeError여야 한다")


def test_bruteforce_sim_fetch_csrf_token_falls_back_to_spa() -> None:
    # 공격 상자의 brute(S4)는 이 시뮬레이터를 그대로 부른다.
    assert bruteforce_sim.fetch_csrf_token(SpaSession(), TARGET_URL) == "spa-csrf"
    assert bruteforce_sim.fetch_csrf_token(SpaSession(html_body=HTML_FORM), TARGET_URL) == "html-csrf"


def test_check_s6_surfaces_login_command_error(monkeypatch) -> None:
    from scripts.net import check_common as cc
    from scripts.net import check_s6

    monkeypatch.setenv("LW_VICTIM_PASSWORD", "test-victim-pw")
    monkeypatch.setattr(cc, "choose_fresh_ip", lambda client, prefix: "172.28.0.120")
    monkeypatch.setattr(cc, "run_oneshot", lambda *a, **k: SimpleNamespace(stdout=""))
    monkeypatch.setattr(cc, "wait_until", lambda condition, **k: True)
    monkeypatch.setattr(cc, "parse_json_line", lambda completed: {
        "step": "login", "error": "ValueError", "success": False, "status": None,
    })
    monkeypatch.setattr(cc, "playbook_runs_for_ip",
                        lambda *a: (_ for _ in ()).throw(AssertionError("메일 단계까지 가면 안 된다")))

    result = check_s6.run(SimpleNamespace(client=None, prefix="172.28.0"))
    assert result.status == "FAIL"
    assert "login 명령 오류(ValueError" in result.reason
    assert "notify_owner_email" not in result.reason
