"""Docker 단지의 앱이 .env의 배포용 SMTP 계정과 상관없이 Mailpit으로 로그인 없이 메일을 보내는지 검사한다.

10/26 C3-1 S6에서 .env의 Gmail 계정 때문에 mailer가 Mailpit에 로그인을 시도해 경고 메일이 모두 실패했다.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _app_section() -> str:
    """docker-compose.yml에서 app 서비스 블록만 잘라 낸다(다른 서비스의 같은 키와 섞이지 않게)."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    return compose.split("\n  app:", 1)[1].split("\n  mailpit:", 1)[0]


def test_app_overrides_smtp_account_to_empty() -> None:
    app = _app_section()
    assert "env_file:" in app
    assert 'SMTP_HOST: "mailpit"' in app
    # env_file보다 environment가 우선하므로 빈 값이 .env의 계정을 덮어쓴다.
    assert 'SMTP_USER: ""' in app
    assert 'SMTP_PASSWORD: ""' in app
