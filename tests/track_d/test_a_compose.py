"""Track D Docker 실행 기반 설정을 검사한다."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def read_project_file(relative_path: str) -> str:
    """프로젝트 기준 경로의 텍스트 파일을 UTF-8로 읽는다."""
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def test_dockerfile_uses_required_runtime() -> None:
    """앱 이미지가 약속된 Python과 Gunicorn 설정을 사용하는지 확인한다."""
    dockerfile = read_project_file("Dockerfile")

    assert "FROM python:3.12-slim" in dockerfile
    assert '"--bind", "0.0.0.0:5000"' in dockerfile
    assert '"--workers", "1"' in dockerfile
    assert '"--threads", "8"' in dockerfile
    assert '"app:app"' in dockerfile


def test_dockerignore_excludes_local_secrets() -> None:
    """비밀값과 로컬 가상환경이 Docker 이미지에 포함되지 않게 한다."""
    dockerignore = read_project_file(".dockerignore")

    assert ".env" in dockerignore
    assert "!.env.example" in dockerignore
    assert "venv/" in dockerignore
    assert ".git" in dockerignore


def test_compose_contains_required_services() -> None:
    """기본 서비스와 이후 단계용 프로필 서비스가 선언됐는지 확인한다."""
    compose = read_project_file("docker-compose.yml")

    required_services = (
        "gateway:",
        "app:",
        "mailpit:",
        "sensor:",
        "l4-detector:",
        "shipper:",
        "fw-agent:",
        "attacker-1:",
        "attacker-2:",
        "attacker-3:",
    )

    for service in required_services:
        assert service in compose


def test_compose_uses_track_d_network_contract() -> None:
    """Edge와 Core 주소가 계약서의 주소표를 따르는지 확인한다."""
    compose = read_project_file("docker-compose.yml")

    assert '"${LW_EDGE_PREFIX}.10"' in compose
    assert '"${LW_EDGE_PREFIX}.101"' in compose
    assert '"${LW_EDGE_PREFIX}.102"' in compose
    assert '"${LW_EDGE_PREFIX}.103"' in compose
    assert '"${LW_EDGE_PREFIX}.0/24"' in compose
    assert '"172.30.0.10"' in compose
    assert '"172.30.0.0/24"' in compose
    assert "internal: true" in compose


def test_compose_exposes_only_gateway_and_mailpit_ui() -> None:
    """브라우저 접근용 Gateway와 Mailpit UI 포트가 선언됐는지 확인한다."""
    compose = read_project_file("docker-compose.yml")

    assert '"127.0.0.1:8080:8080"' in compose
    assert '"127.0.0.1:8025:8025"' in compose
    assert 'TRUSTED_PROXY_IPS: "172.30.0.10"' in compose
    assert 'SMTP_HOST: "mailpit"' in compose


def test_nginx_overwrites_forwarded_for() -> None:
    """클라이언트가 위조한 전달 IP를 이어 붙이지 않고 덮어쓰게 한다."""
    nginx = read_project_file("netwatch/nginx/nginx.conf")

    assert "listen 8080;" in nginx
    assert "proxy_pass http://app:5000;" in nginx
    assert "proxy_set_header Host $host;" in nginx
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in nginx
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in nginx


def test_env_example_contains_role_a_values() -> None:
    """팀원이 필요한 Compose 환경변수를 확인할 수 있게 한다."""
    env_example = read_project_file(".env.example")

    assert "LW_EDGE_PREFIX=172.28.11" in env_example
    assert "SENSOR_IFACE=eth1" in env_example