"""guide57 정문(nginx) 연결 용량 — worker 수·연결 수·전체 상한·keep-alive 시간이 설정돼 있는지 확인한다."""

from pathlib import Path


NGINX = (Path(__file__).resolve().parents[2] / "netwatch" / "nginx" / "nginx.conf").read_text(encoding="utf-8")


def test_worker_capacity_is_raised():
    assert "worker_processes auto;" in NGINX
    assert "worker_rlimit_nofile 16384;" in NGINX
    assert "worker_connections 4096;" in NGINX
    assert "worker_connections 1024;" not in NGINX


def test_total_connection_cap_and_keepalive():
    assert "limit_conn_zone $server_name zone=lw_total:1m;" in NGINX
    assert "limit_conn lw_total 3000;" in NGINX
    assert "keepalive_timeout 15s;" in NGINX
    assert "reset_timedout_connection on;" in NGINX
    # IP별 30개 제한은 그대로 둔다.
    assert "limit_conn lw_perip 30;" in NGINX
