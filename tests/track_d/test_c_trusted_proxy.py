# ============================================================================
# tests/track_d/test_c_trusted_proxy.py — 신뢰 프록시(TRUSTED_PROXY_IPS) 검증 테스트 [작업 C0-1]
# ============================================================================

import config
import helpers


def test_trusted_proxy_empty_list_uses_xff(flask_app, monkeypatch):
    """(a) TRUSTED_PROXY_IPS 목록이 비어 있으면 XFF 헤더 값을 사용한다."""
    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", True)
    monkeypatch.setattr(config, "TRUSTED_PROXY_IPS", [])
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "9.9.9.9"}, environ_base={"REMOTE_ADDR": "1.1.1.1"}
    ):
        assert helpers.get_request_ip() == "9.9.9.9"


def test_trusted_proxy_remote_addr_in_list_uses_xff(flask_app, monkeypatch):
    """(b) remote_addr가 TRUSTED_PROXY_IPS 목록에 있으면 XFF 헤더 값을 사용한다."""
    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", True)
    monkeypatch.setattr(config, "TRUSTED_PROXY_IPS", ["10.0.0.1", "1.1.1.1"])
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "9.9.9.9"}, environ_base={"REMOTE_ADDR": "1.1.1.1"}
    ):
        assert helpers.get_request_ip() == "9.9.9.9"


def test_trusted_proxy_remote_addr_not_in_list_uses_remote_addr(flask_app, monkeypatch):
    """(c) remote_addr가 TRUSTED_PROXY_IPS 목록에 없으면 XFF 헤더를 무시하고 remote_addr를 사용한다."""
    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", True)
    monkeypatch.setattr(config, "TRUSTED_PROXY_IPS", ["10.0.0.1", "10.0.0.2"])
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "9.9.9.9"}, environ_base={"REMOTE_ADDR": "1.1.1.1"}
    ):
        assert helpers.get_request_ip() == "1.1.1.1"


def test_trusted_proxy_disabled_uses_remote_addr(flask_app, monkeypatch):
    """(d) TRUST_FORWARDED_FOR가 False면 목록 설정과 무관하게 remote_addr를 사용한다."""
    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", False)
    monkeypatch.setattr(config, "TRUSTED_PROXY_IPS", ["1.1.1.1"])
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "9.9.9.9"}, environ_base={"REMOTE_ADDR": "1.1.1.1"}
    ):
        assert helpers.get_request_ip() == "1.1.1.1"