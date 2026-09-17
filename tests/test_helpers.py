# ============================================================================
# test_helpers.py — helpers.py의 get_request_ip()/is_bot_submission()이
# 올바르게 판단하는지 확인하는 단위 테스트 (L7 공격 보강 계획 Tier 3)
#
# get_request_ip()는 request.remote_addr/request.headers를 읽어야 하므로,
# flask_app.test_request_context()로 "가짜 요청이 지금 들어온 척"하는 상황을
# 만들어서 그 안에서 호출한다. conftest.py의 flask_app fixture를 그대로
# 재사용한다.
# ============================================================================

import config
import helpers


def test_get_request_ip_uses_remote_addr_by_default(flask_app, monkeypatch):
    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", False)
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "9.9.9.9"}, environ_base={"REMOTE_ADDR": "1.1.1.1"}
    ):
        assert helpers.get_request_ip() == "1.1.1.1"


def test_get_request_ip_trusts_valid_forwarded_header_when_enabled(flask_app, monkeypatch):
    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", True)
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "9.9.9.9, 5.5.5.5"}, environ_base={"REMOTE_ADDR": "1.1.1.1"}
    ):
        assert helpers.get_request_ip() == "9.9.9.9"


def test_get_request_ip_falls_back_when_forwarded_header_is_not_a_valid_ip(flask_app, monkeypatch):
    # SSRF 방지 — 헤더 값이 진짜 IP 형식이 아니면(예: geoip.py의 외부 요청
    # 주소 조작을 노린 문자열), 신뢰하지 않고 실제 접속 IP로 되돌아가야 한다.
    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", True)
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "not-an-ip"}, environ_base={"REMOTE_ADDR": "1.1.1.1"}
    ):
        assert helpers.get_request_ip() == "1.1.1.1"


def test_is_bot_submission_false_when_honeypot_field_missing(flask_app):
    with flask_app.test_request_context("/", method="POST", data={}):
        assert helpers.is_bot_submission() is False


def test_is_bot_submission_false_when_honeypot_field_empty(flask_app):
    with flask_app.test_request_context("/", method="POST", data={"website": ""}):
        assert helpers.is_bot_submission() is False


def test_is_bot_submission_true_when_honeypot_field_filled(flask_app):
    with flask_app.test_request_context("/", method="POST", data={"website": "http://spam.example"}):
        assert helpers.is_bot_submission() is True
