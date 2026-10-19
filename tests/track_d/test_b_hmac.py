"""독립 서명 헬퍼와 고정 시각으로 인증 계약의 경계와 키 분리를 검증한다."""

import pytest
from flask import request

import config
from routes.internal import _hmac


NOW = 1760930000
BODY = b'{"a":1}'
KEYS = {"shipper": "test-ingest-secret", "fw-agent": "test-agent-secret"}


@pytest.fixture
def hmac_app(flask_app, monkeypatch):
    monkeypatch.setattr(config, "NET_INGEST_SECRET", KEYS["shipper"])
    monkeypatch.setattr(config, "NET_AGENT_SECRET", KEYS["fw-agent"])
    monkeypatch.setattr(config, "NET_INTERNAL_MAX_SKEW_SECONDS", 60)
    monkeypatch.setattr(_hmac.time, "time", lambda: NOW)
    return flask_app


def test_contract_reference_signature(signed_headers):
    expected = "2f744cec328f65506df5ad72df7fdd688c7a3cf3c6f90b1e0085849106179de2"
    assert _hmac.sign("test-key", str(NOW), BODY) == expected
    assert signed_headers("shipper", "test-key", BODY, str(NOW))["X-LW-Signature"] == expected


@pytest.mark.parametrize("body", [b"", BODY, b'{ "a": 1 }', "한글".encode()])
def test_sign_matches_independent_helper(signed_headers, body):
    headers = signed_headers("shipper", KEYS["shipper"], body, str(NOW))
    assert _hmac.sign(KEYS["shipper"], str(NOW), body) == headers["X-LW-Signature"]


@pytest.mark.parametrize("sender", KEYS)
@pytest.mark.parametrize("offset", [-60, 0, 60])
def test_valid_signature_preserves_json(hmac_app, signed_headers, sender, offset):
    headers = signed_headers(sender, KEYS[sender], BODY, str(NOW + offset))
    with hmac_app.test_request_context("/", method="POST", data=BODY,
                                       content_type="application/json", headers=headers):
        assert _hmac.verify_request({sender}) == sender
        assert request.get_json() == {"a": 1}


def test_empty_get_body(hmac_app, signed_headers):
    headers = signed_headers("fw-agent", KEYS["fw-agent"], timestamp=str(NOW))
    with hmac_app.test_request_context("/", headers=headers):
        assert _hmac.verify_request({"fw-agent"}) == "fw-agent"


@pytest.mark.parametrize("case,reason", [
    ("disallowed", "disallowed_sender"),
    ("unknown", "disallowed_sender"),
    ("empty_ingest_key", "empty_key"),
    ("empty_agent_key", "empty_key"),
    ("past", "timestamp_skew"),
    ("future", "timestamp_skew"),
    ("invalid_timestamp", "invalid_timestamp"),
    ("unicode_timestamp", "invalid_timestamp"),
    ("tampered", "signature_mismatch"),
    ("wrong_key", "signature_mismatch"),
    ("unicode_signature", "signature_mismatch"),
    ("X-LW-Sender", "missing_header"),
    ("X-LW-Timestamp", "missing_header"),
    ("X-LW-Signature", "missing_header"),
])
def test_rejection_logs_only_reason(hmac_app, signed_headers, monkeypatch, capsys, case, reason):
    sender = "fw-agent" if case == "empty_agent_key" else "shipper"
    timestamp = str(NOW + {"past": -61, "future": 61}.get(case, 0))
    key = KEYS["fw-agent"] if case == "wrong_key" else KEYS[sender]
    headers = signed_headers(sender, key, BODY, timestamp)
    allowed = {"shipper", "fw-agent"}
    body = BODY
    if case == "disallowed":
        allowed = {"fw-agent"}
    elif case == "unknown":
        headers["X-LW-Sender"] = "unknown"
        allowed.add("unknown")
    elif case == "empty_ingest_key":
        monkeypatch.setattr(config, "NET_INGEST_SECRET", "")
    elif case == "empty_agent_key":
        monkeypatch.setattr(config, "NET_AGENT_SECRET", "")
    elif case == "invalid_timestamp":
        headers["X-LW-Timestamp"] = "1760930000.0"
    elif case == "unicode_timestamp":
        headers["X-LW-Timestamp"] = "１７６０９３００００"
    elif case == "tampered":
        body = b'{"a":2}'
    elif case == "unicode_signature":
        headers["X-LW-Signature"] = "서명"
    elif case.startswith("X-LW-"):
        del headers[case]

    capsys.readouterr()
    with hmac_app.test_request_context("/", method="POST", data=body, headers=headers):
        assert _hmac.verify_request(allowed) is None
    assert capsys.readouterr().out == f"internal_hmac: {reason}\n"


def test_skew_uses_configuration(hmac_app, signed_headers, monkeypatch):
    monkeypatch.setattr(config, "NET_INTERNAL_MAX_SKEW_SECONDS", 10)
    headers = signed_headers("shipper", KEYS["shipper"], BODY, str(NOW - 11))
    with hmac_app.test_request_context("/", method="POST", data=BODY, headers=headers):
        assert _hmac.verify_request({"shipper"}) is None
