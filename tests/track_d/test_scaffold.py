# ============================================================================
# tests/track_d/test_scaffold.py — Track D 뼈대 PR(I0-1)이 제자리에 놓였는지 확인한다
#
# 뼈대는 기능을 바꾸지 않는다. 그래서 여기서는 "창구가 등록돼 있고, 아무 요청도 통과시키지
# 않으며, 관찰 훅·전역 한도에서 빠져 있고, 빈 DB 모듈이 db 패키지에 연결돼 있는가"만 본다.
# 역할별 구현이 들어오면 각자의 test_<역할>_*.py가 실제 동작을 검사한다.
# ============================================================================

import pytest

INTERNAL_ENDPOINTS = {
    "internal.net_events": ("POST", "/api/internal/net-events"),
    "internal.list_blocks": ("GET", "/api/internal/blocks"),
    "internal.ack_block": ("POST", "/api/internal/blocks/ack"),
    "internal.heartbeat": ("POST", "/api/internal/heartbeat"),
}


def test_internal_endpoints_are_registered(flask_app):
    rules = {rule.endpoint: rule for rule in flask_app.url_map.iter_rules()}
    for endpoint, (method, path) in INTERNAL_ENDPOINTS.items():
        assert endpoint in rules, endpoint
        assert rules[endpoint].rule == path
        assert method in rules[endpoint].methods


@pytest.mark.parametrize("method,path", list(INTERNAL_ENDPOINTS.values()))
def test_unsigned_request_is_rejected(client, method, path):
    # CSRF 토큰 없이 보내도 400(CSRF)이 아니라 401이어야 한다 — 내부 창구는 CSRF 검사에서 빠지고
    # 서명 검사로만 막는다.
    response = client.open(path, method=method, json={})
    assert response.status_code == 401
    assert response.get_json() == {"error": "unauthorized"}


@pytest.mark.parametrize("method,path", list(INTERNAL_ENDPOINTS.values()))
def test_signed_request_is_still_rejected_before_implementation(client, signed_headers, method, path):
    # 서명 검사(B0-1)가 구현되기 전에는 서명이 있어도 통과시키지 않는다.
    sender = "shipper" if path.endswith("net-events") else "fw-agent"
    headers = signed_headers(sender, "test-ingest-secret", b"{}")
    response = client.open(path, method=method, data=b"{}", headers=headers, content_type="application/json")
    assert response.status_code == 401


def test_internal_endpoints_are_excluded_from_observation_hooks():
    from helpers.hooks import PAGE_ACCESS_EXCLUDED_ENDPOINTS

    assert set(INTERNAL_ENDPOINTS) <= PAGE_ACCESS_EXCLUDED_ENDPOINTS


def test_track_d_db_modules_are_wired():
    import db

    for name in ("network_events", "playbook_runs", "network_blocks", "agent_heartbeats"):
        module = getattr(db, name)
        assert isinstance(module.__all__, list)
        for exported in module.__all__:
            assert getattr(db, exported) is getattr(module, exported)
            assert exported in db.__all__


def test_bump_session_version_placeholder_is_exported():
    import db

    assert "bump_session_version" in db.__all__
    assert callable(db.bump_session_version)


def test_signed_headers_reference_value(signed_headers):
    # 계약서 K3의 기준 예시. B0-1의 sign()과 shipper·fw-agent의 서명이 모두 이 값과 같아야 한다.
    headers = signed_headers("shipper", "test-key", b'{"a":1}', timestamp="1760930000")
    assert headers["X-LW-Sender"] == "shipper"
    assert headers["X-LW-Timestamp"] == "1760930000"
    assert len(headers["X-LW-Signature"]) == 64
    assert headers["X-LW-Signature"] == headers["X-LW-Signature"].lower()
