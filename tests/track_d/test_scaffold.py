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


# 계약서 K3의 기준 예시 서명값. B0-1의 sign(), A의 shipper, C의 fw-agent가 모두 이 값을 만들어야 한다.
K3_REFERENCE_SIGNATURE = "2f744cec328f65506df5ad72df7fdd688c7a3cf3c6f90b1e0085849106179de2"


def test_signed_headers_reference_value(signed_headers):
    headers = signed_headers("shipper", "test-key", b'{"a":1}', timestamp="1760930000")
    assert headers["X-LW-Sender"] == "shipper"
    assert headers["X-LW-Timestamp"] == "1760930000"
    assert headers["X-LW-Signature"] == K3_REFERENCE_SIGNATURE


# 계약서 K1의 설정 이름 전부. 뼈대 PR이 미리 만들어 두고, 각 역할은 값만 조정한다.
K1_CONFIG_DEFAULTS = {
    "NET_INGEST_SECRET": "",
    "NET_INTERNAL_MAX_SKEW_SECONDS": 60,
    "NET_INGEST_MAX_BODY_BYTES": 16384,
    "NET_INGEST_RATE_LIMIT_PER_MINUTE": 600,
    "NET_CORRELATION_WINDOW_MINUTES": 15,
    "NET_FLOOD_WINDOW_MINUTES": 5,
    "NET_SUCCESS_LOGIN_LOOKBACK_MINUTES": 30,
    "NET_ROTATION_WINDOW_MINUTES": 10,
    "NET_SUBNET_MIN_IPS": 3,
    "NET_FLOOD_REPEAT_DAYS": 30,
    "NET_AGENT_SECRET": "",
    "TRUSTED_PROXY_IPS": [],
    "NET_EDGE_SUBNET": "",
    "NET_BLOCK_DEFAULT_TTL_SECONDS": 3600,
    "NET_BLOCK_MAX_TTL_SECONDS": 21600,
    "NET_BLOCK_REPEAT_DAYS": 30,
    "SUSPICIOUS_LOGIN_MAIL_COOLDOWN_SECONDS": 3600,
    "FW_AGENT_STALE_SECONDS": 30,
    "SHIPPER_STALE_SECONDS": 120,
    "AGENT_ALERT_COOLDOWN_SECONDS": 600,
    "LW_NODE_NAME": "",
}


def test_k1_config_names_have_contract_defaults(monkeypatch):
    # .env에 값이 있어도 기본값을 확인할 수 있게, 환경변수를 지우고 config를 새로 읽는다.
    import importlib

    import config

    for name in K1_CONFIG_DEFAULTS:
        monkeypatch.delenv(name, raising=False)
    fresh = importlib.reload(config)
    try:
        for name, default in K1_CONFIG_DEFAULTS.items():
            assert getattr(fresh, name) == default, name
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_trusted_proxy_ips_is_trimmed_list(monkeypatch):
    import importlib

    import config

    monkeypatch.setenv("TRUSTED_PROXY_IPS", " 172.29.0.10 , ,10.0.0.1")
    try:
        assert importlib.reload(config).TRUSTED_PROXY_IPS == ["172.29.0.10", "10.0.0.1"]
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_contract_stubs_exist():
    from security import net_ingest, netblock, playbooks

    for module, names in (
        (net_ingest, ("record_net_blocked", "resolve_net_blocked")),
        (netblock, ("request_block", "request_unblock")),
        (playbooks, ("run",)),
    ):
        for name in names:
            assert callable(getattr(module, name)), f"{module.__name__}.{name}"


def test_ingest_endpoint_has_its_own_rate_limit(client, monkeypatch):
    # 경보 수집 창구는 전역 한도에서 빠지는 대신 보낸이별 한도(NET_INGEST_RATE_LIMIT_PER_MINUTE)를 쓴다.
    # 한도를 넘기면 HTTP_FLOOD로 기록하지 않고 JSON 429만 돌려준다.
    # 10/26 강사 피드백 1: 서명이 틀린 요청(401)은 한도를 쓰지 않는다. 그래서 서명 검사를 통과한 것처럼
    # 바꿔 형식 오류(400)로 600회를 채운 뒤 601번째가 429인지 본다.
    from routes.internal import ingest
    from security import soar

    recorded = []
    monkeypatch.setattr(soar, "record_rejection", lambda *a, **k: recorded.append(a))
    monkeypatch.setattr(ingest, "verify_request", lambda senders: "shipper")
    statuses = [
        client.post("/api/internal/net-events", json={}, headers={"X-LW-Sender": "shipper"}).status_code
        for _ in range(601)
    ]
    assert statuses[:600] == [400] * 600
    assert statuses[600] == 429
    assert recorded == []
