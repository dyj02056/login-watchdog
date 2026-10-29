# ============================================================================
# tests/track_d/test_i_guide57_status.py — 처리 작업대 이벤트 카드의 대역 필터 예외(guide57, 계약서 K10)
#
# SPOOFED_SRC(위조 주소)·GLOBAL_SYN_FLOOD(0.0.0.0)는 출발지가 원래 대역 밖이라, 대역으로 거르면 화면에서
# 늘 사라진다. 이 두 종류만 거르지 않는지 확인한다. 준비물은 test_c_status_api.py의 fixture를 그대로 쓴다.
# ============================================================================

import config
import db
from tests.track_d.test_c_status_api import admin_client, setup_env  # noqa: F401  (fixture 재사용)


def test_l3_notice_categories_bypass_edge_filter(admin_client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(config, "NET_EDGE_SUBNET", "172.28.13.0/24")
    monkeypatch.setattr(db, "list_recent_network_events", lambda limit=50: [
        {"src_ip": "172.28.13.150", "category": "SYN_FLOOD"},
        {"src_ip": "172.28.12.101", "category": "SYN_FLOOD"},
        {"src_ip": "10.0.0.99", "category": "SPOOFED_SRC"},
        {"src_ip": "0.0.0.0", "category": "GLOBAL_SYN_FLOOD"},
        {"src_ip": "10.0.0.98", "category": "ICMP_FLOOD"},
    ])
    monkeypatch.setattr(db, "list_network_blocks_for_dashboard", lambda: [])
    monkeypatch.setattr(db, "get_agent_heartbeats", lambda node: {})

    data = admin_client.get("/api/status").get_json()

    assert [e["category"] for e in data["network_events"]] == ["SYN_FLOOD", "SPOOFED_SRC", "GLOBAL_SYN_FLOOD"]
