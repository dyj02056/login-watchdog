"""L4 측정기가 eth0/eth1 순서와 상관없이 edge 인터페이스를 고르는지 검사한다.

Docker가 네트워크를 붙이는 순서는 PC마다 달라, edge가 eth0인 PC와 eth1인 PC가 함께 있다.
실제 인터페이스 대신 가짜 목록·주소 조회 함수를 넘겨 두 경우를 모두 확인한다.
"""

from __future__ import annotations

from netwatch.l4_detector.detector_core import resolve_sensor_iface


EDGE_PREFIX = "172.28.11"


def fake_net(mapping: dict[str, str]):
    """인터페이스 이름→주소 표로 가짜 목록·조회 함수를 만든다."""

    def list_ifaces() -> list[str]:
        return list(mapping)

    def get_addr(iface: str) -> str:
        # Scapy의 get_if_addr처럼 주소가 없으면 0.0.0.0을 돌려준다.
        return mapping.get(iface, "0.0.0.0")

    return list_ifaces, get_addr


# 10/19 PC: core가 먼저 붙어 eth1이 edge
EDGE_ON_ETH1 = {"lo": "127.0.0.1", "eth0": "172.30.0.10", "eth1": "172.28.11.10"}
# 10/20 다른 PC: edge가 먼저 붙어 eth0이 edge
EDGE_ON_ETH0 = {"lo": "127.0.0.1", "eth0": "172.28.11.10", "eth1": "172.30.0.10"}


def test_configured_edge_iface_is_kept() -> None:
    """지정한 이름에 edge 주소가 있으면 그대로 쓰고 경고하지 않는다."""
    iface, warning = resolve_sensor_iface("eth1", EDGE_PREFIX, *fake_net(EDGE_ON_ETH1), "eth1")

    assert iface == "eth1"
    assert warning is None


def test_configured_core_iface_switches_to_edge() -> None:
    """기본값 eth1이 core인 PC에서는 edge인 eth0으로 바꾸고 경고를 남긴다."""
    iface, warning = resolve_sensor_iface("eth1", EDGE_PREFIX, *fake_net(EDGE_ON_ETH0), "eth1")

    assert iface == "eth0"
    assert warning is not None
    assert "eth0" in warning


def test_auto_finds_edge_on_either_order() -> None:
    """auto나 빈 값이면 순서와 상관없이 edge 주소가 붙은 쪽을 고른다."""
    for value in ("auto", "", "  AUTO "):
        assert resolve_sensor_iface(value, EDGE_PREFIX, *fake_net(EDGE_ON_ETH0), "eth1") == ("eth0", None)
        assert resolve_sensor_iface(value, EDGE_PREFIX, *fake_net(EDGE_ON_ETH1), "eth1") == ("eth1", None)


def test_no_edge_address_keeps_value_with_warning() -> None:
    """edge 주소를 못 찾으면 멈추지 않고 지정값(auto면 fallback)을 쓰며 경고한다."""
    only_core = {"lo": "127.0.0.1", "eth0": "172.30.0.10"}

    iface, warning = resolve_sensor_iface("eth0", EDGE_PREFIX, *fake_net(only_core), "eth1")
    assert iface == "eth0"
    assert warning is not None

    iface, warning = resolve_sensor_iface("auto", EDGE_PREFIX, *fake_net(only_core), "eth1")
    assert iface == "eth1"
    assert warning is not None


def test_missing_edge_prefix_skips_detection() -> None:
    """LW_EDGE_PREFIX가 없으면 주소로 확인할 수 없으므로 지정값을 쓰고 경고한다."""
    iface, warning = resolve_sensor_iface("eth1", "", *fake_net(EDGE_ON_ETH0), "eth1")

    assert iface == "eth1"
    assert warning is not None


def test_lookup_errors_are_ignored() -> None:
    """주소 조회가 실패하는 인터페이스는 후보에서 빼고 나머지로 판단한다."""

    def list_ifaces() -> list[str]:
        return ["broken", "eth0", "eth1"]

    def get_addr(iface: str) -> str:
        if iface == "broken":
            raise OSError("no such device")
        return EDGE_ON_ETH0[iface]

    assert resolve_sensor_iface("broken", EDGE_PREFIX, list_ifaces, get_addr, "eth1")[0] == "eth0"
