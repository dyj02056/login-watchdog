"""Scapy 없이 L4 측정기의 순수 탐지 로직을 검사한다."""

from __future__ import annotations

import re
import sys
from pathlib import Path


from netwatch.l4_detector.detector_core import L4Detector


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FakeClock:
    """테스트가 원하는 만큼만 시간을 이동시키는 가짜 시계."""

    def __init__(self, initial: float = 0.0) -> None:
        self.current = initial

    def __call__(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


def make_detector(
    clock: FakeClock,
    *,
    syn_threshold: int = 3,
    ports_threshold: int = 3,
    window_seconds: float = 10,
    cooldown_seconds: float = 10,
    edge_prefix: str | None = "192.0.2",
) -> L4Detector:
    """테스트에 사용할 L4Detector를 만든다."""
    return L4Detector(
        syn_threshold_per_sec=syn_threshold,
        distinct_ports_threshold=ports_threshold,
        window_seconds=window_seconds,
        cooldown_seconds=cooldown_seconds,
        clock=clock,
        edge_prefix=edge_prefix,
    )


def test_syn_threshold_emits_syn_flood() -> None:
    """최근 1초의 SYN 수가 기준에 도달하면 경보를 낸다."""
    clock = FakeClock()
    detector = make_detector(
        clock,
        syn_threshold=3,
        ports_threshold=100,
    )

    assert detector.observe("198.51.100.10", 8080, "S") == []
    assert detector.observe("198.51.100.10", 8080, "S") == []

    events = detector.observe("198.51.100.10", 8080, "S")

    assert len(events) == 1
    assert events[0]["category"] == "SYN_FLOOD"
    assert events[0]["syn_per_sec"] == 3


def test_syn_below_threshold_emits_nothing() -> None:
    """최근 1초의 SYN 수가 기준보다 작으면 경보를 내지 않는다."""
    clock = FakeClock()
    detector = make_detector(
        clock,
        syn_threshold=3,
        ports_threshold=100,
    )

    assert detector.observe("198.51.100.11", 8080, "S") == []
    assert detector.observe("198.51.100.11", 8080, "S") == []


def test_distinct_ports_emit_port_scan() -> None:
    """시간 창 안의 서로 다른 목적지 포트 수로 스캔을 판단한다."""
    clock = FakeClock()
    detector = make_detector(
        clock,
        syn_threshold=100,
        ports_threshold=3,
    )

    assert detector.observe("198.51.100.20", 80, "S") == []

    # 같은 포트의 반복은 서로 다른 포트 수를 늘리지 않는다.
    assert detector.observe("198.51.100.20", 80, "S") == []
    assert detector.observe("198.51.100.20", 81, "S") == []

    events = detector.observe("198.51.100.20", 82, "S")

    assert len(events) == 1
    assert events[0]["category"] == "PORT_SCAN"
    assert events[0]["distinct_ports_10s"] == 3


def test_syn_ack_is_not_counted_as_syn() -> None:
    """SYN과 ACK가 함께 있는 패킷은 SYN Flood 수에 포함하지 않는다."""
    clock = FakeClock()
    detector = make_detector(
        clock,
        syn_threshold=1,
        ports_threshold=100,
    )

    assert detector.observe("198.51.100.30", 8080, "SA") == []
    assert detector.observe("198.51.100.30", 8080, 0x12) == []


def test_cooldown_suppresses_duplicate_then_allows_again() -> None:
    """Cooldown 동안 중복 경보를 막고 시간이 지나면 다시 허용한다."""
    clock = FakeClock()
    detector = make_detector(
        clock,
        syn_threshold=2,
        ports_threshold=100,
        cooldown_seconds=10,
    )

    detector.observe("198.51.100.40", 8080, "S")
    first = detector.observe("198.51.100.40", 8080, "S")

    assert len(first) == 1

    assert detector.observe("198.51.100.40", 8080, "S") == []

    clock.advance(10.1)

    assert detector.observe("198.51.100.40", 8080, "S") == []
    second = detector.observe("198.51.100.40", 8080, "S")

    assert len(second) == 1
    assert second[0]["category"] == "SYN_FLOOD"


def test_records_outside_window_are_removed() -> None:
    """오래된 출발지 기록이 내부 저장소에 계속 남지 않게 한다."""
    clock = FakeClock()
    detector = make_detector(
        clock,
        syn_threshold=100,
        ports_threshold=100,
        window_seconds=10,
    )

    detector.observe("198.51.100.50", 80, "S")
    detector.observe("198.51.100.50", 80, "S")

    clock.advance(11)

    detector.observe("198.51.100.51", 443, "S")

    assert "198.51.100.50" not in detector._syn_events
    assert "198.51.100.50" not in detector._port_events
    assert len(detector._syn_events["198.51.100.51"]) == 1
    assert len(detector._port_events["198.51.100.51"]) == 1


def test_event_fields_and_timestamp_format() -> None:
    """l4.json 출력 칸과 UTC timestamp 형식을 확인한다."""
    clock = FakeClock(1_760_000_000.123)
    detector = make_detector(
        clock,
        syn_threshold=1,
        ports_threshold=100,
    )

    events = detector.observe("198.51.100.60", 8080, "S")

    assert len(events) == 1
    event = events[0]

    assert set(event) == {
        "timestamp",
        "src_ip",
        "category",
        "syn_per_sec",
        "distinct_ports_10s",
    }
    assert event["src_ip"] == "198.51.100.60"
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T"
        r"\d{2}:\d{2}:\d{2}\.\d{3}Z",
        event["timestamp"],
    )


def test_gateway_and_core_sources_are_excluded() -> None:
    """Gateway 자신과 core 대역에서 온 패킷은 세지 않는다."""
    clock = FakeClock()
    detector = make_detector(
        clock,
        syn_threshold=1,
        ports_threshold=1,
        edge_prefix="192.0.2",
    )

    assert detector.observe("192.0.2.10", 8080, "S") == []
    assert detector.observe("172.30.0.25", 8080, "S") == []

    assert "192.0.2.10" not in detector._syn_events
    assert "192.0.2.10" not in detector._port_events
    assert "172.30.0.25" not in detector._syn_events
    assert "172.30.0.25" not in detector._port_events


def test_compose_passes_l4_detector_environment() -> None:
    """Compose가 PC별 인터페이스와 Edge 대역을 컨테이너에 전달한다."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(
        encoding="utf-8"
    )

    l4_block = compose.split("  l4-detector:", 1)[1].split(
        "\n  shipper:",
        1,
    )[0]

    assert "profiles:" in l4_block
    assert "- net" in l4_block
    assert "environment:" in l4_block
    assert "SENSOR_IFACE: ${SENSOR_IFACE:-eth0}" in l4_block
    assert "LW_EDGE_PREFIX: ${LW_EDGE_PREFIX}" in l4_block
    # l4.json을 shipper와 공유하는 eve 볼륨(최상위 volumes에 선언)
    assert "- eve:/var/log/suricata" in l4_block
    assert "\nvolumes:\n" in compose