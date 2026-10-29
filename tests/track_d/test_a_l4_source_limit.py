"""출발지 상한에 닿았을 때 위조일 수 있는 출발지를 밀어내고 진짜 공격자를 놓치지 않는지 검증한다.

예전에는 상한이 차면 새 출발지를 통째로 버려, 위조 출발지로 상한을 먼저 채운 공격자가 뒤따르는
포트 스캔을 숨길 수 있었다(10/29 보완). SYN 없는 ACK까지 보낸 "확인된" 출발지는 밀려나지 않는다.
"""

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "netwatch" / "l4_detector"))

from detector_core import L4Detector, has_ack_without_syn  # noqa: E402


class FakeClock:
    def __init__(self, now: float = 1_760_930_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _ip(i: int) -> str:
    return f"198.18.{(i >> 8) & 0xFF}.{i & 0xFF}"


def _make(clock, **kwargs):
    warnings = []
    detector = L4Detector(
        syn_threshold_per_sec=100,
        distinct_ports_threshold=15,
        clock=clock,
        on_global_alert=lambda event: None,
        on_warning=warnings.append,
        **kwargs,
    )
    return detector, warnings


def test_ack_without_syn_detection():
    assert has_ack_without_syn("A")
    assert has_ack_without_syn("PA")
    assert has_ack_without_syn(0x10)
    assert not has_ack_without_syn("S")
    assert not has_ack_without_syn("SA")
    assert not has_ack_without_syn(0x12)
    assert not has_ack_without_syn(0x02)


def test_spoofed_sources_do_not_hide_real_port_scan():
    clock = FakeClock()
    detector, warnings = _make(clock, max_sources=10)

    for i in range(10):  # 위조 출발지가 상한을 채운다(SYN만 보냄)
        clock.advance(0.001)
        detector.observe(_ip(i), 8080, "S")
    assert len(detector._port_events) == 10

    events = []
    for port in range(1, 21):  # 진짜 공격자가 포트 스캔을 한다
        clock.advance(0.01)
        events.extend(detector.observe("203.0.113.9", port, "S"))

    assert [e["category"] for e in events] == ["PORT_SCAN"]
    assert len(detector._port_events) <= 10
    assert any("밀어냅니다" in w for w in warnings)


def test_confirmed_source_is_not_evicted():
    clock = FakeClock()
    detector, _ = _make(clock, max_sources=3)

    detector.observe(_ip(0), 8080, "S")
    detector.observe(_ip(0), 8080, "A")  # handshake 뒤 ACK → 확인됨
    detector.observe(_ip(1), 8080, "S")
    detector.observe(_ip(2), 8080, "S")

    for i in range(3, 20):  # 새 출발지가 계속 들어와도 확인된 출발지는 남는다
        clock.advance(0.001)
        detector.observe(_ip(i), 8080, "S")

    assert _ip(0) in detector._port_events
    assert len(detector._port_events) == 3


def test_oldest_idle_unconfirmed_source_is_evicted_first():
    clock = FakeClock()
    detector, _ = _make(clock, max_sources=3)

    for i in range(3):
        clock.advance(0.001)
        detector.observe(_ip(i), 8080, "S")
    clock.advance(0.001)
    detector.observe(_ip(0), 8080, "S")  # 0번이 가장 최근에 움직임 → 1번이 가장 오래 쉼
    clock.advance(0.001)
    detector.observe(_ip(9), 8080, "S")

    assert _ip(1) not in detector._port_events
    assert _ip(0) in detector._port_events
    assert _ip(9) in detector._port_events


def test_all_confirmed_falls_back_to_dropping_new_source():
    clock = FakeClock()
    detector, warnings = _make(clock, max_sources=3)

    for i in range(3):
        detector.observe(_ip(i), 8080, "A")
    detector.observe(_ip(9), 8080, "S")

    assert _ip(9) not in detector._port_events
    assert len(detector._port_events) == 3
    assert len(warnings) == 1
    assert "확인된" in warnings[0]


def test_bookkeeping_is_cleaned_when_sources_expire():
    clock = FakeClock()
    detector, _ = _make(clock, max_sources=100)

    for i in range(20):
        detector.observe(_ip(i), 8080, "S" if i % 2 else "A")
    clock.advance(30)  # 창(10초)을 넘기면 기록이 모두 사라진다
    detector.observe(_ip(99), 8080, "S")

    assert len(detector._port_events) == 1
    assert list(detector._unconfirmed) == [_ip(99)]
    assert detector._confirmed == set()
