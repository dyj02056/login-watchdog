"""출발지를 바꾸는 SYN Flood에서도 L4 측정기가 밀리지 않고, 전체 SYN 경보를 로그로만 내는지 검증한다.

예전에는 패킷마다 모든 출발지 기록을 훑어, 출발지가 수만 개면 패킷 하나에 수만 번 계산했다.
지금은 전체 정리를 1초에 한 번만 하고, 기록하는 출발지 수에 상한을 둔다. 전체 경보는 막을
주소가 없어 l4.json(observe 반환값)에 나오지 않고 on_global_alert로만 넘어간다(10/29 결정).
"""

import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "netwatch" / "l4_detector"))

from detector_core import L4Detector  # noqa: E402


class FakeClock:
    def __init__(self, now: float = 1_760_930_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _random_ip(i: int) -> str:
    # 198.18.0.0/15(시험용 대역) 안에서 패킷마다 다른 출발지를 만든다.
    return f"198.18.{(i >> 8) & 0xFF}.{i & 0xFF}" if i < 65536 else f"198.19.{(i >> 8) & 0xFF}.{i & 0xFF}"


def _make(clock, **kwargs):
    alerts, warnings = [], []
    detector = L4Detector(
        syn_threshold_per_sec=100,
        distinct_ports_threshold=15,
        clock=clock,
        on_global_alert=alerts.append,
        on_warning=warnings.append,
        **kwargs,
    )
    return detector, alerts, warnings


def test_random_source_flood_stays_fast():
    clock = FakeClock()
    detector, _, _ = _make(clock)

    started = time.perf_counter()
    for i in range(100_000):
        clock.advance(0.0001)  # 초당 1만 패킷, 10초 동안
        detector.observe(_random_ip(i % 120_000), 8080, "S")
    elapsed = time.perf_counter() - started

    # 패킷마다 전체를 훑던 방식은 이 입력에서 수십 초 이상 걸린다. 넉넉히 10초 안이면 된다.
    assert elapsed < 10, f"{elapsed:.1f}초"


def test_random_source_flood_raises_global_alert_but_no_block_event():
    clock = FakeClock()
    detector, alerts, _ = _make(clock, global_syn_threshold_per_sec=1000)

    events = []
    for i in range(2000):
        clock.advance(0.0004)  # 0.8초 동안 SYN 2000개, 출발지 모두 다름
        events.extend(detector.observe(_random_ip(i), 8080, "S"))

    assert events == []  # 출발지별 경보(l4.json → 차단)는 하나도 없다
    assert len(alerts) == 1  # cooldown(10초) 안에서는 한 번만
    alert = alerts[0]
    assert alert["category"] == "GLOBAL_SYN_FLOOD"
    assert alert["syn_per_sec"] >= 1000
    assert alert["distinct_sources"] >= 1000
    assert alert["threshold"] == 1000


def test_global_alert_repeats_after_cooldown():
    clock = FakeClock()
    detector, alerts, _ = _make(clock, global_syn_threshold_per_sec=10, cooldown_seconds=10)

    for i in range(20):
        clock.advance(0.01)
        detector.observe(_random_ip(i), 8080, "S")
    clock.advance(11)
    for i in range(20):
        clock.advance(0.01)
        detector.observe(_random_ip(1000 + i), 8080, "S")

    assert len(alerts) == 2


def test_normal_traffic_does_not_raise_global_alert():
    clock = FakeClock()
    detector, alerts, _ = _make(clock, global_syn_threshold_per_sec=1000)

    for i in range(500):  # 초당 50개 접속
        clock.advance(0.02)
        detector.observe(_random_ip(i % 30), 8080, "S")

    assert alerts == []


def test_source_limit_keeps_existing_attacker_and_warns_once():
    clock = FakeClock()
    detector, _, warnings = _make(clock, max_sources=10)

    for i in range(10):
        detector.observe(_random_ip(i), 8080, "A")
    for i in range(10, 50):
        detector.observe(_random_ip(i), 8080, "A")

    assert len(detector._port_events) == 10
    assert _random_ip(0) in detector._port_events
    assert _random_ip(10) not in detector._port_events
    assert len(warnings) == 1
    assert "상한" in warnings[0]

    # 이미 추적 중인 출발지의 SYN Flood는 상한에 걸린 뒤에도 그대로 잡힌다.
    events = []
    for _ in range(100):
        clock.advance(0.001)
        events.extend(detector.observe(_random_ip(0), 8080, "S"))
    assert [e["category"] for e in events] == ["SYN_FLOOD"]


def test_per_source_counts_stay_exact_between_full_prunes():
    # 전체 정리는 1초에 한 번이지만, 현재 출발지 기록은 매번 정리돼 1초 창이 정확해야 한다.
    clock = FakeClock()
    detector, _, _ = _make(clock)

    for _ in range(60):
        clock.advance(0.01)
        detector.observe("198.51.100.7", 8080, "S")
    clock.advance(0.95)  # 처음 SYN들은 1초 창 밖으로 나간다
    events = []
    for _ in range(60):
        clock.advance(0.001)
        events.extend(detector.observe("198.51.100.7", 8080, "S"))

    assert events == []  # 창 안에 남은 SYN은 100개 미만
    assert len(detector._syn_events["198.51.100.7"]) < 100
