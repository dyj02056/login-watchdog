"""guide57 센서·shipper 보완 — L3 경보(SPOOFED_SRC·GLOBAL_SYN_FLOOD·ICMP_FLOOD), l4-detector 생존 줄,
파일별 정지 판단, Suricata 패킷 누락 집계.

Scapy·requests 없이 순수 로직만 확인한다. l4_detector.py는 scapy.all을 가짜 모듈로 바꿔 끼워 import한다.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

from netwatch.l4_detector.detector_core import (
    L4Detector,
    build_capture_filter,
)


ROOT = Path(__file__).resolve().parents[2]

_SHIPPER_SPEC = importlib.util.spec_from_file_location(
    "eve_shipper_guide57_under_test", ROOT / "netwatch" / "shipper" / "eve_shipper.py"
)
shipper = importlib.util.module_from_spec(_SHIPPER_SPEC)
_SHIPPER_SPEC.loader.exec_module(shipper)


def _load_l4_main():
    """scapy 없이 l4_detector.py를 읽는다. sniff 등은 쓰지 않는 함수만 시험한다."""
    fake_all = types.ModuleType("scapy.all")
    for name in ("IP", "TCP", "get_if_addr", "get_if_list", "sniff"):
        setattr(fake_all, name, object())
    sys.modules.setdefault("scapy", types.ModuleType("scapy"))
    sys.modules["scapy.all"] = fake_all
    sys.path.insert(0, str(ROOT / "netwatch" / "l4_detector"))
    try:
        spec = importlib.util.spec_from_file_location(
            "l4_detector_guide57_under_test", ROOT / "netwatch" / "l4_detector" / "l4_detector.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)
        sys.modules.pop("scapy.all", None)


class FakeClock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_detector(clock, **kwargs) -> L4Detector:
    return L4Detector(
        syn_threshold_per_sec=100,
        distinct_ports_threshold=15,
        clock=clock,
        edge_prefix="172.28.13",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# 받는 패킷 조건(BPF)
# ---------------------------------------------------------------------------

def test_capture_filter_limits_tcp_to_gateway_and_adds_foreign_sources():
    text = build_capture_filter("172.28.13")
    assert "tcp and dst host 172.28.13.10" in text
    assert "not src net 172.28.13.0/24" in text
    assert "not src net 172.30.0.0/24" in text


def test_capture_filter_falls_back_to_tcp_without_edge():
    assert build_capture_filter(None) == "tcp"
    assert build_capture_filter("bad") == "tcp"


# ---------------------------------------------------------------------------
# SPOOFED_SRC
# ---------------------------------------------------------------------------

def test_foreign_source_classification():
    detector = make_detector(FakeClock())
    assert detector.is_foreign_source("10.9.9.9") is True
    assert detector.is_foreign_source("172.28.12.101") is True
    assert detector.is_foreign_source("172.28.13.101") is False
    assert detector.is_foreign_source("172.30.0.4") is False


def test_no_foreign_detection_without_edge_prefix():
    detector = L4Detector(100, 15, clock=FakeClock(), edge_prefix=None)
    assert detector.is_foreign_source("10.9.9.9") is False
    assert detector.observe_foreign("10.9.9.9") == []


def test_spoofed_src_emits_after_threshold_with_cooldown():
    clock = FakeClock()
    detector = make_detector(clock, foreign_packets_threshold=5)
    events = []
    for i in range(4):
        events += detector.observe_foreign(f"10.0.0.{i}")
    assert events == []

    events = detector.observe_foreign("10.0.0.99")
    assert len(events) == 1
    event = events[0]
    assert event["category"] == "SPOOFED_SRC"
    assert event["src_ip"] == "10.0.0.99"
    assert event["packets"] == 5 and event["distinct_sources"] == 5
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", event["timestamp"])

    # 같은 창에서 더 와도 cooldown(10초) 안에는 다시 내지 않는다.
    assert detector.observe_foreign("10.0.0.100") == []
    clock.advance(10)
    for _ in range(4):
        assert detector.observe_foreign("10.0.0.1") == []
    assert len(detector.observe_foreign("10.0.0.1")) == 1


def test_packets_seen_counts_every_packet():
    detector = make_detector(FakeClock())
    detector.observe("172.28.13.101", 8080, "S")
    detector.observe_foreign("10.0.0.1")
    detector.observe_foreign("172.28.13.101")
    assert detector.packets_seen == 3


# ---------------------------------------------------------------------------
# l4_detector.py의 l4.json 줄 모양
# ---------------------------------------------------------------------------

def test_global_alert_line_uses_unspecified_source():
    l4_main = _load_l4_main()
    line = l4_main.global_alert_line({
        "timestamp": "2026-10-29T01:00:00.000Z", "category": "GLOBAL_SYN_FLOOD",
        "syn_per_sec": 4100, "distinct_sources": 3214, "threshold": 1000,
    })
    assert line == {
        "timestamp": "2026-10-29T01:00:00.000Z", "src_ip": "0.0.0.0", "category": "GLOBAL_SYN_FLOOD",
        "syn_per_sec": 4100, "distinct_sources": 3214,
    }


def test_heartbeat_line_is_ignored_by_shipper():
    l4_main = _load_l4_main()
    detector = make_detector(FakeClock())
    line = l4_main.heartbeat_line(detector, 1_761_699_600.0)
    assert line["category"] == "HEARTBEAT"
    assert {"packets_seen", "sources_tracked", "evicted"} <= set(line)
    assert shipper.to_event(line, "l4") is None


# ---------------------------------------------------------------------------
# shipper 변환
# ---------------------------------------------------------------------------

def test_shipper_maps_spoofed_src():
    event = shipper.to_event({
        "timestamp": "2026-10-29T01:00:00.000Z", "src_ip": "10.0.0.99", "category": "SPOOFED_SRC",
        "packets": 40, "distinct_sources": 37,
    }, "l4")
    assert event["layer"] == "L3" and event["proto"] is None
    assert event["signature_id"] == 9100003
    assert event["packet_count"] == 40
    assert event["signature"].endswith("(sources=37)")


def test_shipper_maps_global_syn_flood():
    event = shipper.to_event({
        "timestamp": "2026-10-29T01:00:00.000Z", "src_ip": "0.0.0.0", "category": "GLOBAL_SYN_FLOOD",
        "syn_per_sec": 4100, "distinct_sources": 3214,
    }, "l4")
    assert (event["layer"], event["proto"], event["signature_id"]) == ("L4", "TCP", 9100004)
    assert event["src_ip"] == "0.0.0.0" and event["packet_count"] == 4100


def test_shipper_keeps_existing_scapy_events():
    event = shipper.to_event({
        "timestamp": "2026-10-29T01:00:00.000Z", "src_ip": "172.28.13.150", "category": "SYN_FLOOD",
        "syn_per_sec": 300, "distinct_ports_10s": 1,
    }, "l4")
    assert (event["layer"], event["proto"], event["signature"]) == ("L4", "TCP", "LW Scapy SYN flood suspected")


def _alert(sid, proto):
    return {
        "timestamp": "2026-10-29T01:00:00.000Z", "event_type": "alert", "src_ip": "172.28.13.150",
        "proto": proto, "alert": {"signature_id": sid, "signature": "x", "severity": 2, "category": "misc"},
    }


def test_shipper_maps_icmp_flood_rule():
    event = shipper.to_event(_alert(9000005, "ICMP"), "eve")
    assert (event["category"], event["layer"]) == ("ICMP_FLOOD", "L3")


def test_shipper_other_layer_follows_protocol():
    assert shipper.to_event(_alert(2100366, "ICMP"), "eve")["layer"] == "L3"
    assert shipper.to_event(_alert(2100366, "TCP"), "eve")["layer"] == "L4"
    assert shipper.to_event(_alert(2100366, None), "eve")["layer"] == "L4"


# ---------------------------------------------------------------------------
# 파일별 정지 판단과 패킷 누락
# ---------------------------------------------------------------------------

def test_stalled_sensors_reports_single_stopped_file():
    clock = FakeClock()
    watch = shipper.StallWatch(clock=clock, threshold_seconds=120)
    watch.observe(100, 10)
    clock.advance(60)
    watch.observe(200, 10)   # eve만 늘어남
    clock.advance(60)
    stalled, _ = watch.observe(300, 10)
    assert stalled is False                    # "둘 다" 판정은 예전 그대로
    assert watch.stalled_sensors() == ["l4"]   # l4-detector만 멈춘 것은 따로 보인다


def test_stalled_sensors_empty_before_two_observations():
    watch = shipper.StallWatch(clock=FakeClock(), threshold_seconds=120)
    assert watch.stalled_sensors() == []


def test_capture_stats_reports_increments_and_handles_restart():
    stats = shipper.CaptureStats()
    stats.observe({"event_type": "stats", "stats": {"capture": {"kernel_packets": 1000, "kernel_drops": 10}}})
    assert stats.take_delta() == (1000, 10)
    stats.observe({"event_type": "stats", "stats": {"capture": {"kernel_packets": 1500, "kernel_drops": 60}}})
    assert stats.take_delta() == (500, 50)
    assert stats.take_delta() == (0, 0)
    stats.observe({"event_type": "stats", "stats": {"capture": {"kernel_packets": 20, "kernel_drops": 0}}})
    assert stats.take_delta() == (20, 0)


def test_process_tailer_feeds_stats_lines_to_capture_stats():
    lines = [
        json.dumps({"event_type": "stats", "stats": {"capture": {"kernel_packets": 7, "kernel_drops": 1}}}),
    ]
    tailer = SimpleNamespace(read_lines=lambda: lines)
    sent = []
    sender = SimpleNamespace(send=sent.append)
    stats = shipper.CaptureStats()
    shipper.process_tailer(tailer, "eve", shipper.Aggregator(), sender, stats)
    assert stats.take_delta() == (7, 1)
    assert sent == []


def test_heartbeat_body_adds_guide57_fields_only_when_given():
    eve = SimpleNamespace(last_size=1)
    l4 = SimpleNamespace(last_size=2)
    sender = SimpleNamespace(queue_size=0)
    body = shipper.heartbeat_body(eve, l4, sender, stalled_sensor_names=["l4"], kernel_delta=(500, 30))
    assert body["detail"]["stalled_sensors"] == ["l4"]
    assert (body["detail"]["kernel_packets"], body["detail"]["kernel_drops"]) == (500, 30)
    assert "stalled_sensors" not in shipper.heartbeat_body(eve, l4, sender)["detail"]


# ---------------------------------------------------------------------------
# Suricata L3 규칙 파일
# ---------------------------------------------------------------------------

def test_l3_rules_file_defines_icmp_flood_and_is_loaded():
    rules = (ROOT / "netwatch" / "suricata" / "rules" / "l3.rules").read_text(encoding="utf-8")
    rule_lines = [line for line in rules.splitlines() if line.startswith("alert ")]
    assert len(rule_lines) == 1
    assert "sid:9000005;" in rule_lines[0] and "alert icmp" in rule_lines[0] and "itype:8" in rule_lines[0]
    config = (ROOT / "netwatch" / "suricata" / "suricata.yaml").read_text(encoding="utf-8")
    assert "/etc/suricata/custom/rules/l3.rules" in config.split("rule-files:", 1)[1].split("\naf-packet:", 1)[0]
