"""Scapy로 TCP 패킷을 받아 l4.json에 경보를 기록한다.

환경변수 기본값과 이유:
- SENSOR_IFACE=eth1 (또는 auto)
  gateway 네임스페이스에서 edge(공격이 들어오는 쪽) 인터페이스다. Docker가 네트워크를 붙이는
  순서는 PC·재생성마다 달라 edge가 eth0일 때도 eth1일 때도 있다(10/19는 eth1, 10/20 다른 PC는 eth0).
  그래서 시작할 때 LW_EDGE_PREFIX.10 주소가 붙은 인터페이스를 찾아, 지정한 이름에 그 주소가 없으면
  그쪽으로 바꾼다. core는 탐지에서 빼므로 core를 보면 오류 없이 0건이 되기 때문이다.
- L4_SYN_PER_SEC=100
  출발지 하나가 1초에 SYN 100개 이상이면 SYN Flood로 본다. Suricata sid 9000001(5초에 100개
  = 초당 20개)보다 5배 높다 — Suricata가 먼저 울리고, 이 측정기는 심한 폭주만 확인하는 두 번째
  근거다. 두 경보 모두 SYN_FLOOD로 같은 NET-01 차단으로 이어지므로 기준을 낮춰 맞출 이유는 없고,
  낮추면 정상 접속이 몰릴 때 오탐만 는다(10/29 점검, docs/track-d/measurements.md "센서 기준").
- L4_DISTINCT_PORTS_10S=15
  정상적인 단일 서비스 접근과 여러 포트를 탐색하는 동작을 구분한다.
- L4_OUTPUT=/var/log/suricata/l4.json
  Suricata 로그와 같은 볼륨을 shipper가 함께 tail할 수 있게 한다.
- L4_MAX_BYTES=10485760
  l4.json이 무한히 커지지 않도록 10MiB에 도달하면 기존 내용을 비운다.
  shipper는 파일 크기 감소를 감지하고 새로 기록되는 첫 줄부터 다시 읽는다.
- LW_EDGE_PREFIX
  gateway 자신의 .10 주소를 탐지 대상에서 제외하는 데 사용한다.
- L4_MAX_SOURCES=50000
  기록하는 출발지 수 상한. 위조 출발지가 끝없이 늘어도 메모리가 무한히 커지지 않게 한다.
  상한에 닿으면 SYN만 보낸 "확인 안 된" 출발지를 오래 쉰 순서로 내보내고 새 출발지를 받는다
  (위조 출발지로 상한을 채워 진짜 공격자를 숨기는 것을 막기 위해서다). SYN 없는 ACK를 보낸
  출발지는 밀려나지 않으며, 전부 그런 출발지라 자리를 못 만들 때만 새 출발지가 판정에서 빠지고
  전체 SYN 합계에만 들어간다.
- L4_GLOBAL_SYN_PER_SEC=1000
  출발지와 상관없는 전체 SYN 경보 기준. 출발지를 바꾸는 SYN Flood를 보기 위한 것이며,
  막을 주소가 하나로 정해지지 않아 차단으로 잇지 않는다. guide57부터 로그와 함께 l4.json에
  GLOBAL_SYN_FLOOD(src_ip=0.0.0.0) 한 줄을 써서 앱이 Slack으로 알리게 한다(계약서 K4·K5).
- L4_FOREIGN_PACKETS_10S=10
  edge 대역 밖 출발지(위조 주소) 패킷이 10초에 이만큼 넘으면 SPOOFED_SRC 경보(guide57, L3).
- 생존 줄(guide57)
  60초마다 l4.json에 {"category":"HEARTBEAT", ...} 한 줄을 쓴다. shipper가 파일별로 정지를
  판단하므로, 이 줄이 없으면 공격이 없는 동안 l4.json이 늘지 않아 이 측정기가 죽어도 알 수 없었다.
  shipper는 모르는 category를 경보로 보내지 않으므로 이 줄은 앱으로 가지 않는다.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import TextIO

from scapy.all import IP, TCP, get_if_addr, get_if_list, sniff

from detector_core import (
    DEFAULT_FOREIGN_PACKETS_10S,
    DEFAULT_GLOBAL_SYN_PER_SEC,
    DEFAULT_MAX_SOURCES,
    L4Detector,
    build_capture_filter,
    log_global_alert,
    resolve_sensor_iface,
    truncate_output_if_oversized,
    utc_timestamp,
)


DEFAULT_SENSOR_IFACE = "eth1"
DEFAULT_SYN_THRESHOLD = 100
DEFAULT_DISTINCT_PORTS_THRESHOLD = 15
DEFAULT_OUTPUT = "/var/log/suricata/l4.json"
DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024
DEFAULT_WINDOW_SECONDS = 10
DEFAULT_COOLDOWN_SECONDS = 10
# 생존 줄 간격(초). shipper의 정지 기준(SHIPPER_STALL_SECONDS, 기본 120초)의 절반이라 한 번 빠져도 오판하지 않는다.
HEARTBEAT_INTERVAL_SECONDS = 60


def read_positive_int(name: str, default: int) -> int:
    """환경변수에서 1 이상의 정수를 읽는다."""
    raw_value = os.environ.get(name, str(default))

    try:
        value = int(raw_value)
    except ValueError as error:
        raise ValueError(
            f"{name}은 정수여야 합니다: {raw_value!r}"
        ) from error

    if value <= 0:
        raise ValueError(f"{name}은 1 이상이어야 합니다.")

    return value


def write_events(output: TextIO, events: list[dict]) -> None:
    """경보를 한 줄에 JSON 하나인 JSON Lines 형식으로 기록한다."""
    for event in events:
        output.write(
            json.dumps(
                event,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        output.write("\n")

        # shipper가 첫 경보를 바로 읽을 수 있도록 즉시 디스크로 넘긴다.
        output.flush()


def global_alert_line(event: dict) -> dict:
    """on_global_alert가 넘긴 전체 SYN 경보를 l4.json 한 줄 모양으로 바꾼다(계약서 K4).

    막을 출발지가 하나로 정해지지 않으므로 src_ip는 0.0.0.0(출발지 없음)으로 둔다. 앱은 이 주소를
    인프라·특수 주소로 보고 보안 이벤트·차단으로 잇지 않는다.
    """
    return {
        "timestamp": event["timestamp"],
        "src_ip": "0.0.0.0",
        "category": "GLOBAL_SYN_FLOOD",
        "syn_per_sec": event["syn_per_sec"],
        "distinct_sources": event["distinct_sources"],
    }


def heartbeat_line(detector: L4Detector, now: float) -> dict:
    """생존 줄 한 줄. 숫자는 사람이 l4.json을 열어 측정기 상태를 볼 때 쓴다(앱으로는 가지 않음)."""
    return {
        "timestamp": utc_timestamp(now),
        "category": "HEARTBEAT",
        "packets_seen": detector.packets_seen,
        "sources_tracked": detector.sources_tracked,
        "evicted": detector.evicted_count,
    }


def run() -> None:
    """환경설정을 읽고 TCP 패킷 캡처를 시작한다."""
    syn_threshold = read_positive_int(
        "L4_SYN_PER_SEC",
        DEFAULT_SYN_THRESHOLD,
    )
    ports_threshold = read_positive_int(
        "L4_DISTINCT_PORTS_10S",
        DEFAULT_DISTINCT_PORTS_THRESHOLD,
    )
    max_output_bytes = read_positive_int(
        "L4_MAX_BYTES",
        DEFAULT_MAX_OUTPUT_BYTES,
    )
    max_sources = read_positive_int(
        "L4_MAX_SOURCES",
        DEFAULT_MAX_SOURCES,
    )
    global_syn_threshold = read_positive_int(
        "L4_GLOBAL_SYN_PER_SEC",
        DEFAULT_GLOBAL_SYN_PER_SEC,
    )
    foreign_threshold = read_positive_int(
        "L4_FOREIGN_PACKETS_10S",
        DEFAULT_FOREIGN_PACKETS_10S,
    )
    output_path = Path(
        os.environ.get("L4_OUTPUT", DEFAULT_OUTPUT)
    )
    edge_prefix = os.environ.get("LW_EDGE_PREFIX", "").strip()

    if not edge_prefix:
        print(
            "[WARN] LW_EDGE_PREFIX가 없어 gateway .10 제외를 "
            "적용하지 않습니다.",
            file=sys.stderr,
            flush=True,
        )

    sensor_iface, iface_warning = resolve_sensor_iface(
        os.environ.get("SENSOR_IFACE", DEFAULT_SENSOR_IFACE),
        edge_prefix,
        get_if_list,
        get_if_addr,
        DEFAULT_SENSOR_IFACE,
    )

    if iface_warning:
        print(f"[WARN] {iface_warning}", file=sys.stderr, flush=True)

    # 전체 SYN 경보는 sniff 콜백 안에서 생기므로, 아래에서 파일을 연 뒤에 쓰는 함수를 연결한다.
    pending_global: list[dict] = []

    def collect_global(event: dict) -> None:
        log_global_alert(event)
        pending_global.append(global_alert_line(event))

    detector = L4Detector(
        syn_threshold_per_sec=syn_threshold,
        distinct_ports_threshold=ports_threshold,
        window_seconds=DEFAULT_WINDOW_SECONDS,
        cooldown_seconds=DEFAULT_COOLDOWN_SECONDS,
        edge_prefix=edge_prefix or None,
        max_sources=max_sources,
        global_syn_threshold_per_sec=global_syn_threshold,
        on_global_alert=collect_global,
        foreign_packets_threshold=foreign_threshold,
    )
    capture_filter = build_capture_filter(edge_prefix or None)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(
        "[*] L4 측정기를 시작합니다: "
        f"iface={sensor_iface}, "
        f"syn_per_sec={syn_threshold}, "
        f"distinct_ports_10s={ports_threshold}, "
        f"global_syn_per_sec={global_syn_threshold}, "
        f"max_sources={max_sources}, "
        f"foreign_packets_10s={foreign_threshold}, "
        f"filter={capture_filter!r}, "
        f"output={output_path}",
        flush=True,
    )

    with output_path.open(
        "a+",
        encoding="utf-8",
        buffering=1,
    ) as output:
        # sniff 콜백과 생존 줄 스레드가 같은 파일에 쓰므로, 크기 확인·비우기·쓰기를 한 잠금 안에서 한다.
        # 잠금이 없으면 한쪽이 파일을 비우는 사이 다른 쪽 줄이 반쯤 잘려 shipper가 깨진 JSON을 읽는다.
        output_lock = threading.Lock()

        def emit(events: list[dict]) -> None:
            with output_lock:
                if truncate_output_if_oversized(
                    output,
                    max_output_bytes,
                ):
                    print(
                        "[WARN] l4.json이 크기 제한에 도달해 "
                        "기존 내용을 비웠습니다: "
                        f"limit={max_output_bytes} bytes",
                        file=sys.stderr,
                        flush=True,
                    )

                write_events(output, events)

        def heartbeat_loop() -> None:
            """60초마다 생존 줄을 쓴다. 어떤 오류도 측정 스레드를 멈추지 않게 여기서 삼킨다."""
            while True:
                time.sleep(HEARTBEAT_INTERVAL_SECONDS)
                try:
                    emit([heartbeat_line(detector, time.time())])
                except Exception as error:  # noqa: BLE001
                    print(f"[WARN] 생존 줄 기록 실패: {type(error).__name__}", file=sys.stderr, flush=True)

        threading.Thread(target=heartbeat_loop, name="l4-heartbeat", daemon=True).start()
        # 시작하자마자 한 줄 써 두면, 재시작 직후에도 shipper가 l4.json을 "살아 있음"으로 본다.
        emit([heartbeat_line(detector, time.time())])

        def handle_packet(packet: object) -> None:
            """Scapy 패킷 하나를 탐지기에 전달한다."""
            if IP not in packet:
                return

            src_ip = str(packet[IP].src)
            events: list[dict] = []

            if detector.is_foreign_source(src_ip):
                events.extend(detector.observe_foreign(src_ip))

            if TCP in packet and (
                detector.gateway_ip is None
                or str(packet[IP].dst) == str(detector.gateway_ip)
            ):
                events.extend(
                    detector.observe(
                        src_ip=src_ip,
                        dst_port=int(packet[TCP].dport),
                        flags=packet[TCP].flags,
                    )
                )

            if pending_global:
                events.extend(pending_global)
                pending_global.clear()

            if events:
                emit(events)

        sniff(
            iface=sensor_iface,
            filter=capture_filter,
            prn=handle_packet,
            store=False,
        )


def main() -> None:
    """측정기를 실행하고 설정·캡처 오류를 로그로 남긴다."""
    try:
        run()
    except KeyboardInterrupt:
        print(
            "\n[중단] L4 측정기를 종료합니다.",
            file=sys.stderr,
        )
    except (OSError, ValueError) as error:
        print(
            f"[FAIL] L4 측정기를 시작할 수 없습니다: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()