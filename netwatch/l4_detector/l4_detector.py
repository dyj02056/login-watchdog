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
  상한을 넘은 새 출발지는 출발지별 판정에서 빠지고 전체 SYN 합계에만 들어간다.
- L4_GLOBAL_SYN_PER_SEC=1000
  출발지와 상관없는 전체 SYN 경보 기준. 출발지를 바꾸는 SYN Flood를 보기 위한 것이며,
  막을 주소가 하나로 정해지지 않아 l4.json에는 쓰지 않고 로그(stderr)에만 남긴다.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TextIO

from scapy.all import IP, TCP, get_if_addr, get_if_list, sniff

from detector_core import (
    DEFAULT_GLOBAL_SYN_PER_SEC,
    DEFAULT_MAX_SOURCES,
    L4Detector,
    resolve_sensor_iface,
    truncate_output_if_oversized,
)


DEFAULT_SENSOR_IFACE = "eth1"
DEFAULT_SYN_THRESHOLD = 100
DEFAULT_DISTINCT_PORTS_THRESHOLD = 15
DEFAULT_OUTPUT = "/var/log/suricata/l4.json"
DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024
DEFAULT_WINDOW_SECONDS = 10
DEFAULT_COOLDOWN_SECONDS = 10


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

    detector = L4Detector(
        syn_threshold_per_sec=syn_threshold,
        distinct_ports_threshold=ports_threshold,
        window_seconds=DEFAULT_WINDOW_SECONDS,
        cooldown_seconds=DEFAULT_COOLDOWN_SECONDS,
        edge_prefix=edge_prefix or None,
        max_sources=max_sources,
        global_syn_threshold_per_sec=global_syn_threshold,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(
        "[*] L4 측정기를 시작합니다: "
        f"iface={sensor_iface}, "
        f"syn_per_sec={syn_threshold}, "
        f"distinct_ports_10s={ports_threshold}, "
        f"global_syn_per_sec={global_syn_threshold}, "
        f"max_sources={max_sources}, "
        f"output={output_path}",
        flush=True,
    )

    with output_path.open(
        "a+",
        encoding="utf-8",
        buffering=1,
    ) as output:

        def handle_packet(packet: object) -> None:
            """Scapy TCP 패킷 하나를 탐지기에 전달한다."""
            if IP not in packet or TCP not in packet:
                return

            src_ip = str(packet[IP].src)
            dst_port = int(packet[TCP].dport)
            flags = packet[TCP].flags

            events = detector.observe(
                src_ip=src_ip,
                dst_port=dst_port,
                flags=flags,
            )

            if not events:
                return

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

        sniff(
            iface=sensor_iface,
            filter="tcp",
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