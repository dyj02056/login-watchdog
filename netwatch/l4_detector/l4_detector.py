"""Scapy로 TCP 패킷을 받아 l4.json에 경보를 기록한다.

환경변수 기본값과 이유:
- SENSOR_IFACE=eth1 (또는 auto)
  gateway 네임스페이스에서 edge(공격이 들어오는 쪽) 인터페이스다. Docker가 네트워크를 붙이는
  순서는 PC·재생성마다 달라 edge가 eth0일 때도 eth1일 때도 있다(10/19는 eth1, 10/20 다른 PC는 eth0).
  그래서 시작할 때 LW_EDGE_PREFIX.10 주소가 붙은 인터페이스를 찾아, 지정한 이름에 그 주소가 없으면
  그쪽으로 바꾼다. core는 탐지에서 빼므로 core를 보면 오류 없이 0건이 되기 때문이다.
- L4_SYN_PER_SEC=100
  Suricata sid 9000001과 비슷한 수준으로 SYN Flood를 판단한다.
- L4_DISTINCT_PORTS_10S=15
  정상적인 단일 서비스 접근과 여러 포트를 탐색하는 동작을 구분한다.
- L4_OUTPUT=/var/log/suricata/l4.json
  Suricata 로그와 같은 볼륨을 shipper가 함께 tail할 수 있게 한다.
- LW_EDGE_PREFIX
  gateway 자신의 .10 주소를 탐지 대상에서 제외하는 데 사용한다.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TextIO

from scapy.all import IP, TCP, get_if_addr, get_if_list, sniff

from detector_core import L4Detector, resolve_sensor_iface


DEFAULT_SENSOR_IFACE = "eth1"
DEFAULT_SYN_THRESHOLD = 100
DEFAULT_DISTINCT_PORTS_THRESHOLD = 15
DEFAULT_OUTPUT = "/var/log/suricata/l4.json"
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
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(
        "[*] L4 측정기를 시작합니다: "
        f"iface={sensor_iface}, "
        f"syn_per_sec={syn_threshold}, "
        f"distinct_ports_10s={ports_threshold}, "
        f"output={output_path}",
        flush=True,
    )

    with output_path.open(
        "a",
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