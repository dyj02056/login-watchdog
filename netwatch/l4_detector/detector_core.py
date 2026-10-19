"""Scapy에 의존하지 않는 L4 트래픽 측정 로직.

SYN Flood는 출발지별 최근 1초 동안의 SYN 전용 패킷 수로 판단한다.
포트 스캔은 출발지별 최근 window_seconds 동안 접근한 서로 다른
목적지 포트 수로 판단한다.

Docker gateway 자신과 core 네트워크에서 발생한 패킷은 센서 내부
통신이므로 탐지 대상에서 제외한다.
"""

from __future__ import annotations

import ipaddress
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable


SYN_FLAG = 0x02
ACK_FLAG = 0x10
SYN_WINDOW_SECONDS = 1.0
CORE_NETWORK = ipaddress.ip_network("172.29.0.0/24")


def utc_timestamp(timestamp: float) -> str:
    """유닉스 시각을 밀리초 단위 UTC ISO 8601 문자열로 바꾼다."""
    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def has_syn_without_ack(flags: object) -> bool:
    """TCP 플래그가 SYN을 포함하고 ACK는 포함하지 않는지 확인한다."""
    try:
        numeric_flags = int(flags)
    except (TypeError, ValueError):
        text_flags = str(flags).upper()
        return "S" in text_flags and "A" not in text_flags

    return bool(numeric_flags & SYN_FLAG) and not bool(
        numeric_flags & ACK_FLAG
    )


def gateway_ip_from_prefix(
    edge_prefix: str | None,
) -> ipaddress.IPv4Address | None:
    """Edge 앞 세 자리로 gateway의 .10 주소를 만든다."""
    if not edge_prefix:
        return None

    try:
        network = ipaddress.ip_network(
            f"{edge_prefix}.0/24",
            strict=True,
        )
    except ValueError:
        return None

    return ipaddress.ip_address(int(network.network_address) + 10)


class L4Detector:
    """출발지별 SYN 비율과 서로 다른 목적지 포트 수를 측정한다."""

    def __init__(
        self,
        syn_threshold_per_sec: int,
        distinct_ports_threshold: int,
        window_seconds: float = 10,
        cooldown_seconds: float = 10,
        clock: Callable[[], float] = time.time,
        *,
        edge_prefix: str | None = None,
    ) -> None:
        if syn_threshold_per_sec <= 0:
            raise ValueError(
                "syn_threshold_per_sec는 1 이상이어야 합니다."
            )

        if distinct_ports_threshold <= 0:
            raise ValueError(
                "distinct_ports_threshold는 1 이상이어야 합니다."
            )

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds는 0보다 커야 합니다."
            )

        if cooldown_seconds < 0:
            raise ValueError(
                "cooldown_seconds는 0 이상이어야 합니다."
            )

        self.syn_threshold_per_sec = syn_threshold_per_sec
        self.distinct_ports_threshold = distinct_ports_threshold
        self.window_seconds = float(window_seconds)
        self.cooldown_seconds = float(cooldown_seconds)
        self.clock = clock

        self.gateway_ip = gateway_ip_from_prefix(edge_prefix)

        # SYN은 최근 1초의 발생 시각만 보관한다.
        self._syn_events: dict[str, deque[float]] = {}

        # 같은 포트를 반복해도 저장량이 늘지 않도록 포트별 최근 시각만 보관한다.
        self._port_events: dict[str, dict[int, float]] = {}

        # 같은 출발지와 경보 종류의 반복 출력을 제한한다.
        self._last_emitted: dict[tuple[str, str], float] = {}

    def _is_excluded_source(self, src_ip: str) -> bool:
        """Gateway 자신과 core 대역의 패킷인지 확인한다."""
        try:
            address = ipaddress.ip_address(src_ip)
        except ValueError:
            return True

        if address in CORE_NETWORK:
            return True

        return self.gateway_ip is not None and address == self.gateway_ip

    def _prune(self, now: float) -> None:
        """시간 창 밖의 기록과 오래된 cooldown 기록을 제거한다."""
        syn_cutoff = now - SYN_WINDOW_SECONDS

        for src_ip, timestamps in list(self._syn_events.items()):
            while timestamps and timestamps[0] <= syn_cutoff:
                timestamps.popleft()

            if not timestamps:
                del self._syn_events[src_ip]

        port_cutoff = now - self.window_seconds

        for src_ip, ports in list(self._port_events.items()):
            expired_ports = [
                port
                for port, last_seen in ports.items()
                if last_seen <= port_cutoff
            ]

            for port in expired_ports:
                del ports[port]

            if not ports:
                del self._port_events[src_ip]

        cooldown_cutoff = now - self.cooldown_seconds

        for key, emitted_at in list(self._last_emitted.items()):
            if emitted_at <= cooldown_cutoff:
                del self._last_emitted[key]

    def _can_emit(
        self,
        src_ip: str,
        category: str,
        now: float,
    ) -> bool:
        """같은 출발지와 경보가 cooldown 안에 출력됐는지 확인한다."""
        last_emitted = self._last_emitted.get((src_ip, category))

        if last_emitted is None:
            return True

        return now - last_emitted >= self.cooldown_seconds

    def _make_event(
        self,
        *,
        timestamp: float,
        src_ip: str,
        category: str,
        syn_per_sec: int,
        distinct_ports: int,
    ) -> dict:
        """plan-excerpt 2.3① 형식의 l4.json 한 줄을 만든다."""
        return {
            "timestamp": utc_timestamp(timestamp),
            "src_ip": src_ip,
            "category": category,
            "syn_per_sec": syn_per_sec,
            "distinct_ports_10s": distinct_ports,
        }

    def observe(
        self,
        src_ip: str,
        dst_port: int,
        flags: object,
    ) -> list[dict]:
        """TCP 패킷 하나를 반영하고 새로 발생한 경보를 반환한다."""
        now = float(self.clock())
        self._prune(now)

        if self._is_excluded_source(src_ip):
            return []

        if not isinstance(dst_port, int) or not 0 <= dst_port <= 65535:
            return []

        ports = self._port_events.setdefault(src_ip, {})
        ports[dst_port] = now

        if has_syn_without_ack(flags):
            timestamps = self._syn_events.setdefault(
                src_ip,
                deque(),
            )
            timestamps.append(now)

        syn_per_sec = len(self._syn_events.get(src_ip, ()))
        distinct_ports = len(self._port_events.get(src_ip, {}))
        events: list[dict] = []

        if (
            syn_per_sec >= self.syn_threshold_per_sec
            and self._can_emit(src_ip, "SYN_FLOOD", now)
        ):
            events.append(
                self._make_event(
                    timestamp=now,
                    src_ip=src_ip,
                    category="SYN_FLOOD",
                    syn_per_sec=syn_per_sec,
                    distinct_ports=distinct_ports,
                )
            )
            self._last_emitted[(src_ip, "SYN_FLOOD")] = now

        if (
            distinct_ports >= self.distinct_ports_threshold
            and self._can_emit(src_ip, "PORT_SCAN", now)
        ):
            events.append(
                self._make_event(
                    timestamp=now,
                    src_ip=src_ip,
                    category="PORT_SCAN",
                    syn_per_sec=syn_per_sec,
                    distinct_ports=distinct_ports,
                )
            )
            self._last_emitted[(src_ip, "PORT_SCAN")] = now

        return events