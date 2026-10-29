"""Scapy에 의존하지 않는 L4 트래픽 측정 로직.

SYN Flood는 출발지별 최근 1초 동안의 SYN 전용 패킷 수로 판단한다.
포트 스캔은 출발지별 최근 window_seconds 동안 접근한 서로 다른
목적지 포트 수로 판단한다.

Docker gateway 자신과 core 네트워크에서 발생한 패킷은 센서 내부
통신이므로 탐지 대상에서 제외한다.

출발지를 패킷마다 바꾸는 SYN Flood(hping3 --rand-source 등)는 출발지별 기준을
넘지 않으므로, 출발지와 상관없는 "전체 SYN 비율"을 따로 센다. 이 경보는 막을
주소가 하나로 정해지지 않아 차단으로 잇지 않고 on_global_alert로만 넘긴다. 실제 방어는
gateway의 SYN cookies가 맡는다. guide57부터 l4_detector.py가 이 출구에 l4.json 쓰기를 연결해
GLOBAL_SYN_FLOOD 경보(알림 전용, 계약서 K4·K5)로 앱에 보낸다.

edge 대역 밖 출발지가 edge 인터페이스로 들어오면 위조된 주소다(이 PC의 edge에는 자기 대역과
Docker 게이트웨이 .1만 붙어 있다). observe_foreign이 10초 창으로 세어 SPOOFED_SRC 경보를 만든다
(guide57, L3). 이것도 출발지가 가짜라 차단하지 않는다.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import time
from collections import Counter, OrderedDict, deque
from datetime import datetime, timezone
from typing import Callable, TextIO


SYN_FLAG = 0x02
ACK_FLAG = 0x10
SYN_WINDOW_SECONDS = 1.0
# 모든 출발지 기록을 훑는 정리는 이 간격에 한 번만 한다. 패킷마다 하면 출발지가 수만 개일 때
# 패킷 하나에 수만 번 계산해 측정기가 밀린다(10/29 점검). 현재 패킷의 출발지는 매번 따로 정리하므로
# 출발지별 숫자는 정확하다.
PRUNE_INTERVAL_SECONDS = 1.0
# 기록하는 출발지 수 상한. 위조 출발지가 끝없이 늘어도 메모리가 무한히 커지지 않게 한다.
DEFAULT_MAX_SOURCES = 50_000
# 전체 SYN 경보 기준(초당). 출발지별 기준(100)보다 높게 둬 정상 접속이 몰릴 때 울리지 않게 한다.
DEFAULT_GLOBAL_SYN_PER_SEC = 1000
GLOBAL_KEY = "*"
# 위조 출발지(edge 대역 밖) 판정 창과 기준(guide57). 위조 출발지는 한 개만 와도 이상이지만, 잘못 붙은
# 패킷 몇 개로 알림이 울리지 않게 10초에 기본 10개 이상일 때만 경보한다.
FOREIGN_WINDOW_SECONDS = 10.0
DEFAULT_FOREIGN_PACKETS_10S = 10


def log_warning(message: str) -> None:
    """측정기 경고를 stderr에 한 줄 남긴다(docker compose logs l4-detector로 확인)."""
    print(f"[WARN] {message}", file=sys.stderr, flush=True)


def log_global_alert(event: dict) -> None:
    """전체 SYN 경보를 로그로만 남긴다.

    나중에 계약서(K4)에 전체 경보 종류가 생기면 이 함수 대신 l4.json에 쓰는 함수를
    on_global_alert로 넘기면 된다 — 탐지 로직은 바꾸지 않아도 되게 경보 출구를 하나로 모았다.
    """
    log_warning(
        f"전체 SYN 폭주 의심: 최근 1초 SYN {event['syn_per_sec']:,}개"
        f"(기준 {event['threshold']:,}개), 출발지 {event['distinct_sources']:,}곳 — "
        "출발지 위조 가능성이 있어 차단하지 않습니다."
    )
# gateway·app·shipper가 쓰는 core 대역(compose의 core 네트워크와 같아야 한다).
# 예전 172.29.0.0/24는 Docker Desktop(WSL2) 내부 대역과 겹쳐 172.30으로 옮겼다(A0-1 보완).
CORE_NETWORK = ipaddress.ip_network("172.30.0.0/24")

def truncate_output_if_oversized(
    output: TextIO,
    max_bytes: int,
) -> bool:
    """출력 파일이 크기 제한 이상이면 같은 파일을 비운다.

    파일을 삭제하거나 이름을 바꾸지 않고 길이만 0으로 만든다.
    따라서 shipper의 Tailer는 파일 크기 감소를 감지한 뒤 새로 기록되는
    첫 줄부터 다시 읽을 수 있다.

    반환값:
        파일을 비웠으면 True
        제한보다 작아서 유지했으면 False
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes는 1 이상이어야 합니다.")

    # 버퍼에 남아 있는 내용을 실제 파일에 먼저 반영한다.
    output.flush()

    current_size = os.fstat(output.fileno()).st_size

    if current_size < max_bytes:
        return False

    output.seek(0)
    output.truncate(0)
    output.flush()

    return True

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


def has_ack_without_syn(flags: object) -> bool:
    """TCP 플래그가 ACK를 포함하고 SYN은 포함하지 않는지 확인한다(handshake 뒤의 일반 패킷)."""
    try:
        numeric_flags = int(flags)
    except (TypeError, ValueError):
        text_flags = str(flags).upper()
        return "A" in text_flags and "S" not in text_flags

    return bool(numeric_flags & ACK_FLAG) and not bool(numeric_flags & SYN_FLAG)


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


def build_capture_filter(edge_prefix: str | None) -> str:
    """Scapy가 커널에서 받아 올 패킷 조건(BPF)을 만든다(guide57).

    - TCP는 gateway(.10)로 가는 것만 받는다. 출발지별 SYN·포트 수는 gateway를 노리는 패킷만 의미가 있고,
      gateway가 내보내는 응답까지 파이썬으로 올리면 폭주 때 처리 부담만 두 배가 된다.
    - edge 대역 밖·core 대역 밖 출발지는 프로토콜과 상관없이 받는다. 위조 출발지(SPOOFED_SRC) 판정용이며,
      정상일 때는 거의 0건이라 부담이 없다. 커널이 미리 걸러 주므로 파이썬까지 올라오는 패킷이 적다.
    edge 대역을 모르면 예전처럼 모든 TCP를 받는다(위조 판정은 하지 않음).
    """
    gateway_ip = gateway_ip_from_prefix(edge_prefix)
    if gateway_ip is None:
        return "tcp"
    edge = ipaddress.ip_network(f"{gateway_ip}/24", strict=False)
    return (
        f"ip and ((tcp and dst host {gateway_ip}) or "
        f"(not src net {edge} and not src net {CORE_NETWORK}))"
    )


def resolve_sensor_iface(
    configured: str | None,
    edge_prefix: str | None,
    list_ifaces: Callable[[], list[str]],
    get_addr: Callable[[str], str],
    fallback: str,
) -> tuple[str, str | None]:
    """감시할 인터페이스 이름과 경고 문구(없으면 None)를 고른다.

    Docker는 컨테이너에 네트워크를 붙이는 순서를 보장하지 않아, gateway 안에서
    edge가 eth0인 PC와 eth1인 PC가 함께 있다(10/19·10/20 확인). 이름을 고정하면
    어떤 PC에서는 core만 보게 되고, core는 탐지에서 빼므로 오류 없이 0건이 된다.
    그래서 이름 대신 "edge 쪽 gateway 주소(.10)가 붙은 인터페이스"를 기준으로 삼는다.

    - configured가 비었거나 "auto"면 그 기준으로 찾는다.
    - 이름을 지정했어도 그 인터페이스에 edge 주소가 없고 다른 인터페이스에 있으면
      그쪽으로 바꾼다. 지정한 이름이 core라면 어차피 탐지가 0건이라 지킬 이유가 없다.
    - edge 주소를 끝내 못 찾으면 지정값(없으면 fallback)을 그대로 쓰고 경고만 남긴다.
      측정기를 멈추는 것보다 일단 돌면서 로그로 알리는 편이 원인 파악이 쉽다.
    """
    name = (configured or "").strip()
    wants_auto = name.lower() in ("", "auto")
    edge_ip = gateway_ip_from_prefix(edge_prefix)

    if edge_ip is None:
        chosen = fallback if wants_auto else name
        return (
            chosen,
            f"LW_EDGE_PREFIX가 없거나 형식이 틀려 edge 인터페이스를 확인하지 못했습니다. "
            f"{chosen}을 그대로 감시합니다.",
        )

    def has_edge_ip(iface: str) -> bool:
        # 주소가 없거나 조회에 실패한 인터페이스는 후보에서 뺀다(Scapy는 0.0.0.0을 돌려준다).
        try:
            return ipaddress.ip_address(get_addr(iface)) == edge_ip
        except (OSError, ValueError):
            return False

    try:
        matches = [iface for iface in list_ifaces() if has_edge_ip(iface)]
    except OSError:
        matches = []

    if not wants_auto and has_edge_ip(name):
        return name, None

    if matches:
        if wants_auto:
            return matches[0], None
        return (
            matches[0],
            f"SENSOR_IFACE={name}에는 edge 주소 {edge_ip}가 없어 "
            f"{matches[0]}을 대신 감시합니다.",
        )

    chosen = fallback if wants_auto else name
    return (
        chosen,
        f"edge 주소 {edge_ip}가 붙은 인터페이스를 찾지 못했습니다. "
        f"{chosen}을 그대로 감시하지만 탐지가 0건일 수 있습니다.",
    )


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
        max_sources: int = DEFAULT_MAX_SOURCES,
        global_syn_threshold_per_sec: int = DEFAULT_GLOBAL_SYN_PER_SEC,
        on_global_alert: Callable[[dict], None] = log_global_alert,
        on_warning: Callable[[str], None] = log_warning,
        foreign_packets_threshold: int = DEFAULT_FOREIGN_PACKETS_10S,
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

        if max_sources <= 0:
            raise ValueError("max_sources는 1 이상이어야 합니다.")

        if global_syn_threshold_per_sec <= 0:
            raise ValueError(
                "global_syn_threshold_per_sec는 1 이상이어야 합니다."
            )

        if foreign_packets_threshold <= 0:
            raise ValueError(
                "foreign_packets_threshold는 1 이상이어야 합니다."
            )

        self.syn_threshold_per_sec = syn_threshold_per_sec
        self.distinct_ports_threshold = distinct_ports_threshold
        self.window_seconds = float(window_seconds)
        self.cooldown_seconds = float(cooldown_seconds)
        self.clock = clock

        self.gateway_ip = gateway_ip_from_prefix(edge_prefix)
        # 위조 출발지 판정에 쓰는 이 PC의 edge 대역. 대역을 모르면 위조 판정을 하지 않는다.
        self.edge_network = (
            ipaddress.ip_network(f"{self.gateway_ip}/24", strict=False)
            if self.gateway_ip is not None
            else None
        )

        # SYN은 최근 1초의 발생 시각만 보관한다.
        self._syn_events: dict[str, deque[float]] = {}

        # 같은 포트를 반복해도 저장량이 늘지 않도록 포트별 최근 시각만 보관한다.
        self._port_events: dict[str, dict[int, float]] = {}

        # 같은 출발지와 경보 종류의 반복 출력을 제한한다.
        self._last_emitted: dict[tuple[str, str], float] = {}

        self.max_sources = max_sources
        self.global_syn_threshold_per_sec = global_syn_threshold_per_sec
        self.on_global_alert = on_global_alert
        self.on_warning = on_warning
        self._last_prune: float | None = None

        # 출발지 상한에 닿았을 때 누구를 먼저 내보낼지 정하는 장부(10/29 보완).
        # SYN만 보낸 출발지는 주소를 위조했을 수 있어 "확인 안 됨"으로 두고(오래 쉰 순서로 보관),
        # SYN 없는 ACK 패킷까지 보낸 출발지는 "확인됨"으로 올려 상한이 차도 밀려나지 않게 한다.
        self._unconfirmed: OrderedDict[str, None] = OrderedDict()
        self._confirmed: set[str] = set()
        self._evicted_count = 0

        # 출발지와 상관없이 최근 1초의 SYN을 (시각, 출발지)로 보관하고, 출발지 수는 Counter로 센다.
        # 위조 출발지 SYN Flood는 출발지별 기준에 걸리지 않으므로 이 합계로만 보인다.
        self._global_syn: deque[tuple[float, str]] = deque()
        self._global_sources: Counter[str] = Counter()

        # 생존 줄(guide57)에 싣는 누적 숫자. observe·observe_foreign이 받은 패킷 수다.
        self.packets_seen = 0

        # 위조 출발지 10초 고정 창(guide57). 패킷마다 시각을 보관하면 초당 수만 개의 위조 폭주에서 메모리가
        # 커지므로 개수만 세고, 서로 다른 출발지는 max_sources까지만 담는다(넘으면 "이상"으로 표시).
        self.foreign_packets_threshold = foreign_packets_threshold
        self._foreign_window_start: float | None = None
        self._foreign_count = 0
        self._foreign_sources: set[str] = set()
        self._foreign_last_src = ""

    @property
    def sources_tracked(self) -> int:
        """지금 출발지별 판정에 기록 중인 출발지 수(생존 줄용)."""
        return len(self._port_events)

    @property
    def evicted_count(self) -> int:
        """출발지 상한 때문에 지금까지 밀어낸 출발지 수(생존 줄용)."""
        return self._evicted_count

    def is_foreign_source(self, src_ip: str) -> bool:
        """edge 대역 밖이고 core 대역도 아닌 출발지인지 — 이 PC의 edge로 들어왔다면 위조 주소다."""
        if self.edge_network is None:
            return False
        try:
            address = ipaddress.ip_address(src_ip)
        except ValueError:
            return False
        return address not in self.edge_network and address not in CORE_NETWORK

    def observe_foreign(self, src_ip: str) -> list[dict]:
        """edge 대역 밖 출발지 패킷 하나를 반영하고, 10초 창의 기준을 넘으면 SPOOFED_SRC 경보를 낸다.

        창이 끝나기 전에 기준을 넘으면 바로 내보내 알림이 늦지 않게 하고, 같은 경보는 cooldown마다 한 번만
        낸다. src_ip에는 마지막으로 본 위조 주소 하나를 싣는다(계약서 K4 — 실제 발신자가 아님).
        """
        now = float(self.clock())
        self.packets_seen += 1
        if not self.is_foreign_source(src_ip):
            return []

        if (
            self._foreign_window_start is None
            or now - self._foreign_window_start >= FOREIGN_WINDOW_SECONDS
        ):
            self._foreign_window_start = now
            self._foreign_count = 0
            self._foreign_sources = set()

        self._foreign_count += 1
        self._foreign_last_src = src_ip
        if len(self._foreign_sources) < self.max_sources:
            self._foreign_sources.add(src_ip)

        if self._foreign_count < self.foreign_packets_threshold:
            return []
        if not self._can_emit(GLOBAL_KEY, "SPOOFED_SRC", now):
            return []
        self._last_emitted[(GLOBAL_KEY, "SPOOFED_SRC")] = now
        return [{
            "timestamp": utc_timestamp(now),
            "src_ip": self._foreign_last_src,
            "category": "SPOOFED_SRC",
            "packets": self._foreign_count,
            "distinct_sources": len(self._foreign_sources),
        }]

    def _is_excluded_source(self, src_ip: str) -> bool:
        """Gateway 자신과 core 대역의 패킷인지 확인한다."""
        try:
            address = ipaddress.ip_address(src_ip)
        except ValueError:
            return True

        if address in CORE_NETWORK:
            return True

        return self.gateway_ip is not None and address == self.gateway_ip

    def _forget_source(self, src_ip: str) -> None:
        """출발지 기록이 모두 사라졌을 때 확인 여부 장부에서도 뺀다(장부가 끝없이 커지지 않게)."""
        self._unconfirmed.pop(src_ip, None)
        self._confirmed.discard(src_ip)

    def _evict_unconfirmed(self) -> bool:
        """가장 오래 쉰 "확인 안 됨" 출발지 하나를 내보낸다. 내보낼 출발지가 없으면 False.

        새 출발지를 무조건 버리면, 위조 출발지로 상한을 먼저 채운 공격자가 그 뒤의 진짜 공격자를
        출발지별 판정(포트 스캔 포함)에서 숨겨 줄 수 있다. 그래서 위조일 수 있는 쪽을 밀어낸다.
        지금 활발한 출발지는 매 패킷마다 장부 맨 뒤로 가므로 오래 쉰 것부터 나간다.
        """
        if not self._unconfirmed:
            return False
        victim, _ = self._unconfirmed.popitem(last=False)
        self._port_events.pop(victim, None)
        self._syn_events.pop(victim, None)
        self._evicted_count += 1
        return True

    def _prune_source(self, src_ip: str, now: float) -> None:
        """현재 패킷 출발지 한 곳의 오래된 기록만 지운다. 출발지별 숫자를 매번 정확하게 유지한다."""
        timestamps = self._syn_events.get(src_ip)
        if timestamps is not None:
            syn_cutoff = now - SYN_WINDOW_SECONDS
            while timestamps and timestamps[0] <= syn_cutoff:
                timestamps.popleft()
            if not timestamps:
                del self._syn_events[src_ip]

        ports = self._port_events.get(src_ip)
        if ports is not None:
            port_cutoff = now - self.window_seconds
            for port in [p for p, last_seen in ports.items() if last_seen <= port_cutoff]:
                del ports[port]
            if not ports:
                del self._port_events[src_ip]
                self._forget_source(src_ip)

    def _prune_global(self, now: float) -> None:
        """전체 SYN 기록에서 1초가 지난 것을 지운다. 앞에서부터 빼므로 패킷당 평균 O(1)이다."""
        cutoff = now - SYN_WINDOW_SECONDS
        while self._global_syn and self._global_syn[0][0] <= cutoff:
            _, src_ip = self._global_syn.popleft()
            self._global_sources[src_ip] -= 1
            if self._global_sources[src_ip] <= 0:
                del self._global_sources[src_ip]

    def _maybe_prune(self, now: float) -> None:
        """전체 정리는 PRUNE_INTERVAL_SECONDS에 한 번만 한다."""
        if (
            self._last_prune is not None
            and now - self._last_prune < PRUNE_INTERVAL_SECONDS
        ):
            return
        self._last_prune = now
        self._prune(now)

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
                self._forget_source(src_ip)

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

    def _check_global(self, now: float) -> None:
        """전체 SYN 비율이 기준 이상이면 cooldown마다 한 번 on_global_alert로 넘긴다."""
        syn_per_sec = len(self._global_syn)
        if syn_per_sec < self.global_syn_threshold_per_sec:
            return
        if not self._can_emit(GLOBAL_KEY, "GLOBAL_SYN_FLOOD", now):
            return
        self._last_emitted[(GLOBAL_KEY, "GLOBAL_SYN_FLOOD")] = now
        self.on_global_alert({
            "timestamp": utc_timestamp(now),
            "category": "GLOBAL_SYN_FLOOD",
            "syn_per_sec": syn_per_sec,
            "distinct_sources": len(self._global_sources),
            "threshold": self.global_syn_threshold_per_sec,
        })

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
        self.packets_seen += 1
        self._maybe_prune(now)

        if self._is_excluded_source(src_ip):
            return []

        if not isinstance(dst_port, int) or not 0 <= dst_port <= 65535:
            return []

        is_syn = has_syn_without_ack(flags)
        if is_syn:
            # 출발지 상한과 상관없이 전체 합계에는 항상 넣는다 — 위조 출발지 폭주를 보는 유일한 숫자다.
            self._prune_global(now)
            self._global_syn.append((now, src_ip))
            self._global_sources[src_ip] += 1
            self._check_global(now)

        self._prune_source(src_ip, now)

        if src_ip not in self._port_events and len(self._port_events) >= self.max_sources:
            # 확인 안 된(SYN만 본) 출발지를 하나 내보내고 자리를 만든다. 이미 추적 중인 활발한 공격자는
            # 오래 쉰 순서에서 뒤라 밀려나지 않는다. 내보낼 출발지가 없을 때(전부 확인됨)만 새 출발지를 버린다.
            if not self._evict_unconfirmed():
                if self._can_emit(GLOBAL_KEY, "SOURCE_LIMIT", now):
                    self._last_emitted[(GLOBAL_KEY, "SOURCE_LIMIT")] = now
                    self.on_warning(
                        f"기록 중인 출발지가 모두 확인된 출발지로 상한 {self.max_sources:,}곳에 도달해 "
                        "새 출발지는 출발지별 판정에서 빠집니다(전체 SYN 합계에는 포함)."
                    )
                return []
            if self._can_emit(GLOBAL_KEY, "SOURCE_EVICT", now):
                self._last_emitted[(GLOBAL_KEY, "SOURCE_EVICT")] = now
                self.on_warning(
                    f"기록 중인 출발지가 상한 {self.max_sources:,}곳에 도달해 확인 안 된 출발지를 "
                    f"밀어냅니다(누적 {self._evicted_count:,}곳). 출발지 위조 폭주일 수 있습니다."
                )

        if has_ack_without_syn(flags):
            # SYN 뒤 handshake 응답을 받아야 보낼 수 있는 패킷이라 단순 SYN 위조보다 믿을 만하다.
            self._unconfirmed.pop(src_ip, None)
            self._confirmed.add(src_ip)
        elif src_ip not in self._confirmed:
            self._unconfirmed[src_ip] = None
            self._unconfirmed.move_to_end(src_ip)

        ports = self._port_events.setdefault(src_ip, {})
        ports[dst_port] = now

        if is_syn:
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