"""Suricata·Scapy 로그를 내부 API 이벤트로 변환하는 shipper.

앱 코드를 import하지 않고 계약서 K3·K4 규칙을 독립적으로 구현한다.
외부 requests 라이브러리는 main() 안에서만 import하여 순수 로직 테스트가
requests 설치 없이도 실행되게 한다.

센서 정지 판단(A2-3): eve.json과 l4.json이 둘 다 SHIPPER_STALL_SECONDS(기본 120초)
넘게 늘지 않으면 heartbeat에 stalled=true를 담는다(앱이 Slack으로 알림).
- 한 파일만 보면 공격이 없을 때 l4.json이 원래 안 늘어나므로 두 파일을 함께 본다.
- 기본값을 120초로 둔 이유는 Suricata가 60초마다 stats를 쓰기 때문이다. 한 번 빠져도
  정지로 오판하지 않게 그 두 배로 잡았다. 값을 60초 이하로 낮추면 조용할 때 오판한다.
- 정지를 즉시 따로 보내지 않고 30초 heartbeat에 실어 보낸다. 알림 쿨다운은 앱이 맡는다.

파일별 정지(guide57): l4-detector가 60초마다 생존 줄을 쓰게 되어 l4.json도 조용할 때 는다.
그래서 위 "둘 다" 판정(stalled)은 그대로 두고, 파일마다 따로 멈춘 것을 stalled_sensors에 싣는다.
예전에는 Suricata의 60초 stats 때문에 eve.json이 늘 늘어 Scapy가 죽어도 알 수 없었다.
eve.json의 stats 줄에서 capture.kernel_packets·kernel_drops도 읽어 heartbeat에 증가분을 싣는다
(센서가 폭주를 따라가지 못해 패킷을 놓치는지 앱이 알 수 있게).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


# count_field는 packet_count에 옮길 l4.json 칸이다. layer·proto는 계약서 K4 표를 따른다.
# SPOOFED_SRC·GLOBAL_SYN_FLOOD(guide57)는 출발지가 가짜이거나 없으므로 signature에 서로 다른 출발지 수를 덧붙여
# 알림 한 통만 봐도 규모를 알 수 있게 한다.
SCAPY_SIGNATURES = {
    "SYN_FLOOD": {
        "signature_id": 9100001,
        "signature": "LW Scapy SYN flood suspected",
        "layer": "L4",
        "proto": "TCP",
        "count_field": "syn_per_sec",
    },
    "PORT_SCAN": {
        "signature_id": 9100002,
        "signature": "LW Scapy port scan suspected",
        "layer": "L4",
        "proto": "TCP",
        "count_field": "distinct_ports_10s",
    },
    "SPOOFED_SRC": {
        "signature_id": 9100003,
        "signature": "LW Scapy spoofed source outside edge subnet",
        "layer": "L3",
        "proto": None,
        "count_field": "packets",
    },
    "GLOBAL_SYN_FLOOD": {
        "signature_id": 9100004,
        "signature": "LW Scapy global SYN flood (rotating sources)",
        "layer": "L4",
        "proto": "TCP",
        "count_field": "syn_per_sec",
    },
}

SURICATA_SID_MAPPING = {
    9000001: ("SYN_FLOOD", "L4"),
    9000003: ("LOGIN_BURST", "L7"),
    9000004: ("SCANNER_UA", "L7"),
    # guide57 L3 경보 — local.rules의 ICMP echo 폭주 규칙.
    9000005: ("ICMP_FLOOD", "L3"),
}

# OTHER 경보의 계층을 프로토콜로 정한다(guide57, 계약서 K4). ICMP는 IP 계층(L3) 메시지다.
L3_PROTOCOLS = {"ICMP", "IPV6-ICMP"}

DEFAULT_EVE_PATH = "/var/log/suricata/eve.json"
DEFAULT_L4_PATH = "/var/log/suricata/l4.json"
DEFAULT_APP_INTERNAL_URL = "http://app:5000"

# 두 센서 파일이 모두 이 시간 동안 증가하지 않으면 정지로 판단한다.
# 일시적으로 트래픽이 없는 상황을 오인하지 않도록 기본값은 120초다.
DEFAULT_SHIPPER_STALL_SECONDS = 120

HEARTBEAT_INTERVAL_SECONDS = 30
POLL_INTERVAL_SECONDS = 0.2
MAX_QUEUE_SIZE = 1000
RETRY_DELAYS_SECONDS = (1, 2, 4, 8)
MAX_SEND_ATTEMPTS = 5


def utc_datetime(value: str | float | int) -> datetime:
    """ISO 8601 또는 유닉스 시각을 UTC datetime으로 바꾼다."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    text = str(value).strip()

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    parsed = datetime.fromisoformat(text)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def utc_iso(value: str | float | int) -> str:
    """UTC ISO 8601 문자열을 밀리초와 Z 접미사 형식으로 만든다."""
    return (
        utc_datetime(value)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def minute_window_start(value: str | float | int) -> str:
    """경보 시각을 해당 분의 정각으로 내린다."""
    window = utc_datetime(value).replace(
        second=0,
        microsecond=0,
    )
    return (
        window.isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def make_event_id(
    sensor: str,
    src_ip: str,
    category: str,
    signature_id: int,
    window_start: str,
) -> str:
    """계약서 K4 순서로 안정적인 64자 event_id를 만든다."""
    source = (
        f"{sensor}|{src_ip}|{category}|"
        f"{signature_id}|{window_start}"
    )
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def sign_headers(
    secret: str,
    body: bytes,
    now: float | int | Callable[[], float],
) -> dict[str, str]:
    """계약서 K3 규칙으로 shipper 요청 헤더를 만든다."""
    current = now() if callable(now) else now
    timestamp = str(int(current))
    message = timestamp.encode("ascii") + b"." + body
    signature = hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()

    return {
        "X-LW-Sender": "shipper",
        "X-LW-Timestamp": timestamp,
        "X-LW-Signature": signature,
    }


def normalized_classtype(alert: dict) -> str:
    """Suricata alert의 classtype 표현 차이를 정규화한다."""
    raw_value = (
        alert.get("classtype")
        or alert.get("category")
        or ""
    )
    return str(raw_value).strip().lower().replace(" ", "-")


def optional_int(value: object) -> int | None:
    """선택 정수 값을 안전하게 변환한다."""
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def to_event(
    line_dict: dict,
    source: str,
) -> dict | None:
    """eve.json 또는 l4.json 한 줄을 K4 전송 전 이벤트로 바꾼다."""
    normalized_source = source.strip().lower()

    if normalized_source in {"eve", "suricata"}:
        if line_dict.get("event_type") != "alert":
            return None

        alert = line_dict.get("alert")

        if not isinstance(alert, dict):
            return None

        signature_id = optional_int(
            alert.get("signature_id")
        )

        if signature_id is None or signature_id < 1:
            return None

        mapping = SURICATA_SID_MAPPING.get(signature_id)

        if mapping is not None:
            category, layer = mapping
        elif normalized_classtype(alert) == (
            "web-application-attack"
        ):
            category, layer = "WEB_ATTACK", "L7"
        else:
            proto_name = str(line_dict.get("proto") or "").upper()
            category = "OTHER"
            layer = "L3" if proto_name in L3_PROTOCOLS else "L4"

        observed_at = utc_iso(
            line_dict.get("timestamp", time.time())
        )
        severity = optional_int(alert.get("severity"))

        if severity not in (1, 2, 3):
            severity = None

        proto_value = line_dict.get("proto")
        proto = (
            str(proto_value).upper()
            if proto_value is not None
            else None
        )

        return {
            "sensor": "suricata",
            "layer": layer,
            "src_ip": str(line_dict.get("src_ip", "")),
            "dst_port": optional_int(
                line_dict.get(
                    "dest_port",
                    line_dict.get("dst_port"),
                )
            ),
            "proto": proto,
            "category": category,
            "signature_id": signature_id,
            "signature": str(
                alert.get("signature") or "Suricata alert"
            )[:200],
            "sensor_severity": severity,
            "packet_count": 1,
            "observed_at": observed_at,
        }

    if normalized_source in {"l4", "scapy"}:
        category = str(
            line_dict.get("category", "")
        ).upper()
        signature_info = SCAPY_SIGNATURES.get(category)

        if signature_info is None:
            return None

        packet_count = optional_int(
            line_dict.get(signature_info["count_field"])
        )

        if packet_count is None or packet_count < 1:
            packet_count = 1

        signature = signature_info["signature"]
        distinct_sources = optional_int(line_dict.get("distinct_sources"))
        if distinct_sources is not None:
            signature = f"{signature} (sources={distinct_sources})"

        return {
            "sensor": "scapy",
            "layer": signature_info["layer"],
            "src_ip": str(line_dict.get("src_ip", "")),
            "dst_port": None,
            "proto": signature_info["proto"],
            "category": category,
            "signature_id": signature_info["signature_id"],
            "signature": signature[:200],
            "sensor_severity": 1,
            "packet_count": packet_count,
            "observed_at": utc_iso(
                line_dict.get("timestamp", time.time())
            ),
        }

    return None


class Tailer:
    """파일 끝에서 시작해 이후 추가된 완성된 줄만 읽는다."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.position = 0
        self.inode: int | None = None
        self.last_size = 0
        self.initialized = False

    def read_lines(self) -> list[str]:
        """추가된 완성 줄을 읽고 잘림·재생성을 감지한다."""
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            if self.initialized:
                self.inode = None
                self.position = 0
                self.last_size = 0

            return []

        current_inode = int(stat.st_ino)
        current_size = int(stat.st_size)

        if not self.initialized:
            # 시작 전에 쌓인 로그는 재전송하지 않고 끝에서 대기한다.
            self.initialized = True
            self.inode = current_inode
            self.position = current_size
            self.last_size = current_size
            return []

        recreated = (
            self.inode is None
            or self.inode != current_inode
        )
        truncated = current_size < self.position

        if recreated or truncated:
            self.position = 0

        self.inode = current_inode
        self.last_size = current_size

        with self.path.open("rb") as file:
            # inode만으로는 재생성을 놓칠 수 있다: 리눅스는 unlink 직후 새로 만든 파일에
            # 같은 inode 번호를 다시 쓸 수 있어(Windows 로컬에서는 재현되지 않고 CI에서만 터진다)
            # recreated가 False가 되고, 옛 position에서 줄 중간부터 읽어 JSON이 깨진다.
            # 우리는 항상 줄 끝(\n)에서만 멈추므로, position 바로 앞 바이트가 \n이 아니면
            # 내용이 교체된 것으로 보고 처음부터 다시 읽는다(줄 경계로 재생성을 확인).
            if self.position > 0:
                if self.position > current_size:
                    self.position = 0
                else:
                    file.seek(self.position - 1)
                    if file.read(1) != b"\n":
                        self.position = 0

            file.seek(self.position)
            data = file.read()

        if not data:
            return []

        complete_bytes = 0
        complete_lines: list[str] = []

        for raw_line in data.splitlines(keepends=True):
            if not raw_line.endswith(b"\n"):
                break

            complete_bytes += len(raw_line)
            decoded = raw_line.decode(
                "utf-8",
                errors="replace",
            ).rstrip("\r\n")

            if decoded:
                complete_lines.append(decoded)

        self.position += complete_bytes
        return complete_lines


class StallWatch:
    """두 센서 출력 파일의 증가 여부로 센서 정지를 판단한다.

    eve.json과 l4.json이 모두 threshold_seconds 동안 증가하지
    않았을 때만 stalled가 된다.

    파일 크기가 감소한 경우에는 로그 순환 또는 파일 재생성으로
    간주하여 해당 파일이 다시 활동한 것으로 처리한다.
    """

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        threshold_seconds: float = DEFAULT_SHIPPER_STALL_SECONDS,
    ) -> None:
        if threshold_seconds <= 0:
            raise ValueError(
                "threshold_seconds는 0보다 커야 합니다."
            )

        self.clock = clock
        self.threshold_seconds = threshold_seconds

        self._last_sizes: dict[str, int] = {}
        self._last_change_times: dict[str, float] = {}

        self.stalled = False
        self.stalled_seconds = 0

    def observe(
        self,
        eve_bytes: int,
        l4_bytes: int,
    ) -> tuple[bool, int]:
        """현재 파일 크기를 반영하고 정지 상태와 정지 시간을 반환한다."""
        now = self.clock()

        current_sizes = {
            "eve": max(0, int(eve_bytes)),
            "l4": max(0, int(l4_bytes)),
        }

        for name, current_size in current_sizes.items():
            previous_size = self._last_sizes.get(name)

            # 첫 관찰, 파일 증가, 로그 순환·재생성에 따른 크기 감소를
            # 모두 해당 센서 파일의 활동으로 처리한다.
            if (
                previous_size is None
                or current_size != previous_size
            ):
                self._last_change_times[name] = now

            self._last_sizes[name] = current_size

        if len(self._last_change_times) < 2:
            self.stalled = False
            self.stalled_seconds = 0
            return self.stalled, self.stalled_seconds

        # 두 파일 중 더 최근에 바뀐 시각부터 두 파일 모두 멈춘 것이다.
        most_recent_change = max(
            self._last_change_times.values()
        )

        self.stalled_seconds = max(
            0,
            int(now - most_recent_change),
        )
        self.stalled = (
            self.stalled_seconds >= self.threshold_seconds
        )

        return self.stalled, self.stalled_seconds

    def stalled_sensors(self) -> list[str]:
        """파일마다 따로 기준 시간 넘게 늘지 않은 센서 이름("eve"·"l4")을 돌려준다(guide57).

        stalled는 두 파일이 모두 멈췄을 때만 참이다. l4-detector가 생존 줄을 쓰게 된 뒤로는 하나만
        멈춰도 그 센서가 죽은 것이므로, 앱이 어느 센서인지 알 수 있게 따로 계산한다.
        """
        if len(self._last_change_times) < 2:
            return []
        now = self.clock()
        return sorted(
            name
            for name, changed_at in self._last_change_times.items()
            if now - changed_at >= self.threshold_seconds
        )


class CaptureStats:
    """eve.json의 stats 줄에서 패킷 수신·누락 누적값을 읽고, heartbeat마다 증가분을 돌려준다(guide57).

    Suricata는 60초마다 누적값을 쓴다. heartbeat(30초)마다 직전에 보고한 값과의 차이를 싣고,
    누적값이 줄었으면(Suricata 재시작) 새 누적값을 그대로 증가분으로 본다.
    """

    def __init__(self) -> None:
        self.latest_packets = 0
        self.latest_drops = 0
        self._reported_packets = 0
        self._reported_drops = 0

    def observe(self, line_dict: dict) -> None:
        stats = line_dict.get("stats")
        capture = stats.get("capture") if isinstance(stats, dict) else None
        if not isinstance(capture, dict):
            return
        packets = optional_int(capture.get("kernel_packets"))
        drops = optional_int(capture.get("kernel_drops"))
        if packets is not None and packets >= 0:
            self.latest_packets = packets
        if drops is not None and drops >= 0:
            self.latest_drops = drops

    def take_delta(self) -> tuple[int, int]:
        def delta(latest: int, reported: int) -> int:
            return latest - reported if latest >= reported else latest

        result = (
            delta(self.latest_packets, self._reported_packets),
            delta(self.latest_drops, self._reported_drops),
        )
        self._reported_packets = self.latest_packets
        self._reported_drops = self.latest_drops
        return result


class Aggregator:
    """첫 경보는 즉시 보내고 같은 60초 창의 추가분을 누적한다."""

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.clock = clock
        self._windows: dict[tuple, dict] = {}

    def add(self, event: dict) -> list[dict]:
        """이벤트를 창에 추가하고 첫 건이면 즉시 반환한다."""
        body = dict(event)
        window_start = minute_window_start(
            body["observed_at"]
        )
        body["window_start"] = window_start
        body["event_id"] = make_event_id(
            body["sensor"],
            body["src_ip"],
            body["category"],
            int(body["signature_id"]),
            window_start,
        )

        key = (
            body["sensor"],
            body["src_ip"],
            body["category"],
            int(body["signature_id"]),
            window_start,
        )

        state = self._windows.get(key)

        if state is None:
            self._windows[key] = {
                "body": body,
                "dirty": False,
            }
            return [dict(body)]

        existing = state["body"]
        existing["packet_count"] += max(
            1,
            int(body.get("packet_count", 1)),
        )
        existing["observed_at"] = body["observed_at"]
        state["dirty"] = True
        return []

    def tick(self) -> list[dict]:
        """종료된 창의 누적 갱신 본문을 반환하고 상태를 제거한다."""
        now = utc_datetime(self.clock())
        updates: list[dict] = []

        for key, state in list(self._windows.items()):
            window_start = utc_datetime(key[-1])
            window_end = window_start.timestamp() + 60

            if now.timestamp() < window_end:
                continue

            if state["dirty"]:
                updates.append(dict(state["body"]))

            del self._windows[key]

        return updates

def _retry_after_seconds(response: Any) -> int | None:
    """429 응답의 Retry-After(초)를 읽는다. 없거나 이상하면 None, 너무 길면 60초로 자른다.

    앱(Flask-Limiter)은 기본 설정에서 이 헤더를 보내지 않지만, 보내게 바뀌면 그 값을 따르는 편이
    같은 창 안에서 헛되이 다시 보내지 않는다. 60초 상한은 한도 창(분당)보다 오래 붙잡지 않으려는 것이다.
    """
    headers = getattr(response, "headers", None) or {}
    try:
        value = int(headers.get("Retry-After"))
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return min(value, 60)


class Sender:
    """HTTP 전송을 별도 작업 스레드에서 처리하는 제한된 대기열."""

    def __init__(
        self,
        url: str,
        secret: str,
        session: object,
        clock: Callable[[], float] = time.time,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        max_queue_size: int = MAX_QUEUE_SIZE,
    ) -> None:
        self.url = url
        self.secret = secret
        self.session = session
        self.clock = clock
        self.sleeper = sleeper
        self.queue: queue.Queue[dict] = queue.Queue(
            maxsize=max_queue_size
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def queue_size(self) -> int:
        """현재 전송 대기 중인 본문 수를 반환한다."""
        return self.queue.qsize()

    def send(self, body: dict) -> bool:
        """본문을 대기열에 넣고, 가득 찼으면 버린 뒤 False를 반환한다."""
        try:
            self.queue.put_nowait(dict(body))
            return True
        except queue.Full:
            print(
                "[WARN] shipper 전송 대기열이 가득 차 "
                "새 이벤트를 버립니다.",
                file=sys.stderr,
                flush=True,
            )
            return False

    def _deliver(self, body: dict) -> bool:
        """한 본문을 K3 서명과 함께 최대 5회 전송한다."""
        raw_body = json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        for attempt in range(MAX_SEND_ATTEMPTS):
            retry_after: int | None = None
            headers = sign_headers(
                self.secret,
                raw_body,
                self.clock,
            )
            headers["Content-Type"] = "application/json"
            try:
                response = self.session.post(
                    self.url,
                    data=raw_body,
                    headers=headers,
                    timeout=5,
                )
                status_code = int(response.status_code)

                if 200 <= status_code < 300:
                    return True

                # 429는 "형식이 틀림"이 아니라 "지금 바쁨"이다. 다른 4xx처럼 바로 버리면 한도에 걸린
                # 공격 경보가 영영 앱에 닿지 않으므로(10/26 강사 피드백 1), 5xx처럼 물러났다가 다시 보낸다.
                # 서명은 매 시도마다 새 시각으로 다시 만들므로 오래 기다려도 시각 오차에 걸리지 않는다.
                retry_after = _retry_after_seconds(response) if status_code == 429 else None

                if 400 <= status_code < 500 and status_code != 429:
                    print(
                        "[WARN] shipper 요청이 재시도할 수 없는 "
                        f"HTTP {status_code}로 거부됐습니다.",
                        file=sys.stderr,
                        flush=True,
                    )
                    return False

                retryable = status_code == 429 or 500 <= status_code < 600

                if not retryable:
                    print(
                        "[WARN] shipper 요청이 예상하지 못한 "
                        f"HTTP {status_code}를 받았습니다.",
                        file=sys.stderr,
                        flush=True,
                    )
                    return False

                error_text = f"HTTP {status_code}"

            except Exception as error:
                # requests 예외를 import하지 않고 연결 실패 전체를 재시도한다.
                error_text = type(error).__name__

            if attempt >= len(RETRY_DELAYS_SECONDS):
                print(
                    "[FAIL] shipper 전송을 최대 횟수까지 "
                    f"재시도했지만 실패했습니다: {error_text}",
                    file=sys.stderr,
                    flush=True,
                )
                return False

            delay = RETRY_DELAYS_SECONDS[attempt]
            if retry_after is not None:
                delay = max(delay, retry_after)
            print(
                "[WARN] shipper 전송 실패, "
                f"{delay}초 후 재시도합니다: {error_text}",
                file=sys.stderr,
                flush=True,
            )
            self.sleeper(delay)

        return False

    def process_one(self) -> bool | None:
        """테스트 또는 작업 스레드에서 대기열 한 건을 처리한다."""
        try:
            body = self.queue.get_nowait()
        except queue.Empty:
            return None

        try:
            return self._deliver(body)
        finally:
            self.queue.task_done()

    def _worker(self) -> None:
        """중단 요청 전까지 대기열을 계속 처리한다."""
        while (
            not self._stop_event.is_set()
            or not self.queue.empty()
        ):
            try:
                body = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self._deliver(body)
            except Exception as error:
                print(
                    "[FAIL] shipper 전송 작업 오류: "
                    f"{type(error).__name__}",
                    file=sys.stderr,
                    flush=True,
                )
            finally:
                self.queue.task_done()

    def start(self) -> None:
        """전송 작업 스레드를 한 번만 시작한다."""
        if self._thread is not None:
            return

        self._thread = threading.Thread(
            target=self._worker,
            name="shipper-sender",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """작업 스레드에 중단을 요청하고 잠시 기다린다."""
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(timeout=2)


def process_tailer(
    tailer: Tailer,
    source: str,
    aggregator: Aggregator,
    sender: Sender,
    capture_stats: CaptureStats | None = None,
) -> None:
    """Tailer의 새 JSON 줄을 변환·집계해 전송 대기열에 넣는다. stats 줄은 capture_stats에 반영한다."""
    for raw_line in tailer.read_lines():
        try:
            line_dict = json.loads(raw_line)
        except json.JSONDecodeError:
            print(
                f"[WARN] {source} 로그의 잘못된 JSON 줄을 건너뜁니다.",
                file=sys.stderr,
                flush=True,
            )
            continue

        if not isinstance(line_dict, dict):
            continue

        if capture_stats is not None and line_dict.get("event_type") == "stats":
            capture_stats.observe(line_dict)
            continue

        try:
            event = to_event(line_dict, source)
        except (KeyError, TypeError, ValueError) as error:
            print(
                f"[WARN] {source} 이벤트 변환 실패: "
                f"{type(error).__name__}",
                file=sys.stderr,
                flush=True,
            )
            continue

        if event is None:
            continue

        for body in aggregator.add(event):
            sender.send(body)


def heartbeat_body(
    eve_tailer: Tailer,
    l4_tailer: Tailer,
    event_sender: Sender,
    *,
    stalled: bool = False,
    stalled_seconds: int = 0,
    stalled_sensor_names: list[str] | None = None,
    kernel_delta: tuple[int, int] | None = None,
) -> dict:
    """계약서 K9의 shipper heartbeat 본문을 만든다.

    stalled_sensor_names·kernel_delta(guide57)는 넘긴 경우에만 detail에 싣는다 — 넘기지 않는 호출은
    예전 모양 그대로다.
    """
    detail: dict = {
        "eve_bytes": eve_tailer.last_size,
        "l4_bytes": l4_tailer.last_size,
        "queue": event_sender.queue_size,
        "stalled_seconds": max(
            0,
            int(stalled_seconds),
        ),
    }
    if stalled_sensor_names is not None:
        detail["stalled_sensors"] = list(stalled_sensor_names)
    if kernel_delta is not None:
        detail["kernel_packets"], detail["kernel_drops"] = kernel_delta
    return {
        "agent": "shipper",
        "stalled": stalled,
        "detail": detail,
    }


def main(
    *,
    environ: dict[str, str] | None = None,
    clock: Callable[[], float] = time.time,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    """두 센서 로그를 tail하고 이벤트와 heartbeat를 전송한다."""
    active_environ = (
        os.environ
        if environ is None
        else environ
    )

    ingest_url = active_environ.get(
        "NET_INGEST_URL",
        "",
    ).strip()
    ingest_secret = active_environ.get(
        "NET_INGEST_SECRET",
        "",
    ).strip()

    if not ingest_url:
        print(
            "[FAIL] NET_INGEST_URL이 없어 shipper를 시작하지 않습니다.",
            file=sys.stderr,
        )
        return 2

    if not ingest_secret:
        print(
            "[FAIL] NET_INGEST_SECRET이 없어 shipper를 시작하지 않습니다.",
            file=sys.stderr,
        )
        return 2

    app_internal_url = active_environ.get(
        "APP_INTERNAL_URL",
        DEFAULT_APP_INTERNAL_URL,
    ).rstrip("/")
    heartbeat_url = (
        f"{app_internal_url}/api/internal/heartbeat"
    )

    eve_path = active_environ.get(
        "EVE_PATH",
        DEFAULT_EVE_PATH,
    )
    l4_path = active_environ.get(
        "L4_PATH",
        DEFAULT_L4_PATH,
    )
    try:
        stall_seconds = float(
            active_environ.get(
                "SHIPPER_STALL_SECONDS",
                str(DEFAULT_SHIPPER_STALL_SECONDS),
            )
        )
    except ValueError:
        print(
            "[FAIL] SHIPPER_STALL_SECONDS는 숫자여야 합니다.",
            file=sys.stderr,
        )
        return 2

    if stall_seconds <= 0:
        print(
            "[FAIL] SHIPPER_STALL_SECONDS는 0보다 커야 합니다.",
            file=sys.stderr,
        )
        return 2

    # requests는 컨테이너 실행 시에만 필요하다.
    import requests

    eve_tailer = Tailer(eve_path)
    l4_tailer = Tailer(l4_path)
    aggregator = Aggregator(clock)
    capture_stats = CaptureStats()
    stall_watch = StallWatch(
        clock=clock,
        threshold_seconds=stall_seconds,
    )

    event_sender = Sender(
        ingest_url,
        ingest_secret,
        requests.Session(),
        clock,
        sleeper=sleeper,
    )
    heartbeat_sender = Sender(
        heartbeat_url,
        ingest_secret,
        requests.Session(),
        clock,
        sleeper=sleeper,
        max_queue_size=10,
    )

    event_sender.start()
    heartbeat_sender.start()

    last_heartbeat = clock()

    print(
        "[*] shipper를 시작합니다: "
        f"eve={eve_path}, l4={l4_path}",
        flush=True,
    )

    try:
        while True:
            try:
                process_tailer(
                    eve_tailer,
                    "eve",
                    aggregator,
                    event_sender,
                    capture_stats,
                )
                process_tailer(
                    l4_tailer,
                    "l4",
                    aggregator,
                    event_sender,
                )
                previous_stalled = stall_watch.stalled

                stalled, stalled_seconds = stall_watch.observe(
                    eve_bytes=eve_tailer.last_size,
                    l4_bytes=l4_tailer.last_size,
                )

                if stalled != previous_stalled:
                    if stalled:
                        print(
                            "[WARN] 두 센서 출력이 "
                            f"{stalled_seconds}초 동안 증가하지 않아 "
                            "정지 상태로 판단합니다.",
                            file=sys.stderr,
                            flush=True,
                        )
                    else:
                        print(
                            "[OK] 센서 출력 증가를 확인하여 "
                            "정지 상태가 해제되었습니다.",
                            flush=True,
                        )

                for body in aggregator.tick():
                    event_sender.send(body)

                now = clock()

                if (
                    now - last_heartbeat
                    >= HEARTBEAT_INTERVAL_SECONDS
                ):
                    heartbeat_sender.send(
                        heartbeat_body(
                            eve_tailer,
                            l4_tailer,
                            event_sender,
                            stalled=stall_watch.stalled,
                            stalled_seconds=(
                                stall_watch.stalled_seconds
                            ),
                            stalled_sensor_names=stall_watch.stalled_sensors(),
                            kernel_delta=capture_stats.take_delta(),
                        )
                    )
                    last_heartbeat = now

            except Exception as error:
                print(
                    "[WARN] shipper 루프 오류를 건너뜁니다: "
                    f"{type(error).__name__}",
                    file=sys.stderr,
                    flush=True,
                )

            sleeper(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print(
            "\n[중단] shipper를 종료합니다.",
            file=sys.stderr,
        )
        return 0

    finally:
        event_sender.stop()
        heartbeat_sender.stop()


if __name__ == "__main__":
    raise SystemExit(main())