# ============================================================================
# tests/track_d/test_a_shipper.py
#
# A1-3 shipper의 순수 Python 로직을 검증한다.
# 실제 네트워크, Supabase, Docker는 사용하지 않는다.
# ============================================================================

import importlib.util
import json
import re
from pathlib import Path
from types import SimpleNamespace
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SHIPPER_PATH = (
    PROJECT_ROOT
    / "netwatch"
    / "shipper"
    / "eve_shipper.py"
)

SPEC = importlib.util.spec_from_file_location(
    "eve_shipper",
    SHIPPER_PATH,
)
assert SPEC is not None
assert SPEC.loader is not None

shipper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shipper)


def suricata_alert(
    signature_id: int,
    *,
    classtype: str = "misc-activity",
) -> dict:
    """테스트용 Suricata alert 한 줄을 만든다."""
    return {
        "timestamp": "2026-10-20T03:12:44.120Z",
        "event_type": "alert",
        "src_ip": "172.28.11.101",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {
            "signature_id": signature_id,
            "signature": f"test signature {signature_id}",
            "severity": 1,
            "category": classtype,
        },
    }


def scapy_event(category: str) -> dict:
    """테스트용 l4.json 한 줄을 만든다."""
    event = {
        "timestamp": "2026-10-20T03:12:44.120Z",
        "src_ip": "172.28.11.102",
        "dst_port": 8080,
        "proto": "TCP",
        "category": category,
    }

    if category == "SYN_FLOOD":
        event["syn_per_sec"] = 143
    else:
        event["distinct_ports_10s"] = 18

    return event


def test_sign_headers_matches_contract_vector(
    signed_headers,
) -> None:
    """계약서 K3의 고정 HMAC 예시와 일치해야 한다."""
    body = b'{"a":1}'
    now = 1760930000

    headers = shipper.sign_headers(
        "test-key",
        body,
        now,
    )

    assert headers == signed_headers(
        "shipper",
        "test-key",
        body,
        timestamp=str(now),
    )

    assert headers["X-LW-Signature"] == (
        "2f744cec328f65506df5ad72df7fdd688"
        "c7a3cf3c6f90b1e0085849106179de2"
    )


def test_sign_matches_route_implementation_when_available() -> None:
    """B0-1 구현이 합쳐졌다면 앱의 sign()과도 비교한다."""
    from routes.internal._hmac import sign

    body = b'{"a":1}'
    timestamp = "1760930000"

    try:
        expected = sign(
            "test-key",
            timestamp,
            body,
        )
    except NotImplementedError:
        pytest.skip("B0-1 sign()이 아직 구현되지 않음")

    actual = shipper.sign_headers(
        "test-key",
        body,
        int(timestamp),
    )["X-LW-Signature"]

    assert actual == expected


@pytest.mark.parametrize(
    (
        "signature_id",
        "classtype",
        "expected_category",
        "expected_layer",
    ),
    [
        (9000001, "misc-activity", "SYN_FLOOD", "L4"),
        (9000003, "misc-activity", "LOGIN_BURST", "L7"),
        (9000004, "misc-activity", "SCANNER_UA", "L7"),
        (
            1234567,
            "web-application-attack",
            "WEB_ATTACK",
            "L7",
        ),
        (7654321, "misc-activity", "OTHER", "L4"),
    ],
)
def test_to_event_maps_suricata_alerts(
    signature_id: int,
    classtype: str,
    expected_category: str,
    expected_layer: str,
) -> None:
    """Suricata 경보를 계약서 K4 분류표대로 변환한다."""
    event = shipper.to_event(
        suricata_alert(
            signature_id,
            classtype=classtype,
        ),
        "suricata",
    )

    assert event is not None
    assert event["sensor"] == "suricata"
    assert event["signature_id"] == signature_id
    assert event["category"] == expected_category
    assert event["layer"] == expected_layer
    assert event["src_ip"] == "172.28.11.101"
    assert event["dst_port"] == 8080
    assert event["packet_count"] == 1
    assert event["observed_at"].endswith("Z")


def test_to_event_ignores_non_alert_eve_line() -> None:
    """flow·http 등 Suricata 비경보 행은 무시한다."""
    line = {
        "timestamp": "2026-10-20T03:12:44.120Z",
        "event_type": "flow",
        "src_ip": "172.28.11.101",
    }

    assert shipper.to_event(line, "suricata") is None


def test_to_event_ignores_eve_stats_line() -> None:
    """Suricata 생존 신호용 stats 행은 경보로 보내지 않는다."""
    line = {
        "timestamp": "2026-10-20T03:12:44.120Z",
        "event_type": "stats",
        "stats": {"uptime": 60},
    }

    assert shipper.to_event(line, "suricata") is None


@pytest.mark.parametrize(
    ("category", "expected_id", "expected_count"),
    [
        ("SYN_FLOOD", 9100001, 143),
        ("PORT_SCAN", 9100002, 18),
    ],
)
def test_to_event_maps_l4_detector_lines(
    category: str,
    expected_id: int,
    expected_count: int,
) -> None:
    """Scapy 측정기 경보를 계약서 K4 형식으로 변환한다."""
    event = shipper.to_event(
        scapy_event(category),
        "scapy",
    )

    assert event is not None
    assert event["sensor"] == "scapy"
    assert event["layer"] == "L4"
    assert event["category"] == category
    assert event["signature_id"] == expected_id
    assert event["packet_count"] == expected_count


def test_window_start_and_event_id_format() -> None:
    """시각을 분 단위로 내리고 event_id를 64자 hex로 만든다."""
    event = shipper.to_event(
        suricata_alert(9000001),
        "suricata",
    )
    assert event is not None

    aggregator = shipper.Aggregator(
        clock=lambda: 1760930000.0,
    )

    outgoing = aggregator.add(event)

    assert len(outgoing) == 1

    body = outgoing[0]

    assert body["window_start"] == (
        "2026-10-20T03:12:00Z"
    )
    assert re.fullmatch(
        r"[0-9a-f]{64}",
        body["event_id"],
    )


def test_aggregator_sends_first_event_immediately() -> None:
    """같은 창의 첫 경보는 즉시 반환한다."""
    aggregator = shipper.Aggregator(
        clock=lambda: 1760930000.0,
    )
    event = shipper.to_event(
        suricata_alert(9000001),
        "suricata",
    )
    assert event is not None

    outgoing = aggregator.add(event)

    assert len(outgoing) == 1
    assert outgoing[0]["packet_count"] == 1


def test_aggregator_updates_same_window_on_tick() -> None:
    """같은 창의 추가 경보는 누적 후 창 종료 때 갱신한다."""
    current_time = [1760930000.0]

    aggregator = shipper.Aggregator(
        clock=lambda: current_time[0],
    )
    event = shipper.to_event(
        suricata_alert(9000001),
        "suricata",
    )
    assert event is not None

    first = aggregator.add(dict(event))
    second = aggregator.add(dict(event))

    assert len(first) == 1
    assert second == []

    first_id = first[0]["event_id"]

    # 경보의 창(03:12)이 끝난 이후로 이동한다.
    current_time[0] = 1792465981.0

    updates = aggregator.tick()

    assert len(updates) == 1
    assert updates[0]["packet_count"] == 2
    assert updates[0]["event_id"] == first_id


def test_tailer_reads_only_new_lines(tmp_path: Path) -> None:
    """최초에는 EOF로 이동하고 이후 추가된 줄만 읽는다."""
    path = tmp_path / "eve.json"
    path.write_text(
        '{"old": 1}\n',
        encoding="utf-8",
    )

    tailer = shipper.Tailer(path)

    assert tailer.read_lines() == []

    with path.open("a", encoding="utf-8") as file:
        file.write('{"new": 2}\n')

    lines = tailer.read_lines()

    assert len(lines) == 1
    assert json.loads(lines[0]) == {"new": 2}


def test_tailer_reads_from_start_after_truncation(
    tmp_path: Path,
) -> None:
    """파일 크기가 줄면 새 파일의 처음부터 다시 읽는다."""
    path = tmp_path / "eve.json"
    path.write_text(
        '{"old": "long contents"}\n',
        encoding="utf-8",
    )

    tailer = shipper.Tailer(path)
    assert tailer.read_lines() == []

    path.write_text(
        '{"reset": 1}\n',
        encoding="utf-8",
    )

    lines = tailer.read_lines()

    assert len(lines) == 1
    assert json.loads(lines[0]) == {"reset": 1}


def test_tailer_reads_recreated_file_from_start(
    tmp_path: Path,
) -> None:
    """inode가 달라진 재생성 파일은 처음부터 읽는다."""
    path = tmp_path / "eve.json"
    path.write_text(
        '{"old": 1}\n',
        encoding="utf-8",
    )

    tailer = shipper.Tailer(path)
    assert tailer.read_lines() == []

    path.unlink()
    path.write_text(
        '{"recreated": 2}\n',
        encoding="utf-8",
    )

    lines = tailer.read_lines()

    assert len(lines) == 1
    assert json.loads(lines[0]) == {"recreated": 2}

class FakeResponse:
    """Sender 테스트용 가짜 HTTP 응답."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeSession:
    """호출 기록과 준비된 응답을 반환하는 가짜 세션."""

    def __init__(
        self,
        results: list[FakeResponse | Exception],
    ) -> None:
        self.results = list(results)
        self.calls: list[dict] = []

    def post(
        self,
        url: str,
        *,
        data: bytes,
        headers: dict[str, str],
        timeout: float,
    ) -> FakeResponse:
        self.calls.append(
            {
                "url": url,
                "data": data,
                "headers": headers,
                "timeout": timeout,
            }
        )

        result = self.results.pop(0)

        if isinstance(result, Exception):
            raise result

        return result


def sample_body() -> dict:
    """Sender 테스트에 사용할 정상적인 K4 본문을 만든다."""
    event = shipper.to_event(
        suricata_alert(9000001),
        "suricata",
    )
    assert event is not None

    aggregator = shipper.Aggregator(
        clock=lambda: 1760930000.0,
    )
    return aggregator.add(event)[0]


def test_sender_retries_5xx_with_exponential_backoff() -> None:
    """5xx 응답은 1초·2초 간격으로 재시도한다."""
    session = FakeSession(
        [
            FakeResponse(500),
            FakeResponse(503),
            FakeResponse(200),
        ]
    )
    sleeps: list[float] = []

    sender = shipper.Sender(
        url="http://app:5000/api/internal/net-events",
        secret="test-key",
        session=session,
        clock=lambda: 1760930000.0,
        sleeper=sleeps.append,
    )

    result = sender._deliver(sample_body())

    assert result is True
    assert len(session.calls) == 3
    assert sleeps == [1, 2]


def test_sender_retries_connection_failure() -> None:
    """연결 실패도 재시도 대상으로 처리한다."""
    session = FakeSession(
        [
            ConnectionError("connection failed"),
            FakeResponse(200),
        ]
    )
    sleeps: list[float] = []

    sender = shipper.Sender(
        url="http://app:5000/api/internal/net-events",
        secret="test-key",
        session=session,
        clock=lambda: 1760930000.0,
        sleeper=sleeps.append,
    )

    result = sender._deliver(sample_body())

    assert result is True
    assert len(session.calls) == 2
    assert sleeps == [1]


def test_sender_does_not_retry_4xx() -> None:
    """4xx는 재시도해도 성공할 수 없으므로 즉시 중단한다."""
    session = FakeSession(
        [
            FakeResponse(400),
            FakeResponse(200),
        ]
    )
    sleeps: list[float] = []

    sender = shipper.Sender(
        url="http://app:5000/api/internal/net-events",
        secret="test-key",
        session=session,
        clock=lambda: 1760930000.0,
        sleeper=sleeps.append,
    )

    result = sender._deliver(sample_body())

    assert result is False
    assert len(session.calls) == 1
    assert sleeps == []


def test_sender_attaches_valid_hmac_headers() -> None:
    """전송된 원본 JSON 바이트와 HMAC 서명이 일치해야 한다."""
    session = FakeSession([FakeResponse(200)])

    sender = shipper.Sender(
        url="http://app:5000/api/internal/net-events",
        secret="test-key",
        session=session,
        clock=lambda: 1760930000.0,
        sleeper=lambda seconds: None,
    )

    assert sender._deliver(sample_body()) is True

    call = session.calls[0]
    headers = call["headers"]
    raw_body = call["data"]

    expected = shipper.sign_headers(
        "test-key",
        raw_body,
        1760930000.0,
    )

    assert headers["X-LW-Sender"] == "shipper"
    assert headers["X-LW-Timestamp"] == (
        expected["X-LW-Timestamp"]
    )
    assert headers["X-LW-Signature"] == (
        expected["X-LW-Signature"]
    )
    assert headers["Content-Type"] == "application/json"


def test_sender_queue_has_upper_limit() -> None:
    """가득 찬 대기열에는 추가 경보를 넣지 않는다."""
    session = FakeSession([FakeResponse(200)])

    sender = shipper.Sender(
        url="http://app:5000/api/internal/net-events",
        secret="test-key",
        session=session,
        clock=lambda: 1760930000.0,
        sleeper=lambda seconds: None,
        max_queue_size=1,
    )

    first = sender.send(sample_body())
    second = sender.send(sample_body())

    assert first is True
    assert second is False
    assert sender.queue_size == 1


def test_heartbeat_body_contains_required_detail() -> None:
    """heartbeat 본문은 계약서 K9의 shipper 형식을 따른다."""
    eve_tailer = SimpleNamespace(last_size=104857)
    l4_tailer = SimpleNamespace(last_size=2048)
    event_sender = SimpleNamespace(queue_size=3)

    body = shipper.heartbeat_body(
        eve_tailer=eve_tailer,
        l4_tailer=l4_tailer,
        event_sender=event_sender,
        stalled=True,
        stalled_seconds=125,
    )

    assert body == {
        "agent": "shipper",
        "stalled": True,
        "detail": {
            "eve_bytes": 104857,
            "l4_bytes": 2048,
            "queue": 3,
            "stalled_seconds": 125,
        },
    }

    assert len(
        json.dumps(body).encode("utf-8")
    ) <= 2048


def _compose_service_block(compose: str, name: str) -> str:
    """PyYAML 없이 compose 문자열에서 서비스 한 개의 블록만 잘라 낸다."""
    rest = compose.split(f"\n  {name}:\n", 1)[1]
    markers = (
        rest.find("\n  attacker-1:"),
        rest.find("\n  fw-agent:"),
        rest.find("\nnetworks:"),
        rest.find("\nvolumes:"),
    )
    end = min((i for i in markers if i != -1), default=len(rest))
    return rest[:end]


def test_compose_shipper_builds_from_own_folder() -> None:
    """shipper는 기본으로 켜지고, 루트 .dockerignore에 막히지 않는 빌드 컨텍스트를 쓴다."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    block = _compose_service_block(compose, "shipper")

    assert "profiles:" not in block
    # 루트 .dockerignore가 netwatch/를 빼므로 shipper 폴더 자체를 컨텍스트로 써야 빌드가 된다.
    assert "context: ./netwatch/shipper" in block
    assert "- eve:/var/log/suricata:ro" in block
    assert "NET_INGEST_SECRET: ${NET_INGEST_SECRET}" in block


def test_compose_fw_agent_runs_by_default_without_db_keys() -> None:
    """fw-agent는 기본으로 켜지고, DB 키 없이 필요한 변수만 받는다(계획 P6)."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    block = _compose_service_block(compose, "fw-agent")

    assert "profiles:" not in block
    assert "context: ./netwatch/fw_agent" in block
    assert "- NET_ADMIN" in block
    assert "NET_AGENT_SECRET: ${NET_AGENT_SECRET}" in block
    # .env 전체(env_file)를 넘기지 않는다 — NET_ADMIN 컨테이너에 DB 키 금지.
    assert "env_file" not in block


def test_compose_has_no_stale_core_subnet() -> None:
    """예전 core 대역 172.29는 Docker Desktop(WSL2) 내부 대역과 겹쳐 설정값으로 쓰지 않는다."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    # 주석(# …)으로 "왜 172.30으로 옮겼나"를 설명하는 줄은 허용하고, 실제 설정값에만 없어야 한다.
    config_lines = [
        line for line in compose.splitlines()
        if "172.29." in line and not line.lstrip().startswith("#")
    ]
    assert config_lines == []


def test_compose_passes_stall_seconds_to_shipper() -> None:
    """.env의 SHIPPER_STALL_SECONDS가 shipper 컨테이너까지 전달돼야 한다(기본 120)."""
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    block = _compose_service_block(compose, "shipper")

    assert "SHIPPER_STALL_SECONDS: ${SHIPPER_STALL_SECONDS:-120}" in block


class StallFakeClock:
    """StallWatch 테스트용으로 직접 진행할 수 있는 시계."""

    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_stall_watch_is_stalled_after_threshold() -> None:
    """두 파일이 기준 시간 동안 그대로면 정지로 판단한다."""
    clock = StallFakeClock()
    watch = shipper.StallWatch(
        clock=clock,
        threshold_seconds=120,
    )

    assert watch.observe(100, 20) == (False, 0)

    clock.advance(120)

    assert watch.observe(100, 20) == (True, 120)


def test_stall_watch_recovers_when_either_file_grows() -> None:
    """한 파일이라도 증가하면 정지 상태가 해제된다."""
    clock = StallFakeClock()
    watch = shipper.StallWatch(
        clock=clock,
        threshold_seconds=120,
    )

    watch.observe(100, 20)
    clock.advance(120)

    assert watch.observe(100, 20)[0] is True

    clock.advance(1)

    assert watch.observe(101, 20) == (False, 0)


def test_stall_watch_recovers_after_truncation() -> None:
    """로그 순환으로 파일이 작아지면 정상 상태로 돌아간다."""
    clock = StallFakeClock()
    watch = shipper.StallWatch(
        clock=clock,
        threshold_seconds=120,
    )

    watch.observe(1000, 200)
    clock.advance(120)

    assert watch.observe(1000, 200)[0] is True

    clock.advance(1)

    assert watch.observe(10, 200) == (False, 0)


def test_stall_watch_uses_most_recent_file_growth() -> None:
    """두 파일 중 한 파일이라도 최근에 증가했으면 정지가 아니다."""
    clock = StallFakeClock()
    watch = shipper.StallWatch(
        clock=clock,
        threshold_seconds=120,
    )

    watch.observe(100, 20)

    clock.advance(100)
    watch.observe(101, 20)

    clock.advance(30)

    stalled, stalled_seconds = watch.observe(101, 20)

    assert stalled is False
    assert stalled_seconds == 30


def test_stall_watch_missing_files_become_stalled() -> None:
    """센서가 처음부터 파일을 못 만들면(크기 0 그대로) 기준 시간 뒤 정지로 본다."""
    clock = StallFakeClock()
    watch = shipper.StallWatch(
        clock=clock,
        threshold_seconds=120,
    )

    # Tailer는 파일이 없으면 last_size를 0으로 둔다.
    assert watch.observe(0, 0) == (False, 0)

    clock.advance(119)
    assert watch.observe(0, 0) == (False, 119)

    clock.advance(1)
    assert watch.observe(0, 0) == (True, 120)


@pytest.mark.parametrize("value", ["abc", "0", "-5"])
def test_main_rejects_invalid_stall_seconds(
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SHIPPER_STALL_SECONDS가 숫자가 아니거나 0 이하면 시작하지 않고 2로 끝난다."""
    exit_code = shipper.main(
        environ={
            "NET_INGEST_URL": "http://app:5000/api/internal/net-events",
            "NET_INGEST_SECRET": "test-ingest-secret",
            "SHIPPER_STALL_SECONDS": value,
        },
    )

    assert exit_code == 2
    assert "SHIPPER_STALL_SECONDS" in capsys.readouterr().err
