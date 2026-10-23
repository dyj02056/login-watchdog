# ============================================================================
# scripts/net/measure_common.py — 탐지→차단 시간 측정(I2-2)이 쓰는 부품
#
# 측정 스크립트(measure_detect_to_block.py)에서 Docker·DB 없이 시험할 수 있는 부분만 모았다:
# 시각 읽기, 구간 계산, 목표 판정, 기다리기, 새 IP 고르기, 결과 표 한 줄, 공격 명령 찾기.
# 테스트(tests/track_d/test_i_measure.py)는 이 파일만 불러와 확인한다.
#
# scripts/net/의 다른 파일은 역할 C(C3-1 시나리오 점검) 담당이다. 이 파일과 measure_*만 통합 담당자 것이다.
# ============================================================================

import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

# 상위 계획서 2.8 성능 목표(밀리초). 발표에 쓰는 숫자라 여기 한 곳에만 둔다.
#   T0 network_events.observed_at   센서가 본 시각(그 IP의 첫 SYN_FLOOD)
#   T1 network_blocks.requested_at  앱이 "막아라"를 적은 시각(PENDING_APPLY)
#   T2 network_blocks.applied_at    fw-agent가 "막았음(APPLIED)"을 보고한 시각
GOAL_MS = {
    "t0_t1": 2000,  # 경보 → 차단 요청: shipper 첫 경보 즉시 전송 + 수집·상관분석
    "t1_t2": 2000,  # 차단 요청 → 적용: fw-agent 2초 폴링 + ack
    "t0_t2": 5000,  # 전체 탐지 → L4 차단
}

# 측정용 출발지 IP 범위(같은 /24 안의 .150~.199). 고정 공격 상자(.101~.103)와 겹치지 않는다.
# M1 수동 차단 예시(.150)처럼 이미 network_blocks에 오른 주소는 choose_fresh_ip가 알아서 건너뛴다.
MEASURE_IP_START = 150
MEASURE_IP_END = 199

# 공격 상자 실행 형식 — A2-1(10/27)이 머지되고 통합 담당자가 netwatch/README.md "공격 상자" 절에 옮긴 뒤,
# 그 README의 일회용 실행 형식을 **그대로** 여기에 옮긴다(새로 지어내지 않는다).
# 값이 None이면 측정하지 않고 SKIP한다. 자리표시: {ip} = 이번 실행의 새 출발지 IP, {prefix} = LW_EDGE_PREFIX.
# 시나리오마다 "동시에 띄울 명령 목록"이다 — S5b는 SYN 폭주와 HTTP 폭주를 함께 일으켜야 해서 둘이 된다.
# netwatch/README.md 7.3의 일회용 실행 형식을 그대로 옮긴 것. subprocess로 셸 없이 부른다.
#   - 이미지 이름 lw-attacker:latest, edge 네트워크 이름 lw_edge는 A2-1이 고정했다.
#   - {ip}는 이번 실행의 새 출발지(choose_fresh_ip), {prefix}는 LW_EDGE_PREFIX.
#   - synflood --count 3000·httpflood --requests 200은 S5·S5b 기대 결과(상위 계획서 2.9)에 맞춘 양이다.
#   - S5b는 같은 IP에서 SYN 폭주와 HTTP 폭주를 "동시에" 일으켜야 CR-02(다계층 폭주)가 묶인다 → 명령 두 개.
_ONESHOT = ["docker", "run", "--rm", "--network", "lw_edge", "--ip", "{ip}", "--cap-add", "NET_RAW",
            "-e", "TARGET_URL=http://{prefix}.10:8080", "lw-attacker:latest"]
ATTACK_COMMANDS: dict[str, list[list[str]] | None] = {
    "s5": [_ONESHOT + ["synflood", "--count", "3000"]],
    "s5b": [_ONESHOT + ["synflood", "--count", "3000"],
            _ONESHOT + ["httpflood", "--path", "/login", "--requests", "200"]],
}

# README에 일회용 실행 형식이 들어왔는지 판단하는 표시(A2-1 결정 1: edge 네트워크 이름을 lw_edge로 고정)
README_MARKER = "--network lw_edge"


def parse_ts(value: str | None) -> datetime | None:
    """DB가 돌려준 시각 문자열을 UTC datetime으로. "Z"·"+00:00"·소수점 자릿수가 달라도 읽는다.

    PostgREST는 "2026-10-20T03:12:44.12+00:00"처럼 소수점 자리를 줄여서 줄 때가 있고,
    shipper는 "…Z"로 보낸다. 둘 다 같은 시각으로 읽어야 구간이 맞는다.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # 시간대가 없으면 DB 기본(UTC)으로 본다
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ms(start: datetime | None, end: datetime | None) -> int | None:
    if start is None or end is None:
        return None
    return round((end - start).total_seconds() * 1000)


def compute_intervals(t0: str | None, t1: str | None, t2: str | None) -> dict[str, int | None]:
    """세 시각 문자열로 구간 3개(밀리초)를 만든다. 시각이 하나라도 없으면 그 구간은 None."""
    a, b, c = parse_ts(t0), parse_ts(t1), parse_ts(t2)
    return {"t0_t1": _ms(a, b), "t1_t2": _ms(b, c), "t0_t2": _ms(a, c)}


def judge(intervals: dict[str, int | None]) -> dict[str, bool]:
    """구간마다 목표 안인지. 값이 없으면(차단이 안 됨·기록 누락) 실패로 본다 — 못 잰 것은 통과가 아니다."""
    result = {key: (intervals.get(key) is not None and intervals[key] <= goal) for key, goal in GOAL_MS.items()}
    result["all"] = all(result[key] for key in GOAL_MS)
    return result


def wait_until(condition, timeout: float = 30.0, interval: float = 0.5, clock=time.monotonic, sleep=time.sleep):
    """condition()이 참 같은 값을 돌려줄 때까지 기다렸다가 그 값을 돌려준다. 시간이 다 되면 None.

    DB에 기록이 생기기를 기다릴 때 쓴다. 시계·sleep을 바꿔 끼울 수 있어서 테스트가 실제로 기다리지 않는다.
    """
    deadline = clock() + timeout
    while True:
        value = condition()
        if value:
            return value
        if clock() >= deadline:
            return None
        sleep(interval)


def choose_fresh_ip(prefix: str, used: set[str], start: int = MEASURE_IP_START, end: int = MEASURE_IP_END) -> str | None:
    """측정 범위에서 아직 쓰지 않은 IP 하나. 다 썼으면 None.

    같은 IP를 다시 쓰면 앞 실행의 차단이 남아 있고 "사건당 규칙당 1회" 때문에 플레이북이 다시 돌지 않아
    측정 자체가 되지 않는다. 그래서 network_blocks에 한 번이라도 오른 IP는 피한다.
    """
    for last in range(start, end + 1):
        ip = f"{prefix}.{last}"
        if ip not in used:
            return ip
    return None


def resolve_attack(scenario: str, readme_path: Path, commands: dict | None = None) -> tuple[list[list[str]] | None, str | None]:
    """이 시나리오의 공격 명령 목록과, 못 쓰면 SKIP 이유를 돌려준다.

    README에 일회용 실행 형식이 아직 없거나(A2-1 머지 전), 상수를 아직 옮기지 않았으면 측정하지 않는다.
    """
    table = ATTACK_COMMANDS if commands is None else commands
    if scenario not in table:
        return None, f"모르는 시나리오: {scenario}"
    try:
        readme = readme_path.read_text(encoding="utf-8")
    except OSError:
        readme = ""
    if README_MARKER not in readme:
        return None, "netwatch/README.md에 공격 상자 일회용 실행 형식이 없음 — SKIP (A2-1 머지 후 통합 담당자가 README에 옮기면 측정 가능)"
    cmds = table[scenario]
    if not cmds:
        return None, f"{scenario}의 공격 명령을 아직 README에서 옮기지 않음 — SKIP (measure_common.ATTACK_COMMANDS 채우기)"
    return cmds, None


def fill_command(template: list[str], ip: str, prefix: str) -> list[str]:
    """명령 틀의 {ip}·{prefix} 자리를 채운다. 셸을 거치지 않도록 목록 그대로 둔다."""
    return [part.replace("{ip}", ip).replace("{prefix}", prefix) for part in template]


def _cell(ms: int | None) -> str:
    return "-" if ms is None else f"{ms}"


def format_row(when: datetime, scenario: str, ip: str, intervals: dict[str, int | None], verdict: dict[str, bool], note: str = "") -> str:
    """docs/track-d/measurements.md 결과 표 한 줄(마크다운). 시각은 UTC로 적는다(DB 시각과 같은 기준)."""
    stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    mark = "통과" if verdict["all"] else "초과"
    clean_note = note.replace("|", "/").replace("\n", " ")
    return f"| {stamp} | {scenario.upper()} | {ip} | {_cell(intervals['t0_t1'])} | {_cell(intervals['t1_t2'])} | {_cell(intervals['t0_t2'])} | {mark} | {clean_note} |"


def summarize(values: list[int | None]) -> dict[str, float | int | None]:
    """잰 값들의 중앙값·최댓값(못 잰 값은 빼고 셈, 대신 몇 번 못 쟀는지 함께)."""
    measured = [v for v in values if v is not None]
    return {
        "median": statistics.median(measured) if measured else None,
        "max": max(measured) if measured else None,
        "missing": len(values) - len(measured),
    }
