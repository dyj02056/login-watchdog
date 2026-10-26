# ============================================================================
# scripts/net/check_common.py — 시연 시나리오 자동 점검(C3-1)이 쓰는 공용 부품
#
# 각 시나리오(check_s4·s5·s5b·s6·s8)와 run_all이 함께 쓰는 조각을 모았다:
#   - 시작 전 확인 출력(preflight)
#   - 읽기 전용 DB 조회(db.get_client()로 select만 — 이 스크립트는 DB에 쓰지 않는다)
#   - 기다리기(wait_until, 최대 30초·1초 간격)
#   - 실행마다 새 출발지 IP 고르기(choose_fresh_ip)
#   - 재현 명령 상수(netwatch/README.md 7.3의 "일회용 새 IP 실행" 형식을 그대로 옮긴 것)
#   - Mailpit 조회, 결과 표 한 줄 만들기
#
# 이 파일은 직접 실행하지 않는다(부품 모음). 실행 방법은 run_all.py·check_s*.py의 docstring 참고.
# scripts/net/measure_* 는 통합 담당자(I2-2) 것이라 읽지도 고치지도 않는다.
# ============================================================================

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
import urllib.parse
import urllib.request
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# .env를 먼저 읽어야 SUPABASE_URL·KEY·LW_EDGE_PREFIX가 잡힌다(measure_* 와 같은 방식).
from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

README = ROOT / "netwatch" / "README.md"
RESULTS = ROOT / "docs" / "track-d" / "scenario-results.md"

# 단지에서 함께 켜져 있어야 하는 서비스(README 3장). 상태만 보여 주고, 멈추지는 않는다.
REQUIRED_SERVICES = ("gateway", "app", "mailpit", "sensor", "l4-detector", "shipper", "fw-agent")

# 이 점검이 쓰는 새 출발지 IP 범위(.111~.139). 다른 용도와 겹치지 않게 범위를 나눠 둔다:
#   .1 내 브라우저 / .10 gateway / .101~.103 고정 상자 / .140 S7 위조 전용 /
#   .150~.199 통합 담당자의 5초 측정(measure_*)·M1 수동 차단 예시.
# 같은 IP를 다시 쓰면 앞 시나리오의 차단과 "사건당 규칙당 1회"에 막혀 재현이 안 되므로
# network_blocks와 security_incidents(닫힌 사건 포함)에 아직 없는 주소만 고른다.
CHECK_IP_START = 111
CHECK_IP_END = 139

# S6 login이 쓰는 테스트 계정. 시연 대역 PC에서 C3-1을 돌릴 때는 victim_c를 쓴다(README 7.4).
VICTIM_USERNAME = "victim_c"

# S8 전용: gateway를 거치지 않는 요청이라 공격 상자로는 보낼 수 없다(공격 상자는 edge에만 붙어 있다).
# core 네트워크에 붙은 shipper 안에서 보낸다. 경로는 실행마다 달라야 그 요청의 행만 찾을 수 있다.
S8_PATH_PREFIX = "/lw-check-s8-"

# ── 재현 명령 상수 (netwatch/README.md 7.3 "일회용 새 IP 실행" 형식을 그대로 옮긴 것) ──
# 재현 명령은 새로 만들지 않는다. README에 적힌 docker run 형식을 상수로만 옮겨 subprocess로 부른다.
# 자리표시: {ip} = 이번 실행의 새 출발지 IP, {prefix} = LW_EDGE_PREFIX.
#   - 이미지 lw-attacker:latest, edge 네트워크 이름 lw_edge는 A가 고정했다.
_ONESHOT = ["docker", "run", "--rm", "--network", "lw_edge", "--ip", "{ip}", "--cap-add", "NET_RAW",
            "-e", "TARGET_URL=http://{prefix}.10:8080", "lw-attacker:latest"]

# S6 login 명령: victim 계정으로 올바른 비밀번호 로그인 1회.
# 비밀번호 값을 argv에 적지 않으려고 `-e LW_VICTIM_PASSWORD`(값 없이)로 현재 셸의 환경 변수를
# 그대로 컨테이너에 넘긴다. 값은 코드·로그 어디에도 남지 않는다(README 7.4).
_LOGIN = ["docker", "run", "--rm", "--network", "lw_edge", "--ip", "{ip}", "--cap-add", "NET_RAW",
          "-e", "TARGET_URL=http://{prefix}.10:8080", "-e", "LW_VICTIM_PASSWORD",
          "lw-attacker:latest", "login", "--username", VICTIM_USERNAME]

# S5b: SYN 폭주와 HTTP 폭주를 "같은 IP에서 동시에" 보내야 CR-02(다계층 폭주)로 묶인다.
# 같은 네트워크에서 두 컨테이너가 같은 --ip를 잡을 수는 없으므로(두 번째가 Address already in use로 죽음),
# IP만 쥐고 기다리는 자리 잡기 컨테이너를 먼저 띄우고 공격 두 개는 --network container:로 그 망을 함께 쓴다.
# (README 7.3 "S5b" 절의 방식. 이름은 측정용 lw-measure-* 와 겹치지 않게 lw-check-* 로 둔다.)
_ANCHOR = ["docker", "run", "-d", "--rm", "--name", "lw-check-{ip}", "--network", "lw_edge", "--ip", "{ip}",
           "--entrypoint", "sleep", "lw-attacker:latest", "300"]
_ANCHOR_REMOVE = ["docker", "rm", "-f", "lw-check-{ip}"]
_SHARED = ["docker", "run", "--rm", "--network", "container:lw-check-{ip}", "--cap-add", "NET_RAW",
           "-e", "TARGET_URL=http://{prefix}.10:8080", "lw-attacker:latest"]

# 시나리오별 공격 명령 틀. S8은 shipper 안에서 직접 보내므로 여기 없다(check_s8 참고).
SCAN = _ONESHOT + ["scan"]
WEBSCAN = _ONESHOT + ["webscan"]
# brute는 --username을 주지 않아 lw.py 기본값(nonexistent-user)을 쓴다. CR-01에는 IP 기준 실패
# (FAILURE_THRESHOLD 5)만 있으면 되고, victim 계정으로 실패를 쌓으면 계정 잠금(ACCOUNT_FAILURE_THRESHOLD 8)에
# 걸려 S6 로그인이 CR-03이 아닌 이유로 막힐 수 있기 때문이다.
BRUTE = _ONESHOT + ["brute", "--attempts", "6"]
SCANNER_UA = _ONESHOT + ["scanner-ua"]
LOGIN = list(_LOGIN)
SYNFLOOD = _ONESHOT + ["synflood", "--count", "3000"]
S5B_ANCHOR = list(_ANCHOR)
S5B_ANCHOR_REMOVE = list(_ANCHOR_REMOVE)
S5B_SYNFLOOD = _SHARED + ["synflood", "--count", "3000"]
S5B_HTTPFLOOD = _SHARED + ["httpflood", "--path", "/login", "--requests", "200"]

# 기다리는 한도(초). 재현 결과가 DB에 반영될 때까지 넉넉히 기다린다.
WAIT_SECONDS = 30
WAIT_INTERVAL = 1.0

# 점검 한 건의 결과. status는 PASS / FAIL / SKIP.
CheckResult = namedtuple("CheckResult", "scenario status reason ip")


def fill(template: list[str], ip: str, prefix: str) -> list[str]:
    """명령 틀의 {ip}·{prefix} 자리를 채운다. 셸을 거치지 않도록 목록 그대로 둔다."""
    return [part.replace("{ip}", ip).replace("{prefix}", prefix) for part in template]


def wait_until(condition, timeout: float = WAIT_SECONDS, interval: float = WAIT_INTERVAL,
               clock=time.monotonic, sleep=time.sleep):
    """condition()이 참 같은 값을 돌려줄 때까지 기다렸다가 그 값을 돌려준다. 시간이 다 되면 None.

    센서→shipper→DB를 거쳐 몇 초 늦게 기록되는 결과(경보·차단·플레이북 실행)를 기다릴 때 쓴다.
    시계·sleep을 바꿔 끼울 수 있게 두어, 혹시 테스트가 생겨도 실제로 기다리지 않게 한다.
    """
    deadline = clock() + timeout
    while True:
        value = condition()
        if value:
            return value
        if clock() >= deadline:
            return None
        sleep(interval)


def get_reader():
    """읽기 전용 Supabase 클라이언트. db는 .env를 읽은 뒤에 불러야 URL·KEY가 잡힌다."""
    import db  # noqa: E402  (load_dotenv 뒤에 늦게 불러야 한다)

    return db.get_client()


def choose_fresh_ip(client, prefix: str, start: int = CHECK_IP_START, end: int = CHECK_IP_END) -> str | None:
    """점검 범위에서 아직 쓰지 않은 새 출발지 IP 하나. 다 썼으면 None.

    network_blocks에 한 번이라도 오른 IP, 그리고 사건이 한 번이라도 있었던 IP(닫힌 사건 포함)는 피한다.
    차단·열린 사건이 남아 있으면 앞 실행에 막혀 같은 재현이 다시 일어나지 않고, 닫힌 사건의 IP라도 다시 쓰면
    그 IP로 남은 옛 경고 메일·playbook_runs·NET_SCANNER_UA가 이번 판정에 섞이기 때문이다.
    그만큼 범위(.111~.139)가 빨리 떨어지므로, 다 쓰면 None을 돌려주고 시나리오는 SKIP한다(정리 후 재시도).
    """
    blocked = client.table("network_blocks").select("ip_address").like("ip_address", f"{prefix}.%").execute().data or []
    used = {row["ip_address"] for row in blocked}
    incidents = (
        client.table("security_incidents")
        .select("ip_address")
        .like("ip_address", f"{prefix}.%")
        .execute()
        .data
        or []
    )
    used |= {row["ip_address"] for row in incidents}
    for last in range(start, end + 1):
        ip = f"{prefix}.{last}"
        if ip not in used:
            return ip
    return None


# ── 시나리오들이 함께 쓰는 읽기 전용 조회 (모두 select만) ──

def latest_incident_rules(client, ip: str) -> list[str]:
    """그 IP의 가장 최근 사건 matched_rules. 사건이 없으면 빈 목록."""
    rows = (
        client.table("security_incidents")
        .select("matched_rules")
        .eq("ip_address", ip)
        .order("last_event_at", desc=True)
        .limit(1)
        .execute()
        .data
    )
    return (rows[0].get("matched_rules") or []) if rows else []


def network_block(client, ip: str) -> dict | None:
    """그 IP의 network_blocks 행(없으면 None)."""
    rows = client.table("network_blocks").select("*").eq("ip_address", ip).limit(1).execute().data
    return rows[0] if rows else None


def lockout(client, ip: str) -> dict | None:
    """그 IP의 lockouts 행(앱 잠금). 없으면 None."""
    rows = client.table("lockouts").select("*").eq("ip_address", ip).limit(1).execute().data
    return rows[0] if rows else None


def open_net_blocked(client, ip: str) -> list[dict]:
    """그 IP의 미해결 NET_BLOCKED(CRITICAL) 이벤트."""
    return (
        client.table("security_events")
        .select("severity, resolved_at")
        .eq("ip_address", ip)
        .eq("event_type", "NET_BLOCKED")
        .is_("resolved_at", "null")
        .execute()
        .data
        or []
    )


def has_net_scanner_ua(client, ip: str) -> bool:
    """그 IP의 NET_SCANNER_UA(source=NET)가 이미 기록됐는가. S6에서 로그인 전에 이걸 기다린다."""
    rows = (
        client.table("security_events")
        .select("id")
        .eq("ip_address", ip)
        .eq("event_type", "NET_SCANNER_UA")
        .eq("source", "NET")
        .limit(1)
        .execute()
        .data
    )
    return bool(rows)


def playbook_runs_for_ip(client, ip: str, playbook: str) -> list[dict]:
    """그 IP 사건들의 playbook_runs 중 해당 플레이북 실행 기록.

    실행마다 새 IP를 쓰므로 이 IP에 묶인 사건은 이번 실행 것뿐이다.
    trigger_ref가 'incident:<사건 id>:<규칙>' 꼴이라(K12) 사건 id로 묶는다.
    """
    incidents = client.table("security_incidents").select("id").eq("ip_address", ip).execute().data or []
    runs: list[dict] = []
    for incident in incidents:
        runs += (
            client.table("playbook_runs")
            .select("playbook, step, status, error, ran_at")
            .eq("playbook", playbook)
            .like("trigger_ref", f"incident:{incident['id']}:%")
            .execute()
            .data
            or []
        )
    return runs


def not_found_rows(client, path: str) -> list[dict]:
    """그 경로로 들어온 404 기록(not_found_attempts). S8에서 ip가 위조값(1.2.3.4)이 아님을 본다."""
    return (
        client.table("not_found_attempts")
        .select("ip_address, path")
        .eq("path", path)
        .execute()
        .data
        or []
    )


# ── Mailpit (받은 메일 화면) 조회 ──

def mailpit_match_count(query: str) -> int | None:
    """Mailpit에서 query가 들어간 메일 수. 접속이 안 되면 None(판정은 호출부가 결정).

    S6 경고 메일은 본문에 그 IP가 들어가므로, 이번 실행의 새 IP로 검색하면 이 실행 것만 센다.
    (http://localhost:8025/api/v1/search — Mailpit 검색 API)
    """
    url = "http://localhost:8025/api/v1/search?query=" + urllib.parse.quote(query)
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 (로컬 Mailpit 고정 주소)
            data = json.load(response)
    except (OSError, ValueError):
        return None
    if "messages_count" in data:
        return int(data["messages_count"])
    return len(data.get("messages", []))


# ── 공격 재현 실행 (subprocess, 셸 없이) ──

def run_oneshot(template: list[str], ip: str, prefix: str, timeout: int = 180,
                capture: bool = False) -> subprocess.CompletedProcess:
    """일회용 공격 컨테이너를 한 번 띄우고 끝날 때까지 기다린다.

    capture=True면 컨테이너 stdout(lw.py가 내는 JSON 한 줄)을 받아 돌려준다. docker 출력은 UTF-8이라
    encoding을 UTF-8로 고정한다(한국어 Windows에서 cp949로 읽다 깨지는 것 방지 — measure_* 와 같은 이유).
    """
    cmd = fill(template, ip, prefix)
    return subprocess.run(cmd, cwd=ROOT, capture_output=capture, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def parse_json_line(completed: subprocess.CompletedProcess) -> dict | None:
    """lw.py가 stdout에 낸 JSON 한 줄을 읽는다. 없으면 None(사람용 출력은 stderr로 빠져 있다)."""
    text = (getattr(completed, "stdout", "") or "").strip()
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


def s8_request_command(path: str) -> list[str]:
    """S8: shipper 컨테이너 안에서 http://app:5000/<없는 경로>에 X-Forwarded-For를 붙여 GET 1회.

    gateway를 거치지 않는 경로라 공격 상자(edge 전용)로는 못 보낸다. core 망에 붙은 shipper에는
    requests가 있어 그 안에서 보낸다. 앱이 이 요청의 X-Forwarded-For를 믿지 않아야(신뢰 프록시가 아님)
    not_found_attempts의 ip가 1.2.3.4가 아니게 된다 — 그것이 S8의 기대 결과다.
    """
    code = (
        "import requests;"
        "requests.get('http://app:5000" + path + "',"
        "headers={'X-Forwarded-For':'1.2.3.4'},timeout=5)"
    )
    return ["docker", "compose", "exec", "-T", "shipper", "python", "-c", code]


def random_s8_path() -> str:
    """실행마다 다른 없는 경로. 그래야 그 요청이 남긴 not_found_attempts 행만 골라낼 수 있다."""
    return S8_PATH_PREFIX + secrets.token_hex(4)


# ── 시작 전 확인 출력 ──

def preflight() -> None:
    """시작 전에 사람이 확인할 것(단지 상태·시연용 .env)을 출력한다. 비밀값은 '있음/없음'만 보여 준다."""
    print("── 시작 전 확인 (아래가 준비됐는지 보세요) ──")
    print("  · docker compose up -d 로 단지가 켜져 있어야 합니다(아래 서비스 상태 확인).")
    print("  · 시연용 .env(LW_EDGE_PREFIX 등)가 내 대역으로 맞춰져 있어야 합니다.")
    print("  · S6는 victim_c 계정과 환경 변수 LW_VICTIM_PASSWORD가 있어야 합니다(없으면 S6 SKIP).")
    print("  · Mailpit 화면: http://localhost:8025 (S6 경고 메일 확인용)")
    try:
        # docker 출력은 UTF-8. encoding을 고정하지 않으면 한국어 Windows에서 깨져 stdout이 비는 수가 있다.
        out = subprocess.run(["docker", "compose", "ps", "--format", "json"], cwd=ROOT,
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
        text = out.stdout.strip()
        rows = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
        states = {row.get("Service"): row.get("State") for row in rows}
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        states = {}
        print(f"  docker compose ps 실패: {type(error).__name__}")
    for name in REQUIRED_SERVICES:
        print(f"  서비스 {name:<12} {states.get(name, '없음')}")
    for name in ("LW_NODE_NAME", "LW_EDGE_PREFIX"):
        print(f"  .env {name:<15} {'있음' if os.environ.get(name) else '없음'}")
    print(f"  LW_VICTIM_PASSWORD  {'있음' if os.environ.get('LW_VICTIM_PASSWORD') else '없음'}")


def edge_prefix() -> str:
    """LW_EDGE_PREFIX(없으면 빈 문자열). 대상 IP를 만드는 데 쓴다."""
    return os.environ.get("LW_EDGE_PREFIX", "").strip()


# ── 결과 표 (docs/track-d/scenario-results.md) ──

def format_row(when: datetime, result: CheckResult) -> str:
    """결과 표 한 줄(마크다운). 시각은 UTC로 적는다(DB 시각과 같은 기준)."""
    stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    reason = (result.reason or "").replace("|", "/").replace("\n", " ")
    ip = result.ip or "-"
    return f"| {stamp} | {result.scenario} | {result.status} | {ip} | {reason} |"


def append_rows(lines: list[str]) -> None:
    """scenario-results.md 맨 아래에 결과 줄들을 덧붙인다. 파일이 없으면 머리말과 함께 만든다."""
    if not RESULTS.exists():
        RESULTS.write_text(RESULTS_HEADER, encoding="utf-8")
    with RESULTS.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


RESULTS_HEADER = """# Track D 시연 시나리오 자동 점검 결과 (C3-1)

> `python -m scripts.net.run_all` 을 돌릴 때마다 아래 표에 결과가 **덧붙여집니다**(지우지 않습니다).
> PASS/FAIL은 "기대 결과가 DB·응답·메일에 실제로 생겼는지"를 확인한 결과입니다.
> 실행 방법과 각 시나리오가 무엇을 확인하는지는 `scripts/net/run_all.py`, `check_s*.py`의 docstring을 보세요.

| 시각(UTC) | 시나리오 | 결과 | 출발지 IP | 비고(실패·건너뜀 이유) |
|---|---|---|---|---|
"""
