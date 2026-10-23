"""탐지 → L4 차단 시간 측정 (I2-2) — 발표 핵심 숫자 "5초 안에 막는다"를 재서 기록한다.

    python -m scripts.net.measure_detect_to_block --scenario s5 --repeat 3
    python -m scripts.net.measure_detect_to_block --scenario s5b --repeat 3

저장소 루트에서, docker compose로 단지(sensor·l4-detector·shipper·fw-agent·app)를 켠 뒤 실행한다.
실행마다 측정 범위(.150~.199)에서 아직 차단된 적 없는 새 출발지 IP로 일회용 공격 컨테이너를 띄우고,
DB에 남은 시각 세 개를 읽어 구간을 잰다.

  T0 network_events.observed_at   (그 IP의 첫 SYN_FLOOD — 센서가 본 시각)
  T1 network_blocks.requested_at  (앱이 "막아라"를 적은 시각)
  T2 network_blocks.applied_at    (fw-agent가 "막았음"을 보고한 시각)
  T3 security_events NET_BLOCKED detected_at (확인용 — 구간에는 쓰지 않음)

왜 PC 시계가 아니라 DB 시각으로 재나: 공격 컨테이너·센서·앱·DB가 각각 다른 시계를 쓴다. 스크립트가 "공격 시작"을
자기 시계로 찍으면 컨테이너 시작 시간과 시계 차이가 섞여 숫자가 흔들린다. DB에 남은 기록끼리 빼면
같은 파이프라인 안의 시각만 비교하게 된다(T0은 센서 원래 시각을 shipper가 그대로 보낸 값).

DB는 읽기만 한다(select). 결과는 docs/track-d/measurements.md 맨 아래 표에 한 줄씩 붙인다.
종료 코드: 0 모두 목표 안 / 1 목표를 넘은(또는 못 잰) 실행이 있음 / 2 공격 명령이 없어 측정하지 않음(SKIP).
비밀값(.env의 키·비밀번호)은 어디에도 출력하지 않는다 — 시작할 때 "있음/없음"만 보여 준다.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from scripts.net import measure_common as mc  # noqa: E402

README = ROOT / "netwatch" / "README.md"
RESULTS = ROOT / "docs" / "track-d" / "measurements.md"
REQUIRED_SERVICES = ("sensor", "l4-detector", "shipper", "fw-agent", "app")
# 기다리는 한도. 목표(5초)보다 훨씬 길게 잡아, 늦더라도 "몇 초 걸렸는지"는 남긴다.
WAIT_SECONDS = 30
# 공격 시작 직전 시각에서 이만큼 앞부터 network_events를 찾는다(컨테이너 시계와 PC 시계의 작은 차이 대비).
SINCE_SLACK_SECONDS = 5


def preflight(prefix: str | None) -> None:
    """시작 전 확인 목록을 출력한다. 값은 보여 주지 않는다(이름과 있음/없음만)."""
    print("── 시작 전 확인 ──")
    try:
        out = subprocess.run(["docker", "compose", "ps", "--format", "json"], cwd=ROOT, capture_output=True, text=True, timeout=20)
        # docker compose 버전에 따라 JSON 배열 하나 또는 한 줄에 하나씩 나온다
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
    if not prefix:
        print("  (!) LW_EDGE_PREFIX가 없어 측정할 IP를 만들 수 없습니다.")


def used_ips(client, prefix: str) -> set[str]:
    """network_blocks에 한 번이라도 오른 이 대역 IP(상태 무관) — 다시 쓰지 않는다."""
    rows = client.table("network_blocks").select("ip_address").like("ip_address", f"{prefix}.%").execute().data or []
    return {row["ip_address"] for row in rows}


def first_syn_flood(client, ip: str, since_iso: str) -> str | None:
    rows = (
        client.table("network_events")
        .select("observed_at")
        .eq("src_ip", ip)
        .eq("category", "SYN_FLOOD")
        .gte("observed_at", since_iso)
        .order("observed_at")
        .limit(1)
        .execute()
        .data
    )
    return rows[0]["observed_at"] if rows else None


def block_row(client, ip: str) -> dict | None:
    rows = client.table("network_blocks").select("status, requested_at, applied_at").eq("ip_address", ip).limit(1).execute().data
    return rows[0] if rows else None


def net_blocked_at(client, ip: str, since_iso: str) -> str | None:
    rows = (
        client.table("security_events")
        .select("detected_at")
        .eq("ip_address", ip)
        .eq("event_type", "NET_BLOCKED")
        .gte("detected_at", since_iso)
        .order("detected_at")
        .limit(1)
        .execute()
        .data
    )
    return rows[0]["detected_at"] if rows else None


def has_cr02(client, ip: str) -> bool:
    """S5b 확인용: 그 IP의 가장 최근 사건 matched_rules에 CR-02가 있는가(판정에는 넣지 않고 비고에만)."""
    rows = (
        client.table("security_incidents")
        .select("matched_rules")
        .eq("ip_address", ip)
        .order("last_event_at", desc=True)
        .limit(1)
        .execute()
        .data
    )
    return bool(rows) and "CR-02" in (rows[0].get("matched_rules") or [])


def run_once(client, scenario: str, prefix: str, commands: list[list[str]], used: set[str]) -> tuple[str, dict, dict, str] | None:
    """한 번 재현하고 잰다. 쓸 IP가 없으면 None."""
    ip = mc.choose_fresh_ip(prefix, used)
    if ip is None:
        print(f"  측정 범위(.{mc.MEASURE_IP_START}~.{mc.MEASURE_IP_END})의 IP를 모두 썼습니다. 오래된 차단 기록 정리 후 다시 하세요.")
        return None
    used.add(ip)
    since = (datetime.now(timezone.utc) - timedelta(seconds=SINCE_SLACK_SECONDS)).isoformat()
    print(f"  [{scenario.upper()}] 출발지 {ip} — 공격 시작")
    # 시나리오의 명령을 동시에 띄운다(S5b는 SYN 폭주 + HTTP 폭주). 셸을 거치지 않는다.
    procs = [subprocess.Popen(mc.fill_command(cmd, ip, prefix), cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for cmd in commands]

    t0 = mc.wait_until(lambda: first_syn_flood(client, ip, since), timeout=WAIT_SECONDS)
    row = mc.wait_until(lambda: (r := block_row(client, ip)) and r.get("applied_at") and r, timeout=WAIT_SECONDS) or block_row(client, ip) or {}
    t3 = mc.wait_until(lambda: net_blocked_at(client, ip, since), timeout=10)

    for proc in procs:
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()

    intervals = mc.compute_intervals(t0, row.get("requested_at"), row.get("applied_at"))
    verdict = mc.judge(intervals)
    notes = []
    if t0 is None:
        notes.append("SYN_FLOOD 경보 없음")
    if not row:
        notes.append("차단 요청 없음")
    elif not row.get("applied_at"):
        notes.append(f"적용 안 됨({row.get('status')})")
    if t3 is None:
        notes.append("NET_BLOCKED 기록 없음")
    if scenario == "s5b":
        notes.append("CR-02 있음" if has_cr02(client, ip) else "CR-02 없음")
    note = ", ".join(notes)
    print(f"  → T0→T1 {intervals['t0_t1']}ms · T1→T2 {intervals['t1_t2']}ms · 전체 {intervals['t0_t2']}ms · {'통과' if verdict['all'] else '초과'} {note}")
    return ip, intervals, verdict, note


def append_rows(lines: list[str]) -> None:
    with RESULTS.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="탐지 → L4 차단 시간 측정 (S5·S5b)")
    parser.add_argument("--scenario", choices=["s5", "s5b"], required=True)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args(argv)
    # Windows 기본 콘솔(cp949)에 없는 글자가 섞여도 측정이 멈추지 않게, 못 찍는 글자는 ?로 바꿔 출력한다
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    prefix = os.environ.get("LW_EDGE_PREFIX", "").strip()
    preflight(prefix)

    commands, skip_reason = mc.resolve_attack(args.scenario, README)
    if skip_reason:
        print(f"── {skip_reason}")
        return 2
    if not prefix:
        return 2

    import db  # .env를 읽은 뒤에 불러야 SUPABASE_URL·KEY가 잡힌다

    client = db.get_client()
    used = used_ips(client, prefix)
    rows, totals, failed = [], [], False
    for _ in range(max(1, args.repeat)):
        result = run_once(client, args.scenario, prefix, commands, used)
        if result is None:
            failed = True
            break
        ip, intervals, verdict, note = result
        rows.append(mc.format_row(datetime.now(timezone.utc), args.scenario, ip, intervals, verdict, note))
        totals.append(intervals["t0_t2"])
        failed = failed or not verdict["all"]

    append_rows(rows)
    summary = mc.summarize(totals)
    print(f"── {args.scenario.upper()} 전체(T0→T2) 중앙값 {summary['median']}ms · 최댓값 {summary['max']}ms · 못 잰 횟수 {summary['missing']}")
    print(f"   결과를 {RESULTS.relative_to(ROOT)}에 {len(rows)}줄 추가했습니다.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
