"""S5b 자동 점검 — 같은 IP에서 SYN 폭주와 HTTP 폭주가 동시에 와 CR-02(다계층 폭주)로 묶이는지 확인한다.

실행 방법(저장소 루트에서, docker compose로 단지를 켠 뒤):
    python -m scripts.net.check_s5b

재현: 이번 실행의 새 출발지 IP를 "자리 잡기" 컨테이너(sleep)로 먼저 쥔 뒤,
      synflood와 httpflood를 --network container: 로 같은 망에 붙여 "동시에" 보낸다(README 7.3 S5b 방식).
      같은 --ip로 컨테이너 두 개를 직접 띄우면 두 번째가 Address already in use로 죽기 때문이다.
기대 결과(모두 맞아야 PASS):
    - 그 IP의 사건 matched_rules에 "CR-02"
    - 그 IP의 network_blocks에 TTL 있음(expires_at not null)
DB는 읽기만 한다.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone

from scripts.net import check_common as cc

SCENARIO = "S5b"


def run(ctx) -> cc.CheckResult:
    client, prefix = ctx.client, ctx.prefix
    ip = cc.choose_fresh_ip(client, prefix)
    if ip is None:
        return cc.CheckResult(SCENARIO, "SKIP", f"점검용 IP({cc.CHECK_IP_LABEL})를 모두 썼음 — 오래된 차단·사건 정리 후 재시도", None)

    print(f"  [{SCENARIO}] 출발지 {ip} — SYN 폭주 + HTTP 폭주(같은 IP, 동시)")
    # 앞 실행이 끊겨 같은 이름의 자리 잡기 컨테이너가 남아 있으면 먼저 지운다.
    subprocess.run(cc.fill(cc.S5B_ANCHOR_REMOVE, ip, prefix), cwd=cc.ROOT, capture_output=True, timeout=30)
    anchor = subprocess.run(cc.fill(cc.S5B_ANCHOR, ip, prefix), cwd=cc.ROOT, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=60)
    if anchor.returncode != 0:
        reason = (anchor.stderr.strip().splitlines() or ["원인 불명"])[0][:120]
        return cc.CheckResult(SCENARIO, "FAIL", f"자리 잡기 컨테이너 실패: {reason}", ip)

    try:
        # 두 공격을 동시에 띄운다. 공격 컨테이너 출력은 버린다(판정은 DB로 한다).
        procs = [
            subprocess.Popen(cc.fill(cmd, ip, prefix), cwd=cc.ROOT,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for cmd in (cc.S5B_SYNFLOOD, cc.S5B_HTTPFLOOD)
        ]
        block = cc.wait_until(lambda: (b := cc.network_block(client, ip)) and b.get("expires_at") and b)
        for proc in procs:
            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        # 자리 잡기 컨테이너는 반드시 지운다(남으면 그 IP를 계속 물고 있다).
        subprocess.run(cc.fill(cc.S5B_ANCHOR_REMOVE, ip, prefix), cwd=cc.ROOT, capture_output=True, timeout=30)

    if block is None:
        block = cc.network_block(client, ip) or {}
    rules = cc.latest_incident_rules(client, ip)

    fails = []
    if "CR-02" not in rules:
        fails.append(f"사건 matched_rules에 CR-02 없음(현재 {rules or '없음'})")
    if not block.get("expires_at"):
        fails.append("network_blocks.expires_at(TTL) 없음")

    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)
    return cc.CheckResult(SCENARIO, "PASS", "CR-02·TTL L4 차단 확인", ip)


def main() -> int:
    cc.preflight()
    prefix = cc.edge_prefix()
    if not prefix:
        print("  (!) LW_EDGE_PREFIX가 없어 대상 IP를 만들 수 없습니다.")
        return 2
    from types import SimpleNamespace

    ctx = SimpleNamespace(client=cc.get_reader(), prefix=prefix)
    result = run(ctx)
    cc.append_rows([cc.format_row(datetime.now(timezone.utc), result)])
    print(f"  → {result.scenario} {result.status} {result.reason}")
    return 0 if result.status in ("PASS", "SKIP") else 1


if __name__ == "__main__":
    sys.exit(main())
