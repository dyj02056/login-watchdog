"""S5 자동 점검 — SYN 폭주(위조 가능 증거)가 "앱 잠금 없이" TTL L4 차단으로만 이어지는지 확인한다.

실행 방법(저장소 루트에서, docker compose로 단지를 켠 뒤):
    python -m scripts.net.check_s5

재현: 이번 실행의 새 출발지 IP로 일회용 공격 컨테이너를 띄워 synflood 를 보낸다(README 7.3 형식).
기대 결과(모두 맞아야 PASS):
    - 그 IP의 network_blocks status=APPLIED, expires_at 있음(TTL)
    - 그 IP의 앱 잠금(lockouts) 없음 — 위조 가능 증거로는 앱 계정을 잠그지 않는다
    - 그 IP의 미해결 NET_BLOCKED(CRITICAL) 있음
DB는 읽기만 한다.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from scripts.net import check_common as cc

SCENARIO = "S5"


def run(ctx) -> cc.CheckResult:
    client, prefix = ctx.client, ctx.prefix
    ip = cc.choose_fresh_ip(client, prefix)
    if ip is None:
        return cc.CheckResult(SCENARIO, "SKIP", f"점검용 IP({cc.CHECK_IP_LABEL})를 모두 썼음 — 오래된 차단·사건 정리 후 재시도", None)

    print(f"  [{SCENARIO}] 출발지 {ip} — SYN 폭주")
    cc.run_oneshot(cc.SYNFLOOD, ip, prefix)

    block = cc.wait_until(lambda: (b := cc.network_block(client, ip)) and b.get("status") == "APPLIED" and b)
    if block is None:
        block = cc.network_block(client, ip) or {}
    # NET_BLOCKED는 fw-agent가 APPLIED를 보고한 뒤 기록되므로 조금 더 기다린다.
    blocked_events = cc.wait_until(lambda: cc.open_net_blocked(client, ip) or None, timeout=10) or []
    lock = cc.lockout(client, ip)

    fails = []
    if block.get("status") != "APPLIED":
        fails.append(f"network_blocks status가 APPLIED 아님(현재 {block.get('status') or '없음'})")
    if not block.get("expires_at"):
        fails.append("network_blocks.expires_at(TTL) 없음 — 위조 가능 증거는 TTL 차단이어야 함")
    if lock is not None:
        fails.append(f"앱 잠금(lockouts)이 생김(있으면 안 됨, lock_type={lock.get('lock_type')})")
    if not any(e.get("severity") == "CRITICAL" for e in blocked_events):
        fails.append("미해결 NET_BLOCKED(CRITICAL) 없음")

    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)
    return cc.CheckResult(SCENARIO, "PASS", "TTL L4 차단·앱 잠금 없음·미해결 NET_BLOCKED 확인", ip)


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
