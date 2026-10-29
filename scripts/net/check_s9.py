"""S9 자동 점검 — ICMP 폭주가 L3 경보로 기록되고, 주소 차단 없이 커널 속도 제한으로만 깎이는지 확인한다(guide57).

실행 방법(저장소 루트에서, docker compose로 단지를 켜고 공격 상자 이미지를 새로 만든 뒤):
    python -m scripts.net.check_s9

재현: 이번 실행의 새 출발지 IP로 일회용 공격 컨테이너를 띄워 icmpflood(ICMP echo 3000개, 초당 1000개)를 보낸다.
기대 결과(모두 맞아야 PASS):
    - 그 IP의 network_events ICMP_FLOOD(L3) 있음, 보안 이벤트 NET_ICMP_FLOOD 있음
    - 그 IP의 network_blocks 행 없음 — ICMP도 위조할 수 있어 주소로 막지 않는다
    - 정문 LW_L3 체인의 DROP 누적 카운터가 공격 전보다 늘어남 — 출발지별 초당 50개를 넘는 만큼 버렸다
    - 그 IP에서 gateway로 TCP 연결이 됨(ICMP만 깎이고 정상 접속은 막히지 않음)
DB는 읽기만 한다.

시각 비교 주의(10/29 보정): 보안 이벤트의 detected_at은 Supabase 시계로 찍히는데, PC 시계가 DB보다 몇 초 앞서면
PC 시각으로 거를 때 방금 생긴 이벤트가 빠진다. 그래서 찾아낸 경보의 received_at(DB 시계)을 기준으로 다시 찾는다.
버린 패킷 수도 heartbeat의 10초 증가분 대신 공격 전·후 누적 카운터를 직접 비교한다.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from types import SimpleNamespace

from scripts.net import check_common as cc

SCENARIO = "S9"


def run(ctx) -> cc.CheckResult:
    client, prefix = ctx.client, ctx.prefix
    ip = cc.choose_fresh_ip(client, prefix)
    if ip is None:
        return cc.CheckResult(SCENARIO, "SKIP", f"점검용 IP({cc.CHECK_IP_LABEL})를 모두 썼음 — 오래된 차단·사건 정리 후 재시도", None)

    cc.mark_used(ip)
    since = datetime.now(timezone.utc).isoformat()
    dropped_before = cc.icmp_dropped_total()
    print(f"  [{SCENARIO}] 출발지 {ip} — ICMP 폭주")
    cc.run_oneshot(cc.ICMPFLOOD, ip, prefix)

    fails: list[str] = []
    events = cc.wait_until(lambda: cc.network_events_since(client, "ICMP_FLOOD", since, src_ip=ip) or None) or []
    if not events:
        fails.append("network_events ICMP_FLOOD 없음")
    elif any(e.get("layer") != "L3" for e in events):
        fails.append("ICMP_FLOOD의 layer가 L3가 아님")
    # 경보가 DB에 도착한 시각(DB 시계) 조금 앞부터 찾는다. 경보가 없으면 PC 시각에 여유를 둔다.
    received = sorted(e["received_at"] for e in events if e.get("received_at"))
    db_since = cc.shift_iso(received[0], -5) if received else cc.shift_iso(since, -cc.CLOCK_SKEW_MARGIN_SECONDS)
    if not cc.wait_until(lambda: cc.security_events_since(client, ip, "NET_ICMP_FLOOD", db_since) or None, timeout=10):
        fails.append("보안 이벤트 NET_ICMP_FLOOD 없음")
    if cc.network_block(client, ip) is not None:
        fails.append("network_blocks 행이 생김(ICMP는 주소로 막지 않아야 함)")
    dropped_after = cc.icmp_dropped_total()
    if dropped_before is None or dropped_after is None:
        fails.append("LW_L3 카운터를 읽지 못함 — docker compose exec fw-agent iptables -t raw -L LW_L3 확인")
    elif dropped_after <= dropped_before:
        detail = cc.fw_agent_detail(client)
        fails.append(f"LW_L3가 ICMP를 버리지 않음(누적 {dropped_before}→{dropped_after}, l3_ok={detail.get('l3_ok')})")
    reachable = cc.probe_reachable(ip, prefix)
    if reachable is not True:
        fails.append(f"ICMP 폭주 뒤 TCP 연결이 안 됨(reachable={reachable})")

    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)
    return cc.CheckResult(SCENARIO, "PASS", "ICMP_FLOOD(L3) 기록·주소 차단 없음·LW_L3 속도 제한 동작·TCP 정상", ip)


def main() -> int:
    cc.preflight()
    prefix = cc.edge_prefix()
    if not prefix:
        print("  (!) LW_EDGE_PREFIX가 없어 대상 IP를 만들 수 없습니다.")
        return 2
    ctx = SimpleNamespace(client=cc.get_reader(), prefix=prefix)
    result = run(ctx)
    cc.append_rows([cc.format_row(datetime.now(timezone.utc), result)])
    print(f"  → {result.scenario} {result.status} {result.reason}")
    return 0 if result.status in ("PASS", "SKIP") else 1


if __name__ == "__main__":
    sys.exit(main())
