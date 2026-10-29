"""S7 자동 점검 — 출발지를 위조한 SYN 폭주가 우리 서비스·남의 주소를 영구로 막지 않는지 확인한다(guide57).

실행 방법(저장소 루트에서, docker compose로 단지를 켜고 공격 상자 이미지를 새로 만든 뒤):
    python -m scripts.net.check_s7

재현: 이번 실행의 새 출발지 IP로 일회용 공격 컨테이너를 띄우고, 그 안에서 출발지를 꾸민 SYN을 보낸다.
    ① 출발지를 바꾸는 폭주(edge .200~.254를 돌려 씀) → 막을 주소가 없음
    ② 출발지를 core 주소(172.30.0.250)로 위조 → 우리 인프라라 막으면 안 됨
    ③ 출발지를 edge .140으로 위조 → 위조 가능 증거라 TTL 차단까지만
    ④ 출발지를 edge 대역 밖(192.0.2.50)으로 위조 → 위조가 확실한 주소, SPOOFED_SRC 기록
기대 결과(모두 맞아야 PASS):
    ① .200~.254에 새 차단 행 없음, GLOBAL_SYN_FLOOD 기록 있음
    ② 172.30.0.250의 차단 행·NET_SYN_FLOOD 보안 이벤트 없음
    ③ .140 차단 행이 SPOOFABLE이고 expires_at 있음(영구 아님), .140 앱 잠금 없음
    ④ 192.0.2.50 차단 행 없음, SPOOFED_SRC 기록 있음
    끝으로 공격 컨테이너 IP에서 gateway로 TCP 연결이 됨(정문이 멈추지 않음)
DB는 읽기만 한다.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from types import SimpleNamespace

from scripts.net import check_common as cc

SCENARIO = "S7"


def _spoofed(spoof: str) -> list[str]:
    return [part.replace("{spoof}", spoof) for part in cc.S7_SPOOFED]


def run(ctx) -> cc.CheckResult:
    client, prefix = ctx.client, ctx.prefix
    ip = cc.choose_fresh_ip(client, prefix)
    if ip is None:
        return cc.CheckResult(SCENARIO, "SKIP", f"점검용 IP({cc.CHECK_IP_LABEL})를 모두 썼음 — 오래된 차단·사건 정리 후 재시도", None)

    cc.mark_used(ip)
    since = datetime.now(timezone.utc).isoformat()
    edge_spoof = f"{prefix}.140"
    rotating = [f"{prefix}.{last}" for last in cc.S7_ROTATING_HOSTS]
    fails: list[str] = []

    print(f"  [{SCENARIO}] 공격 상자 {ip} — ① 출발지를 바꾸는 SYN 폭주")
    cc.run_oneshot(cc.S7_ROTATING, ip, prefix)
    for spoof, label in ((cc.S7_CORE_SPOOF, "②"), (edge_spoof, "③"), (cc.S7_FOREIGN_SPOOF, "④")):
        print(f"  [{SCENARIO}] 공격 상자 {ip} — {label} 출발지 {spoof}로 위조한 SYN 폭주")
        cc.run_oneshot(_spoofed(spoof), ip, prefix)

    # ① 전체 SYN 경보가 들어오고, 돌려 쓴 출발지는 하나도 막히지 않아야 한다.
    if not cc.wait_until(lambda: cc.network_events_since(client, "GLOBAL_SYN_FLOOD", since) or None):
        fails.append("① GLOBAL_SYN_FLOOD 기록 없음")
    rotating_blocks = cc.network_blocks_since(client, rotating, since)
    if rotating_blocks:
        fails.append(f"① 돌려 쓴 출발지가 차단됨({len(rotating_blocks)}곳, 예: {rotating_blocks[0]['ip_address']})")

    # ③ 위조 가능 증거는 TTL 차단까지만. 차단이 생길 때까지 기다린다(이미 걸려 있던 차단이어도 된다).
    block = cc.wait_until(lambda: cc.network_block(client, edge_spoof)) or {}
    if not block:
        fails.append(f"③ {edge_spoof} 차단 행 없음")
    elif block.get("evidence") != "SPOOFABLE" or not block.get("expires_at"):
        fails.append(f"③ {edge_spoof} 차단이 TTL(SPOOFABLE)이 아님(evidence={block.get('evidence')}, expires_at={block.get('expires_at')})")
    if cc.lockout(client, edge_spoof) is not None:
        fails.append(f"③ {edge_spoof}에 앱 잠금이 생김(위조 가능 증거로는 잠그지 않아야 함)")

    # ④ edge 대역 밖 위조는 SPOOFED_SRC로 기록되고 막지 않는다.
    if not cc.wait_until(lambda: cc.network_events_since(client, "SPOOFED_SRC", since) or None):
        fails.append("④ SPOOFED_SRC 기록 없음")
    if cc.network_block(client, cc.S7_FOREIGN_SPOOF) is not None:
        fails.append(f"④ {cc.S7_FOREIGN_SPOOF} 차단 행이 생김")

    # ② 우리 core 주소는 어떤 경로로도 막히거나 사건이 되지 않는다. 다른 확인을 기다리는 동안 처리가 끝났다.
    if cc.network_block(client, cc.S7_CORE_SPOOF) is not None:
        fails.append(f"② core 주소 {cc.S7_CORE_SPOOF} 차단 행이 생김")
    # "있으면 안 되는" 확인이라 DB 시계와 PC 시계 차이만큼 넓게 본다(check_common.CLOCK_SKEW_MARGIN_SECONDS).
    if cc.security_events_since(client, cc.S7_CORE_SPOOF, "NET_SYN_FLOOD", cc.shift_iso(since, -cc.CLOCK_SKEW_MARGIN_SECONDS)):
        fails.append(f"② core 주소 {cc.S7_CORE_SPOOF}가 보안 이벤트로 올라감")

    reachable = cc.probe_reachable(ip, prefix)
    if reachable is not True:
        fails.append(f"공격 상자에서 gateway 연결 확인 실패(reachable={reachable})")

    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)
    return cc.CheckResult(
        SCENARIO, "PASS",
        f"위조 출발지 4종 — 돌려 쓴 출발지·core·대역 밖 주소 차단 없음, {edge_spoof}는 TTL만, 정문 정상",
        ip,
    )


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
