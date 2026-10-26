"""S4 자동 점검 — 정찰→웹 스캔→무차별 대입 킬체인(CR-01)이 영구 차단으로 이어지는지 확인한다.

실행 방법(저장소 루트에서, docker compose로 단지를 켠 뒤):
    python -m scripts.net.check_s4
run_all이 함께 돌릴 때는 run_all.py가 이 모듈의 run(ctx)을 부른다.

재현: 이번 실행의 새 출발지 IP로 일회용 공격 컨테이너를 띄워 scan → webscan → brute 를 "같은 IP"로 보낸다.
      (netwatch/README.md 7.3의 일회용 실행 형식. 한 시나리오 안의 세 단계는 같은 IP를 쓴다.)
기대 결과(모두 맞아야 PASS):
    - 그 IP의 사건 matched_rules에 "CR-01"
    - 그 IP의 영구 잠금(lockouts.lock_type=PERMANENT, recoverable=ADMIN_ONLY)
    - network_blocks: evidence=CONNECTED, expires_at=null(영구)
DB는 읽기만 한다. 공격 재현 외에 새 요청을 만들지 않는다.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from scripts.net import check_common as cc

SCENARIO = "S4"


def run(ctx) -> cc.CheckResult:
    """한 번 재현하고 확인한다. ctx는 run_all이 만든 (client, prefix)."""
    client, prefix = ctx.client, ctx.prefix
    ip = cc.choose_fresh_ip(client, prefix)
    if ip is None:
        return cc.CheckResult(SCENARIO, "SKIP", "점검용 IP(.111~.139)를 모두 썼음 — 오래된 차단·사건 정리 후 재시도", None)

    print(f"  [{SCENARIO}] 출발지 {ip} — 정찰·웹스캔·무차별 대입(같은 IP)")
    # 세 단계를 순서대로 같은 IP로 보낸다. 각 컨테이너는 --rm으로 끝나며 IP를 놓으므로 다음 단계가 같은 --ip를 쓸 수 있다.
    cc.run_oneshot(cc.SCAN, ip, prefix)
    cc.run_oneshot(cc.WEBSCAN, ip, prefix)
    cc.run_oneshot(cc.BRUTE, ip, prefix)

    # CR-01 킬체인이 묶이고 영구 차단이 적용될 때까지 기다린다.
    block = cc.wait_until(lambda: (b := cc.network_block(client, ip)) and b.get("applied_at") and b)
    rules = cc.latest_incident_rules(client, ip)
    lock = cc.lockout(client, ip)
    if block is None:
        block = cc.network_block(client, ip) or {}

    fails = []
    if "CR-01" not in rules:
        fails.append(f"사건 matched_rules에 CR-01 없음(현재 {rules or '없음'})")
    if not (lock and lock.get("lock_type") == "PERMANENT" and lock.get("recoverable") == "ADMIN_ONLY"):
        fails.append(f"영구 잠금(ADMIN_ONLY) 아님(lockouts={_brief_lock(lock)})")
    if block.get("evidence") != "CONNECTED":
        fails.append(f"network_blocks.evidence가 CONNECTED 아님(현재 {block.get('evidence') or '없음'})")
    if block.get("expires_at") is not None:
        fails.append(f"network_blocks.expires_at이 영구(null) 아님(현재 {block.get('expires_at')})")

    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)
    return cc.CheckResult(SCENARIO, "PASS", "CR-01·영구 잠금·영구 L4 차단 확인", ip)


def _brief_lock(lock: dict | None) -> str:
    if not lock:
        return "없음"
    return f"{lock.get('lock_type')}/{lock.get('recoverable')}"


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
