"""S4 자동 점검 — 정찰→웹 스캔→무차별 대입 킬체인(CR-01)이 영구 차단으로 이어지는지 확인한다.

실행 방법(저장소 루트에서, docker compose로 단지를 켠 뒤):
    python -m scripts.net.check_s4
run_all이 함께 돌릴 때는 run_all.py가 이 모듈의 run(ctx)을 부른다.

재현: 이번 실행의 새 출발지 IP로 일회용 공격 컨테이너를 띄워 scan → webscan → brute 를 "같은 IP"로 보낸다.
      (netwatch/README.md 7.3의 일회용 실행 형식. 한 시나리오 안의 세 단계는 같은 IP를 쓴다.)
기대 결과(모두 맞아야 PASS):
    - 그 IP의 사건 matched_rules에 "CR-01"
    - 그 IP의 영구 잠금(lockouts.lock_type=PERMANENT, recoverable=ADMIN_ONLY)
    - network_blocks: evidence=CONNECTED, expires_at=null(영구), status=APPLIED, applied_at 있음
      (차단 "요청"이 아니라 fw-agent가 실제로 ipset에 넣고 보고한 것까지 확인한다. 10/26 강사 피드백 6:
       예전에는 FAILED·applied_at 없음도 PASS로 나왔다)
    - 실제 접속: 그 IP → gateway TCP 연결 안 됨, 같은 대역의 다른 새 IP → 연결 됨(probe, DB 흔적 없음)
    - --with-release일 때만: 운영 스크립트로 영구 해제 → status=REMOVED → 그 IP에서 다시 연결 됨
DB는 읽기만 한다(--with-release의 해제는 예외 — 관리자 "영구 해제"와 같은 경로로 바꾼다).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone

from scripts.net import check_common as cc

SCENARIO = "S4"


def run(ctx) -> cc.CheckResult:
    """한 번 재현하고 확인한다. ctx는 run_all이 만든 (client, prefix)."""
    client, prefix = ctx.client, ctx.prefix
    ip = cc.choose_fresh_ip(client, prefix)
    if ip is None:
        return cc.CheckResult(SCENARIO, "SKIP", f"점검용 IP({cc.CHECK_IP_LABEL})를 모두 썼음 — 오래된 차단·사건 정리 후 재시도", None)

    print(f"  [{SCENARIO}] 출발지 {ip} — 정찰·웹스캔·무차별 대입(같은 IP)")
    # 세 단계를 순서대로 같은 IP로 보낸다. 각 컨테이너는 --rm으로 끝나며 IP를 놓으므로 다음 단계가 같은 --ip를 쓸 수 있다.
    cc.run_oneshot(cc.SCAN, ip, prefix)
    cc.run_oneshot(cc.WEBSCAN, ip, prefix)
    cc.run_oneshot(cc.BRUTE, ip, prefix)

    # CR-01 킬체인이 묶이고 영구 차단이 "적용 완료"될 때까지 기다린다. 시간이 다 되면 그 순간의 행으로
    # 판정하되 아래 status·applied_at 조건에서 FAIL이 난다(요청만 있고 적용이 안 된 상태를 PASS로 보지 않음).
    block = cc.wait_until(lambda: (b := cc.network_block(client, ip)) and _applied(b) and b)
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
    if block.get("status") != "APPLIED":
        error = f", last_error={block.get('last_error')}" if block.get("last_error") else ""
        fails.append(f"network_blocks.status가 APPLIED 아님(현재 {block.get('status') or '없음'}{error})")
    if not block.get("applied_at"):
        fails.append("network_blocks.applied_at 없음 — fw-agent의 적용 보고가 없음")
    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)

    # 장부가 APPLIED여도 실제 ipset·iptables가 빠져 있으면 막히지 않는다. 대상 IP와 대조 IP를 같은 방법으로
    # 찔러 "대상만 막히고 다른 IP는 열려 있음"을 함께 확인한다(다른 IP까지 막히면 허용 목록·대역 설정 오류).
    target_reachable = cc.probe_reachable(ip, prefix)
    other_ip = cc.choose_fresh_ip(client, prefix)
    other_reachable = cc.probe_reachable(other_ip, prefix) if other_ip else None
    if target_reachable is not False:
        fails.append(f"대상 IP에서 gateway 연결이 막히지 않음(probe={_probe_text(target_reachable)})")
    if other_ip is None:
        fails.append("대조용 정상 IP를 고르지 못함(점검 범위를 모두 씀)")
    elif other_reachable is not True:
        fails.append(f"대조 IP {other_ip}에서 gateway 연결이 안 됨(probe={_probe_text(other_reachable)})")
    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)

    if not getattr(ctx, "with_release", False):
        return cc.CheckResult(SCENARIO, "PASS", f"CR-01·영구 잠금·영구 L4 차단 적용·대상만 접속 차단(대조 {other_ip}) 확인", ip)

    released = subprocess.run(cc.fill(cc.RELEASE_IP, ip, prefix), cwd=cc.ROOT, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=120)
    if released.returncode != 0:
        reason = (released.stderr.strip().splitlines() or ["원인 불명"])[-1][:120]
        return cc.CheckResult(SCENARIO, "FAIL", f"영구 해제 스크립트 실패: {reason}", ip)
    removed = cc.wait_until(lambda: (b := cc.network_block(client, ip)) and b.get("status") == "REMOVED" and b)
    if removed is None:
        now = cc.network_block(client, ip) or {}
        return cc.CheckResult(SCENARIO, "FAIL", f"해제 후 network_blocks.status가 REMOVED 아님(현재 {now.get('status') or '없음'})", ip)
    after = cc.probe_reachable(ip, prefix)
    if after is not True:
        return cc.CheckResult(SCENARIO, "FAIL", f"해제 후에도 대상 IP에서 gateway 연결이 안 됨(probe={_probe_text(after)})", ip)
    return cc.CheckResult(SCENARIO, "PASS",
                          f"CR-01·영구 L4 차단 적용·대상만 접속 차단(대조 {other_ip})·해제 후 재접속 확인", ip)


def _applied(block: dict) -> bool:
    """fw-agent가 실제 적용을 보고한 행인지(status=APPLIED이고 applied_at이 있음)."""
    return block.get("status") == "APPLIED" and bool(block.get("applied_at"))


def _probe_text(value: bool | None) -> str:
    return {True: "연결됨", False: "막힘", None: "판정 불가"}[value]


def _brief_lock(lock: dict | None) -> str:
    if not lock:
        return "없음"
    return f"{lock.get('lock_type')}/{lock.get('recoverable')}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="S4 킬체인 점검")
    parser.add_argument("--with-release", action="store_true",
                        help="차단 확인 뒤 영구 해제까지 하고 대상 IP가 다시 접속되는지 확인(DB를 바꾼다)")
    args = parser.parse_args(argv)
    cc.preflight()
    prefix = cc.edge_prefix()
    if not prefix:
        print("  (!) LW_EDGE_PREFIX가 없어 대상 IP를 만들 수 없습니다.")
        return 2
    from types import SimpleNamespace

    ctx = SimpleNamespace(client=cc.get_reader(), prefix=prefix, with_release=args.with_release)
    result = run(ctx)
    cc.append_rows([cc.format_row(datetime.now(timezone.utc), result)])
    print(f"  → {result.scenario} {result.status} {result.reason}")
    return 0 if result.status in ("PASS", "SKIP") else 1


if __name__ == "__main__":
    sys.exit(main())
