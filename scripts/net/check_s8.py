"""S8 자동 점검 — 신뢰하지 않는 출발지의 위조 X-Forwarded-For를 앱이 믿지 않는지 확인한다.

실행 방법(저장소 루트에서, docker compose로 단지를 켠 뒤):
    python -m scripts.net.check_s8

재현(이 시나리오만 공격 상자를 쓰지 않는다):
    gateway를 거치지 않는 요청은 edge 전용 공격 상자로 보낼 수 없다. 그래서 core 망에 붙은 shipper 안에서
    docker compose exec -T shipper python -c "..." 로 http://app:5000/<실행마다 다른 없는 경로> 에
    X-Forwarded-For: 1.2.3.4 를 붙여 GET 을 한 번만 보낸다(shipper 이미지에 requests가 있다).
    이 요청 하나 말고는 새 요청을 만들지 않는다.
기대 결과(PASS):
    - not_found_attempts에서 그 경로의 행을 찾았고, 그 ip_address가 1.2.3.4가 "아님"
      (shipper는 신뢰 프록시가 아니라 앱이 위조 헤더를 무시하고 실제 출발지를 기록해야 한다)
    - 행이 없으면 FAIL
DB는 읽기만 한다.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone

from scripts.net import check_common as cc

SCENARIO = "S8"
SPOOFED = "1.2.3.4"


def run(ctx) -> cc.CheckResult:
    client = ctx.client
    path = cc.random_s8_path()
    print(f"  [{SCENARIO}] shipper 안에서 {path} 로 위조 X-Forwarded-For GET 1회")
    sent = subprocess.run(cc.s8_request_command(path), cwd=cc.ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=60)
    if sent.returncode != 0:
        reason = (sent.stderr.strip().splitlines() or ["원인 불명"])[0][:120]
        # 결과 표의 "출발지 IP" 칸은 앱이 실제로 기록한 주소를 적는 자리다. 위조값을 적으면 그 주소에서
        # 온 것처럼 읽히므로, 기록을 못 찾은 경우에는 비워 둔다(표에는 "-").
        return cc.CheckResult(SCENARIO, "FAIL", f"shipper에서 요청을 보내지 못함: {reason}", None)

    rows = cc.wait_until(lambda: cc.not_found_rows(client, path) or None) or []
    if not rows:
        return cc.CheckResult(SCENARIO, "FAIL", f"not_found_attempts에 {path} 행이 없음", None)
    recorded = sorted({row.get("ip_address") or "?" for row in rows})
    recorded_ip = ", ".join(recorded)
    if SPOOFED in recorded:
        return cc.CheckResult(SCENARIO, "FAIL", f"위조 주소 {SPOOFED}가 그대로 기록됨(헤더를 믿어 버림)", recorded_ip)
    return cc.CheckResult(SCENARIO, "PASS", f"위조 헤더({SPOOFED}) 무시됨 — 실제 출발지가 기록됨", recorded_ip)


def main() -> int:
    cc.preflight()
    from types import SimpleNamespace

    ctx = SimpleNamespace(client=cc.get_reader(), prefix=cc.edge_prefix())
    result = run(ctx)
    cc.append_rows([cc.format_row(datetime.now(timezone.utc), result)])
    print(f"  → {result.scenario} {result.status} {result.reason}")
    return 0 if result.status in ("PASS", "SKIP") else 1


if __name__ == "__main__":
    sys.exit(main())
