"""Track D 시연 시나리오 자동 점검 묶음 실행 (C3-1).

실행 방법(저장소 루트에서, docker compose로 단지를 켜고 시연용 .env를 쓴 뒤):
    python -m scripts.net.run_all                # 시나리오들을 3번씩 순서대로
    python -m scripts.net.run_all --repeat 1     # 한 번씩만
    python -m scripts.net.run_all --with-release # S4에서 영구 해제 후 재접속까지 확인
    # S6를 재현하려면 같은 창에 victim 비밀번호를 넣어 둔다(없으면 S6는 SKIP):
    #   $env:LW_VICTIM_PASSWORD = Read-Host "victim 비밀번호"   # PowerShell

하는 일:
    - S4 → S5 → S5b → S6 → S7 → S8 → S9 를 순서대로 --repeat 번 돌린다.
    - 각 시나리오는 재현(일회용 새 IP 공격 컨테이너, S8만 shipper 안에서 직접)을 한 뒤
      "기대 결과가 DB·응답·메일에 실제로 생겼는지"를 확인해 PASS/FAIL/SKIP을 낸다.
    - 결과 표(시각·시나리오·결과·출발지 IP·비고)를 docs/track-d/scenario-results.md 맨 아래에 덧붙인다.
종료 코드: 하나라도 FAIL이면 1, 그 외(PASS·SKIP만) 0. (SKIP은 실패로 보지 않는다.)

S7(출발지 위조)·S9(ICMP 폭주)는 guide57에서 공격 상자에 synflood --spoof-source/--rand-source와 icmpflood가
생기면서 자동 점검을 붙였다(예전에는 재현 명령이 없어 S7을 SKIP으로만 표시했다).

DB는 읽기만 한다. 비밀값은 어디에도 출력하지 않는다(시작할 때 '있음/없음'만).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

from scripts.net import check_common as cc
from scripts.net import check_s4, check_s5, check_s5b, check_s6, check_s7, check_s8, check_s9

# 순서가 있는 이유: S4(킬체인)·S5·S5b·S6은 서로 다른 공격이지만 모두 새 IP로 돌아 간섭하지 않는다.
# 보기 좋게 시나리오 번호 순서로 둔다.
CHECKS = [
    ("S4", check_s4.run),
    ("S5", check_s5.run),
    ("S5b", check_s5b.run),
    ("S6", check_s6.run),
    ("S7", check_s7.run),
    ("S8", check_s8.run),
    ("S9", check_s9.run),
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Track D 시연 시나리오 자동 점검 묶음 실행")
    parser.add_argument("--repeat", type=int, default=3, help="시나리오들을 몇 번씩 돌릴지(기본 3)")
    parser.add_argument("--with-release", action="store_true",
                        help="S4에서 영구 해제 후 재접속까지 확인(해제는 DB를 바꾼다)")
    args = parser.parse_args(argv)
    # Windows 기본 콘솔(cp949)에 없는 글자가 섞여도 멈추지 않게 못 찍는 글자는 ?로 바꾼다(measure_* 와 같은 처리).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    cc.preflight()
    prefix = cc.edge_prefix()
    if not prefix:
        print("  (!) LW_EDGE_PREFIX가 없어 대상 IP를 만들 수 없습니다. 점검을 중단합니다.")
        return 2

    ctx = SimpleNamespace(client=cc.get_reader(), prefix=prefix, with_release=args.with_release)
    rows: list[str] = []
    results: list[cc.CheckResult] = []
    repeat = max(1, args.repeat)

    for round_no in range(1, repeat + 1):
        print(f"── 회차 {round_no}/{repeat} ──")
        for name, runner in CHECKS:
            try:
                result = runner(ctx)
            except Exception as error:  # 한 시나리오가 터져도 나머지는 계속 돌린다.
                result = cc.CheckResult(name, "FAIL", f"점검 중 예외: {type(error).__name__}: {error}", None)
            _record(result, rows, results)

    cc.append_rows(rows)

    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")
    print(f"── 끝: PASS {passed} · FAIL {failed} · SKIP {skipped} (표 {len(rows)}줄을 {cc.RESULTS.name}에 추가)")
    return 1 if failed else 0


def _record(result: cc.CheckResult, rows: list[str], results: list[cc.CheckResult]) -> None:
    rows.append(cc.format_row(datetime.now(timezone.utc), result))
    results.append(result)
    print(f"  → {result.scenario} {result.status} {result.reason}")


if __name__ == "__main__":
    sys.exit(main())
