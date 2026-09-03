# ============================================================================
# daily_report.py — 지난 하루(기본 24시간) 동안의 로그인 시도/잠금 현황을
# 텍스트로 요약해서 콘솔에 출력하는 스크립트
#
# 원래 기획서(research.md 질문 8)는 "LLM(AI)이 로그를 읽고 자연어로 요약해주는
# 리포트"를 그리고 있었지만, plan.md 8행/365행에 적혀있듯 프롬프트 설계·모델
# 선택 등 세부 사양이 정해지지 않아 "이번 계획 범위에서 제외"로 의도적으로
# 미뤄둔 기능이다. 그 결정 자체는 바뀌지 않았다.
#
# 다만 이 파일이 0바이트로 방치되어 있으면 "검증/운영 스크립트가 실제로는
# 하나도 없다"는 문제가 남으므로, AI 요약 없이도 바로 쓸 수 있는 축소판(숫자
# 집계 기반 요약)을 우선 채워둔다. 나중에 LLM 연동을 붙일 때도 이 집계 로직
# (db.list_attempts_since / db.list_lockouts_since)은 "요약할 원본 데이터를
# 모으는 부분"으로 그대로 재사용할 수 있다.
# ============================================================================

import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timezone

from dotenv import load_dotenv

# 이 스크립트는 scripts/ 폴더 안에 있어서, "python scripts/daily_report.py"로
# 실행하면 파이썬이 기본적으로 scripts/ 폴더에서만 모듈을 찾는다. db.py는
# 프로젝트 루트(scripts/의 부모 폴더)에 있으므로, 그 루트 폴더를 sys.path에
# 직접 추가해줘야 "import db"가 어느 위치에서 실행하든 항상 성공한다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import db  # noqa: E402  (load_dotenv()가 SUPABASE_URL 등을 먼저 읽어들인 뒤에 import 해야 함)


def build_report(hours: int) -> str:
    """지난 `hours`시간의 로그인 시도/잠금 기록을 모아 사람이 읽을 텍스트 리포트로 만든다."""
    attempts = db.list_attempts_since(hours)
    lockouts = db.list_lockouts_since(hours)

    total = len(attempts)
    failures = [a for a in attempts if not a["success"]]
    successes = total - len(failures)

    # Counter: 리스트 안에서 어떤 값이 몇 번씩 나왔는지 세어주는 표준 라이브러리 도구.
    # "실패가 가장 많았던 IP 상위 5개"를 뽑을 때 쓴다.
    failure_ip_counts = Counter(a["ip_address"] for a in failures)
    top_ips = failure_ip_counts.most_common(5)

    lines = [
        f"===== 로그인 워치독 일일 리포트 (최근 {hours}시간) =====",
        f"생성 시각: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"전체 로그인 시도: {total}건 (성공 {successes}건 / 실패 {len(failures)}건)",
        f"신규 IP 잠금 발생: {len(lockouts)}건",
        "",
    ]

    if top_ips:
        lines.append("실패가 가장 많았던 IP (상위 5개):")
        for ip, count in top_ips:
            lines.append(f"  - {ip}: 실패 {count}건")
    else:
        lines.append("실패한 로그인 시도가 없었습니다.")

    if lockouts:
        lines.append("")
        lines.append("이 기간에 잠긴 IP 목록:")
        for lockout in lockouts:
            lines.append(
                f"  - {lockout['ip_address']} "
                f"(실패 {lockout['failure_count']}회, {lockout['locked_at']} 잠금)"
            )

    lines.append("")
    lines.append(
        "[참고] 이 리포트는 숫자 집계만 보여준다. 이상 징후에 대한 자연어 해설/AI 요약은 "
        "아직 범위 밖 기능이다(research.md 질문 8, plan.md 참고)."
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="로그인 워치독 일일 요약 리포트를 출력한다.")
    parser.add_argument(
        "--hours", type=int, default=24,
        help="몇 시간 동안의 기록을 집계할지 (기본값 24시간 = 하루)",
    )
    args = parser.parse_args()
    print(build_report(args.hours))


if __name__ == "__main__":
    main()
