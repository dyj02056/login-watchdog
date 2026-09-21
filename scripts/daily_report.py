# ============================================================================
# daily_report.py — 지정한 시간 범위(상대 시간 또는 정적 기간) 동안의
# 로그인 시도/잠금 현황을 텍스트 리포트로 생성하고 출력/저장하는 스크립트.
# ============================================================================

import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timezone

from dotenv import load_dotenv

# 이 스크립트는 scripts/ 폴더 안에 있으므로,
# 프로젝트 최상위(루트) 폴더를 sys.path에 추가하여 import db 가 항상 성공하도록 함.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import db  # noqa: E402


def build_report(
    hours: int = None,
    start: str = None,
    end: str = None,
    llm_summary: str = None,
) -> str:
    """로그인 시도/잠금 기록을 모아 사람이 읽을 수 있는 텍스트 리포트를 생성한다.

    Args:
        hours (int, optional): 최근 몇 시간의 기록을 집계할지 설정 (기본값: 24시간).
        start (str, optional): 정적 조회 시작 시각 (예: '2026-09-01T00:00:00').
        end (str, optional): 정적 조회 종료 시각 (예: '2026-09-01T12:00:00').
        llm_summary (str, optional): LLM이 생성한 보안 요약/총평 문장.
    """
    # 1. 정적 기간 조회 (--start 및 --end 지정 시)
    if start and end:
        attempts = db.list_attempts_between(start, end)
        # lockouts 표에도 between 조회가 구현되어 있다면 사용, 없을 경우 list_lockouts_since로 fallback
        if hasattr(db, "list_lockouts_between"):
            lockouts = db.list_lockouts_between(start, end)
        else:
            lockouts = db.list_lockouts_since(24)
        period_info = f"조회 기간: {start} ~ {end}"

    # 2. 상대적 시간 조회 (--hours 지정 시 또는 기본 동작)
    else:
        target_hours = hours if hours is not None else 24
        attempts = db.list_attempts_since(target_hours)
        lockouts = db.list_lockouts_since(target_hours)
        period_info = f"최근 {target_hours}시간 기준"

    total = len(attempts)
    failures = [a for a in attempts if not a["success"]]
    successes = total - len(failures)

    failure_ip_counts = Counter(a["ip_address"] for a in failures)
    top_ips = failure_ip_counts.most_common(5)

    lines = [
        f"===== 로그인 워치독 보안 리포트 ({period_info}) =====",
        f"생성 시각: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
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

    # LLM 보안 총평 섹션 (llm_summary 값이 전달되었을 때 추가)
    if llm_summary:
        lines.append("")
        lines.append("--------------------------------------------------")
        lines.append("[AI 보안 총평 & 분석]")
        lines.append(llm_summary)
        lines.append("--------------------------------------------------")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="로그인 워치독 일일/기간별 요약 리포트를 출력 및 저장합니다."
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="몇 시간 전부터 현재까지 집계할지 설정 (기본값: 24시간)",
    )
    parser.add_argument(
        "--start",
        type=str,
        default=None,
        help="조회 시작 시각 (ISO format, 예: 2026-09-01T00:00:00)",
    )
    parser.add_argument(
        "--end",
        type=str,
        default=None,
        help="조회 종료 시각 (ISO format, 예: 2026-09-01T12:00:00)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="리포트 결과를 저장할 파일 경로 (예: report.txt)",
    )
    args = parser.parse_args()

    # --start 와 --end 가 모두 들어온 경우는 정적 기간 조회
    if args.start and args.end:
        report_text = build_report(start=args.start, end=args.end)
    else:
        report_text = build_report(hours=args.hours)

    # 콘솔 출력
    print(report_text)

    # 파일 저장 옵션 지정 시 저장 실행
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n[+] 리포트가 성공적으로 저장되었습니다: {args.output}")


if __name__ == "__main__":
    main()