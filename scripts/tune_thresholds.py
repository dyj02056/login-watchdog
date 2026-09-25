# ============================================================================
# tune_thresholds.py — 최근 N일간 CRITICAL(IP/계정 잠금) 이벤트 중, 관리자가
# 자동 만료(LOCKOUT_DURATION_SECONDS)를 다 기다리지 않고 훨씬 빨리 수동으로
# 풀어준 비율을 집계해서, 지금 탐지 임계값이 너무 예민한 건 아닌지 점검하는
# 리포트 스크립트 (Track C guide30, 임계값 튜닝)
#
# "조기 해제"란? IP/계정을 잠근 뒤(CRITICAL 이벤트), 자동으로 풀릴 시각이 되기도
# 전에 관리자가 대시보드의 "즉시 해제" 버튼이나 scripts/unlock_ip.py로 먼저
# 풀어준 경우를 말한다. 이 비율이 높으면 "정상 사용자까지 잠그고 있어서
# 관리자가 계속 수동으로 풀어주고 있다"는 신호로 볼 수 있다 — 그렇다면
# FAILURE_THRESHOLD 같은 임계값을 더 느슨하게 조정하는 걸 검토해야 한다.
#
# 판단 기준: resolved_at - detected_at 간격이 config.LOCKOUT_DURATION_SECONDS의
# --early-release-ratio(기본 50%) 미만이면 "조기 해제"로 분류한다. 관리자가
# 정확히 언제 버튼을 눌렀는지 초 단위로 알 수는 없지만, 자동 만료 시간의
# 절반도 안 돼서 풀렸다면 "자동 만료를 기다리지 않았다"고 봐도 무방하다.
#
# 이 스크립트는 새 표를 만들지 않고 기존 security_events만 조회한다 — 다른
# 조사·조치 스크립트와 달리 서버에 아무 영향도 주지 않는 완전한 읽기 전용 도구다.
# ============================================================================

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime

from dotenv import load_dotenv

# daily_report.py/unlock_ip.py와 동일한 이유: scripts/ 폴더 밖(프로젝트 루트)에
# 있는 db.py/config.py를 "python scripts/tune_thresholds.py"로 실행해도 항상
# 찾을 수 있도록 경로를 추가해준다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import config  # noqa: E402  (load_dotenv()가 SUPABASE_URL 등을 먼저 읽어들인 뒤에 import 해야 함)
import db  # noqa: E402

DEFAULT_EARLY_RELEASE_RATIO = 0.5

# 이 비율 이상이 "조기 해제"면 화면에 재검토 권장 표시를 붙인다. 정답이 있는
# 값이 아니라 팀이 임의로 정한 기준이므로, 실제로 운영하면서 편한 값으로
# 바꿔도 된다 — 이 스크립트는 판단을 대신 내려주는 게 아니라 판단에 참고할
# 숫자만 보여준다.
REVIEW_RECOMMENDATION_RATIO = 0.3


def elapsed_seconds(detected_at: str, resolved_at: str) -> float:
    """두 ISO 시각 문자열(예: "2026-09-25T09:08:50+00:00") 사이의 초 단위 간격을 계산한다."""
    detected = datetime.fromisoformat(detected_at)
    resolved = datetime.fromisoformat(resolved_at)
    return (resolved - detected).total_seconds()


def build_report(days: int, early_release_ratio: float) -> str:
    """지난 `days`일간의 CRITICAL 이벤트를 event_type별로 묶어서, 조기 해제
    비율을 계산한 사람이 읽기 좋은 리포트 문자열을 만든다.
    """
    events = db.list_resolved_critical_events_since(days * 24)
    early_release_cutoff = config.LOCKOUT_DURATION_SECONDS * early_release_ratio

    by_type = defaultdict(lambda: {"total": 0, "early": 0})
    for event in events:
        elapsed = elapsed_seconds(event["detected_at"], event["resolved_at"])
        stats = by_type[event["event_type"]]
        stats["total"] += 1
        if elapsed < early_release_cutoff:
            stats["early"] += 1

    lines = [
        f"===== 로그인 워치독 임계값 튜닝 리포트 (최근 {days}일) =====",
        f"기준: 잠금 후 {early_release_cutoff:.0f}초 미만에 풀리면 '조기 해제'로 분류"
        f" (자동 해제 시간 {config.LOCKOUT_DURATION_SECONDS}초의 {early_release_ratio:.0%})",
        "",
    ]

    if not by_type:
        lines.append("해당 기간에 해결된 CRITICAL 이벤트가 없습니다.")
        return "\n".join(lines)

    total_all = 0
    early_all = 0
    for event_type, stats in sorted(by_type.items()):
        total, early = stats["total"], stats["early"]
        total_all += total
        early_all += early
        ratio = early / total if total else 0
        flag = " <- 기준 재검토 권장" if ratio >= REVIEW_RECOMMENDATION_RATIO else ""
        lines.append(f"{event_type}: {total}건 중 {early}건({ratio:.0%}) 조기 해제{flag}")

    overall_ratio = early_all / total_all if total_all else 0
    lines.append("")
    lines.append(f"전체: {total_all}건 중 {early_all}건({overall_ratio:.0%}) 조기 해제")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="최근 N일간 CRITICAL 잠금 중 조기 해제 비율을 집계해 임계값 재검토 여부를 판단하는 리포트."
    )
    parser.add_argument("--days", type=int, default=7, help="며칠 전부터 집계할지 (기본값: 7일)")
    parser.add_argument(
        "--early-release-ratio",
        type=float,
        default=DEFAULT_EARLY_RELEASE_RATIO,
        # argparse는 help 문자열의 "%"를 %(default)s 같은 서식 지정자로 해석하려
        # 시도한다 — 글자 그대로의 "%"를 쓰려면 "%%"로 이스케이프해야
        # add_argument() 시점에 ValueError("badly formed help string")가 나지 않는다.
        help=f"자동 해제 시간 대비 몇 %% 미만이면 조기 해제로 볼지, 0~1 사이 값 (기본값: {DEFAULT_EARLY_RELEASE_RATIO})",
    )
    args = parser.parse_args()

    if args.days <= 0:
        parser.error("--days는 1 이상의 정수여야 합니다.")
    if not (0 < args.early_release_ratio < 1):
        parser.error("--early-release-ratio는 0과 1 사이여야 합니다.")

    print(build_report(args.days, args.early_release_ratio))


if __name__ == "__main__":
    main()
