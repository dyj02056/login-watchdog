# 14단원 — 임계값 튜닝 리포트 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "14-tune-thresholds"
TITLE = "14. 임계값 튜닝 리포트"
SUBTITLE = "'우리 임계값이 너무 예민한 건 아닐까?'를 데이터로 점검하는 리포트 스크립트의 코드 흐름도"

FILE_ROLES = {
    "scripts/management/tune_thresholds.py": "터미널에서 실행하는 읽기 전용 리포트 스크립트. 서버 상태를 바꾸지 않는다.",
    "db/security_events.py": "위험등급 이벤트 표를 읽는 저장소 파일. 해결된 CRITICAL 이벤트를 모아 준다.",
    "config.py": "자동 잠금 해제 시간(LOCKOUT_DURATION_SECONDS) 등 설정값 모음.",
}

TUNE = "scripts/management/tune_thresholds.py"

s1 = Scenario("report", "리포트가 만들어지는 과정",
              "탐지 임계값이 너무 예민하면 정상 사용자까지 자주 잠기고, 관리자가 매번 수동으로 풀어줘야 합니다. 이 리포트는 '관리자가 자동 해제를 기다리지 않고 훨씬 빨리 풀어준 비율(조기 해제)'을 세서 그 신호를 보여줍니다.")
s1.screen("터미널에서 실행", "python scripts/management/tune_thresholds.py --days 7  (읽기 전용 — 서버에 아무 영향도 주지 않습니다)",
          fn=f"{TUNE}:main", hl=('parser.add_argument("--days"', "args = parser.parse_args()"))
s1.step("① 입력값 확인", "--days 는 1 이상, --early-release-ratio 는 0~1 사이여야 합니다.",
        fn=f"{TUNE}:main", hl=("if args.days <= 0:", "parser.error"), reject="--days 는 1 이상의 정수여야 합니다.")
s1.step("② 해결된 CRITICAL 이벤트 가져오기", "지난 N일 동안의 CRITICAL 이벤트 중, 발생 시각과 해결 시각이 모두 있는 것만 가져옵니다(아직 안 풀린 것은 간격을 계산할 수 없음).",
        fn=f"{TUNE}:build_report", hl="events = db.list_resolved_critical_events_since(days * 24)",
        calls=[call("db.list_resolved_critical_events_since", "해결된 CRITICAL 이벤트 목록", "event_type·detected_at·resolved_at 만 조회합니다.")])
s1.step("③ 잠금~해제 간격 계산", "발생 시각과 해결 시각의 차이를 초 단위로 구합니다. 영구 잠금 이벤트는 '자동 만료'가 없어 이 기준이 성립하지 않으므로 제외합니다.",
        fn=f"{TUNE}:build_report", hl=("for event in events:", "elapsed = elapsed_seconds"),
        calls=[call(f"{TUNE}:elapsed_seconds", "두 시각의 차이(초)", "ISO 시각 문자열 두 개를 받아 간격을 계산합니다.")])
s1.step("④ 자동 해제 시간의 50% 미만이면 '조기 해제'", "기본 5분(300초) × 0.5 = 150초 미만에 풀렸다면 자동 만료를 기다리지 않은 것으로 봅니다.",
        fn=f"{TUNE}:build_report", hl=("early_release_cutoff = config.LOCKOUT_DURATION_SECONDS * early_release_ratio", "early_release_cutoff = config.LOCKOUT_DURATION_SECONDS * early_release_ratio"),
        calls=[call(snippet=("config.py", "LOCKOUT_DURATION_SECONDS =", "LOCKOUT_DURATION_SECONDS ="), title="자동 해제 시간 (300초)", plain="이 값의 50% 미만이면 조기 해제로 분류합니다.", label="LOCKOUT_DURATION_SECONDS")])
s1.step("⑤ 유형별로 세고, 30% 이상이면 재검토 권장", "event_type 별로 '총 건수 / 조기 해제 건수 / 비율'을 출력하고, 비율이 30% 이상이면 '← 기준 재검토 권장' 표시를 붙입니다.",
        fn=f"{TUNE}:build_report", hl=("ratio = early / total if total else 0", 'lines.append(f"{event_type}'),
        calls=[call(snippet=(TUNE, "REVIEW_RECOMMENDATION_RATIO =", "REVIEW_RECOMMENDATION_RATIO ="), title="재검토 권장 기준 (30%)", plain="정답이 있는 값이 아니라 팀이 임의로 정한 기준입니다.", label="REVIEW_RECOMMENDATION_RATIO")])
s1.step("⑥ 전체 합계를 출력", "리포트는 판단을 대신 내려주지 않고 참고 수치만 보여줍니다.",
        fn=f"{TUNE}:build_report", hl=("overall_ratio = early_all / total_all if total_all else 0", 'return "\\n".join(lines)'))

SCENARIOS = [s1.build()]
