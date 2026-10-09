# ============================================================================
# security/ — 보안 엔진: 탐지 → 상관분석 → 대응
#
#   security/detector.py   — "수상한가?" 판정만 한다 (임계값 비교, 잠금 상태 조회)
#   security/correlate.py  — 같은 IP의 서로 다른 이벤트를 하나의 사건으로 묶는다 (SIEM, guide27)
#   soar/         — 판정 결과를 실제 조치(잠금·알림·해제·조기 경보)로 실행한다 (SOAR, guide28)
#   security/lockdown.py   — 임시 잠금을 영구 잠금으로 승격·해제·복구한다 (guide33)
#
# 이 파일은 일부러 비워둔다(재내보내기 없음) — 호출부는 `from security import detector`처럼
# 모듈 단위로 가져다 쓰고, 테스트도 `monkeypatch.setattr(detector, ...)`로 그 모듈을 바꿔치기한다.
# 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================
