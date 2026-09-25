# ============================================================================
# test_tune_thresholds.py — scripts/tune_thresholds.py(Track C guide30)가
# CRITICAL 이벤트의 조기 해제 비율을 올바르게 집계하는지 확인하는 단위 테스트
#
# test_unlock_ip.py와 동일한 이유로, scripts/ 폴더를 sys.path에 추가해서
# "import tune_thresholds"가 되게 한다.
# ============================================================================

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)

import config
import db
import tune_thresholds  # noqa: E402  (위 sys.path 추가 이후에 import 해야 함)


def _event(event_type, detected_at, resolved_at):
    return {"event_type": event_type, "detected_at": detected_at, "resolved_at": resolved_at}


def test_elapsed_seconds_computes_difference_between_iso_timestamps():
    result = tune_thresholds.elapsed_seconds(
        "2026-09-25T09:00:00+00:00", "2026-09-25T09:01:30+00:00"
    )

    assert result == 90.0


def test_build_report_says_no_events_when_none_found(monkeypatch):
    monkeypatch.setattr(db, "list_resolved_critical_events_since", lambda hours: [])

    report = tune_thresholds.build_report(days=7, early_release_ratio=0.5)

    assert "해당 기간에 해결된 CRITICAL 이벤트가 없습니다." in report


def test_build_report_classifies_fast_release_as_early(monkeypatch):
    # LOCKOUT_DURATION_SECONDS 기본값은 300초 — 30초 만에 풀렸으면 300*0.5=150초
    # 기준보다 훨씬 빠르므로 "조기 해제"로 잡혀야 한다.
    events = [
        _event("BRUTE_FORCE", "2026-09-25T09:00:00+00:00", "2026-09-25T09:00:30+00:00"),
    ]
    monkeypatch.setattr(db, "list_resolved_critical_events_since", lambda hours: events)

    report = tune_thresholds.build_report(days=7, early_release_ratio=0.5)

    assert "BRUTE_FORCE: 1건 중 1건(100%) 조기 해제" in report
    assert "전체: 1건 중 1건(100%) 조기 해제" in report


def test_build_report_does_not_classify_full_duration_release_as_early(monkeypatch):
    # 자동 만료 시간(300초)을 거의 다 채우고 풀린 경우는 조기 해제가 아니다.
    events = [
        _event("BRUTE_FORCE", "2026-09-25T09:00:00+00:00", "2026-09-25T09:05:00+00:00"),
    ]
    monkeypatch.setattr(db, "list_resolved_critical_events_since", lambda hours: events)

    report = tune_thresholds.build_report(days=7, early_release_ratio=0.5)

    assert "BRUTE_FORCE: 1건 중 0건(0%) 조기 해제" in report


def test_build_report_groups_by_event_type_separately(monkeypatch):
    events = [
        _event("BRUTE_FORCE", "2026-09-25T09:00:00+00:00", "2026-09-25T09:00:10+00:00"),  # 조기
        _event("BRUTE_FORCE", "2026-09-25T09:00:00+00:00", "2026-09-25T09:05:00+00:00"),  # 정상
        _event("PASSWORD_SPRAYING", "2026-09-25T09:00:00+00:00", "2026-09-25T09:00:05+00:00"),  # 조기
    ]
    monkeypatch.setattr(db, "list_resolved_critical_events_since", lambda hours: events)

    report = tune_thresholds.build_report(days=7, early_release_ratio=0.5)

    assert "BRUTE_FORCE: 2건 중 1건(50%) 조기 해제" in report
    assert "PASSWORD_SPRAYING: 1건 중 1건(100%) 조기 해제" in report
    assert "전체: 3건 중 2건(67%) 조기 해제" in report


def test_build_report_flags_high_ratio_for_review(monkeypatch):
    # REVIEW_RECOMMENDATION_RATIO(0.3) 이상이면 재검토 권장 표시가 붙어야 한다.
    events = [
        _event("BRUTE_FORCE", "2026-09-25T09:00:00+00:00", "2026-09-25T09:00:10+00:00"),
    ]
    monkeypatch.setattr(db, "list_resolved_critical_events_since", lambda hours: events)

    report = tune_thresholds.build_report(days=7, early_release_ratio=0.5)

    assert "기준 재검토 권장" in report


def test_build_report_passes_days_converted_to_hours(monkeypatch):
    seen_hours = []
    monkeypatch.setattr(
        db, "list_resolved_critical_events_since", lambda hours: seen_hours.append(hours) or []
    )

    tune_thresholds.build_report(days=3, early_release_ratio=0.5)

    assert seen_hours == [3 * 24]


def test_build_report_uses_configured_lockout_duration_for_cutoff(monkeypatch):
    monkeypatch.setattr(config, "LOCKOUT_DURATION_SECONDS", 1000)
    monkeypatch.setattr(db, "list_resolved_critical_events_since", lambda hours: [])

    report = tune_thresholds.build_report(days=7, early_release_ratio=0.5)

    assert "잠금 후 500초 미만" in report
