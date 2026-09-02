# ============================================================================
# test_config.py — "회귀 테스트(regression test)"
#
# 회귀 테스트란: 기획서에서 정해둔 숫자(5회, 60초, 300초)를 나중에 누군가
# 실수로 바꿔도 곧바로 알아챌 수 있게, "이 값들은 항상 이래야 한다"고
# 못 박아두는 테스트다. 로직을 검증하는 게 아니라 "숫자 자체"를 지킨다.
# ============================================================================

import config


def test_failure_threshold_is_5():
    assert config.FAILURE_THRESHOLD == 5


def test_detection_window_is_60_seconds():
    assert config.DETECTION_WINDOW_SECONDS == 60


def test_lockout_duration_is_300_seconds():
    assert config.LOCKOUT_DURATION_SECONDS == 300
