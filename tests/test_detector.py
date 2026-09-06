# ============================================================================
# test_detector.py — detector.py(판사 역할)가 진짜 Supabase 없이도
# 올바르게 판단하는지 확인하는 단위 테스트
#
# monkeypatch란? pytest가 기본으로 제공하는 도구로, 테스트가 끝나면 자동으로
# 원래 상태로 되돌려주는 "임시 부품 교체"다. 여기서는 db.count_recent_failures와
# db.get_active_lockout을 "내가 정해준 값을 그대로 돌려주는 가짜 함수"로 잠깐
# 바꿔치기해서, 진짜 데이터베이스에 접속하지 않고도 detector.py의 판정
# 로직(부등호 비교, None 여부 확인)만 순수하게 확인한다.
# ============================================================================

import db
import detector


def test_is_suspicious_false_when_failures_below_threshold(monkeypatch):
    # count_recent_failures가 4를 돌려주는 상황을 흉내낸다 (기준치 5 이하).
    monkeypatch.setattr(db, "count_recent_failures", lambda ip: 4)

    suspicious, count = detector.is_suspicious("1.2.3.4")

    assert suspicious is False
    assert count == 4


def test_is_suspicious_false_at_exact_threshold(monkeypatch):
    # 정확히 5번 실패한 "경계값(boundary)"에서는 아직 수상하지 않아야 한다
    # (기획서 규칙: "5회 초과"부터 수상함, 5회 자체는 아직 봐준다).
    monkeypatch.setattr(db, "count_recent_failures", lambda ip: 5)

    suspicious, count = detector.is_suspicious("1.2.3.4")

    assert suspicious is False
    assert count == 5


def test_is_suspicious_true_when_failures_exceed_threshold(monkeypatch):
    # 6번 실패하면 기준치(5)를 "초과"했으므로 수상해야 한다.
    monkeypatch.setattr(db, "count_recent_failures", lambda ip: 6)

    suspicious, count = detector.is_suspicious("1.2.3.4")

    assert suspicious is True
    assert count == 6


def test_is_admin_suspicious_false_at_exact_threshold(monkeypatch):
    # count_recent_failures와 마찬가지로 count_recent_admin_failures를 흉내낸다 —
    # 관리자 로그인 실패는 admin_login_log에서 세므로 별도 함수를 바꿔치기한다.
    monkeypatch.setattr(db, "count_recent_admin_failures", lambda ip: 5)

    suspicious, count = detector.is_admin_suspicious("1.2.3.4")

    assert suspicious is False
    assert count == 5


def test_is_admin_suspicious_true_when_failures_exceed_threshold(monkeypatch):
    monkeypatch.setattr(db, "count_recent_admin_failures", lambda ip: 6)

    suspicious, count = detector.is_admin_suspicious("1.2.3.4")

    assert suspicious is True
    assert count == 6


def test_count_distinct_usernames_passes_through_db_value(monkeypatch):
    # count_distinct_usernames는 판정을 하지 않고 db.py가 센 값을 그대로 전달만 한다.
    monkeypatch.setattr(db, "count_recent_distinct_usernames", lambda ip: 3)

    assert detector.count_distinct_usernames("1.2.3.4") == 3


def test_count_distinct_admin_usernames_passes_through_db_value(monkeypatch):
    monkeypatch.setattr(db, "count_recent_distinct_admin_usernames", lambda ip: 2)

    assert detector.count_distinct_admin_usernames("1.2.3.4") == 2


def test_is_signup_rate_limited_false_below_limit(monkeypatch):
    # SIGNUP_RATE_LIMIT 기본값은 5 — 4번까지는 아직 제한하지 않는다.
    monkeypatch.setattr(db, "count_recent_signup_attempts", lambda ip: 4)

    assert detector.is_signup_rate_limited("1.2.3.4") is False


def test_is_signup_rate_limited_true_at_limit(monkeypatch):
    # 로그인 실패(초과부터 잠금)와 달리, 가입 시도는 "기준치 이상"이면 바로 막는다.
    monkeypatch.setattr(db, "count_recent_signup_attempts", lambda ip: 5)

    assert detector.is_signup_rate_limited("1.2.3.4") is True


def test_is_post_rate_limited_false_below_limit(monkeypatch):
    # POST_RATE_LIMIT 기본값은 5 — 4번까지는 아직 제한하지 않는다.
    monkeypatch.setattr(db, "count_recent_post_attempts", lambda ip: 4)

    assert detector.is_post_rate_limited("1.2.3.4") is False


def test_is_post_rate_limited_true_at_limit(monkeypatch):
    # is_signup_rate_limited와 동일하게 "기준치 이상"이면 바로 막는다.
    monkeypatch.setattr(db, "count_recent_post_attempts", lambda ip: 5)

    assert detector.is_post_rate_limited("1.2.3.4") is True


def test_is_comment_rate_limited_false_below_limit(monkeypatch):
    # COMMENT_RATE_LIMIT 기본값은 10 — 9번까지는 아직 제한하지 않는다.
    monkeypatch.setattr(db, "count_recent_comment_attempts", lambda ip: 9)

    assert detector.is_comment_rate_limited("1.2.3.4") is False


def test_is_comment_rate_limited_true_at_limit(monkeypatch):
    monkeypatch.setattr(db, "count_recent_comment_attempts", lambda ip: 10)

    assert detector.is_comment_rate_limited("1.2.3.4") is True


def test_is_web_scanning_false_at_exact_threshold(monkeypatch):
    # WEB_SCANNING_ALERT_THRESHOLD 기본값은 10 — 정확히 10회는 아직 수상하지 않다
    # (is_suspicious와 동일하게 "초과"부터 수상함).
    monkeypatch.setattr(db, "count_recent_not_found_attempts", lambda ip: 10)

    suspicious, count = detector.is_web_scanning("1.2.3.4")

    assert suspicious is False
    assert count == 10


def test_is_web_scanning_true_when_exceeds_threshold(monkeypatch):
    monkeypatch.setattr(db, "count_recent_not_found_attempts", lambda ip: 11)

    suspicious, count = detector.is_web_scanning("1.2.3.4")

    assert suspicious is True
    assert count == 11


def test_is_unauthorized_access_suspicious_false_at_exact_threshold(monkeypatch):
    # UNAUTHORIZED_ACCESS_ALERT_THRESHOLD 기본값은 10 — 정확히 10회는 아직 아니다.
    monkeypatch.setattr(db, "count_recent_unauthorized_attempts", lambda ip: 10)

    suspicious, count = detector.is_unauthorized_access_suspicious("1.2.3.4")

    assert suspicious is False
    assert count == 10


def test_is_unauthorized_access_suspicious_true_when_exceeds_threshold(monkeypatch):
    monkeypatch.setattr(db, "count_recent_unauthorized_attempts", lambda ip: 11)

    suspicious, count = detector.is_unauthorized_access_suspicious("1.2.3.4")

    assert suspicious is True
    assert count == 11


def test_is_page_access_suspicious_false_at_exact_threshold(monkeypatch):
    # PAGE_ACCESS_ALERT_THRESHOLD 기본값은 20 — 정확히 20회는 아직 아니다.
    monkeypatch.setattr(db, "count_recent_page_access_attempts", lambda ip, path: 20)

    suspicious, count = detector.is_page_access_suspicious("1.2.3.4", "/board")

    assert suspicious is False
    assert count == 20


def test_is_page_access_suspicious_true_when_exceeds_threshold(monkeypatch):
    monkeypatch.setattr(db, "count_recent_page_access_attempts", lambda ip, path: 21)

    suspicious, count = detector.is_page_access_suspicious("1.2.3.4", "/board")

    assert suspicious is True
    assert count == 21


def test_is_locked_true_when_lockout_exists(monkeypatch):
    # get_active_lockout이 "잠금 정보가 있다"는 뜻으로 딕셔너리를 돌려주는 상황을 흉내낸다.
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: {"ip_address": ip, "active": True})

    assert detector.is_locked("1.2.3.4") is True


def test_is_locked_false_when_no_lockout(monkeypatch):
    # get_active_lockout이 "잠긴 게 없다"는 뜻으로 None을 돌려주는 상황을 흉내낸다.
    monkeypatch.setattr(db, "get_active_lockout", lambda ip: None)

    assert detector.is_locked("1.2.3.4") is False
