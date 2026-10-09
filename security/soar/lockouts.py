# ============================================================================
# security/soar/lockouts.py — 잠금 집행(IP/회원 계정/관리자 계정)과 자동·수동 해제
#
# 예전 soar.py(497줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from security import soar` 후 `soar.enforce_lockout(...)`으로
# 쓴다(security/soar/__init__.py가 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

from datetime import datetime, timezone

import db
from notify import alert
from security import lockdown
from security.soar._events import _record_event


def enforce_lockout(
    ip: str, failure_count: int, distinct_usernames: int, is_admin: bool = False
) -> None:
    """이 IP에 실제로 잠금을 걸고, 그 사실을 Slack으로 알리고, CRITICAL 이벤트로 기록한다.

    네 단계로 이루어진다:
    1. db.create_lockout()으로 "이 IP는 지금부터 5분간 잠김"을 데이터베이스에 저장
    2. alert.send_lockout_alert()로 "IP, 실패 횟수, 조치 내용"을 담은 알림을 전송
    3. _record_event()로 위험등급(CRITICAL)과 함께 security_events에 기록하고 상관분석 훅 호출
       (security-risk-response-summary.md 5절 — 관리자 대시보드/이력 조회용)
    4. lockdown.after_temporary_lock()으로 잠금 이력을 남기고 영구 잠금 승격 여부 판단(guide33)

    알림을 "잠그는 순간에 딱 한 번만" 보내는 이유: 만약 잠긴 상태에서도 계속
    로그인을 시도할 때마다 매번 알림을 보내면, 관리자가 알림 폭탄을 맞아 정작
    중요한 알림을 놓치게 된다(이른바 "알림 피로"). 그래서 "새로 잠기는 순간"에만 알린다.

    distinct_usernames는 detector.count_distinct_usernames()(또는 관리자용)가 센
    "이 IP가 최근에 시도한 서로 다른 아이디 개수"다 — 1개면 계정 하나에 집중된
    Brute Force, 2개 이상이면 여러 계정을 돌아가며 두드리는 Password Spraying으로
    의심할 수 있으므로, notify/alert.py가 Slack 메시지에 이 값으로 패턴을 구분해 보여준다.

    is_admin은 이 잠금이 /login이 아니라 /admin/login에서 발생했는지를 나타낸다 —
    관리자 로그인 무차별 대입은 Brute Force/Password Spraying과 별도의 event_type으로
    기록하고, notify/alert.py의 Slack 메시지에도 그대로 표시한다.
    """
    db.create_lockout(ip, failure_count)
    alert.send_lockout_alert(
        ip, failure_count, datetime.now(timezone.utc), distinct_usernames, is_admin
    )

    if is_admin:
        event_type = "ADMIN_BRUTE_FORCE"
    elif distinct_usernames > 1:
        event_type = "PASSWORD_SPRAYING"
    else:
        event_type = "BRUTE_FORCE"
    _record_event(event_type, "CRITICAL", ip, None, failure_count, "LOCKED")

    # 잠금 이력을 남기고, 최근 기간 안에 N번째 잠금이면 영구 잠금으로 승격한다
    # (guide33, T1/T5). 임시 잠금 알림·이벤트 기록이 모두 끝난 뒤에 실행해서, 영구
    # 잠금 이벤트(PERMANENT_LOCK)가 같은 사건의 "그 다음 단계"로 기록되게 한다.
    lockdown.after_temporary_lock("ip", ip, event_type, failure_count)


def enforce_account_lockout(
    username: str, failure_count: int, distinct_ip_count: int, triggering_ip: str
) -> None:
    """이 계정에 실제로 잠금을 걸고, Slack으로 알리고, CRITICAL 이벤트로 기록한다.

    enforce_lockout()(IP 잠금)과 짝을 이루는 계정 잠금 버전이다 — 공격이 여러
    IP에 나뉘어 있어 IP 잠금만으로는 못 잡을 때, 계정 자체를 잠가서 막는다
    (L7 공격 보강 계획 Tier 1: 분산/저속 브루트포스 대응).

    triggering_ip는 "잠금을 유발한 마지막 시도의 IP"다 — 실제 잠금 판단
    기준(계정 전체 실패 횟수, IP와 무관)과는 별개로, security_events에서
    이벤트를 훑어보는 관리자가 "가장 최근엔 어디서 왔는지" 참고할 수 있게
    남겨둔다.
    """
    db.create_account_lockout(username, failure_count)
    alert.send_account_lockout_alert(
        username, failure_count, datetime.now(timezone.utc), distinct_ip_count
    )
    _record_event(
        "DISTRIBUTED_BRUTE_FORCE",
        "CRITICAL",
        triggering_ip,
        None,
        failure_count,
        "ACCOUNT_LOCKED",
        username=username,
    )
    # 계정 잠금 이력 + 영구 승격 판단(guide33, T2). enforce_lockout()의 같은 자리 주석 참고.
    lockdown.after_temporary_lock(
        "account", username, "DISTRIBUTED_BRUTE_FORCE", failure_count, triggering_ip=triggering_ip
    )


def enforce_admin_account_lockout(
    username: str, failure_count: int, distinct_ip_count: int, triggering_ip: str
) -> None:
    """관리자 계정에 잠금을 걸고, Slack으로 알리고, CRITICAL 이벤트로 기록한다(guide38).

    enforce_account_lockout()의 관리자 버전이다. 다른 점은 둘이다.
    - 회원 표(account_lockouts)가 아니라 admin_account_lockouts에 잠근다 — 같은 이름의
      회원과 서로 영향을 주지 않게 한다.
    - 영구 잠금으로 올리지 않는다(lockdown.after_temporary_lock을 부르지 않는다). 관리자를
      영구히 못 들어오게 만드는 것 자체가 공격자가 노리는 서비스 거부가 되기 때문이다.
      감사 추적을 위해 잠금 이력(lock_history)에는 한 줄 남긴다.
    """
    db.create_admin_account_lockout(username, failure_count)
    alert.send_account_lockout_alert(
        username, failure_count, datetime.now(timezone.utc), distinct_ip_count, is_admin=True
    )
    _record_event(
        db.ADMIN_ACCOUNT_LOCK_EVENT_TYPE,
        "CRITICAL",
        triggering_ip,
        None,
        failure_count,
        "ACCOUNT_LOCKED",
        username=username,
    )
    db.insert_lock_history(
        "admin_account", username, "TEMPORARY", "THRESHOLD", db.ADMIN_ACCOUNT_LOCK_EVENT_TYPE
    )


def _release_admin_account(username: str) -> bool:
    """관리자 계정 잠금을 풀고, 그 잠금의 CRITICAL 이벤트만 정리한다(같은 이름 회원 이벤트는 그대로)."""
    released = db.release_admin_account_lockout(username)
    if released:
        db.resolve_security_events_for_username(username, [db.ADMIN_ACCOUNT_LOCK_EVENT_TYPE])
    return released


def try_release_expired_admin_account_lockouts() -> None:
    """잠금 시간이 지난 관리자 계정 잠금을 풀어준다(try_release_expired_account_lockouts()의 관리자 버전)."""
    for lockout in db.list_expired_active_admin_account_lockouts():
        _release_admin_account(lockout["username"])


def manual_release_admin_account(username: str) -> bool:
    """대시보드 "즉시 해제"(super_admin 전용) 또는 CLI로 관리자 계정 잠금을 푼다. 잠겨 있지 않았으면 False."""
    if db.get_active_admin_account_lockout(username) is None:
        return False
    return _release_admin_account(username)


def try_release_expired_account_lockouts() -> None:
    """5분이 지났는데 아직 안 풀린 계정 잠금들을 찾아서 전부 풀어준다.

    try_release_expired_lockouts()(IP 잠금)와 동일하게, 별도의 타이머 프로그램
    없이 요청이 들어올 때마다 확인하는 방식으로 "자동 해제"를 흉내낸다.
    """
    for lockout in db.list_expired_active_account_lockouts():
        db.release_account_lockout(lockout["username"])
        db.resolve_security_events_for_username(lockout["username"])


def try_release_expired_lockouts() -> None:
    """"5분이 지났는데 아직 안 풀린" 잠금들을 찾아서 전부 풀어준다.

    이 프로젝트는 "정해진 시각이 되면 자동으로 실행되는 타이머 프로그램"을
    따로 두지 않는다(구현이 복잡해지므로 이번 계획 범위 밖). 대신 이 함수를
    `/login` 요청이 들어올 때, 그리고 대시보드가 상태를 갱신할 때(정해진 간격마다 —
    config.ADMIN_STATUS_RELEASE_INTERVAL_SECONDS, guide46) 호출해서
    "혹시 지금 풀어줘야 할 게 있나?"를 그때그때 확인하는 방식으로 "자동 해제"를
    흉내낸다. 트래픽(요청)이 없으면 실제 해제 반영이 살짝 늦어질 수 있지만,
    이 프로젝트 규모에서는 문제되지 않는다.
    """
    for lockout in db.list_expired_active_lockouts():
        db.release_lockout(lockout["ip_address"])
        db.resolve_security_events_for_ip(lockout["ip_address"])
        # 연관 사건(security_incidents)은 여기서 닫지 않는다 — 접속 차단을 거두는
        # 것과 "관리자가 검토를 마쳤다"는 판단은 별개이므로, 사건은 관리자가
        # 대시보드의 "해결" 버튼(db.resolve_incident)을 눌러야만 CLOSED가 된다.


def manual_release(ip: str) -> bool:
    """관리자가 대시보드의 "즉시 해제" 버튼을 눌렀을 때 호출되는 함수.

    동작 순서:
    1. 지금 잠겨있는 IP 목록을 전부 가져와서, 그 안에 이 ip가 있는지 확인한다.
    2. 있다면 실제로 풀어주고 True(성공)를 돌려준다.
    3. 애초에 잠긴 적이 없다면 아무것도 하지 않고 False(할 일 없음)를 돌려준다.

    주의: 이 함수는 "이 요청을 보낸 사람이 진짜 관리자인지"는 전혀 확인하지 않는다.
    그 권한 확인은 라우트의 require_permission 문지기(helpers/auth.py)가 미리 걸러주고, 이 함수는
    "이미 권한이 확인된 사람"의 요청만 받는다고 가정하고 동작한다.
    """
    active = {row["ip_address"]: row for row in db.list_active_lockouts()}
    if ip not in active:
        return False
    # 영구 잠금은 이 "즉시 해제"로 풀지 않는다 — 사유 기록과 권한 분리(release_permanent_lock,
    # super_admin 전용)가 필요한 별도 경로(lockdown.release)로만 풀 수 있다(guide33).
    if active[ip].get("lock_type") == "PERMANENT":
        return False
    db.release_lockout(ip)
    db.resolve_security_events_for_ip(ip)
    # 연관 사건은 닫지 않는다 — try_release_expired_lockouts()의 같은 자리 주석 참고.
    return True


def manual_release_account(username: str) -> bool:
    """관리자가 대시보드에서 잠긴 "계정"의 "즉시 해제" 버튼을 눌렀을 때 호출된다.

    manual_release()의 계정 버전이다. 지금 잠긴 계정이 아니면 아무것도 하지 않고
    False를, 풀었다면 관련 보안 이벤트까지 정리하고 True를 돌려준다 —
    try_release_expired_account_lockouts()의 자동 해제와 같은 후속 처리다.
    """
    lockout = db.get_active_account_lockout(username)
    if lockout is None:
        return False
    # 영구 계정 잠금은 lockdown.release()로만 푼다(manual_release()의 같은 자리 주석 참고).
    if lockout.get("lock_type") == "PERMANENT":
        return False
    db.release_account_lockout(username)
    db.resolve_security_events_for_username(username)
    return True
