# ============================================================================
# soar.py — "집행관" 역할: 판정 결과를 실제 조치(잠금 / 알림 / 해제)로 실행한다
#
# SOAR = Security Orchestration, Automation and Response
#        (보안 이상 징후를 자동으로 판단해 대응 조치까지 실행한다는 뜻의 보안 업계 용어)
#
# detector.py가 "수상하다"고 판단만 해주면, 이 파일이 그 판단을 받아서
# 실제로 db.py를 통해 잠금을 기록하고, alert.py를 통해 Slack 알림을 보낸다.
# "누가 이 조치를 실행할 권한이 있는가"(예: 관리자 로그인 여부)는 이 파일이
# 신경 쓰지 않는다 — 그건 5단계에서 만들 app.py가 확인해야 할 몫이다.
# ============================================================================

from datetime import datetime, timezone

import alert
import db


def enforce_lockout(ip: str, failure_count: int, distinct_usernames: int) -> None:
    """이 IP에 실제로 잠금을 걸고, 그 사실을 Slack으로 알린다.

    두 단계로 이루어진다:
    1. db.create_lockout()으로 "이 IP는 지금부터 5분간 잠김"을 데이터베이스에 저장
    2. alert.send_lockout_alert()로 "IP, 실패 횟수, 조치 내용"을 담은 알림을 전송

    알림을 "잠그는 순간에 딱 한 번만" 보내는 이유: 만약 잠긴 상태에서도 계속
    로그인을 시도할 때마다 매번 알림을 보내면, 관리자가 알림 폭탄을 맞아 정작
    중요한 알림을 놓치게 된다(이른바 "알림 피로"). 그래서 "새로 잠기는 순간"에만 알린다.

    distinct_usernames는 detector.count_distinct_usernames()(또는 관리자용)가 센
    "이 IP가 최근에 시도한 서로 다른 아이디 개수"다 — 1개면 계정 하나에 집중된
    Brute Force, 2개 이상이면 여러 계정을 돌아가며 두드리는 Password Spraying으로
    의심할 수 있으므로, alert.py가 Slack 메시지에 이 값으로 패턴을 구분해 보여준다.
    """
    db.create_lockout(ip, failure_count)
    alert.send_lockout_alert(ip, failure_count, datetime.now(timezone.utc), distinct_usernames)


def notify_web_scanning(ip: str, count: int, path: str) -> None:
    """Web Scanning 의심 알림을 Slack으로 보낸다.

    enforce_lockout()과 달리 db.create_lockout()을 호출하지 않는다 — 404를
    유발한 요청은 애초에 존재하지 않는 경로를 두드린 것이라 "잠글" 대상이
    없고, 이 IP를 실제로 잠그면 정상적인 다른 페이지 이용까지 막아버려 오히려
    과한 조치가 된다. 그래서 여기서는 관찰(알림)만 한다.
    """
    alert.send_web_scanning_alert(ip, count, path)


def notify_unauthorized_access(ip: str, count: int, path: str) -> None:
    """Unauthorized Access 의심 알림을 Slack으로 보낸다.

    notify_web_scanning()과 마찬가지로 db.create_lockout()을 호출하지 않는다.
    이번엔 이유가 조금 다르다 — 대상 경로 자체가 없는 404와 달리 여기 대상은
    "존재하는 관리자 API"이므로 원칙적으로는 잠글 수도 있지만, 그렇게 하면
    관리자 대시보드가 세션 만료 직후 자동 폴링으로 이 상태에 걸렸을 때 관리자
    본인의 IP까지 잠가버려 재로그인조차 막아버리는 자충수가 될 수 있다.
    그래서 이 항목도 관찰(알림)까지만 자동화하고, 잠글지 여부는 알림을 받은
    관리자가 직접 판단하게 남겨둔다.
    """
    alert.send_unauthorized_access_alert(ip, count, path)


def notify_page_access(ip: str, count: int, path: str) -> None:
    """반복 페이지 접근 의심 알림을 Slack으로 보낸다.

    notify_web_scanning()/notify_unauthorized_access()와 마찬가지로 db.create_lockout()을
    호출하지 않는다 — 같은 페이지를 자주 보는 것만으로 IP를 잠그면, 단순히 그 페이지를
    새로고침하며 기다리던 정상 사용자까지 막아버릴 위험이 있다. 그래서 관찰(알림)까지만
    자동화하고, 잠글지 여부는 알림을 받은 관리자가 직접 판단하게 남겨둔다.
    """
    alert.send_page_access_alert(ip, count, path)


def try_release_expired_lockouts() -> None:
    """"5분이 지났는데 아직 안 풀린" 잠금들을 찾아서 전부 풀어준다.

    이 프로젝트는 "정해진 시각이 되면 자동으로 실행되는 타이머 프로그램"을
    따로 두지 않는다(구현이 복잡해지므로 이번 계획 범위 밖). 대신 이 함수를
    `/login` 요청이 들어올 때, 그리고 대시보드가 새로고침될 때마다 호출해서
    "혹시 지금 풀어줘야 할 게 있나?"를 그때그때 확인하는 방식으로 "자동 해제"를
    흉내낸다. 트래픽(요청)이 없으면 실제 해제 반영이 살짝 늦어질 수 있지만,
    이 프로젝트 규모에서는 문제되지 않는다.
    """
    for lockout in db.list_expired_active_lockouts():
        db.release_lockout(lockout["ip_address"])


def manual_release(ip: str) -> bool:
    """관리자가 대시보드의 "즉시 해제" 버튼을 눌렀을 때 호출되는 함수.

    동작 순서:
    1. 지금 잠겨있는 IP 목록을 전부 가져와서, 그 안에 이 ip가 있는지 확인한다.
    2. 있다면 실제로 풀어주고 True(성공)를 돌려준다.
    3. 애초에 잠긴 적이 없다면 아무것도 하지 않고 False(할 일 없음)를 돌려준다.

    주의: 이 함수는 "이 요청을 보낸 사람이 진짜 관리자인지"는 전혀 확인하지 않는다.
    그 권한 확인은 app.py의 login_required 장치가 미리 걸러주고, 이 함수는
    "이미 권한이 확인된 사람"의 요청만 받는다고 가정하고 동작한다.
    """
    active_ips = {row["ip_address"] for row in db.list_active_lockouts()}
    if ip not in active_ips:
        return False
    db.release_lockout(ip)
    return True
