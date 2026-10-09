# ============================================================================
# security/soar/observe.py — 잠그지 않고 관찰만 하는 조치(알림 + 이벤트 기록)와 요청 거부 기록
#
# 예전 soar.py(497줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from security import soar` 후 `soar.enforce_lockout(...)`으로
# 쓴다(security/soar/__init__.py가 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import db
from notify import alert
from security import correlate
from security.soar._events import _record_event


def notify_bot_detected(ip: str, path: str) -> None:
    """허니팟 필드가 채워진 요청(자동화 스크립트/봇 의심)을 MEDIUM 이벤트로 기록한다.

    Slack 알림은 보내지 않는다 — 로그인 실패 반복이나 게시글 도배처럼 그 자체로
    실제 피해로 이어지는 사건이 아니라 "이 트래픽에 자동화 스크립트가 섞여
    있다"는 관찰 정보이므로, notify_web_scanning() 등과 같은 급의 MEDIUM으로
    로그에만 남긴다 (L7 공격 보강 계획 Tier 3).
    """
    _record_event("BOT_DETECTED", "MEDIUM", ip, path, 1, "REJECTED")


def notify_macro_pattern(ip: str, count: int) -> None:
    """매크로/봇 의심 알림을 Slack으로 보내고, MEDIUM 이벤트로 기록한다
    (Track C guide29). notify_web_scanning() 등과 마찬가지로 db.create_lockout()을
    호출하지 않는다 — 경로 하나가 아니라 여러 경로에 걸친 패턴이라 잠글 단일
    대상이 없고, 관찰(알림 + 이벤트 기록)까지만 자동화한다. path는 이 이벤트가
    특정 경로 하나가 아니라 IP 전체의 패턴을 가리키므로 None으로 남겨둔다
    (enforce_lockout이 IP 단위 CRITICAL 이벤트에 path=None을 쓰는 것과 같은 이유).
    """
    alert.send_macro_pattern_alert(ip, count)
    _record_event("API_MACRO_PATTERN", "MEDIUM", ip, None, count, "ALERTED")


def notify_web_scanning(ip: str, count: int, path: str) -> None:
    """Web Scanning 의심 알림을 Slack으로 보내고, MEDIUM 이벤트로 기록한다.

    enforce_lockout()과 달리 db.create_lockout()을 호출하지 않는다 — 404를
    유발한 요청은 애초에 존재하지 않는 경로를 두드린 것이라 "잠글" 대상이
    없고, 이 IP를 실제로 잠그면 정상적인 다른 페이지 이용까지 막아버려 오히려
    과한 조치가 된다. 그래서 여기서는 관찰(알림 + 이벤트 기록)만 한다.
    """
    alert.send_web_scanning_alert(ip, count, path)
    _record_event("WEB_SCANNING", "MEDIUM", ip, path, count, "ALERTED")


def notify_unauthorized_access(ip: str, count: int, path: str) -> None:
    """Unauthorized Access 의심 알림을 Slack으로 보내고, MEDIUM 이벤트로 기록한다.

    notify_web_scanning()과 마찬가지로 db.create_lockout()을 호출하지 않는다.
    이번엔 이유가 조금 다르다 — 대상 경로 자체가 없는 404와 달리 여기 대상은
    "존재하는 관리자 API"이므로 원칙적으로는 잠글 수도 있지만, 그렇게 하면
    관리자 대시보드가 세션 만료 직후 자동 폴링으로 이 상태에 걸렸을 때 관리자
    본인의 IP까지 잠가버려 재로그인조차 막아버리는 자충수가 될 수 있다.
    그래서 이 항목도 관찰(알림 + 이벤트 기록)까지만 자동화하고, 잠글지 여부는
    알림을 받은 관리자가 직접 판단하게 남겨둔다.
    """
    alert.send_unauthorized_access_alert(ip, count, path)
    _record_event("UNAUTHORIZED_ACCESS", "MEDIUM", ip, path, count, "ALERTED")


def notify_page_access(ip: str, count: int, path: str) -> None:
    """반복 페이지 접근 의심 알림을 Slack으로 보내고, MEDIUM 이벤트로 기록한다.

    notify_web_scanning()/notify_unauthorized_access()와 마찬가지로 db.create_lockout()을
    호출하지 않는다 — 같은 페이지를 자주 보는 것만으로 IP를 잠그면, 단순히 그 페이지를
    새로고침하며 기다리던 정상 사용자까지 막아버릴 위험이 있다. 그래서 관찰(알림 + 이벤트
    기록)까지만 자동화하고, 잠글지 여부는 알림을 받은 관리자가 직접 판단하게 남겨둔다.
    """
    alert.send_page_access_alert(ip, count, path)
    _record_event("PAGE_ACCESS", "MEDIUM", ip, path, count, "ALERTED")


def record_rejection(event_type: str, ip: str, path: str, count: int) -> None:
    """가입·게시글·댓글 요청 거부와 요청 한도 초과(HTTP_FLOOD, app.py)를 HIGH로
    security_events에 기록한다. Slack 알림은 보내지
    않는다 — CRITICAL/MEDIUM과 달리 이 등급은 "관리자가 나중에 대시보드에서 확인"하는
    선까지만 자동화하기로 했다(security-risk-response-summary.md 5절).

    is_signup_rate_limited() 등은 차단되는 동안 시도 자체를 로그에 남기지 않아 count가
    차단 기간 내내 고정된다 — MEDIUM의 is_first_over_threshold처럼 "지금이 막 넘긴
    순간"이라는 신호가 없다는 뜻이다. 그래서 매 거부마다 새 행을 만드는 대신,
    is_locked()와 같은 방식으로 "이 IP·유형에 이미 미해결 이벤트가 있으면 새로 만들지
    않는다"는 상태 기반 중복 방지를 쓴다 — 없으면 봇 한 대가 60초 창 안에 거부당할
    때마다 새 행이 쌓여 security_events가 HIGH로 도배되고 CRITICAL/MEDIUM이 묻힌다.

    다만 "새로 안 만든다"고 끝내면 이미 열린 사건이 실제로 몇 번이나 반복됐는지
    알 수 없다(count가 처음 거부됐을 때 값에 영원히 고정됨) — 그래서 미해결
    이벤트가 있으면 무시하는 대신, 그 행의 count를 1 올린다. 관리자가 "처리
    완료"를 누르면 다음 거부부터 다시 새 이벤트가 생긴다.

    db.insert_security_event_or_bump()를 쓰는 이유: 여기서 "미해결 이벤트가
    있는지" 확인한 바로 그 순간과 실제로 새로 삽입하는 순간 사이에 아주 잠깐의
    틈이 있어서, 동시에 두 요청이 이 함수를 거의 같은 순간에 통과하면 둘 다
    "없음"을 보고 각자 삽입해버릴 수 있다(경쟁 조건). insert_security_event_or_bump는
    그 드문 경우에도 DB의 유니크 인덱스가 두 번째 삽입을 막아주면 count 증가로
    자동 대체한다.
    """
    existing = db.get_unresolved_security_event(ip, event_type)
    if existing:
        db.update_security_event_count(existing["id"], existing["count"] + 1)
    else:
        db.insert_security_event_or_bump(event_type, "HIGH", ip, path, count, "REJECTED")
    correlate.check_and_correlate(ip, event_type, "HIGH")
