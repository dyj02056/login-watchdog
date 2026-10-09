# ============================================================================
# notify/alert.py — "전화 교환원" 역할: Slack에 실제로 메시지를 전송한다
#
# 이 파일이 하는 일은 딱 하나, "메시지를 조립해서 Slack 웹훅 주소로 던지는 것"뿐이다.
# "언제 알림을 보낼지"를 결정하는 판단은 이 파일의 몫이 아니고 security/soar/(대부분),
# security/correlate.py·lockdown.py, notify/mailer.py(메일 발송 실패)가 결정해서
# 이 파일의 함수를 호출해줄 때만 동작한다.
# ============================================================================

import os
import sys
from datetime import datetime

import requests

import config


def _safe_print(text: str) -> None:
    """콘솔 출력이 인코딩 문제(예: 한국어 Windows 터미널의 cp949가 못 찍는 글자)로 실패해도
    알림 한 건 때문에 로그인 요청 전체가 500으로 죽지 않게, 못 찍는 글자는 ?로 바꿔 출력한다."""
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(text.encode(encoding, errors="replace").decode(encoding), flush=True)


def _send_slack_message(message: str) -> None:
    """조립된 메시지 문자열 하나를 Slack 웹훅으로 전송한다 (없으면 콘솔 출력으로 대체).

    이 파일의 send_*_alert() 함수들은 전부 "메시지를 어떻게
    조립하는지"만 다르고 "그 메시지를 어떻게 내보내는지"는 완전히 같으므로,
    전송 부분만 이 함수로 뽑아서 공유한다.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if not webhook_url:
        # 웹훅 주소가 비어있다 = 아직 Slack 채널이 정해지지 않음 → 콘솔 출력으로 대체
        # flush=True: 파이썬은 기본적으로 출력을 잠깐 모아뒀다가 한꺼번에 내보내는
        # "버퍼링"을 하는데, 그러면 서버 로그를 실시간으로 볼 때 메시지가 늦게 나타나거나
        # 안 보일 수 있다. flush=True는 "모아두지 말고 지금 즉시 내보내라"는 뜻이다.
        _safe_print(f"[alert] SLACK_WEBHOOK_URL 미설정 - 콘솔 로그로 대체 전송:\n{message}")
        return

    try:
        # 실제로 Slack 서버에 "이 메시지를 채널에 올려줘"라고 요청을 보낸다.
        # timeout=5 : 5초 안에 응답이 없으면 무한정 기다리지 않고 포기한다.
        response = requests.post(webhook_url, json={"text": message}, timeout=5)
        # 응답이 200(성공)이 아니라 4xx/5xx(오류) 코드라면 예외를 발생시켜 아래 except로 넘어간다.
        response.raise_for_status()
    except requests.RequestException as e:
        # 네트워크가 끊겼거나 Slack 쪽에서 오류가 났을 때: 프로그램을 중단시키지 않고
        # 문제가 있었다는 사실만 콘솔에 남긴다. (로그인 기능 자체는 계속 정상 동작해야 함)
        print(f"[alert] Slack 알림 전송 실패: {e}", flush=True)


def send_lockout_alert(
    ip: str, failure_count: int, locked_at: datetime, distinct_usernames: int, is_admin: bool = False
) -> None:
    """IP 잠금이 발생했다는 사실을 Slack 채널에 메시지로 알린다.

    동작 순서:
    1. "시각 / IP / 실패 횟수 / 공격 유형 / 조치 내용"을 사람이 읽기 좋은 문장으로 조립한다.
    2. .env에 SLACK_WEBHOOK_URL이 설정돼 있으면 그 주소로 실제 전송을 시도한다.
    3. 설정돼 있지 않으면(아직 팀이 어느 Slack 채널을 쓸지 정하지 않은 상태),
       전송 대신 터미널 화면에 같은 메시지를 출력해서 개발 중에도 확인 가능하게 한다.
       → 나중에 SLACK_WEBHOOK_URL 값만 채워 넣으면, 이 함수는 코드 수정 없이
         자동으로 "진짜 Slack 전송" 모드로 바뀐다.
    4. 전송 중 네트워크 오류 등으로 실패하더라도, 이 실패가 로그인 기능 전체를
       멈춰 세우면 안 되므로 예외(에러)를 붙잡아서 콘솔에 로그만 남기고 조용히 넘어간다.
    """
    # config.LOCKOUT_DURATION_SECONDS(초 단위, 예: 300)를 분 단위로 바꿔서 메시지에 넣는다.
    minutes = config.LOCKOUT_DURATION_SECONDS // 60

    # is_admin이면 관리자 로그인(/admin/login)에서 발생한 잠금이므로, 계정 하나에 집중된
    # 공격인지 여러 계정을 순회한 공격인지와 무관하게 별도 유형으로 표시한다 — 관리자
    # 계정이 뚫리면 회원 삭제·잠금 해제까지 장악되므로 일반 회원 로그인 시도보다 우선순위가
    # 높다는 걸 메시지만 보고도 바로 알 수 있게 하기 위해서다.
    # distinct_usernames가 2개 이상이면 "한 계정을 집중 공격"이 아니라 "여러 계정을
    # 돌아가며 시도"하는 것이므로, Brute Force와 구분해서 Password Spraying으로 표시한다.
    if is_admin:
        pattern_line = "공격 유형: 관리자 로그인 무차별 대입"
    elif distinct_usernames > 1:
        pattern_line = f"공격 유형: Password Spraying 의심 (서로 다른 아이디 {distinct_usernames}개 시도)"
    else:
        pattern_line = "공격 유형: Brute Force (단일 계정 집중 시도)"

    # ":rotating_light:"는 Slack에서 🚨(경광등) 이모지로 자동 변환되는 표기법이다.
    # "[CRITICAL]"은 위험등급을 한눈에 보여준다(security-risk-response-summary.md 5-5절).
    message = (
        ":rotating_light: [CRITICAL] 로그인 워치독 알림\n"
        f"시각: {locked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"시도 IP: {ip}\n"
        f"실패 횟수: {failure_count}회\n"
        f"{pattern_line}\n"
        f"조치: {minutes}분간 IP 잠금 처리"
    )

    # Slack 웹훅(Incoming Webhook)이란: Slack이 채널마다 발급해주는 전용 주소.
    # 이 주소에 {"text": "..."} 형태의 데이터를 보내기만 하면 그 채널에 메시지가 올라온다.
    # 로그인 절차나 복잡한 인증 없이 "주소 하나 + 짧은 데이터 한 덩어리"로 끝나는
    # 가장 단순한 연동 방식이다.
    _send_slack_message(message)


def send_account_lockout_alert(
    username: str, failure_count: int, locked_at: datetime, distinct_ip_count: int, is_admin: bool = False
) -> None:
    """계정(아이디) 잠금이 발생했다는 사실을 Slack 채널에 메시지로 알린다.

    send_lockout_alert()(IP 잠금)와 메시지 조립 구조는 같지만, 대상이 IP가
    아니라 계정이다 — 여러 IP에 걸쳐 나뉘어 들어온 공격이 계정 전체 실패
    횟수 기준으로 잠긴 경우이므로, "몇 개의 IP가 관련됐는지"를 함께 보여줘서
    분산 브루트포스임을 한눈에 알 수 있게 한다.

    is_admin=True면 관리자 계정 잠금(guide38)이다 — 대상이 관리자 계정이라는 점을
    표시해서 회원 계정 잠금과 구분한다.
    """
    minutes = config.LOCKOUT_DURATION_SECONDS // 60
    target_label = "관리자 계정" if is_admin else "대상 계정"
    message = (
        ":rotating_light: [CRITICAL] 로그인 워치독 알림\n"
        f"시각: {locked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"{target_label}: {username}\n"
        f"실패 횟수: {failure_count}회 (서로 다른 IP {distinct_ip_count}개에서 분산 시도)\n"
        "공격 유형: 분산/저속 브루트포스 의심 (여러 IP가 한 계정을 나눠서 집중 공격)\n"
        f"조치: {minutes}분간 계정 잠금 처리"
    )
    _send_slack_message(message)


def send_web_scanning_alert(ip: str, count: int, path: str) -> None:
    """Web Scanning(존재하지 않는 경로 반복 요청)이 의심된다는 사실을 Slack에 알린다.

    send_lockout_alert()와 메시지 조립 구조는 같지만, IP를 잠그는 "조치"가 없다
    — 이미 존재하지 않는 경로 요청이라 막을 대상 자체가 없고, 관리자에게
    "이런 패턴이 관찰되고 있다"는 사실만 알리면 충분하기 때문이다
    (21단계, attack_response_state.md 구현 대상 #1).
    """
    message = (
        ":mag: [MEDIUM] 로그인 워치독 알림\n"
        "공격 유형: Web Scanning 의심 (존재하지 않는 경로 반복 요청)\n"
        f"시도 IP: {ip}\n"
        f"최근 {config.DETECTION_WINDOW_SECONDS}초간 요청 횟수: {count}회\n"
        f"최근 요청 경로: {path}\n"
        "조치: 별도 잠금 없음 (관찰 목적)"
    )
    _send_slack_message(message)


def send_page_access_alert(ip: str, count: int, path: str) -> None:
    """반복 페이지 접근(같은 IP가 같은 페이지를 반복 요청)이 의심된다는 사실을
    Slack에 알린다. send_web_scanning_alert()와 마찬가지로 잠그지 않는다 —
    "이 페이지를 자주 보는 것" 자체는 그 IP를 잠글 만큼 확실한 공격 신호가
    아니므로, 관찰(알림)까지만 자동화하고 실제 조치는 관리자 판단에 맡긴다
    (attack_response_state.md 구현 대상 #4).
    """
    message = (
        ":mag: [MEDIUM] 로그인 워치독 알림\n"
        "공격 유형: 반복 페이지 접근 의심 (같은 페이지 반복 요청)\n"
        f"시도 IP: {ip}\n"
        f"최근 {config.DETECTION_WINDOW_SECONDS}초간 요청 횟수: {count}회\n"
        f"요청 경로: {path}\n"
        "조치: 별도 잠금 없음 (관찰 목적)"
    )
    _send_slack_message(message)


def send_incident_escalation_alert(ip: str, event_types: list[str], severity_max: str) -> None:
    """한 IP에서 여러 종류의 공격이 겹쳐 사건(security_incidents)이 심각한
    수준에 도달했을 때, 개별 이벤트 알림과 별도로 "복합 공격 발생"을 강조해서
    알린다 (Track C guide28, SOAR 플레이북).

    send_lockout_alert() 등 개별 이벤트 알림은 이미 각자 따로 나가고 있으므로,
    이 알림은 "그 이벤트들이 사실 한 IP에서 겹치고 있다"는 상관관계 자체를
    강조하는 것이 목적이다 — security/correlate.py가 이미 CRITICAL·서로 다른 유형
    config.INCIDENT_ESCALATION_MIN_EVENT_TYPES개 이상일 때만, 그리고 사건당
    한 번만(db.mark_incident_escalated) 호출한다.
    """
    message = (
        ":bangbang: [CRITICAL] 로그인 워치독 SOAR 플레이북 알림\n"
        f"IP: {ip}\n"
        f"연관된 공격 유형 {len(event_types)}종: {', '.join(event_types)}\n"
        f"최고 위험등급: {severity_max}\n"
        "판단: 한 출처에서 여러 단계에 걸친 공격 흐름으로 의심됨 (SIEM 상관분석)\n"
        "조치: 관리자 대시보드 '연관 사건' 표에서 상세 확인 요망"
    )
    _send_slack_message(message)


def send_macro_pattern_alert(ip: str, count: int) -> None:
    """매크로/봇 의심(짧은 시간 안에 서로 다른 API 여러 개 호출)이 감지됐다는
    사실을 Slack에 알린다 (Track C guide29). send_web_scanning_alert()와
    마찬가지로 잠그지 않는다 — 특정 경로 하나가 아니라 여러 경로에 걸친
    패턴이라 "이 경로를 막는다" 같은 조치 자체가 성립하지 않고, 관찰(알림)까지만
    자동화한다.
    """
    message = (
        ":robot_face: [MEDIUM] 로그인 워치독 알림\n"
        "공격 유형: 매크로/봇 의심 (짧은 시간 안에 서로 다른 API 다수 호출)\n"
        f"시도 IP: {ip}\n"
        f"최근 {config.DETECTION_WINDOW_SECONDS}초간 호출한 서로 다른 API 경로 수: {count}개\n"
        "조치: 별도 잠금 없음 (관찰 목적)"
    )
    _send_slack_message(message)


def send_pending_approval_alert(
    label: str, target_kind: str, target_value: str, count: int, threshold: int, reason: str
) -> None:
    """LLM이 "임계값 코앞" 구간에서 위험하다고 판단해 access_requests에 새
    PENDING 요청을 등록했을 때, 관리자에게 확인을 요청하는 알림을 보낸다
    (Track A, guide31).

    다른 알림들과 달리 이 알림은 "이미 조치가 실행됐다"는 통보가 아니라
    "아직 아무 조치도 안 했으니 대시보드에서 승인/반려를 결정해달라"는
    요청이다 — 그래서 메시지 끝의 "조치" 줄도 다른 함수들처럼 완료형이 아니라
    요청형으로 적는다.
    """
    message = (
        ":robot_face: [AI 조기 경보] 로그인 워치독 알림\n"
        f"패턴: {label}\n"
        f"대상({target_kind}): {target_value}\n"
        f"현재 수치: {count}회 (자동 대응 기준치 {threshold}회에는 아직 도달하지 않음)\n"
        f"AI 판단 근거: {reason}\n"
        "조치: 아직 자동 실행 없음 — 관리자 대시보드 'AI 조기 경보' 표에서 승인/반려 요망"
    )
    _send_slack_message(message)


def send_unauthorized_access_alert(ip: str, count: int, path: str) -> None:
    """Unauthorized Access(로그인 세션 없이 관리자 API 반복 호출)가 의심된다는
    사실을 Slack에 알린다. send_web_scanning_alert()와 마찬가지로 잠그지는
    않는다 — 대시보드 화면이 열려있는 채로 세션만 만료된 정상 사용자도 자동
    폴링(ADMIN_DASHBOARD_POLL_MS)으로 이 상태에 잠깐 걸릴 수 있어서, 여기서
    IP를 잠가버리면 정작 그 관리자 본인이 재로그인조차 못 하게 될 위험이
    있기 때문이다 (attack_response_state.md 구현 대상 #2).
    """
    message = (
        ":mag: [MEDIUM] 로그인 워치독 알림\n"
        "공격 유형: Unauthorized Access 의심 (세션 없이 관리자 API 반복 호출)\n"
        f"시도 IP: {ip}\n"
        f"최근 {config.DETECTION_WINDOW_SECONDS}초간 요청 횟수: {count}회\n"
        f"최근 요청 경로: {path}\n"
        "조치: 별도 잠금 없음 (관찰 목적)"
    )
    _send_slack_message(message)


# ============================================================================
# 영구 잠금 + 이메일 복구 (guide33 / guide34-a)
# ============================================================================

_PERMANENT_REASON_LABELS = {
    "REPEAT_OFFENDER": "반복 위반(최근 기간 내 잠금 횟수 초과)",
    "SIEM_CRITICAL": "SIEM 상관분석 — CRITICAL 사건",
    "SIEM_HIGH": "SIEM 상관분석 — HIGH 사건(관리자 승인 또는 자동 승격)",
    "NETWORK_IDS": "네트워크 침입 탐지",
    "ADMIN_MANUAL": "관리자 수동 승격",
}

_RECOVERABLE_LABELS = {
    "SELF": "본인 이메일 인증으로 해제 가능",
    "EXEMPTION": "본인 이메일 인증 시 '본인+본인 기기' 예외만 발급 가능",
    "ADMIN_ONLY": "관리자만 해제 가능",
}


def send_permanent_lock_alert(
    target_kind: str, target_value: str, reason: str, recoverable: str, strikes: int | None = None
) -> None:
    """영구 잠금이 새로 걸렸을 때 Slack에 알린다. 승격은 조건부 UPDATE로 "실제로 바뀐
    순간"에만 일어나므로(db.promote_lockout_permanent), 이 알림도 딱 한 번만 나간다."""
    kind_label = "IP" if target_kind == "ip" else "계정"
    strikes_line = f"\n최근 잠금 횟수: {strikes}회" if strikes else ""
    message = (
        ":no_entry: [CRITICAL] 로그인 워치독 영구 잠금 알림\n"
        f"대상({kind_label}): {target_value}\n"
        f"승격 사유: {_PERMANENT_REASON_LABELS.get(reason, reason)}"
        f"{strikes_line}\n"
        f"복구 방식: {_RECOVERABLE_LABELS.get(recoverable, recoverable)}\n"
        "조치: 자동 만료 없는 영구 잠금, 관리자 대시보드 '현재 잠긴 IP / 계정' 카드에서 확인"
    )
    _send_slack_message(message)


def send_permanent_release_alert(target_kind: str, target_value: str, actor: str, note: str) -> None:
    """관리자(또는 운영 스크립트)가 영구 잠금을 해제했다는 사실을 Slack에 알린다."""
    kind_label = "IP" if target_kind == "ip" else "계정"
    message = (
        ":unlock: [INFO] 로그인 워치독 영구 잠금 해제 알림\n"
        f"대상({kind_label}): {target_value}\n"
        f"해제자: {actor}\n"
        f"사유: {note}"
    )
    _send_slack_message(message)


def send_recovery_completed_alert(target_kind: str, target_value: str, username: str) -> None:
    """사용자가 이메일 인증으로 영구 잠금 복구를 완료했다는 사실을 Slack에 알린다."""
    if target_kind == "account":
        result_line = f"결과: 계정 '{target_value}' 영구 잠금 해제 (보호관찰 시작)"
    else:
        result_line = f"결과: IP {target_value}에 대해 '{username}' 계정+요청 기기 예외 발급"
    message = (
        ":email: [INFO] 로그인 워치독 이메일 복구 완료 알림\n"
        f"{result_line}"
    )
    _send_slack_message(message)


_MAIL_FAILURE_HINTS = {
    "CONFIG": "환경변수(MAIL_BACKEND=smtp, SMTP_HOST, PUBLIC_BASE_URL 등)를 확인하세요.",
    "AUTH": "SMTP_USER와 SMTP_PASSWORD(Gmail은 일반 비밀번호가 아니라 '앱 비밀번호')를 확인하세요.",
    "CONNECT": "SMTP_HOST/SMTP_PORT와 SMTP_STARTTLS/SMTP_USE_SSL 조합을 확인하세요(587=STARTTLS, 465=SSL).",
    "OTHER": "발신자(MAIL_FROM)가 SMTP 계정과 같은지, 서버 일시 장애는 아닌지 확인하세요.",
    "INTERNAL": "메일 설정 문제가 아닙니다. Vercel Runtime Logs에서 [recovery] 오류(DB 연결 등)를 확인하세요.",
}


def send_mail_failure_alert(category: str, detail: str) -> None:
    """메일(복구·이메일 인증·비밀번호 재설정 등)을 보내지 못했다는 사실(설정 문제 가능성)을
    Slack에 알린다. 메시지 제목은 "복구 메일"이지만 notify/mailer.py가 보내는 모든 메일의
    실패가 여기로 온다. 사용자 화면에는
    계정 존재 여부가 드러나지 않게 항상 같은 안내가 나가므로, 이 알림이 없으면 메일 설정이
    틀려도 아무도 모른다. detail에는 비밀번호·토큰·메일 본문이 들어가지 않는다."""
    message = (
        ":warning: [HIGH] 로그인 워치독 복구 메일 발송 실패\n"
        f"원인 분류: {category}\n"
        f"상세: {detail}\n"
        f"조치: {_MAIL_FAILURE_HINTS.get(category, _MAIL_FAILURE_HINTS['OTHER'])}\n"
        "영향: 영구 잠금된 사용자가 이메일 인증으로 복구할 수 없습니다(관리자 해제는 가능)."
    )
    _send_slack_message(message)
