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
    """조립된 메시지 문자열 하나를 Slack 웹훅으로 전송한다 (없으면 콘솔 출력으로 대체)."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if not webhook_url:
        _safe_print(f"[alert] SLACK_WEBHOOK_URL 미설정 - 콘솔 로그로 대체 전송:\n{message}")
        return

    try:
        response = requests.post(webhook_url, json={"text": message}, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[alert] Slack 알림 전송 실패: {e}", flush=True)


def send_lockout_alert(
    ip: str, failure_count: int, locked_at: datetime, distinct_usernames: int, is_admin: bool = False
) -> None:
    minutes = config.LOCKOUT_DURATION_SECONDS // 60

    if is_admin:
        pattern_line = "공격 유형: 관리자 로그인 무차별 대입"
    elif distinct_usernames > 1:
        pattern_line = f"공격 유형: Password Spraying 의심 (서로 다른 아이디 {distinct_usernames}개 시도)"
    else:
        pattern_line = "공격 유형: Brute Force (단일 계정 집중 시도)"

    message = (
        ":rotating_light: [CRITICAL] 로그인 워치독 알림\n"
        f"시각: {locked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"시도 IP: {ip}\n"
        f"실패 횟수: {failure_count}회\n"
        f"{pattern_line}\n"
        f"조치: {minutes}분간 IP 잠금 처리"
    )
    _send_slack_message(message)


def send_account_lockout_alert(
    username: str, failure_count: int, locked_at: datetime, distinct_ip_count: int, is_admin: bool = False
) -> None:
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
    message = (
        ":mag: [MEDIUM] 로그인 워치독 알림\n"
        "공격 유형: Unauthorized Access 의심 (세션 없이 관리자 API 반복 호출)\n"
        f"시도 IP: {ip}\n"
        f"최근 {config.DETECTION_WINDOW_SECONDS}초간 요청 횟수: {count}회\n"
        f"최근 요청 경로: {path}\n"
        "조치: 별도 잠금 없음 (관찰 목적)"
    )
    _send_slack_message(message)


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
    kind_label = "IP" if target_kind == "ip" else "계정"
    message = (
        ":unlock: [INFO] 로그인 워치독 영구 잠금 해제 알림\n"
        f"대상({kind_label}): {target_value}\n"
        f"해제자: {actor}\n"
        f"사유: {note}"
    )
    _send_slack_message(message)


def send_recovery_completed_alert(target_kind: str, target_value: str, username: str) -> None:
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
    message = (
        ":warning: [HIGH] 로그인 워치독 복구 메일 발송 실패\n"
        f"원인 분류: {category}\n"
        f"상세: {detail}\n"
        f"조치: {_MAIL_FAILURE_HINTS.get(category, _MAIL_FAILURE_HINTS['OTHER'])}\n"
        "영향: 영구 잠금된 사용자가 이메일 인증으로 복구할 수 없습니다(관리자 해제는 가능)."
    )
    _send_slack_message(message)


def send_component_alert(component: str, message: str) -> None:
    """fw-agent/shipper 등 시스템 구성요소 이상/정지 발생 시 Slack에 알린다."""
    text = (
        f":warning: [HIGH] 로그인 워치독 장애 알림\n"
        f"대상 장비/에이전트: {component}\n"
        f"상세 내용: {message}"
    )
    _send_slack_message(text)