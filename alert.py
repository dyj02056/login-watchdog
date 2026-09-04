# ============================================================================
# alert.py — "전화 교환원" 역할: Slack에 실제로 메시지를 전송한다
#
# 이 파일이 하는 일은 딱 하나, "메시지를 조립해서 Slack 웹훅 주소로 던지는 것"뿐이다.
# "언제 알림을 보낼지"를 결정하는 판단은 이 파일의 몫이 아니고 soar.py가 결정해서
# 이 파일의 함수를 호출해줄 때만 동작한다.
# ============================================================================

import os
from datetime import datetime

import requests

import config


def _send_slack_message(message: str) -> None:
    """조립된 메시지 문자열 하나를 Slack 웹훅으로 전송한다 (없으면 콘솔 출력으로 대체).

    send_lockout_alert()/send_web_scanning_alert() 둘 다 "메시지를 어떻게
    조립하는지"만 다르고 "그 메시지를 어떻게 내보내는지"는 완전히 같으므로,
    전송 부분만 이 함수로 뽑아서 공유한다.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if not webhook_url:
        # 웹훅 주소가 비어있다 = 아직 Slack 채널이 정해지지 않음 → 콘솔 출력으로 대체
        # flush=True: 파이썬은 기본적으로 출력을 잠깐 모아뒀다가 한꺼번에 내보내는
        # "버퍼링"을 하는데, 그러면 서버 로그를 실시간으로 볼 때 메시지가 늦게 나타나거나
        # 안 보일 수 있다. flush=True는 "모아두지 말고 지금 즉시 내보내라"는 뜻이다.
        print(f"[alert] SLACK_WEBHOOK_URL 미설정 - 콘솔 로그로 대체 전송:\n{message}", flush=True)
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
    ip: str, failure_count: int, locked_at: datetime, distinct_usernames: int
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

    # distinct_usernames가 2개 이상이면 "한 계정을 집중 공격"이 아니라 "여러 계정을
    # 돌아가며 시도"하는 것이므로, Brute Force와 구분해서 Password Spraying으로 표시한다.
    if distinct_usernames > 1:
        pattern_line = f"공격 유형: Password Spraying 의심 (서로 다른 아이디 {distinct_usernames}개 시도)"
    else:
        pattern_line = "공격 유형: Brute Force (단일 계정 집중 시도)"

    # ":rotating_light:"는 Slack에서 🚨(경광등) 이모지로 자동 변환되는 표기법이다.
    message = (
        ":rotating_light: 로그인 워치독 알림\n"
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


def send_web_scanning_alert(ip: str, count: int, path: str) -> None:
    """Web Scanning(존재하지 않는 경로 반복 요청)이 의심된다는 사실을 Slack에 알린다.

    send_lockout_alert()와 메시지 조립 구조는 같지만, IP를 잠그는 "조치"가 없다
    — 이미 존재하지 않는 경로 요청이라 막을 대상 자체가 없고, 관리자에게
    "이런 패턴이 관찰되고 있다"는 사실만 알리면 충분하기 때문이다
    (21단계, attack_response_state.md 구현 대상 #1).
    """
    message = (
        ":mag: 로그인 워치독 알림\n"
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
        ":mag: 로그인 워치독 알림\n"
        "공격 유형: 반복 페이지 접근 의심 (같은 페이지 반복 요청)\n"
        f"시도 IP: {ip}\n"
        f"최근 {config.DETECTION_WINDOW_SECONDS}초간 요청 횟수: {count}회\n"
        f"요청 경로: {path}\n"
        "조치: 별도 잠금 없음 (관찰 목적)"
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
        ":mag: 로그인 워치독 알림\n"
        "공격 유형: Unauthorized Access 의심 (세션 없이 관리자 API 반복 호출)\n"
        f"시도 IP: {ip}\n"
        f"최근 {config.DETECTION_WINDOW_SECONDS}초간 요청 횟수: {count}회\n"
        f"최근 요청 경로: {path}\n"
        "조치: 별도 잠금 없음 (관찰 목적)"
    )
    _send_slack_message(message)
