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


def send_lockout_alert(ip: str, failure_count: int, locked_at: datetime) -> None:
    """IP 잠금이 발생했다는 사실을 Slack 채널에 메시지로 알린다.

    동작 순서:
    1. "시각 / IP / 실패 횟수 / 조치 내용"을 사람이 읽기 좋은 문장으로 조립한다.
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

    # ":rotating_light:"는 Slack에서 🚨(경광등) 이모지로 자동 변환되는 표기법이다.
    message = (
        ":rotating_light: 로그인 워치독 알림\n"
        f"시각: {locked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"시도 IP: {ip}\n"
        f"실패 횟수: {failure_count}회\n"
        f"조치: {minutes}분간 IP 잠금 처리"
    )

    # Slack 웹훅(Incoming Webhook)이란: Slack이 채널마다 발급해주는 전용 주소.
    # 이 주소에 {"text": "..."} 형태의 데이터를 보내기만 하면 그 채널에 메시지가 올라온다.
    # 로그인 절차나 복잡한 인증 없이 "주소 하나 + 짧은 데이터 한 덩어리"로 끝나는
    # 가장 단순한 연동 방식이다.
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
