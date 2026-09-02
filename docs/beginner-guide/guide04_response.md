# 4단계 — `detector.py` / `soar.py` / `alert.py` (판정 → 조치 → 알림)

[◀ 3단계](guide03_db.md) · [전체 목차](beginner-guide.md) · [5단계 ▶](guide05_app.md)


### 우리가 한 일
1. [detector.py](../../detector.py) — "지금 이 IP가 수상한가? 지금 잠겨있는가?"만 **판단**하는 파일
2. [soar.py](../../soar.py) — 판단 결과를 받아서 실제로 **잠그고, 알림을 보내고, 풀어주는 실행** 파일
3. [alert.py](../../alert.py) — Slack으로 **메시지를 실제로 전송**하는 파일
4. 세 파일을 실제 데이터로 이어붙여서(수상 판정 → 잠금 → 알림 → 수동 해제) 전체 흐름이 맞물려 돌아가는지 확인

### 왜 했는가 (쉬운 설명)

**왜 "판단"과 "실행"과 "알림"을 세 파일로 쪼갰나?**
한 파일에 다 몰아넣으면 "수상한지 확인하는 코드"와 "Slack에 보내는 코드"가 뒤엉켜서, 나중에 "Slack 대신 이메일로 알림을 바꾸고 싶다"처럼 하나만 바꾸고 싶어도 전체 파일을 다시 읽어야 합니다. 세 역할로 나눠두면 각자 독립적으로 이해하고 고칠 수 있습니다.
- `detector.py` = **판사**: "이 IP, 유죄인가 무죄인가?"만 판단. 판결 후에 어떻게 처벌할지는 관여 안 함.
- `soar.py` = **집행관**: 판사의 판결을 받아서 실제로 "문을 잠그고, 관련 부서에 통보하라"를 지시.
- `alert.py` = **전화 교환원**: "통보하라"는 지시를 받으면 실제로 Slack에 전화를 걸어 메시지를 전달. 전화를 어떻게 거는지(웹훅 URL, 네트워크 요청)는 이 파일만 알면 됨.

(참고로 SOAR라는 이름은 보안 분야 용어 "Security Orchestration, Automation and Response"의 줄임말로, "이상 징후 판단 후 자동으로 대응 조치를 실행한다"는 개념을 가리킵니다.)

**`detector.py` 함수 설명**
- `is_suspicious(ip)`: `db.py`에서 만든 "최근 실패 횟수 세기" 함수를 불러서, 그 횟수가 기준(5회)을 넘었는지 True/False로 알려줍니다. 몇 번 실패했는지 숫자도 같이 돌려줍니다.
- `is_locked(ip)`: 이 IP가 지금 잠긴 상태인지 True/False로 알려줍니다.

이 두 함수는 **묻기만 하고 아무것도 바꾸지 않습니다.** 데이터베이스에 아무 것도 쓰지 않고, 그냥 "지금 상태가 어떤지"만 조회해서 답합니다.

**`soar.py` 함수 설명**
- `enforce_lockout(ip, failure_count)`: 실제로 잠금을 겁니다(`db.create_lockout`) → 곧바로 Slack 알림을 보냅니다(`alert.send_lockout_alert`). "판단"이 아니라 "실행"이라서 호출되는 순간 실제로 데이터베이스와 Slack에 변화가 생깁니다.
- `try_release_expired_lockouts()`: "잠근 지 5분이 지났는데 아직 잠김 상태로 남아있는" IP들을 찾아서 전부 풀어줍니다. 이 함수는 별도의 자동 타이머 없이, `/login` 요청이나 대시보드 새로고침이 들어올 때마다 "혹시 풀어줄 게 있나?" 하고 확인하는 방식으로 동작합니다(4-4절 "다음 요청 시 지연 정리" 방식).
- `manual_release(ip)`: 관리자가 대시보드에서 "즉시 해제" 버튼을 눌렀을 때 호출됩니다. 실제로 잠긴 상태였다면 풀어주고 `True`, 애초에 잠긴 게 없었다면 아무 일도 안 하고 `False`를 돌려줍니다. **"이 사람이 관리자가 맞는지" 확인하는 건 이 함수의 역할이 아닙니다** — 그건 5단계에서 만들 `app.py`가 담당합니다(권한 확인과 실행 로직을 분리).

**`alert.py` 함수 설명**
- `send_lockout_alert(ip, failure_count, locked_at)`: "시각 / 시도 IP / 실패 횟수 / 조치 결과"를 한 문장으로 조립해서 Slack 웹훅 주소로 전송합니다.
- **Slack 웹훅(Incoming Webhook)이 뭔가?** Slack이 채널마다 발급해주는 "이 주소로 메시지를 던지면 그 채널에 자동으로 글이 올라온다"는 전용 URL입니다. 복잡한 로그인 절차 없이, 그 주소에 `{"text": "메시지 내용"}`이라는 짧은 데이터만 던지면 끝나서 구현이 매우 간단합니다.
- `.env`의 `SLACK_WEBHOOK_URL`이 아직 비어있는 상태(팀이 어느 워크스페이스를 쓸지 아직 안 정함, plan.md 1절 결정 #4 보류)이므로, 지금은 실제 전송 대신 **터미널 화면에 메시지를 그대로 출력**하도록 만들어뒀습니다. 나중에 워크스페이스가 정해져서 `.env`에 URL만 채워 넣으면, 코드를 전혀 안 고쳐도 자동으로 진짜 Slack 전송으로 바뀝니다.
- 만약 Slack 전송이 네트워크 문제 등으로 실패하더라도, 이 실패 때문에 로그인 기능 자체가 멈추면 안 되므로 오류를 붙잡아서(예외 처리) 콘솔에 로그만 남기고 넘어가도록 만들었습니다 — "알림 보내기 실패"가 "사용자 로그인 불가"로 번지지 않게 하는 안전장치입니다.

**실제로 테스트한 흐름**
가짜 IP로 실패 기록을 6번 쌓고(임계값 5 초과) → `is_suspicious`가 `True, 6`을 정확히 돌려주는지 → `enforce_lockout` 호출 후 `is_locked`가 `True`로 바뀌는지 → `manual_release`로 풀었을 때 `is_locked`가 다시 `False`로 바뀌고, 이미 풀린 IP를 또 풀려고 하면 `False`(할 일 없음)를 정확히 돌려주는지까지 전부 확인했습니다. 테스트에 쓴 가짜 데이터는 확인 후 바로 삭제했습니다.

### 실제 코드 함께 보기

**[detector.py](../../detector.py) 전체 — "판사"는 코드도 짧습니다 (딱 2개 함수, 아무것도 저장하지 않음)**
```python
import db
from config import FAILURE_THRESHOLD


def is_suspicious(ip: str) -> tuple[bool, int]:
    """이 IP가 "수상한 상태"인지 판단한다.

    판단 기준: 최근 60초(config.DETECTION_WINDOW_SECONDS) 안에 실패한 횟수가
    기준치(FAILURE_THRESHOLD, 기본 5회)를 "초과"했는가?

    반환값은 (수상한가?, 실제 실패 횟수) 형태의 튜플(값 2개를 한 번에 묶어서 돌려주는 것).
    예: (True, 6)  → "수상함, 지금까지 6번 실패했음"
        (False, 3) → "아직 수상하지 않음, 3번 실패했음"
    """
    failure_count = db.count_recent_failures(ip)
    return failure_count > FAILURE_THRESHOLD, failure_count


def is_locked(ip: str) -> bool:
    """이 IP가 지금 이 순간 잠긴 상태인지 True/False로 알려준다."""
    return db.get_active_lockout(ip) is not None
```
`failure_count > FAILURE_THRESHOLD`는 "실패 횟수가 기준치보다 크다"는 부등호 비교를 그대로 코드로 옮긴 것입니다. 이 한 줄이 "5번까지는 봐주고, 6번째부터 수상하다고 판단한다"는 규칙 전체를 담당합니다 — `config.py`에서 `FAILURE_THRESHOLD` 값만 바꾸면 이 규칙도 자동으로 같이 바뀝니다(1단계에서 설명한 "숫자를 한 곳에 모아두는" 설계가 여기서 실제로 힘을 발휘하는 지점입니다).

**[soar.py](../../soar.py) 전체 — 판정 결과를 실제 조치로 옮기는 3개 함수**
```python
from datetime import datetime, timezone

import alert
import db


def enforce_lockout(ip: str, failure_count: int) -> None:
    """이 IP에 실제로 잠금을 걸고, 그 사실을 Slack으로 알린다.

    1. db.create_lockout()으로 "이 IP는 지금부터 5분간 잠김"을 데이터베이스에 저장
    2. alert.send_lockout_alert()로 "IP, 실패 횟수, 조치 내용"을 담은 알림을 전송
    """
    db.create_lockout(ip, failure_count)
    alert.send_lockout_alert(ip, failure_count, datetime.now(timezone.utc))


def try_release_expired_lockouts() -> None:
    """"5분이 지났는데 아직 안 풀린" 잠금들을 찾아서 전부 풀어준다.

    별도의 자동 타이머 프로그램 없이, `/login` 요청이나 대시보드 새로고침이
    들어올 때마다 "혹시 지금 풀어줘야 할 게 있나?"를 확인하는 방식으로 동작한다.
    """
    for lockout in db.list_expired_active_lockouts():
        db.release_lockout(lockout["ip_address"])


def manual_release(ip: str) -> bool:
    """관리자가 대시보드의 "즉시 해제" 버튼을 눌렀을 때 호출되는 함수.

    1. 지금 잠겨있는 IP 목록 안에 이 ip가 있는지 확인한다.
    2. 있다면 실제로 풀어주고 True(성공)를 돌려준다.
    3. 애초에 잠긴 적이 없다면 아무것도 하지 않고 False(할 일 없음)를 돌려준다.
    """
    active_ips = {row["ip_address"] for row in db.list_active_lockouts()}
    if ip not in active_ips:
        return False
    db.release_lockout(ip)
    return True
```
`for lockout in db.list_expired_active_lockouts():` 부분은 "만료된 잠금 목록을 하나씩 꺼내면서, 그때마다 아래 줄(`db.release_lockout(...)`)을 반복 실행해라"는 뜻의 "반복문"입니다. 목록에 3개가 들어있으면 3번, 0개면 0번(즉 아무 일도 안 함) 실행됩니다.

**[alert.py](../../alert.py) 전체 — Slack에 실제로 메시지를 보내는 함수 1개**
```python
def send_lockout_alert(ip: str, failure_count: int, locked_at: datetime) -> None:
    minutes = config.LOCKOUT_DURATION_SECONDS // 60

    message = (
        ":rotating_light: 로그인 워치독 알림\n"
        f"시각: {locked_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"시도 IP: {ip}\n"
        f"실패 횟수: {failure_count}회\n"
        f"조치: {minutes}분간 IP 잠금 처리"
    )

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if not webhook_url:
        # 웹훅 주소가 비어있다 = 아직 Slack 채널이 정해지지 않음 → 콘솔 출력으로 대체
        print(f"[alert] SLACK_WEBHOOK_URL 미설정 - 콘솔 로그로 대체 전송:\n{message}")
        return

    try:
        # 실제로 Slack 서버에 "이 메시지를 채널에 올려줘"라고 요청을 보낸다.
        response = requests.post(webhook_url, json={"text": message}, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        # 네트워크가 끊겼거나 Slack 쪽에서 오류가 났을 때: 프로그램을 중단시키지 않고
        # 문제가 있었다는 사실만 콘솔에 남긴다.
        print(f"[alert] Slack 알림 전송 실패: {e}")
```
`try:` ~ `except requests.RequestException as e:` 부분이 "일단 시도해보고(try), 만약 도중에 문제(네트워크 오류 등)가 생기면(except) 프로그램이 멈추지 않고 이 블록 안의 코드로 넘어가라"는 안전장치입니다. 한국어로 풀면 "Slack에 메시지 보내기를 시도하되, 혹시 실패하면 에러로 프로그램을 죽이지 말고 그냥 콘솔에 '실패했다'고만 적고 넘어가라"는 뜻입니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [detector.py](../../detector.py) (신규 작성 — 판정 함수 2개)
- [soar.py](../../soar.py) (신규 작성 — 조치 함수 3개)
- [alert.py](../../alert.py) (신규 작성 — Slack 알림 함수 1개)
- Supabase 표 데이터는 테스트 후 전부 원상 복구(0건)
