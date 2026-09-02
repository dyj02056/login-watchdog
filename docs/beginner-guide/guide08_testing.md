# 8단계 — pytest 단위 테스트 (진짜 서버 없이 코드만 자동으로 검증하기)

[◀ 7단계](guide07_alert.md) · [전체 목차](beginner-guide.md) · [9단계 ▶](guide09_quota.md)


### 우리가 한 일
1. [tests/test_config.py](../../tests/test_config.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_soar.py](../../tests/test_soar.py), [tests/test_db.py](../../tests/test_db.py) 4개 파일에 총 16개의 테스트 작성
2. `pytest` 명령 한 번으로 16개를 전부 자동 실행 → 전부 통과 확인
3. 회귀 테스트가 진짜로 실수를 잡아내는지 보여주기 위해, `config.py`의 숫자를 일부러 하나 틀리게 바꿔서 테스트가 실패하는 것까지 확인한 뒤 원상 복구

### 왜 했는가 (쉬운 설명)

**지금까지 방식과 무엇이 다른가**
5~7단계에서는 실제로 서버를 켜고 브라우저를 조작하거나, 파이썬 스크립트로 진짜 Supabase에 데이터를 넣었다 빼며 확인했습니다. 이 방식은 "실제로 다 연결된 상태에서 진짜처럼 확인한다"는 확실한 장점이 있지만, 매번 서버를 켜야 하고 네트워크 응답을 기다려야 하고 테스트 데이터를 치워야 하는 수고가 듭니다.

**단위 테스트(unit test)**는 프로그램을 이루는 작은 부품(함수) 하나하나를 떼어내서, "이런 입력을 주면 이런 결과가 나와야 정상이다"라는 규칙을 코드로 미리 적어두고 자동으로 확인하는 방식입니다. `pytest`는 이런 테스트 코드 파일들을 모아 한 번에 실행하고 결과를 보고해주는 도구입니다.

**"가짜로 바꿔치기한다"(monkeypatch)는 게 정확히 뭔가**
`detector.is_suspicious(ip)`를 예로 들면, 이 함수는 내부적으로 `db.count_recent_failures(ip)`를 호출해서 진짜 Supabase에 묻습니다. 그런데 우리가 확인하고 싶은 건 "숫자가 6이면 True를 돌려주는가"라는 **판정 로직**이지, Supabase 연결 자체가 아닙니다. 그래서 테스트 코드 안에서 pytest가 제공하는 `monkeypatch`라는 도구로 "`db.count_recent_failures`가 호출되면 진짜 DB에 묻지 말고, 내가 정해준 숫자(6)를 그냥 즉시 돌려줘"라고 잠깐 바꿔치기해둡니다. 테스트가 끝나면 pytest가 자동으로 원래 함수로 되돌려놓아서, 다른 테스트나 실제 프로그램에는 전혀 영향을 주지 않습니다.

이걸 비유하면, 자동차 브레이크 성능을 확인할 때 매번 진짜 도로에 나가 운전하는 대신 브레이크만 떼어내 실험실 기계에 걸어놓고 "이만큼 힘을 주면 이만큼 멈추는가"만 확인하는 것과 같습니다. 도로(진짜 Supabase) 상태와 무관하게 브레이크(판정 로직) 자체만 순수하게 검사할 수 있습니다.

**4개 테스트 파일이 각각 확인하는 것**
- **`test_config.py`(회귀 테스트)**: 기획서가 정한 숫자(실패 5회, 60초, 300초)가 코드에도 정확히 그대로 박혀 있는지 확인합니다. 로직을 검사하는 게 아니라 "숫자 자체"를 지키는 안전장치입니다. 누군가 나중에 실수로 `config.py`의 숫자를 잘못 고치면, 다음에 `pytest`를 돌렸을 때 바로 빨간 글씨로 알려줍니다.
- **`test_detector.py`**: 실패 횟수가 4/5/6일 때 `is_suspicious()`가 각각 정확히 False/False/True를 돌려주는지 "경계값(boundary)"을 촘촘히 확인합니다. 5는 아직 봐주고 6부터 잠근다는 규칙이 코드에도 정확히 그렇게 박혀 있는지 확인하는 것입니다.
- **`test_soar.py`**: `enforce_lockout()`이 "잠그기 → 알리기" 순서를 지키는지, `try_release_expired_lockouts()`가 만료된 IP만 정확히 풀어주고 안 만료된 건 건드리지 않는지, `manual_release()`가 잠긴 IP는 풀고(True) 안 잠긴 IP는 아무 일도 안 하는지(False) 확인합니다.
- **`test_db.py`**: `verify_admin_credentials()`가 맞는 비밀번호는 통과시키고(True), 틀린 비밀번호나 존재하지 않는 아이디는 거부하는지(False) 확인합니다. Supabase 클라이언트인 척하는 가짜 객체(`_FakeQuery`)를 직접 만들어서 `db.get_client()`를 바꿔치기했습니다.

### 실제 코드 함께 보기

**경계값 테스트 — `test_detector.py`**
```python
def test_is_suspicious_false_at_exact_threshold(monkeypatch):
    # 정확히 5번 실패한 "경계값"에서는 아직 수상하지 않아야 한다
    # (기획서 규칙: "5회 초과"부터 수상함, 5회 자체는 아직 봐준다).
    monkeypatch.setattr(db, "count_recent_failures", lambda ip: 5)

    suspicious, count = detector.is_suspicious("1.2.3.4")

    assert suspicious is False
    assert count == 5
```
`monkeypatch.setattr(db, "count_recent_failures", lambda ip: 5)`가 바꿔치기 그 자체입니다. `lambda ip: 5`는 "어떤 IP를 받든 무조건 5를 돌려주는 즉석 가짜 함수"를 뜻합니다. `assert`는 "이 조건이 참이 아니면 테스트를 실패로 처리해라"는 pytest의 기본 문법입니다.

**호출 순서까지 확인하는 테스트 — `test_soar.py`**
```python
def test_enforce_lockout_creates_lockout_then_sends_alert(monkeypatch):
    calls = []  # 호출된 순서를 기록해둘 리스트

    def fake_create_lockout(ip, failure_count):
        calls.append(("create_lockout", ip, failure_count))

    def fake_send_lockout_alert(ip, failure_count, locked_at):
        calls.append(("send_lockout_alert", ip, failure_count))

    monkeypatch.setattr(db, "create_lockout", fake_create_lockout)
    monkeypatch.setattr(alert, "send_lockout_alert", fake_send_lockout_alert)

    soar.enforce_lockout("9.9.9.9", 6)

    assert calls == [
        ("create_lockout", "9.9.9.9", 6),
        ("send_lockout_alert", "9.9.9.9", 6),
    ]
```
가짜 함수들이 실제 작업(DB 저장, Slack 전송) 대신 "내가 호출됐다"는 사실만 `calls` 리스트에 순서대로 적어둡니다. 테스트 마지막에 이 리스트의 순서가 "잠그기 다음에 알리기"인지 정확히 확인합니다 — 4단계에서 "알림은 잠그는 순간에만, 잠근 다음에 보낸다"고 설계했던 규칙이 실제로 지켜지는지를 코드로 증명하는 셈입니다.

**Supabase인 척하는 가짜 객체 — `test_db.py`**
```python
class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def table(self, *args, **kwargs):
        return self

    def select(self, *args, **kwargs):
        return self

    def eq(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def execute(self):
        return _FakeResult(self._rows)
```
`db.py`가 `.table().select().eq().limit().execute()`처럼 메서드를 사슬(체인)처럼 이어 부르는 걸 흉내내려고, `table`/`select`/`eq`/`limit`은 전부 "그냥 나 자신을 다시 돌려줘라"고 만들어서 체인이 끊기지 않게 하고, 맨 마지막 `execute()`에서만 미리 준비해둔 가짜 데이터를 내놓습니다. 이렇게 하면 진짜 `db.verify_admin_credentials()` 코드를 한 글자도 안 고치고 그대로 실행시키면서, 그 아래 깔린 "진짜 Supabase 연결"만 가짜로 바꿔치기할 수 있습니다.

### 회귀 테스트가 실수를 잡아내는 모습을 실제로 확인

`config.py`의 `FAILURE_THRESHOLD` 기본값을 5에서 6으로 일부러 잘못 바꾼 뒤 `pytest`를 돌려봤습니다.
```
tests/test_config.py::test_failure_threshold_is_5 FAILED
    assert config.FAILURE_THRESHOLD == 5
E   assert 6 == 5
```
정확히 "5여야 하는데 6이다"라고 콕 짚어 실패를 알려줬습니다. 값을 다시 5로 되돌리자 16개 테스트가 전부 통과했습니다. 이게 바로 회귀 테스트의 존재 이유입니다 — 사람이 매번 눈으로 `config.py`를 들여다보지 않아도, 실수를 즉시, 자동으로 잡아낼 수 있습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [tests/test_config.py](../../tests/test_config.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_soar.py](../../tests/test_soar.py) (기존 빈 뼈대 파일에 내용 작성)
- [tests/test_db.py](../../tests/test_db.py) (신규 작성)
- `pytest tests/` 실행 결과 16개 테스트 전부 통과, 실제 Supabase 데이터는 전혀 건드리지 않음
