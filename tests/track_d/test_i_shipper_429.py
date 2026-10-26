"""shipper가 429(한도 초과)를 받으면 버리지 않고 물러났다가 다시 보내는지 검사한다(10/26 강사 피드백 1).

다른 4xx(형식 오류·인증 실패)는 다시 보내도 성공할 수 없으므로 지금처럼 바로 포기한다
(test_a_shipper.py의 test_sender_does_not_retry_4xx가 그대로 지킨다).
"""

from __future__ import annotations

from tests.track_d.test_a_shipper import FakeResponse, FakeSession, sample_body, shipper


class HeaderResponse(FakeResponse):
    def __init__(self, status_code: int, headers: dict[str, str]) -> None:
        super().__init__(status_code)
        self.headers = headers


def _sender(session, sleeps):
    return shipper.Sender(
        url="http://app:5000/api/internal/net-events",
        secret="test-key",
        session=session,
        clock=lambda: 1760930000.0,
        sleeper=sleeps.append,
    )


def test_sender_retries_429_with_backoff() -> None:
    session = FakeSession([FakeResponse(429), FakeResponse(429), FakeResponse(200)])
    sleeps: list[float] = []

    assert _sender(session, sleeps)._deliver(sample_body()) is True
    assert len(session.calls) == 3
    assert sleeps == [1, 2]


def test_sender_honors_retry_after_up_to_60_seconds() -> None:
    session = FakeSession([
        HeaderResponse(429, {"Retry-After": "7"}),
        HeaderResponse(429, {"Retry-After": "600"}),
        FakeResponse(200),
    ])
    sleeps: list[float] = []

    assert _sender(session, sleeps)._deliver(sample_body()) is True
    # 기본 물러남(1·2초)보다 길면 Retry-After를 따르고, 60초를 넘기지 않는다.
    assert sleeps == [7, 60]


def test_sender_gives_up_after_max_attempts_on_429() -> None:
    session = FakeSession([FakeResponse(429)] * shipper.MAX_SEND_ATTEMPTS)
    sleeps: list[float] = []

    assert _sender(session, sleeps)._deliver(sample_body()) is False
    assert len(session.calls) == shipper.MAX_SEND_ATTEMPTS
    assert sleeps == list(shipper.RETRY_DELAYS_SECONDS)
