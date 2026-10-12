# ============================================================================
# tests/track_d/conftest.py — Track D 테스트 공용 준비물
#
# Track D 뼈대 PR(I0-1)이 만들고 통합 담당자만 고친다. 각 역할의 테스트는
# tests/track_d/test_<역할>_*.py에 새로 만든다(tests/conftest.py의 flask_app·client fixture도
# 그대로 쓸 수 있다).
#
# signed_headers는 내부 API(/api/internal/*) 요청에 붙일 서명 헤더를 만든다(계약서 K3).
# 일부러 routes/internal/_hmac.py의 sign()을 쓰지 않고 hmac 표준 라이브러리로 직접 계산한다 —
# 같은 규칙을 두 번 독립적으로 구현해 두면, 역할 B의 sign()이 계약서와 다르게 만들어졌을 때
# 테스트가 바로 잡아낸다(교차 검증). shipper·fw-agent 테스트도 같은 기준값과 비교한다.
# ============================================================================

import hashlib
import hmac
import time

import pytest


def _make_signed_headers(sender: str, key: str, body: bytes = b"", timestamp: str | None = None) -> dict:
    """X-LW-Sender / X-LW-Timestamp / X-LW-Signature 헤더 세 개를 만든다(계약서 K3).

    서명 대상은 timestamp(ASCII) + b"." + body(보낸 바이트 그대로). GET 요청은 body=b"".
    timestamp를 주지 않으면 지금 시각(유닉스 초)을 쓴다.
    """
    if timestamp is None:
        timestamp = str(int(time.time()))
    signature = hmac.new(key.encode(), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    return {
        "X-LW-Sender": sender,
        "X-LW-Timestamp": timestamp,
        "X-LW-Signature": signature,
    }


@pytest.fixture
def signed_headers():
    """테스트에서 signed_headers("shipper", "test-ingest-secret", body)처럼 부르는 함수를 돌려준다."""
    return _make_signed_headers
