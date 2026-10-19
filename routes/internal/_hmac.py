"""내부 API의 원본 본문과 시각을 인증한다(계약서 K3).

P7에 따라 shipper와 fw-agent의 키를 분리해 한쪽 키가 유출되어도 다른
보낸이의 권한을 사용할 수 없게 한다. 시각 오차를 기본 60초로 제한해
오래된 요청의 재전송을 막는다. 허용 시간 안의 중복 재전송까지 막지는 않는다.
"""

import hashlib
import hmac
import time

from flask import request

import config


def sign(key: str, timestamp: str, body: bytes) -> str:
    """송신 측과 같은 바이트 규칙을 사용해 서명 호환성을 보장한다."""
    return hmac.new(key.encode(), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def verify_request(allowed_senders: set[str]) -> str | None:
    """실패 상세는 로그에만 남기고 호출자는 공통 인증 실패로 응답하게 한다."""
    sender = request.headers.get("X-LW-Sender")
    timestamp = request.headers.get("X-LW-Timestamp")
    signature = request.headers.get("X-LW-Signature")
    if not sender or not timestamp or not signature:
        print("internal_hmac: missing_header")
        return None
    if sender not in allowed_senders or sender not in {"shipper", "fw-agent"}:
        print("internal_hmac: disallowed_sender")
        return None

    key = config.NET_INGEST_SECRET if sender == "shipper" else config.NET_AGENT_SECRET
    if not key:
        print("internal_hmac: empty_key")
        return None
    try:
        timestamp.encode("ascii")
        timestamp_value = int(timestamp)
    except (ValueError, UnicodeEncodeError):
        print("internal_hmac: invalid_timestamp")
        return None
    if abs(time.time() - timestamp_value) > config.NET_INTERNAL_MAX_SKEW_SECONDS:
        print("internal_hmac: timestamp_skew")
        return None

    # 원본 바이트를 캐시해야 이후 라우트에서 get_json()으로 본문을 다시 읽을 수 있다.
    expected = sign(key, timestamp, request.get_data(cache=True))
    # 비ASCII 입력도 예외로 중단되지 않고 인증 실패로 처리한다.
    if not hmac.compare_digest(expected.encode("ascii"), signature.encode("utf-8")):
        print("internal_hmac: signature_mismatch")
        return None
    return sender
