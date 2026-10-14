# ============================================================================
# routes/internal/_hmac.py — 내부 API 서명(HMAC) 검증 공용 함수 (계약서 K3)
#
# 담당: 역할 B (B0-1에서 구현). 지금은 Track D 뼈대 PR(I0-1)이 넣은 껍데기다.
#
# 뼈대 단계의 verify_request()는 "항상 거절(None)"을 돌려준다 — 구현 전에 내부 창구가
# 실수로 열려 있지 않도록, 서명 검사가 생기기 전까지는 어떤 요청도 통과시키지 않는다.
# ============================================================================


def sign(key: str, timestamp: str, body: bytes) -> str:
    """서명 문자열(hex)을 만든다. 테스트와 보내는 쪽(shipper·fw-agent) 구현의 기준값.

    B0-1에서 구현한다(계약서 K3).
    """
    raise NotImplementedError("B0-1에서 구현 — 계약서 K3")


def verify_request(allowed_senders: set[str]) -> str | None:
    """현재 flask.request의 서명을 검증한다.

    성공하면 보낸이 이름('shipper' | 'fw-agent'), 실패하면 None.
    B0-1에서 구현하기 전까지는 항상 None(거절)을 돌려준다.
    """
    return None
