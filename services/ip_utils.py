# ============================================================================
# services/ip_utils.py — 접속 IP를 "탐지·잠금 단위"로 정규화한다 (guide42)
#
# 왜 필요한가: IPv6 사용자는 보통 /64 대역(앞 64비트가 같은 2^64개 주소)을 통째로 받아서 주소를
# 바꾸는 비용이 거의 없다. 주소 하나를 단위로 세고 잠그면, 시도마다 주소를 바꾸는 것만으로 IP 잠금·
# IP 단위 탐지·요청 제한·영구 잠금이 모두 무력화된다. 그래서 IPv6는 대역(기본 /64)을 한 단위로 본다.
#
#   203.0.113.10            → 203.0.113.10          (IPv4는 그대로)
#   2001:db8:1:2:abcd::5    → 2001:db8:1:2::/64     (IPv6는 대역)
#   ::ffff:203.0.113.10     → 203.0.113.10          (IPv4가 들어 있는 IPv6는 IPv4로)
#   ::1                     → ::1                   (루프백은 그대로 — 로컬 개발 편의)
#
# helpers.get_request_ip()가 이 함수를 거친 값을 돌려주므로, 그 값을 쓰는 로그인 실패 집계·IP 잠금·
# 요청 제한·보안 이벤트·상관분석·IP 예외·복구/재설정 IP 한도가 전부 같은 단위로 동작한다.
# Flask에 의존하지 않는 순수 함수라 security/lockdown.py(허용 목록)와 scripts/unlock_ip.py도 같이 쓴다.
# ============================================================================

import ipaddress

import config


def _prefix_length() -> int:
    """IPv6 대역 길이. 설정값이 1~128 밖이면 기본 64를 쓴다."""
    length = config.IPV6_PREFIX_LENGTH
    return length if 1 <= length <= 128 else 64


def normalize_ip(raw: str | None) -> str | None:
    """접속 IP(또는 이미 정규화된 대역 문자열)를 탐지·잠금 단위 문자열로 바꾼다.
    IP 형식이 아니면 그대로 돌려준다 — 형식 검증은 호출부(get_request_ip)의 몫이다."""
    if not raw:
        return raw
    if "/" in raw:
        # 이미 대역 형태("2001:db8:1:2::/64")로 들어온 값 — 허용 목록·해제 스크립트 입력 등.
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return raw
        if network.version == 6:
            return str(ipaddress.ip_network(f"{network.network_address}/{_prefix_length()}", strict=False))
        return str(network)

    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    if address.is_loopback:
        return str(address)
    return str(ipaddress.ip_network(f"{address}/{_prefix_length()}", strict=False))


def lookup_address(key: str) -> str | None:
    """위치 조회(geoip)에 넘길 실제 주소. 대역 키면 대표 주소(네트워크 주소)를, IP면 그대로,
    둘 다 아니면 None(조회하지 않음 — 외부 요청 주소에 이상한 문자열이 섞이지 않게)."""
    if "/" in key:
        try:
            return str(ipaddress.ip_network(key, strict=False).network_address)
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_address(key))
    except ValueError:
        return None
