# ============================================================================
# geoip.py — IP 주소로 "어느 나라, 어느 도시에서 접속했는지" 알아내는 부품
#
# alert.py가 Slack이라는 외부 서비스와의 통신만 전담하는 것처럼, 이 파일은
# ip-api.com이라는 외부 서비스와의 통신만 전담한다. db.py(Supabase)나
# app.py(화면)는 이 파일이 내부적으로 무엇을 하는지 몰라도, get_locations()
# 함수 하나만 부르면 위치 정보를 받을 수 있다.
#
# 가장 중요한 설계 포인트는 "캐싱"이다. ip-api.com 무료 사용은 분당 45건까지만
# 허용하는데, 대시보드가 10초마다 최근 로그인 시도를 다시 그리면서 그때마다
# 새로 조회하면 순식간에 한도를 넘긴다. 그래서 한 번 조회한 IP는 db.py를 통해
# Supabase에 저장해두고, 다음부터는 외부 API 대신 그 저장값을 재사용한다.
# ============================================================================

import requests

import db

_API_URL = "http://ip-api.com/json/{ip}"


def _fetch_location(ip: str) -> dict:
    """ip-api.com에 실제로 물어봐서 이 IP의 국가/지역/도시를 알아낸다.

    이 함수는 캐시를 전혀 신경 쓰지 않는다 — "무조건 새로 조회한다"는 역할만
    한다. 캐시를 먼저 확인할지 말지는 이 함수를 부르는 get_locations()가 결정한다.

    실패하는 경우가 두 가지 있다:
    1. 네트워크 자체가 안 되거나 응답이 이상한 경우 (requests.RequestException)
    2. 127.0.0.1 같은 사설/예약된 IP라서 애초에 위치가 없는 경우
       (ip-api.com이 {"status": "fail", "message": "reserved range"} 같은
       응답을 돌려준다)
    두 경우 다 "조회 실패"로 취급하고, 국가/지역/도시는 전부 None으로 채운다.
    """
    try:
        response = requests.get(
            _API_URL.format(ip=ip),
            params={"fields": "status,country,regionName,city"},
            timeout=5,
        )
        data = response.json()
    except requests.RequestException:
        return {"country": None, "region_name": None, "city": None, "lookup_failed": True}

    if data.get("status") != "success":
        return {"country": None, "region_name": None, "city": None, "lookup_failed": True}

    return {
        "country": data.get("country"),
        "region_name": data.get("regionName"),
        "city": data.get("city"),
        "lookup_failed": False,
    }


def get_locations(ips: list[str]) -> dict[str, dict]:
    """여러 IP의 위치를 한 번에 조회한다. 캐시에 없는 IP만 새로 ip-api.com에 묻는다.

    처리 순서:
    1. 중복 IP를 제거한다(같은 IP가 로그에 여러 번 나타나는 건 흔한 일이라,
       똑같은 IP를 두 번 조회하는 낭비를 막는다).
    2. db.get_cached_ip_locations()로 "이미 알고 있는 IP들"을 한 번에 가져온다.
    3. 캐시에 없는 IP만 하나씩 _fetch_location()으로 새로 조회하고, 결과를
       db.save_ip_location()으로 캐시에 저장해서 다음에는 또 안 물어봐도 되게 한다.

    반환값은 {"1.2.3.4": {"country": ..., "region_name": ..., "city": ..., "lookup_failed": ...}, ...}
    형태다.
    """
    unique_ips = list(dict.fromkeys(ips))  # 순서는 유지하면서 중복만 제거
    cached = db.get_cached_ip_locations(unique_ips)

    result = {}
    for ip in unique_ips:
        if ip in cached:
            result[ip] = cached[ip]
            continue
        location = _fetch_location(ip)
        db.save_ip_location(ip, location["country"], location["region_name"], location["city"], location["lookup_failed"])
        result[ip] = location
    return result


def format_location(location: dict) -> str:
    """위치 정보 딕셔너리를 화면에 그대로 보여줄 짧은 문자열로 바꾼다.

    예: {"country": "South Korea", "city": "Seoul", ...} → "South Korea · Seoul"
    조회에 실패했거나 값이 하나도 없으면 "위치 확인 불가"를 돌려준다.
    """
    if location.get("lookup_failed"):
        return "위치 확인 불가"
    parts = [p for p in (location.get("country"), location.get("city")) if p]
    return " · ".join(parts) if parts else "위치 확인 불가"
