# ============================================================================
# test_geoip.py — geoip.py가 캐시를 올바르게 활용하는지, 문자열을 올바르게
# 조립하는지 확인하는 단위 테스트
#
# 여기서는 진짜 ip-api.com에 접속하지 않는다. requests.get 자체를 가짜로
# 바꿔치기해서 "외부 API가 이런 응답을 줬다고 치자"는 상황을 만들고,
# db.get_cached_ip_locations / db.save_ip_location도 가짜로 바꿔서 진짜
# Supabase 없이 "캐시에 있었다/없었다"는 상황을 마음대로 조작한다.
# ============================================================================

import requests

import db
import geoip


class _FakeResponse:
    """requests.get()이 돌려주는 응답 객체를 흉내낸다. .json()만 있으면 된다."""

    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def test_format_location_with_country_and_city():
    location = {"country": "South Korea", "region_name": "Seoul", "city": "Seoul", "lookup_failed": False}
    assert geoip.format_location(location) == "South Korea · Seoul"


def test_format_location_lookup_failed():
    location = {"country": None, "region_name": None, "city": None, "lookup_failed": True}
    assert geoip.format_location(location) == "위치 확인 불가"


def test_get_locations_uses_cache_and_skips_external_call(monkeypatch):
    cached_row = {"country": "Australia", "region_name": "NSW", "city": "Sydney", "lookup_failed": False}
    monkeypatch.setattr(db, "get_cached_ip_locations", lambda ips: {"1.1.1.1": cached_row})

    def fail_if_called(*args, **kwargs):
        raise AssertionError("캐시에 있는 IP인데 외부 API를 또 호출하면 안 된다")

    monkeypatch.setattr(requests, "get", fail_if_called)

    result = geoip.get_locations(["1.1.1.1"])

    assert result == {"1.1.1.1": cached_row}


def test_get_locations_fetches_and_caches_new_ip(monkeypatch):
    monkeypatch.setattr(db, "get_cached_ip_locations", lambda ips: {})  # 캐시에 아무것도 없음

    saved = []
    monkeypatch.setattr(
        db, "save_ip_location", lambda ip, country, region_name, city, lookup_failed:
        saved.append((ip, country, region_name, city, lookup_failed))
    )
    monkeypatch.setattr(
        requests, "get",
        lambda url, params=None, timeout=None: _FakeResponse(
            {"status": "success", "country": "United States", "regionName": "Virginia", "city": "Ashburn"}
        ),
    )

    result = geoip.get_locations(["8.8.8.8"])

    assert result["8.8.8.8"] == {
        "country": "United States",
        "region_name": "Virginia",
        "city": "Ashburn",
        "lookup_failed": False,
    }
    # 새로 조회한 결과가 캐시에 저장되도록 db.save_ip_location이 호출됐는지 확인
    assert saved == [("8.8.8.8", "United States", "Virginia", "Ashburn", False)]


def test_get_locations_marks_reserved_range_as_failed(monkeypatch):
    # 127.0.0.1 같은 사설 IP에 ip-api.com이 실제로 돌려주는 응답 형태를 그대로 흉내낸다.
    monkeypatch.setattr(db, "get_cached_ip_locations", lambda ips: {})
    monkeypatch.setattr(db, "save_ip_location", lambda *args: None)
    monkeypatch.setattr(
        requests, "get",
        lambda url, params=None, timeout=None: _FakeResponse({"status": "fail", "message": "reserved range"}),
    )

    result = geoip.get_locations(["127.0.0.1"])

    assert result["127.0.0.1"]["lookup_failed"] is True


def test_get_locations_dedupes_duplicate_ips(monkeypatch):
    monkeypatch.setattr(db, "get_cached_ip_locations", lambda ips: {})
    call_count = {"n": 0}

    def fake_get(url, params=None, timeout=None):
        call_count["n"] += 1
        return _FakeResponse({"status": "success", "country": "France", "regionName": "IDF", "city": "Paris"})

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(db, "save_ip_location", lambda *args: None)

    # 같은 IP가 목록에 두 번 들어있어도, 외부 API는 딱 한 번만 불러야 한다.
    geoip.get_locations(["5.5.5.5", "5.5.5.5"])

    assert call_count["n"] == 1
