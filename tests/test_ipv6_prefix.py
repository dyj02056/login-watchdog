# ============================================================================
# test_ipv6_prefix.py — IPv6 주소를 /64 대역 단위로 세고 잠근다 (guide42)
#
# IPv6 사용자는 /64 대역 안에서 주소를 거의 공짜로 바꿀 수 있어서, 주소 하나 단위로 세면 IP 잠금·
# 요청 제한이 모두 우회된다. 이 파일은
#   - ip_utils.normalize_ip / lookup_address의 변환 규칙
#   - get_request_ip()가 실제 요청에서 대역 키를 돌려주는지(접속 주소·X-Forwarded-For 모두)
#   - 같은 /64의 서로 다른 주소가 로그인 실패·요청 제한을 공유하고, 다른 /64는 따로 세는지
#   - 허용 목록·위치 조회·해제 스크립트가 같은 키로 맞물리는지
# 를 확인한다.
# ============================================================================

import os
import sys

import pytest

import config
import db
from security import detector, lockdown, soar
from services import geoip
from services.ip_utils import lookup_address, normalize_ip

from tests.test_app import get_csrf_token  # noqa: E402

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "management")
)
import unlock_ip  # noqa: E402

SAME_BLOCK_A = "2001:db8:1:2::a"
SAME_BLOCK_B = "2001:db8:1:2:ffff:ffff:ffff:ffff"
OTHER_BLOCK = "2001:db8:1:3::a"
BLOCK_KEY = "2001:db8:1:2::/64"


# ---------------------------------------------------------------------------
# 변환 규칙
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("203.0.113.10", "203.0.113.10"),                 # IPv4는 그대로
    (SAME_BLOCK_A, BLOCK_KEY),                        # IPv6는 /64 대역
    (SAME_BLOCK_B, BLOCK_KEY),
    ("2001:DB8:1:2:0:0:0:A", BLOCK_KEY),              # 표기가 달라도 같은 키
    (OTHER_BLOCK, "2001:db8:1:3::/64"),
    ("::ffff:203.0.113.10", "203.0.113.10"),          # IPv4가 들어 있는 IPv6는 IPv4로
    ("::1", "::1"),                                   # 루프백은 그대로
    (BLOCK_KEY, BLOCK_KEY),                           # 이미 대역 키여도 같은 결과(멱등)
    ("2001:db8:1:2::/48", "2001:db8:1::/64"),         # 다른 길이의 대역도 설정 길이로 맞춘다
    ("not-an-ip", "not-an-ip"),                       # IP가 아니면 건드리지 않는다
    ("", ""),
    (None, None),
])
def test_normalize_ip(raw, expected):
    assert normalize_ip(raw) == expected


def test_prefix_length_is_configurable(monkeypatch):
    monkeypatch.setattr(config, "IPV6_PREFIX_LENGTH", 56)
    assert normalize_ip("2001:db8:1:2ff::1") == "2001:db8:1:200::/56"

    monkeypatch.setattr(config, "IPV6_PREFIX_LENGTH", 999)  # 범위 밖이면 64
    assert normalize_ip(SAME_BLOCK_A) == BLOCK_KEY


@pytest.mark.parametrize("key, expected", [
    (BLOCK_KEY, "2001:db8:1:2::"),
    ("203.0.113.10", "203.0.113.10"),
    ("evil.example/../x", None),
    ("not-an-ip", None),
])
def test_lookup_address(key, expected):
    assert lookup_address(key) == expected


# ---------------------------------------------------------------------------
# 실제 요청
# ---------------------------------------------------------------------------

def test_request_ip_is_the_block_key_for_ipv6_clients(flask_app):
    from helpers import get_request_ip

    with flask_app.test_request_context("/", environ_base={"REMOTE_ADDR": SAME_BLOCK_A}):
        assert get_request_ip() == BLOCK_KEY
    with flask_app.test_request_context("/", environ_base={"REMOTE_ADDR": "203.0.113.10"}):
        assert get_request_ip() == "203.0.113.10"


def test_forwarded_ipv6_is_also_normalized_and_bad_values_still_fall_back(flask_app, monkeypatch):
    from helpers import get_request_ip

    monkeypatch.setattr(config, "TRUST_FORWARDED_FOR", True)
    with flask_app.test_request_context("/", headers={"X-Forwarded-For": f"{SAME_BLOCK_B}, 10.0.0.1"}):
        assert get_request_ip() == BLOCK_KEY
    with flask_app.test_request_context(
        "/", headers={"X-Forwarded-For": "http://evil/"}, environ_base={"REMOTE_ADDR": SAME_BLOCK_A}
    ):
        assert get_request_ip() == BLOCK_KEY


def test_login_failures_from_one_block_are_counted_under_one_key(client, monkeypatch):
    logged = []
    monkeypatch.setattr(soar, "try_release_expired_lockouts", lambda: None)
    monkeypatch.setattr(soar, "try_release_expired_account_lockouts", lambda: None)
    monkeypatch.setattr(detector, "is_locked", lambda ip: False)
    monkeypatch.setattr(detector, "is_account_locked", lambda u: False)
    monkeypatch.setattr(db, "verify_user_credentials", lambda u, p: False)
    monkeypatch.setattr(db, "log_attempt", lambda ip, u, success: logged.append(ip))
    monkeypatch.setattr(detector, "is_suspicious", lambda ip: (False, 1))
    monkeypatch.setattr(detector, "is_account_suspicious", lambda u: (False, 1))

    for address in (SAME_BLOCK_A, SAME_BLOCK_B, OTHER_BLOCK):
        token = get_csrf_token(client, "/login")
        client.post(
            "/login", data={"username": "alice", "password": "x", "csrf_token": token},
            environ_base={"REMOTE_ADDR": address},
        )

    assert logged == [BLOCK_KEY, BLOCK_KEY, "2001:db8:1:3::/64"]


def test_rate_limit_is_shared_across_one_block(client, monkeypatch):
    # /recovery/verify의 IP당 분당 10회 한도로 확인한다 — 같은 /64의 다른 주소로 바꿔도 같은 한도다.
    monkeypatch.setattr(soar, "record_rejection", lambda *a, **k: None)
    monkeypatch.setattr(db, "get_latest_pending_recovery_for_username", lambda u: None)

    def submit(address):
        token = get_csrf_token(client, "/recovery/verify")
        return client.post(
            "/recovery/verify", data={"username": "ghost", "code": "123456", "csrf_token": token},
            environ_base={"REMOTE_ADDR": address},
        ).status_code

    first = [submit(SAME_BLOCK_A) for _ in range(config.RECOVERY_VERIFY_RATE_LIMIT_PER_MINUTE)]

    assert first == [200] * config.RECOVERY_VERIFY_RATE_LIMIT_PER_MINUTE
    assert submit(SAME_BLOCK_B) == 429      # 주소를 바꿔도 같은 대역이면 막힌다
    assert submit(OTHER_BLOCK) == 200       # 다른 대역은 따로 센다


# ---------------------------------------------------------------------------
# 맞물리는 곳
# ---------------------------------------------------------------------------

def test_allowlist_entry_with_a_full_ipv6_address_matches_the_block(monkeypatch):
    monkeypatch.setattr(config, "PERMANENT_LOCK_IP_ALLOWLIST", frozenset({SAME_BLOCK_A, "203.0.113.10"}))

    assert lockdown.is_ip_allowlisted(BLOCK_KEY) is True
    assert lockdown.is_ip_allowlisted("203.0.113.10") is True
    assert lockdown.is_ip_allowlisted("2001:db8:1:3::/64") is False


def test_geoip_looks_up_the_block_by_its_network_address(monkeypatch):
    requested = []

    class Response:
        def json(self):
            return {"status": "success", "country": "Korea", "regionName": "Seoul", "city": "Seoul"}

    monkeypatch.setattr(geoip.requests, "get", lambda url, params=None, timeout=None: requested.append(url) or Response())

    location = geoip._fetch_location(BLOCK_KEY)

    assert requested == ["http://ip-api.com/json/2001:db8:1:2::"]
    assert location["lookup_failed"] is False


def test_geoip_does_not_call_out_for_garbage(monkeypatch):
    monkeypatch.setattr(geoip.requests, "get", lambda *a, **k: pytest.fail("이상한 값으로 외부 요청을 보냈다"))

    assert geoip._fetch_location("evil.example/../x")["lookup_failed"] is True


def test_unlock_script_accepts_a_full_ipv6_address(monkeypatch):
    unlocked = []
    monkeypatch.setattr(unlock_ip, "unlock_one", lambda ip, permanent, note: unlocked.append(ip))
    monkeypatch.setattr(sys, "argv", ["unlock_ip.py", "--ip", SAME_BLOCK_B])

    unlock_ip.main()

    assert unlocked == [BLOCK_KEY]
