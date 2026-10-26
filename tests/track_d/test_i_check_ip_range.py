"""C3-1 점검용 새 출발지 IP 범위가 다른 용도와 겹치지 않고, 앞 범위를 다 쓰면 .11~.99로 넘어가는지 검사한다.

10/26 .111~.139(29개)가 하루 세 번 실행에 바닥나 3회차가 SKIP됐다.
"""

from __future__ import annotations

from scripts.net import check_common as cc

PREFIX = "172.28.0"


class FakeReader:
    """network_blocks·security_incidents select만 흉내 낸다(.like 조건은 이미 prefix로 걸렀다고 본다)."""

    def __init__(self, blocked: list[str], incidents: list[str]) -> None:
        self.rows = {"network_blocks": blocked, "security_incidents": incidents}
        self._table = None

    def table(self, name):
        self._table = name
        return self

    def select(self, *a):
        return self

    def like(self, *a):
        return self

    def execute(self):
        return type("R", (), {"data": [{"ip_address": ip} for ip in self.rows[self._table]]})()


def _all_check_ips() -> set[int]:
    return {last for start, end in cc.CHECK_IP_RANGES for last in range(start, end + 1)}


def test_check_ranges_include_11_to_99_and_avoid_reserved() -> None:
    ips = _all_check_ips()
    assert set(range(11, 100)) <= ips
    assert set(range(111, 140)) <= ips
    reserved = {1, 10, 101, 102, 103, 140, *range(150, 200)}
    assert not ips & reserved
    # .2~.9는 Docker 자동 할당과 겹칠 수 있어 쓰지 않는다
    assert not ips & set(range(2, 10))


def test_choose_fresh_ip_moves_to_lower_range_when_111_139_used() -> None:
    used = [f"{PREFIX}.{last}" for last in range(111, 140)]
    reader = FakeReader(blocked=used[:20], incidents=used[20:])
    assert cc.choose_fresh_ip(reader, PREFIX) == f"{PREFIX}.11"


def test_choose_fresh_ip_prefers_original_range_first() -> None:
    reader = FakeReader(blocked=[f"{PREFIX}.111"], incidents=[])
    assert cc.choose_fresh_ip(reader, PREFIX) == f"{PREFIX}.112"


def test_choose_fresh_ip_returns_none_when_all_ranges_used() -> None:
    used = [f"{PREFIX}.{last}" for last in sorted(_all_check_ips())]
    assert cc.choose_fresh_ip(FakeReader(blocked=used, incidents=[]), PREFIX) is None


def test_choose_fresh_ip_explicit_range_still_works() -> None:
    reader = FakeReader(blocked=[f"{PREFIX}.120"], incidents=[])
    assert cc.choose_fresh_ip(reader, PREFIX, start=120, end=121) == f"{PREFIX}.121"
