"""guide57 공격 상자(위조 출발지·ICMP)와 S7·S9 자동 점검 판정 규칙.

실제 컨테이너·raw 소켓·DB 없이 명령 모양과 판정만 본다.
"""

from __future__ import annotations

import importlib.util
import io
import json
import random
import socket
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.net import check_common as cc
from scripts.net import check_s7, check_s9, run_all


ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("lw_guide57_under_test", ROOT / "netwatch" / "attacker" / "lw.py")
lw = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lw)

TARGET_URL = "http://172.28.13.10:8080"
PREFIX = "172.28.13"


class FakeRunner:
    def __init__(self):
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def run_cli(argv, **kwargs):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = lw.main(argv, environ={"TARGET_URL": TARGET_URL}, stdout=stdout, stderr=stderr, **kwargs)
    text = stdout.getvalue().strip()
    return code, (json.loads(text) if text else None), stderr.getvalue()


# ---------------------------------------------------------------------------
# lw.py — 위조 출발지 허용 범위
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["172.28.13.140", "172.28.13.200", "172.30.0.250", "192.0.2.50"])
def test_allowed_spoof_sources(value):
    assert lw.validate_spoof_source(value, "172.28.13.10") == value


@pytest.mark.parametrize("value", ["8.8.8.8", "172.28.12.140", "172.28.13.10", "2001:db8::1", "nope"])
def test_rejected_spoof_sources(value):
    with pytest.raises(ValueError):
        lw.validate_spoof_source(value, "172.28.13.10")


def test_synflood_spoof_source_adds_hping3_a_flag():
    runner = FakeRunner()
    code, result, _ = run_cli(["synflood", "--count", "100", "--spoof-source", "172.28.13.140"], runner=runner)
    assert code == 0 and result["spoof_source"] == "172.28.13.140"
    command = runner.commands[0]
    assert command[command.index("-a") + 1] == "172.28.13.140"
    assert command[-1] == "172.28.13.10"


def test_synflood_rejects_internet_spoof_source_before_running():
    runner = FakeRunner()
    code, result, err = run_cli(["synflood", "--spoof-source", "8.8.8.8"], runner=runner)
    assert code == 2 and result is None and runner.commands == []
    assert "인터넷" in err


def test_synflood_rand_source_uses_rotating_sender_not_hping3():
    runner = FakeRunner()
    calls = []

    def fake_sender(host, port, count):
        calls.append((host, port, count))
        return count

    code, result, _ = run_cli(["synflood", "--rand-source", "--count", "300"], runner=runner, rotating_sender=fake_sender)
    assert code == 0 and result["mode"] == "rand-source" and result["sent"] == 300
    assert calls == [("172.28.13.10", 8080, 300)]
    assert runner.commands == []


def test_spoof_and_rand_source_are_exclusive():
    with pytest.raises(SystemExit):
        run_cli(["synflood", "--rand-source", "--spoof-source", "172.28.13.140"])


def test_icmpflood_command_is_bounded():
    runner = FakeRunner()
    code, result, _ = run_cli(["icmpflood", "--count", "500"], runner=runner)
    assert code == 0 and result["step"] == "icmpflood" and result["sent"] == 500
    command = runner.commands[0]
    assert command[:2] == ["hping3", "--icmp"]
    assert ["-i", "u1000"] == command[command.index("-i"):command.index("-i") + 2]
    assert ["-c", "500"] == command[command.index("-c"):command.index("-c") + 2]
    with pytest.raises(SystemExit):
        run_cli(["icmpflood", "--count", str(lw.MAX_ICMP_COUNT + 1)])


# ---------------------------------------------------------------------------
# lw.py — 출발지를 바꾸는 SYN
# ---------------------------------------------------------------------------

def test_rotating_sources_stay_in_reserved_edge_range():
    sources = lw.rotating_sources("172.28.13.10")
    assert sources[0] == "172.28.13.200" and sources[-1] == "172.28.13.254"
    assert len(sources) == len(cc.S7_ROTATING_HOSTS)


def test_build_syn_packet_has_valid_headers():
    packet = lw.build_syn_packet("172.28.13.200", "172.28.13.10", 40000, 8080, 12345, ip_id=7)
    assert len(packet) == 40
    version_ihl, _, total, ip_id, _, ttl, proto, _, src, dst = struct.unpack("!BBHHHBBH4s4s", packet[:20])
    assert (version_ihl, total, ip_id, ttl, proto) == (0x45, 40, 7, 64, socket.IPPROTO_TCP)
    assert socket.inet_ntoa(src) == "172.28.13.200" and socket.inet_ntoa(dst) == "172.28.13.10"
    assert lw._checksum(packet[:20]) == 0  # 체크섬이 맞으면 헤더 전체 합이 0
    sport, dport, seq, _, offset_flags = struct.unpack("!HHIIH", packet[20:34])
    assert (sport, dport, seq, offset_flags & 0x3F) == (40000, 8080, 12345, 0x02)
    pseudo = packet[12:20] + struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20)
    assert lw._checksum(pseudo + packet[20:]) == 0


def test_send_rotating_syn_paces_and_rotates():
    sent, sleeps = [], []
    count = lw.send_rotating_syn(
        "172.28.13.10", 8080, 250,
        send=lambda packet, dst: sent.append(socket.inet_ntoa(packet[12:16])),
        sleep=sleeps.append, rng=random.Random(1),
    )
    assert count == 250 and len(sent) == 250
    assert set(sent) <= set(lw.rotating_sources("172.28.13.10")) and len(set(sent)) > 20
    assert len(sleeps) == 3 and all(0 < s <= 0.05 for s in sleeps)


# ---------------------------------------------------------------------------
# S7·S9 판정
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_cc(monkeypatch):
    state = SimpleNamespace(
        fresh=["172.28.13.120"], oneshots=[], marked=[], sec_since=[], dropped=[100, 250],
        events={"GLOBAL_SYN_FLOOD": [{}], "SPOOFED_SRC": [{}],
                "ICMP_FLOOD": [{"layer": "L3", "received_at": "2026-10-29T12:44:32.968773+00:00"}]},
        blocks={f"{PREFIX}.140": {"evidence": "SPOOFABLE", "expires_at": "2026-10-29T02:00:00+00:00"}},
        rotating_blocks=[], sec_events={"NET_ICMP_FLOOD": [{}]}, locks={}, reachable=True,
        fw_detail={"icmp_dropped": 120, "l3_ok": True},
    )
    monkeypatch.setattr(cc, "choose_fresh_ip", lambda client, prefix: state.fresh[0] if state.fresh else None)
    monkeypatch.setattr(cc, "run_oneshot", lambda template, ip, prefix, **k: state.oneshots.append(list(template)))
    monkeypatch.setattr(cc, "wait_until", lambda condition, **k: condition() or None)
    monkeypatch.setattr(cc, "network_events_since", lambda client, category, since, src_ip=None: state.events.get(category, []))
    monkeypatch.setattr(cc, "network_blocks_since", lambda client, ips, since: state.rotating_blocks)
    monkeypatch.setattr(cc, "network_block", lambda client, ip: state.blocks.get(ip))
    monkeypatch.setattr(cc, "lockout", lambda client, ip: state.locks.get(ip))
    def security_events_since(client, ip, et, since):
        state.sec_since.append((ip, et, since))
        return state.sec_events.get(et, []) if ip != cc.S7_CORE_SPOOF else state.sec_events.get("core", [])

    monkeypatch.setattr(cc, "security_events_since", security_events_since)
    monkeypatch.setattr(cc, "mark_used", state.marked.append)
    monkeypatch.setattr(cc, "icmp_dropped_total", lambda: state.dropped.pop(0) if state.dropped else None)
    monkeypatch.setattr(cc, "probe_reachable", lambda ip, prefix: state.reachable)
    monkeypatch.setattr(cc, "fw_agent_detail", lambda client: state.fw_detail)
    return state


def _ctx():
    return SimpleNamespace(client=object(), prefix=PREFIX)


def test_s7_pass_and_sends_four_attacks(fake_cc):
    result = check_s7.run(_ctx())
    assert result.status == "PASS", result.reason
    assert "--rand-source" in fake_cc.oneshots[0]
    spoofs = [t[t.index("--spoof-source") + 1] for t in fake_cc.oneshots[1:]]
    assert spoofs == [cc.S7_CORE_SPOOF, f"{PREFIX}.140", cc.S7_FOREIGN_SPOOF]


@pytest.mark.parametrize(("mutate", "expected"), [
    (lambda s: s.events.pop("GLOBAL_SYN_FLOOD"), "① GLOBAL_SYN_FLOOD"),
    (lambda s: s.rotating_blocks.append({"ip_address": f"{PREFIX}.201"}), "① 돌려 쓴 출발지"),
    (lambda s: s.blocks.__setitem__(cc.S7_CORE_SPOOF, {"status": "APPLIED"}), "② core"),
    (lambda s: s.sec_events.__setitem__("core", [{}]), "② core"),
    (lambda s: s.blocks.__setitem__(f"{PREFIX}.140", {"evidence": "CONNECTED", "expires_at": None}), "③"),
    (lambda s: s.locks.__setitem__(f"{PREFIX}.140", {"lock_type": "PERMANENT"}), "③"),
    (lambda s: s.events.pop("SPOOFED_SRC"), "④ SPOOFED_SRC"),
    (lambda s: s.blocks.__setitem__(cc.S7_FOREIGN_SPOOF, {"status": "APPLIED"}), "④"),
    (lambda s: setattr(s, "reachable", False), "gateway 연결"),
])
def test_s7_fail_reasons(fake_cc, mutate, expected):
    mutate(fake_cc)
    result = check_s7.run(_ctx())
    assert result.status == "FAIL" and expected in result.reason


def test_s9_pass(fake_cc):
    result = check_s9.run(_ctx())
    assert result.status == "PASS", result.reason
    assert fake_cc.oneshots[0][-3:] == ["icmpflood", "--count", "3000"]


@pytest.mark.parametrize(("mutate", "expected"), [
    (lambda s: s.events.pop("ICMP_FLOOD"), "ICMP_FLOOD 없음"),
    (lambda s: s.events.__setitem__("ICMP_FLOOD", [{"layer": "L4"}]), "L3"),
    (lambda s: s.sec_events.pop("NET_ICMP_FLOOD"), "NET_ICMP_FLOOD"),
    (lambda s: s.blocks.__setitem__("172.28.13.120", {"status": "APPLIED"}), "network_blocks"),
    (lambda s: setattr(s, "dropped", [100, 100]), "버리지 않음"),
    (lambda s: setattr(s, "dropped", [None, 100]), "카운터를 읽지 못함"),
    (lambda s: setattr(s, "reachable", False), "TCP 연결"),
])
def test_s9_fail_reasons(fake_cc, mutate, expected):
    mutate(fake_cc)
    result = check_s9.run(_ctx())
    assert result.status == "FAIL" and expected in result.reason


def test_skip_when_no_fresh_ip(fake_cc):
    fake_cc.fresh.clear()
    assert check_s7.run(_ctx()).status == "SKIP"
    assert check_s9.run(_ctx()).status == "SKIP"


def test_run_all_includes_s7_and_s9_in_order():
    assert [name for name, _ in run_all.CHECKS] == ["S4", "S5", "S5b", "S6", "S7", "S8", "S9"]


# ---------------------------------------------------------------------------
# 10/29 보정 — DB 시계 기준 비교·누적 카운터·실행 중 IP 재사용 방지
# ---------------------------------------------------------------------------

def test_s9_looks_up_security_event_from_db_receive_time(fake_cc):
    """PC 시계가 DB보다 7초 앞서도(10/29 실측) 경보의 received_at(DB 시계) 기준으로 찾는다."""
    check_s9.run(_ctx())
    (ip, event_type, since), = fake_cc.sec_since
    assert (ip, event_type) == ("172.28.13.120", "NET_ICMP_FLOOD")
    assert since == "2026-10-29T12:44:27.968773+00:00"  # received_at - 5초


def test_s7_and_s9_mark_attacker_ip_used(fake_cc):
    check_s7.run(_ctx())
    check_s9.run(_ctx())
    assert fake_cc.marked == ["172.28.13.120", "172.28.13.120"]


def test_s7_core_check_widens_since_by_clock_margin(fake_cc):
    check_s7.run(_ctx())
    from datetime import datetime, timedelta, timezone

    (core_since,) = [since for ip, _, since in fake_cc.sec_since if ip == cc.S7_CORE_SPOOF]
    widened = datetime.fromisoformat(core_since)
    assert widened <= datetime.now(timezone.utc) - timedelta(seconds=cc.CLOCK_SKEW_MARGIN_SECONDS - 5)


def test_shift_iso():
    assert cc.shift_iso("2026-10-29T12:44:32.968773+00:00", -5) == "2026-10-29T12:44:27.968773+00:00"
    assert cc.shift_iso("2026-10-29T12:44:32Z", 60) == "2026-10-29T12:45:32+00:00"


def test_choose_fresh_ip_skips_ips_marked_this_run(monkeypatch):
    class Reader:
        def table(self, name):
            return self

        def select(self, *a):
            return self

        def like(self, *a):
            return self

        def execute(self):
            return SimpleNamespace(data=[])

    monkeypatch.setattr(cc, "_USED_THIS_RUN", set())
    assert cc.choose_fresh_ip(Reader(), PREFIX) == f"{PREFIX}.111"
    cc.mark_used(f"{PREFIX}.111")
    assert cc.choose_fresh_ip(Reader(), PREFIX) == f"{PREFIX}.112"
