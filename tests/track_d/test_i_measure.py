# ============================================================================
# tests/track_d/test_i_measure.py — 탐지→차단 시간 측정(I2-2)의 계산·판정 부품 확인
#
# 실제 측정은 Docker 단지와 공용 DB가 있어야 해서 pytest로 돌리지 않는다. 여기서는 숫자를 만드는 부분
# (시각 읽기, 구간, 목표 판정, 새 IP 고르기, SKIP 판단, 결과 표 한 줄)만 가짜 값으로 확인한다.
# scripts/는 패키지가 아니므로 파일을 직접 불러온다(netwatch/ 테스트와 같은 방식).
# ============================================================================

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("measure_common", ROOT / "scripts" / "net" / "measure_common.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mc = _load()


# ── 시각 읽기 ──

@pytest.mark.parametrize(
    "text",
    ["2026-10-20T03:12:44.120Z", "2026-10-20T03:12:44.12+00:00", "2026-10-20T12:12:44.120+09:00", "2026-10-20T03:12:44.120"],
)
def test_parse_ts_reads_z_offset_and_short_fraction_as_same_utc_time(text):
    assert mc.parse_ts(text) == datetime(2026, 10, 20, 3, 12, 44, 120000, tzinfo=timezone.utc)


@pytest.mark.parametrize("text", [None, "", "not-a-time"])
def test_parse_ts_returns_none_for_missing_or_bad_value(text):
    assert mc.parse_ts(text) is None


# ── 구간 계산·판정 ──

def test_compute_intervals_in_milliseconds():
    got = mc.compute_intervals("2026-10-20T03:12:44.120Z", "2026-10-20T03:12:45.020+00:00", "2026-10-20T03:12:46.900Z")
    assert got == {"t0_t1": 900, "t1_t2": 1880, "t0_t2": 2780}


def test_missing_time_makes_that_interval_none():
    got = mc.compute_intervals("2026-10-20T03:12:44Z", "2026-10-20T03:12:45Z", None)
    assert got == {"t0_t1": 1000, "t1_t2": None, "t0_t2": None}


def test_judge_passes_inside_goals():
    verdict = mc.judge({"t0_t1": 1999, "t1_t2": 2000, "t0_t2": 4999})
    assert verdict == {"t0_t1": True, "t1_t2": True, "t0_t2": True, "all": True}


def test_judge_fails_when_one_interval_over_goal():
    verdict = mc.judge({"t0_t1": 2500, "t1_t2": 1000, "t0_t2": 3500})
    assert verdict["t0_t1"] is False
    assert verdict["all"] is False


def test_judge_counts_unmeasured_as_failure():
    # 차단이 안 돼 T2가 없으면 "못 잰 것"이지 통과가 아니다
    verdict = mc.judge({"t0_t1": 800, "t1_t2": None, "t0_t2": None})
    assert verdict["all"] is False


def test_summarize_median_max_and_missing():
    assert mc.summarize([3000, None, 4000, 3500]) == {"median": 3500, "max": 4000, "missing": 1}
    assert mc.summarize([None]) == {"median": None, "max": None, "missing": 1}


# ── 기다리기 ──

def test_wait_until_returns_value_without_real_sleep():
    now = [0.0]
    calls = iter([None, None, "2026-10-20T03:12:44Z"])
    got = mc.wait_until(lambda: next(calls), timeout=30, interval=0.5, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    assert got == "2026-10-20T03:12:44Z"
    assert now[0] == 1.0


def test_wait_until_gives_up_after_timeout():
    now = [0.0]
    got = mc.wait_until(lambda: None, timeout=2, interval=0.5, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    assert got is None
    assert now[0] == 2.0


# ── 새 IP 고르기 ──

def test_choose_fresh_ip_skips_already_used():
    used = {"172.28.13.150", "172.28.13.151"}
    assert mc.choose_fresh_ip("172.28.13", used) == "172.28.13.152"


def test_choose_fresh_ip_none_when_range_exhausted():
    used = {f"172.28.13.{n}" for n in range(150, 200)}
    assert mc.choose_fresh_ip("172.28.13", used) is None


def test_measure_range_does_not_overlap_fixed_attackers():
    # 고정 공격 상자(.101~.103, 계약서 K2)와 겹치면 수동 시연 기록과 섞인다
    assert mc.MEASURE_IP_START > 103


# ── 공격 명령 찾기(SKIP) ──

def test_skip_when_readme_missing(tmp_path):
    cmds, reason = mc.resolve_attack("s5", tmp_path / "README.md", commands={"s5": [["docker", "run"]]})
    assert cmds is None
    assert "SKIP" in reason


def test_skip_when_readme_has_no_attack_format(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# netwatch\n켜기: docker compose up -d\n", encoding="utf-8")
    cmds, reason = mc.resolve_attack("s5", readme, commands={"s5": [["docker", "run"]]})
    assert cmds is None and "SKIP" in reason


def test_skip_when_constant_not_filled_yet(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("docker run --rm --network lw_edge --ip ...", encoding="utf-8")
    cmds, reason = mc.resolve_attack("s5", readme, commands={"s5": None})
    assert cmds is None and "ATTACK_COMMANDS" in reason


def test_resolve_attack_returns_commands_when_ready(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("docker run --rm --network lw_edge --ip ...", encoding="utf-8")
    table = {"s5": [["docker", "run", "--ip", "{ip}"]]}
    cmds, reason = mc.resolve_attack("s5", readme, commands=table)
    assert reason is None and cmds == table["s5"]


def test_attack_commands_filled_from_readme_oneshot_form():
    # A2-1 머지 후: README 7.3의 일회용 docker run 형식을 그대로 옮겼다(더는 None이 아니다).
    assert mc.ATTACK_COMMANDS["s5"] is not None and mc.ATTACK_COMMANDS["s5b"] is not None
    # 모든 명령은 셸 없이 부를 수 있게 lw-attacker 이미지를 일회용(--rm)으로 띄우고 {ip}·{prefix}를 남겨 둔다
    for cmds in mc.ATTACK_COMMANDS.values():
        for cmd in cmds:
            assert cmd[:3] == ["docker", "run", "--rm"]
            assert "lw-attacker:latest" in cmd and "{ip}" in cmd
    # S5는 synflood 하나, S5b는 CR-02(다계층 폭주)를 묶으려고 같은 IP에서 synflood + httpflood 둘
    subcmd = lambda c: c[c.index("lw-attacker:latest") + 1]
    assert [subcmd(c) for c in mc.ATTACK_COMMANDS["s5"]] == ["synflood"]
    assert {subcmd(c) for c in mc.ATTACK_COMMANDS["s5b"]} == {"synflood", "httpflood"}


def test_fill_command_replaces_placeholders_without_shell():
    got = mc.fill_command(["docker", "run", "--ip", "{ip}", "-e", "TARGET_URL=http://{prefix}.10:8080"], "172.28.13.152", "172.28.13")
    assert got == ["docker", "run", "--ip", "172.28.13.152", "-e", "TARGET_URL=http://172.28.13.10:8080"]


# ── 결과 표 한 줄 ──

def test_format_row_matches_results_table():
    when = datetime(2026, 10, 30, 5, 1, 2, tzinfo=timezone.utc)
    intervals = {"t0_t1": 900, "t1_t2": 1880, "t0_t2": 2780}
    row = mc.format_row(when, "s5", "172.28.0.152", intervals, mc.judge(intervals))
    assert row == "| 2026-10-30 05:01:02Z | S5 | 172.28.0.152 | 900 | 1880 | 2780 | 통과 |  |"


def test_format_row_marks_failure_and_keeps_table_shape():
    when = datetime(2026, 10, 30, 5, 1, 2, tzinfo=timezone.utc)
    intervals = {"t0_t1": 900, "t1_t2": None, "t0_t2": None}
    row = mc.format_row(when, "s5b", "172.28.0.153", intervals, mc.judge(intervals), note="적용 안 됨|FAILED")
    assert "| S5B |" in row and "| - | - | 초과 |" in row
    # 비고에 "|"가 들어와도 칸 수가 늘지 않아야 마크다운 표가 깨지지 않는다
    assert row.count("|") == 9


def test_results_doc_has_matching_header():
    text = (ROOT / "docs" / "track-d" / "measurements.md").read_text(encoding="utf-8")
    header = "| 시각(UTC) | 시나리오 | 출발지 IP | T0→T1(ms) | T1→T2(ms) | T0→T2(ms) | 판정 | 비고 |"
    assert header in text
