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


# ── T1 기준(첫 block_l4_ttl) ──

def test_first_block_run_at_picks_earliest_ok_block_step():
    # 10/26 S5b 예행: NET-01(33.897)이 먼저, CR-02(36.115)가 뒤에 같은 IP를 다시 막았다. T1은 앞쪽이어야 한다
    runs = [
        {"step": "block_l4_ttl", "status": "OK", "ran_at": "2026-10-26T01:04:36.115268+00:00"},
        {"step": "block_l4_ttl", "status": "OK", "ran_at": "2026-10-26T01:04:33.897303+00:00"},
    ]
    assert mc.first_block_run_at(runs) == "2026-10-26T01:04:33.897303+00:00"


def test_first_block_run_at_ignores_failed_and_other_steps():
    runs = [
        {"step": "block_l4_ttl", "status": "FAILED", "ran_at": "2026-10-26T01:04:33.0Z"},
        {"step": "notify_slack", "status": "OK", "ran_at": "2026-10-26T01:04:33.5Z"},
        {"step": "block_l4_ttl", "status": "SKIPPED", "ran_at": "2026-10-26T01:04:33.6Z"},
        {"step": "block_l4_ttl", "status": "OK", "ran_at": "2026-10-26T01:04:34.0Z"},
    ]
    assert mc.first_block_run_at(runs) == "2026-10-26T01:04:34.0Z"


def test_first_block_run_at_compares_times_not_strings():
    # "Z"와 "+00:00", 소수점 자릿수가 섞여도 시각으로 비교해야 한다(문자열 비교면 순서가 틀어진다)
    runs = [
        {"step": "block_l4_ttl", "status": "OK", "ran_at": "2026-10-26T01:04:33.9+00:00"},
        {"step": "block_l4_ttl", "status": "OK", "ran_at": "2026-10-26T01:04:33.12Z"},
    ]
    assert mc.first_block_run_at(runs) == "2026-10-26T01:04:33.12Z"


@pytest.mark.parametrize("runs", [[], [{"step": "block_l4_ttl", "status": "OK", "ran_at": None}]])
def test_first_block_run_at_none_without_usable_record(runs):
    assert mc.first_block_run_at(runs) is None


def test_choose_t1_prefers_playbook_run_over_overwritten_requested_at():
    t1, note = mc.choose_t1("2026-10-26T01:04:33.897303+00:00", "2026-10-26T01:04:35.919536+00:00")
    assert t1 == "2026-10-26T01:04:33.897303+00:00" and note is None


def test_choose_t1_falls_back_to_requested_at_and_says_so():
    t1, note = mc.choose_t1(None, "2026-10-26T01:03:00.256096+00:00")
    assert t1 == "2026-10-26T01:03:00.256096+00:00"
    assert "requested_at" in note


def test_choose_t1_none_when_nothing_recorded():
    assert mc.choose_t1(None, None) == (None, None)


def test_s5b_rehearsal_recomputed_with_first_block_run():
    # 10/26 S5b 예행 기록을 새 기준으로 다시 계산: T0→T1이 목표 안으로 들어오고 전체는 그대로다
    t0 = "2026-10-26T01:04:32.519+00:00"
    t1, _ = mc.choose_t1("2026-10-26T01:04:33.897303+00:00", "2026-10-26T01:04:35.919536+00:00")
    got = mc.compute_intervals(t0, t1, "2026-10-26T01:04:36.322824+00:00")
    assert got == {"t0_t1": 1378, "t1_t2": 2426, "t0_t2": 3804}


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
            # S5b는 --ip 대신 container:lw-measure-{ip}로 IP를 잡으므로 "{ip}"가 칸 안에 들어 있으면 된다
            assert "lw-attacker:latest" in cmd and any("{ip}" in part for part in cmd)
    # S5는 synflood 하나, S5b는 CR-02(다계층 폭주)를 묶으려고 같은 IP에서 synflood + httpflood 둘
    subcmd = lambda c: c[c.index("lw-attacker:latest") + 1]
    assert [subcmd(c) for c in mc.ATTACK_COMMANDS["s5"]] == ["synflood"]
    assert {subcmd(c) for c in mc.ATTACK_COMMANDS["s5b"]} == {"synflood", "httpflood"}


def test_s5b_attacks_share_one_ip_through_anchor_container():
    # 같은 네트워크에서 두 컨테이너가 같은 --ip를 잡으면 두 번째가 "Address already in use"로 죽는다(10/26 확인).
    # 그래서 S5b 공격 두 개는 --ip를 직접 잡지 않고, 자리 잡기 컨테이너의 네트워크를 함께 쓴다.
    for cmd in mc.ATTACK_COMMANDS["s5b"]:
        assert "--ip" not in cmd
        assert cmd[cmd.index("--network") + 1] == "container:lw-measure-{ip}"
        assert "NET_RAW" in cmd  # synflood는 raw 소켓이 필요하다
    # 자리 잡기 컨테이너가 그 IP를 쥐고, 이름이 공격 쪽이 가리키는 이름과 같아야 한다
    anchor = mc.ANCHOR_COMMAND
    assert anchor[anchor.index("--ip") + 1] == "{ip}"
    assert anchor[anchor.index("--network") + 1] == "lw_edge"
    assert "container:" + anchor[anchor.index("--name") + 1] == "container:lw-measure-{ip}"
    assert "-d" in anchor and "--rm" in anchor
    assert mc.ANCHOR_REMOVE == ["docker", "rm", "-f", "lw-measure-{ip}"]


def test_needs_anchor_only_for_shared_network_commands():
    assert mc.needs_anchor(mc.ATTACK_COMMANDS["s5b"]) is True
    assert mc.needs_anchor(mc.ATTACK_COMMANDS["s5"]) is False


def test_each_measure_run_holds_its_ip_only_once():
    # 한 실행에서 --ip로 IP를 잡는 컨테이너는 정확히 하나여야 한다(S5: 공격 자체, S5b: 자리 잡기)
    def ip_holders(cmds):
        return sum(cmd.count("--ip") for cmd in cmds)
    assert ip_holders(mc.ATTACK_COMMANDS["s5"]) == 1
    assert ip_holders([mc.ANCHOR_COMMAND] + mc.ATTACK_COMMANDS["s5b"]) == 1


def test_fill_command_names_anchor_per_ip():
    got = mc.fill_command(mc.ATTACK_COMMANDS["s5b"][1], "172.28.0.152", "172.28.0")
    assert "container:lw-measure-172.28.0.152" in got
    assert "TARGET_URL=http://172.28.0.10:8080" in got


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
