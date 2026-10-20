# ============================================================================
# tests/track_d/test_a_suricata_rules.py
#
# A1-1 Suricata 자체 규칙, 설정 파일, Compose 구성을 텍스트로 검증한다.
# 실제 Suricata 문법 검사는 A2-2 CI 작업에서 수행한다.
# ============================================================================

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOCAL_RULES_PATH = (
    PROJECT_ROOT
    / "netwatch"
    / "suricata"
    / "rules"
    / "local.rules"
)

SURICATA_CONFIG_PATH = (
    PROJECT_ROOT
    / "netwatch"
    / "suricata"
    / "suricata.yaml"
)

ENTRYPOINT_PATH = (
    PROJECT_ROOT
    / "netwatch"
    / "suricata"
    / "entrypoint.sh"
)

COMPOSE_PATH = PROJECT_ROOT / "docker-compose.yml"


def read_text(path: Path) -> str:
    """UTF-8 텍스트 파일을 읽는다."""
    return path.read_text(encoding="utf-8")


def rule_lines() -> list[str]:
    """주석과 빈 줄을 제외한 Suricata 규칙 목록을 반환한다."""
    lines = read_text(LOCAL_RULES_PATH).splitlines()

    return [
        line.strip()
        for line in lines
        if line.strip()
        and not line.lstrip().startswith("#")
    ]


def sid_from_rule(rule: str) -> int:
    """Suricata 규칙 한 줄에서 SID를 추출한다."""
    match = re.search(r"\bsid\s*:\s*(\d+)\s*;", rule)

    assert match is not None, (
        f"SID가 없는 규칙입니다: {rule}"
    )

    return int(match.group(1))


def sensor_compose_block() -> str:
    """docker-compose.yml에서 sensor 서비스 블록을 가져온다."""
    compose = read_text(COMPOSE_PATH)

    return compose.split("  sensor:", 1)[1].split(
        "\n  l4-detector:",
        1,
    )[0]


def test_required_suricata_files_exist() -> None:
    """A1-1에 필요한 설정 파일이 모두 존재해야 한다."""
    assert LOCAL_RULES_PATH.is_file()
    assert SURICATA_CONFIG_PATH.is_file()
    assert ENTRYPOINT_PATH.is_file()


def test_all_local_rules_start_with_alert() -> None:
    """모든 자체 규칙은 alert 동작으로 시작해야 한다."""
    rules = rule_lines()

    assert rules
    assert all(
        rule.startswith("alert ")
        for rule in rules
    )


def test_local_rule_sids_are_unique_and_reserved() -> None:
    """자체 규칙 SID는 중복 없이 예약 범위 안에 있어야 한다."""
    sids = [
        sid_from_rule(rule)
        for rule in rule_lines()
    ]

    assert len(sids) == len(set(sids))

    assert all(
        9_000_000 <= sid <= 9_099_999
        for sid in sids
    )


def test_required_local_rule_sids_exist() -> None:
    """계약서 K4에서 사용하는 세 SID가 모두 있어야 한다."""
    sids = {
        sid_from_rule(rule)
        for rule in rule_lines()
    }

    assert sids == {
        9_000_001,
        9_000_003,
        9_000_004,
    }


def test_syn_flood_rule_matches_plan() -> None:
    """9000001은 SYN Flood 탐지 조건을 유지해야 한다."""
    rule = next(
        rule
        for rule in rule_lines()
        if sid_from_rule(rule) == 9_000_001
    )

    assert rule.startswith("alert tcp ")
    assert "flags:S,12;" in rule
    assert (
        "threshold:type both, track by_src, "
        "count 100, seconds 5;"
    ) in rule
    assert "classtype:attempted-dos;" in rule


def test_login_burst_rule_matches_plan() -> None:
    """9000003은 /login POST burst 조건을 유지해야 한다."""
    rule = next(
        rule
        for rule in rule_lines()
        if sid_from_rule(rule) == 9_000_003
    )

    assert rule.startswith("alert http ")
    assert 'http.method; content:"POST";' in rule
    assert 'http.uri; content:"/login"; startswith;' in rule
    assert (
        "threshold:type both, track by_src, "
        "count 20, seconds 10;"
    ) in rule
    assert "classtype:attempted-user;" in rule


def test_scanner_user_agent_rule_matches_plan() -> None:
    """9000004는 계약된 스캐너 User-Agent 목록을 사용한다."""
    rule = next(
        rule
        for rule in rule_lines()
        if sid_from_rule(rule) == 9_000_004
    )

    assert rule.startswith("alert http ")
    assert "http.user_agent;" in rule

    assert (
        'pcre:"/(sqlmap|nikto|nmap|masscan|'
        'dirbuster|gobuster)/i";'
    ) in rule

    assert (
        "classtype:web-application-attack;"
    ) in rule


def test_scanner_category_mapping_comment_exists() -> None:
    """9000004는 classtype가 아닌 SID로 SCANNER_UA에 매핑된다."""
    rules_text = read_text(LOCAL_RULES_PATH)

    assert "9000004" in rules_text
    assert "SCANNER_UA" in rules_text
    assert "SID" in rules_text or "sid" in rules_text


def test_local_rules_document_reserved_sid_ranges() -> None:
    """Suricata와 Scapy의 예약 SID 범위를 주석으로 설명해야 한다."""
    rules_text = read_text(LOCAL_RULES_PATH)

    assert "9000000~9099999" in rules_text
    assert "9100001" in rules_text
    assert "Scapy" in rules_text
    assert "매핑이 깨지" in rules_text


def test_suricata_config_loads_et_open_and_local_rules() -> None:
    """ET Open과 local.rules를 rule-files에서 함께 로드해야 한다."""
    config = read_text(SURICATA_CONFIG_PATH)

    rule_files_block = config.split(
        "rule-files:",
        1,
    )[1].split(
        "\naf-packet:",
        1,
    )[0]

    assert "suricata.rules" in rule_files_block
    assert "local.rules" in rule_files_block

    # -S 방식은 다른 규칙을 제외할 수 있으므로 사용하지 않는다.
    assert "\n-S " not in config


def test_suricata_config_writes_required_eve_types() -> None:
    """eve.json에 alert·flow·http 이벤트를 기록해야 한다."""
    config = read_text(SURICATA_CONFIG_PATH)

    assert "filename: eve.json" in config
    assert "- alert" in config
    assert "- flow" in config
    assert "- http:" in config


def test_suricata_config_uses_runtime_placeholders() -> None:
    """PC별 대역과 인터페이스를 시작 시 치환해야 한다."""
    config = read_text(SURICATA_CONFIG_PATH)

    assert "__HOME_NET__" in config
    assert "__SENSOR_IFACE__" in config

    # gateway 한 주소만 HOME_NET으로 고정하면 안 된다.
    assert "${LW_EDGE_PREFIX}.10/32" not in config


def test_entrypoint_downloads_et_open_only_when_missing() -> None:
    """ET Open 규칙은 기존 파일이 없을 때만 내려받아야 한다."""
    entrypoint = read_text(ENTRYPOINT_PATH)

    assert 'if [ -s "${ET_RULE_FILE}" ]' in entrypoint
    assert "suricata-update" in entrypoint
    assert "local.rules만으로 시작" in entrypoint


def test_entrypoint_uses_af_packet_interface() -> None:
    """실행 시 SENSOR_IFACE를 AF_PACKET 인터페이스로 사용한다."""
    entrypoint = read_text(ENTRYPOINT_PATH)

    assert '--af-packet="${SENSOR_IFACE}"' in entrypoint


def test_compose_uses_fixed_suricata_image_tag() -> None:
    """sensor 이미지는 latest가 아닌 검증된 버전으로 고정한다."""
    sensor_block = sensor_compose_block()

    match = re.search(
        r"image:\s*jasonish/suricata:([^\s]+)",
        sensor_block,
    )

    assert match is not None

    tag = match.group(1)

    assert tag != "latest"
    assert tag == "7.0.17"


def test_compose_passes_sensor_environment_and_volumes() -> None:
    """Compose가 인터페이스·대역·규칙 볼륨을 sensor에 전달한다."""
    sensor_block = sensor_compose_block()

    assert (
        # [A1-1 보완] 계약서 K1의 compose 기본값은 eth1이다(10/19 eth0에서 변경).
        "SENSOR_IFACE: ${SENSOR_IFACE:-eth1}"
        in sensor_block
    )
    assert (
        "LW_EDGE_PREFIX: ${LW_EDGE_PREFIX}"
        in sensor_block
    )
    assert (
        "./netwatch/suricata:"
        "/etc/suricata/custom:ro"
        in sensor_block
    )
    assert (
        "eve:/var/log/suricata"
        in sensor_block
    )
    assert (
        "suricata-rules:"
        "/var/lib/suricata/rules"
        in sensor_block
    )


def test_sensor_remains_enabled_by_default_after_a1_3() -> None:
    """통합된 A1-3 정책에 따라 sensor는 기본 실행 서비스다."""
    sensor_block = sensor_compose_block()

    assert "profiles:" not in sensor_block


# --- [A1-1 보완] 인터페이스 자동 선택·줄바꿈 (계약서 K1, 2026-10-20) ---


def test_entrypoint_picks_interface_by_edge_address() -> None:
    """이름 대신 ${LW_EDGE_PREFIX}.10이 붙은 인터페이스를 고르고, 못 찾으면 eth1로 시작한다."""
    entrypoint = read_text(ENTRYPOINT_PATH)

    assert 'EDGE_IP="${LW_EDGE_PREFIX}.10"' in entrypoint
    assert "ip -o -4 addr show" in entrypoint
    assert 'FALLBACK_IFACE="eth1"' in entrypoint
    # 비었거나 auto면 자동, 이름이 edge 쪽이 아니면 edge 쪽으로 바꾸고 경고한다.
    assert '""|[Aa][Uu][Tt][Oo])' in entrypoint
    assert "edge 주소(${EDGE_IP})가 없어" in entrypoint
    # 인터페이스를 고른 뒤에 설정 치환이 일어나야 고른 값이 suricata.yaml에 들어간다.
    assert entrypoint.index('EDGE_IFACE="$(find_edge_iface)"') < entrypoint.index("s|__SENSOR_IFACE__|")


def test_entrypoint_has_lf_line_endings() -> None:
    """CRLF면 컨테이너의 sh가 "set: -: invalid option"으로 바로 멈춘다."""
    assert b"\r" not in ENTRYPOINT_PATH.read_bytes()


def test_gitattributes_keeps_shell_scripts_lf() -> None:
    """Windows의 core.autocrlf=true가 셸 스크립트를 CRLF로 꺼내지 않게 한다."""
    gitattributes = read_text(PROJECT_ROOT / ".gitattributes")

    assert "*.sh text eol=lf" in gitattributes