#!/bin/sh
# ============================================================================
# Login Watchdog Suricata 시작 스크립트
#
# 역할:
#   1. PC별 edge 대역과 감시 인터페이스를 suricata.yaml에 반영한다.
#   2. ET Open 규칙이 없을 때만 suricata-update를 실행한다.
#   3. ET Open 다운로드 실패 시 빈 suricata.rules를 만들고 local.rules만으로
#      Suricata를 시작한다.
#
# 환경변수:
#   LW_EDGE_PREFIX: edge 대역의 앞 세 자리(기본값: 172.28.0)
#   SENSOR_IFACE: gateway 네임스페이스의 edge 인터페이스(기본값: 자동 — 비었거나 auto면
#                 ${LW_EDGE_PREFIX}.10이 붙은 인터페이스를 찾는다)
#
# 줄바꿈 주의: 이 파일은 LF여야 한다. CRLF면 컨테이너의 sh가 "set: -: invalid option"으로
# 바로 멈춘다. 저장소 루트 .gitattributes의 "*.sh text eol=lf"가 Windows에서도 LF로 꺼내 준다.
# ============================================================================

set -eu

CUSTOM_CONFIG="/etc/suricata/custom/suricata.yaml"
RUNTIME_CONFIG="/tmp/login-watchdog-suricata.yaml"
ET_RULE_DIR="/var/lib/suricata/rules"
ET_RULE_FILE="${ET_RULE_DIR}/suricata.rules"

LW_EDGE_PREFIX="${LW_EDGE_PREFIX:-172.28.0}"
REQUESTED_IFACE="${SENSOR_IFACE:-}"
# edge 주소를 끝내 못 찾았을 때 쓰는 마지막 대안. compose 기본값과 같은 eth1(계약서 K1).
FALLBACK_IFACE="eth1"
EDGE_IP="${LW_EDGE_PREFIX}.10"

# HOME_NET은 gateway 한 주소만 지정하지 않고 edge·core 대역 전체를 사용한다.
HOME_NET="[${LW_EDGE_PREFIX}.0/24,172.30.0.0/24]"

# ---------------------------------------------------------------------------
# 감시 인터페이스 고르기 (계약서 K1, 2026-10-20)
#
# Docker는 컨테이너에 네트워크를 붙이는 순서를 보장하지 않아, gateway 안에서 edge가
# eth0인 PC와 eth1인 PC가 함께 있다. 이름을 고정하면 어떤 PC에서는 core만 보게 되고,
# 그러면 오류 없이 탐지가 0건이 된다. 그래서 이름 대신 "edge 쪽 gateway 주소(.10)가
# 붙은 인터페이스"를 기준으로 삼는다. l4-detector의 resolve_sensor_iface
# (netwatch/l4_detector/detector_core.py)와 같은 규칙이다.
#   - SENSOR_IFACE가 비었거나 auto면 edge 주소가 붙은 인터페이스를 쓴다.
#   - 이름을 지정했어도 그 인터페이스에 edge 주소가 없으면 edge 쪽으로 바꾸고 경고한다.
#   - edge 주소를 끝내 못 찾으면 지정값(없으면 eth1)으로 시작하고 경고만 남긴다.
#     센서를 멈추는 것보다 일단 돌면서 로그로 알리는 편이 원인 파악이 쉽다.
# ---------------------------------------------------------------------------
find_edge_iface() {
    # "2: eth1    inet 172.28.11.10/24 ..." 에서 주소가 EDGE_IP인 줄의 이름만 뽑는다.
    ip -o -4 addr show 2>/dev/null \
        | awk -v want="${EDGE_IP}" '{ split($4, a, "/"); if (a[1] == want) { sub(/@.*/, "", $2); print $2; exit } }' \
        || true
}

EDGE_IFACE="$(find_edge_iface)"

case "${REQUESTED_IFACE}" in
    ""|[Aa][Uu][Tt][Oo]) WANTS_AUTO=1 ;;
    *) WANTS_AUTO=0 ;;
esac

if [ -n "${EDGE_IFACE}" ]; then
    if [ "${WANTS_AUTO}" -eq 0 ] && [ "${REQUESTED_IFACE}" != "${EDGE_IFACE}" ]; then
        echo "[WARN] SENSOR_IFACE=${REQUESTED_IFACE}에 edge 주소(${EDGE_IP})가 없어 ${EDGE_IFACE}를 감시합니다. .env의 SENSOR_IFACE를 ${EDGE_IFACE}로 고치거나 auto로 두세요." >&2
    fi
    SENSOR_IFACE="${EDGE_IFACE}"
else
    if [ "${WANTS_AUTO}" -eq 1 ]; then
        SENSOR_IFACE="${FALLBACK_IFACE}"
    else
        SENSOR_IFACE="${REQUESTED_IFACE}"
    fi
    echo "[WARN] edge 주소(${EDGE_IP})가 붙은 인터페이스를 찾지 못해 ${SENSOR_IFACE}를 그대로 감시합니다. 탐지가 0건이면 .env의 LW_EDGE_PREFIX·SENSOR_IFACE를 확인하세요." >&2
fi

mkdir -p "${ET_RULE_DIR}"
mkdir -p /var/log/suricata

# 읽기 전용으로 마운트된 원본 설정을 복사한 뒤 환경별 값으로 치환한다.
cp "${CUSTOM_CONFIG}" "${RUNTIME_CONFIG}"

sed -i \
    -e "s|__HOME_NET__|${HOME_NET}|g" \
    -e "s|__SENSOR_IFACE__|${SENSOR_IFACE}|g" \
    "${RUNTIME_CONFIG}"

echo "[*] Suricata 설정: iface=${SENSOR_IFACE}, HOME_NET=${HOME_NET}"

# 이미 ET Open 규칙이 있으면 다시 다운로드하지 않는다.
if [ -s "${ET_RULE_FILE}" ]; then
    echo "[*] 기존 ET Open 규칙을 사용합니다: ${ET_RULE_FILE}"
else
    echo "[*] ET Open 규칙을 처음 내려받습니다."

    if suricata-update; then
        echo "[*] ET Open 규칙 다운로드를 완료했습니다."
    else
        echo "[WARN] ET Open 규칙 다운로드에 실패했습니다. local.rules만으로 시작합니다." >&2

        # suricata.yaml의 rule-files에는 suricata.rules가 등록되어 있으므로
        # 파일 누락으로 기동이 실패하지 않도록 빈 규칙 파일을 만든다.
        : > "${ET_RULE_FILE}"
    fi
fi

# 다운로드 명령이 성공했지만 파일이 만들어지지 않은 비정상 상황도 처리한다.
if [ ! -e "${ET_RULE_FILE}" ]; then
    echo "[WARN] ET Open 규칙 파일이 없어 local.rules만 사용합니다." >&2
    : > "${ET_RULE_FILE}"
fi

echo "[*] Suricata를 시작합니다."

exec suricata \
    -c "${RUNTIME_CONFIG}" \
    --af-packet="${SENSOR_IFACE}"
