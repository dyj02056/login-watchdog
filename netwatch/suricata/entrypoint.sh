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
#   SENSOR_IFACE: gateway 네임스페이스의 edge 인터페이스(기본값: eth0)
# ============================================================================

set -eu

CUSTOM_CONFIG="/etc/suricata/custom/suricata.yaml"
RUNTIME_CONFIG="/tmp/login-watchdog-suricata.yaml"
ET_RULE_DIR="/var/lib/suricata/rules"
ET_RULE_FILE="${ET_RULE_DIR}/suricata.rules"

LW_EDGE_PREFIX="${LW_EDGE_PREFIX:-172.28.0}"
SENSOR_IFACE="${SENSOR_IFACE:-eth0}"

# HOME_NET은 gateway 한 주소만 지정하지 않고 edge·core 대역 전체를 사용한다.
HOME_NET="[${LW_EDGE_PREFIX}.0/24,172.30.0.0/24]"

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