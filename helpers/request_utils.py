# ============================================================================
# helpers/request_utils.py — 요청 정보(IP, 허니팟) 읽기와 화면용 작은 변환 함수
#
# 예전 helpers.py(314줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from helpers import ...`로 가져다 쓴다(helpers/__init__.py가
# 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import ipaddress

from flask import request

import config
from services import geoip
from services.ip_utils import normalize_ip


def _attach_locations(attempts: list[dict]) -> list[dict]:
    """로그인 시도 목록 각 줄에 "location"이라는 새 칸을 추가해서 돌려준다.

    geoip.get_locations()는 IP 목록을 한 번에 넘기면 IP 하나당 몇 번씩
    조회하는 게 아니라 필요한 만큼만(캐시에 없는 것만) 조회해준다. 여기서는
    그 결과를 각 시도 기록에 사람이 읽을 문자열(geoip.format_location())로
    바꿔 붙여주기만 한다.
    """
    ips = [attempt["ip_address"] for attempt in attempts]
    locations = geoip.get_locations(ips)
    for attempt in attempts:
        attempt["location"] = geoip.format_location(locations[attempt["ip_address"]])
    return attempts


# 허니팟(봇 탐지)용 숨김 필드 이름 (L7 공격 보강 계획 Tier 3). 로그인/가입/
# 글쓰기/댓글/회원 정보 변경/복구 요청/비밀번호 찾기 폼(templates/login_form.html 등)에 CSS(.hp-field, tokens.css
# 참고)로 화면에서 안 보이게 심어둔 입력칸이다. 사람은 화면에 보이는 칸만
# 채우므로 이 칸은 항상 비어있어야 정상이고, 폼의 모든 입력칸을 기계적으로
# 채우는 자동화 스크립트만 이 칸까지 채우게 된다. reCAPTCHA 같은 외부
# 서비스는 API 키 발급이 필요해 데모 프로젝트 성격과 안 맞아서, 이 무료·
# 의존성 없는 방식을 대신 택했다.
HONEYPOT_FIELD_NAME = "website"


def is_bot_submission() -> bool:
    """이번 폼 제출에 허니팟 필드가 채워져 있으면 True(봇 의심)를 돌려준다."""
    return bool(request.form.get(HONEYPOT_FIELD_NAME, "").strip())


def get_request_ip() -> str:
    """이번 요청을 보낸 사람의 IP 주소를 알아낸다.

    보통은 request.remote_addr(브라우저가 서버에 직접 연결한 진짜 주소)를 쓴다.
    다만 config.TRUST_FORWARDED_FOR가 켜져 있을 때만(데모/시연 전용 설정) 예외적으로
    X-Forwarded-For 헤더 값을 대신 신뢰한다 — 로컬 데모 환경에서는 팀원 전원이
    같은 127.0.0.1(내 컴퓨터 자신을 가리키는 특수 주소)로 접속하게 되어 서로 다른
    공격자 IP를 흉내낼 수 없기 때문에, 시뮬레이션 스크립트가 "나는 1.2.3.4에서
    왔다"고 헤더로 주장하면 그걸 믿어주는 우회로를 마련해둔 것이다.
    실제 운영 서비스에서는 이 헤더를 함부로 신뢰하면 공격자가 IP를 속여
    잠금을 피해갈 수 있으므로 위험하다 — 그래서 기본값은 꺼짐(False)이다.

    SSRF 방지 (L7 공격 보강 계획 Tier 3): 이 값은 이후 services/geoip.py가 외부
    위치 조회 API 주소에 그대로 끼워 넣는 데 쓰인다. X-Forwarded-For는
    클라이언트가 보내는 값이라 형식 검증 없이 그대로 신뢰하면, TRUST_FORWARDED_FOR
    를 켠 환경에서 그 문자열이 외부 요청 주소에 섞여 들어갈 수 있다.
    ipaddress.ip_address()로 "진짜 IP 형식인가"부터 확인하고, 아니면 헤더값을
    버리고 원래 접속 IP(request.remote_addr)로 되돌아간다.

    IPv6 대역 단위 (guide42): 돌려주는 값은 ip_utils.normalize_ip()를 거친 "탐지·잠금 단위"다 —
    IPv4는 그대로, IPv6는 /64 대역(예: 2001:db8:1:2::/64)이다. IPv6 사용자는 대역 안에서 주소를
    거의 공짜로 바꿀 수 있어서, 주소 하나 단위로 세면 IP 잠금·요청 제한이 모두 우회되기 때문이다.
    이 함수 하나만 바꾸면 이 값을 쓰는 탐지·잠금·요청 제한·이벤트가 전부 같은 단위로 동작한다.
    """
    if config.TRUST_FORWARDED_FOR:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # 이 헤더는 "1.2.3.4, 5.6.7.8"처럼 여러 IP가 콤마로 이어질 수 있어서
            # 맨 앞(가장 처음 요청을 보낸 곳) 값만 잘라서 쓴다.
            candidate = forwarded.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return normalize_ip(request.remote_addr)
            return normalize_ip(candidate)
    return normalize_ip(request.remote_addr)


def mask_username(username: str) -> str:
    """확인 화면에 보여줄 아이디를 일부 가린다(예: user → u**r). 복구·이메일 확인·비밀번호 재설정 화면이 같이 쓴다."""
    if len(username) <= 2:
        return username[0] + "*" if username else ""
    return username[0] + "*" * (len(username) - 2) + username[-1]


def public_base_url() -> str:
    """메일에 넣을 링크의 기준 주소. PUBLIC_BASE_URL만 쓴다 — request.host_url(Host 헤더)은
    공격자가 조작할 수 있어서, 피해자에게 공격자 주소로 된 링크가 가게 만들 수 있기 때문이다.
    값이 없으면 개발 환경에서만 로컬 주소로 대신하고, 운영에서는 빈 문자열(= 메일을 보내지 않음).
    복구 메일(guide34-a), 이메일 인증 메일(guide40), 비밀번호 재설정 메일(guide41)이 같이 쓴다."""
    if config.PUBLIC_BASE_URL:
        return config.PUBLIC_BASE_URL
    return "" if config.IS_PRODUCTION else "http://127.0.0.1:5000"
