# 29단원 — IPv6 /64 대역 단위 정규화 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "29-ipv6-prefix"
TITLE = "29. IPv6 /64 대역 단위 정규화"
SUBTITLE = "요청 IP 를 '탐지·잠금 단위'로 바꾸는 한 곳(get_request_ip)과, 그 값이 쓰이는 곳들의 코드 흐름도"

IPU = "services/ip_utils.py:normalize_ip"

FILE_ROLES = {
    "helpers/request_utils.py": "요청 IP 를 알아내는 유일한 함수 get_request_ip() 가 있는 공용 도구.",
    "services/ip_utils.py": "IP 주소를 검증·정규화하는 순수 함수 모음. Flask 에 의존하지 않아 다른 곳에서도 같이 쓴다.",
    "security/lockdown.py": "영구 잠금 로직 파일. 허용 목록 IP 도 같은 단위로 비교한다.",
    "services/geoip.py": "IP 위치 조회 부품. 대역 키면 대표 주소로 조회한다.",
}

s1 = Scenario("normalize", "요청 IP → 탐지·잠금 단위 키",
              "IPv6 사용자는 보통 /64 대역(2⁶⁴개 주소)을 통째로 받아 주소를 거의 공짜로 바꿀 수 있습니다. 주소 하나 단위로 세면 시도마다 주소를 바꾸는 것만으로 IP 잠금·IP 단위 탐지·요청 제한·영구 잠금이 모두 무력화됩니다. 그래서 IPv6 는 '대역'을 한 단위로 봅니다.")
s1.screen("요청이 도착한다", "모든 탐지·잠금·요청 제한은 요청 IP 를 이 함수 하나로 얻습니다.",
          fn="helpers/request_utils.py:get_request_ip", hl="def get_request_ip() -> str:")
s1.step("① X-Forwarded-For 는 '데모 설정'일 때만 믿는다 + 형식 검증", "기본은 접속 주소(remote_addr)를 씁니다. TRUST_FORWARDED_FOR 가 켜져 있을 때만 헤더 값을 믿되, 진짜 IP 형식이 아니면 버리고 원래 접속 IP 로 돌아갑니다(SSRF 방지, 15단원).",
        fn="helpers/request_utils.py:get_request_ip", hl=("if config.TRUST_FORWARDED_FOR:", "return normalize_ip(request.remote_addr)"))
s1.step("② IPv4 는 그대로", "203.0.113.10 → 203.0.113.10",
        fn=IPU, hl=("if address.version == 4:", "return str(address)"))
s1.step("③ IPv4 가 들어 있는 IPv6 는 IPv4 로", "::ffff:203.0.113.10 → 203.0.113.10 (같은 사람이 두 표기로 접속해도 한 사람으로 센다)",
        fn=IPU, hl=("if address.ipv4_mapped is not None:", "return str(address.ipv4_mapped)"))
s1.step("④ 루프백(내 컴퓨터)은 그대로", "::1 → ::1 (로컬 개발 편의)",
        fn=IPU, hl=("if address.is_loopback:", "return str(address)"))
s1.step("⑤ 그 외 IPv6 는 /64 대역 키로", "2001:db8:1:2:abcd::5 → 2001:db8:1:2::/64. 같은 /64 안의 주소는 모두 같은 키가 됩니다.",
        fn=IPU, hl='return str(ipaddress.ip_network(f"{address}/{_prefix_length()}", strict=False))',
        calls=[call("services/ip_utils.py:_prefix_length", "대역 길이 (기본 64)", "설정값이 1~128 밖이면 64 로 되돌립니다."),
               call(snippet=("config.py", "IPV6_PREFIX_LENGTH =", "IPV6_PREFIX_LENGTH ="), title="IPV6_PREFIX_LENGTH", plain="환경변수로 바꿀 수 있습니다.", label="IPV6_PREFIX_LENGTH")])
s1.step("⑥ 탐지·잠금·요청 제한이 전부 이 키로 동작", "get_request_ip() 값을 쓰는 로그인 실패 집계·IP 잠금·요청 제한·보안 이벤트·상관분석·IP 예외가 자동으로 대역 단위가 됩니다. 이 함수 하나만 바꿔서 전부 바뀐 것입니다.",
        fn="routes/auth.py:login_submit", hl="ip = get_request_ip()",
        calls=[call("detector.is_suspicious", "실패 횟수 판정", "이 키 단위로 셉니다.", later="5단원",
                    then=[call("db.count_recent_failures", "이 키의 최근 실패 세기", "login_attempts 의 ip_address 칸에 이 키가 저장되어 있습니다.")]),
               call("detector.is_locked", "IP 잠금 여부", "lockouts 표의 이 키로 찾습니다.", later="5단원")])

s2 = Scenario("same", "같은 단위로 비교하는 곳들",
              "대역 키와 일반 IP 가 섞여 비교되면 안 맞는 일이 생깁니다. 그래서 비교하는 모든 곳이 양쪽을 같은 단위로 정규화합니다.")
s2.screen("정규화된 키가 쓰이는 세 곳", "허용 목록 비교 · 위치 조회 · 요청 제한.",
          snippet=("app.py", "limiter = Limiter(", "re:^\\)"), label="app.py Limiter", hl=("key_func=get_request_ip,", "key_func=get_request_ip,"))
s2.step("① 허용 목록도 같은 단위로 비교", ".env 에 관리자 PC 의 IPv6 전체 주소를 적어도, 요청 IP 가 /64 대역 키로 들어오기 때문에 양쪽을 정규화해서 비교해야 같은 대역이 허용 목록으로 인정됩니다.",
        fn="security/lockdown.py:is_ip_allowlisted", hl=("key = normalize_ip(ip)", "return any(normalize_ip(entry) == key for entry in config.PERMANENT_LOCK_IP_ALLOWLIST)"),
        calls=[call(IPU, "정규화", "양쪽 모두 같은 함수를 거칩니다.")])
s2.step("② 위치 조회는 대역의 대표 주소로", "대역 키(…/64)로는 외부 서비스에 물을 수 없으므로 대표(네트워크) 주소로 조회합니다. IP 도 대역도 아니면 외부 요청을 보내지 않습니다.",
        fn="services/ip_utils.py:lookup_address", hl=('if "/" in key:', "return None"),
        calls=[call("services/geoip.py:_fetch_location", "외부 위치 조회", "4단원.", later="4단원")])

SCENARIOS = [s1.build(), s2.build()]
