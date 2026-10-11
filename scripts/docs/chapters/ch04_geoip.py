# 4단원 — IP 위치 조회 (GeoIP) 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "04-geoip"
TITLE = "4. IP 위치 조회 (GeoIP)"
SUBTITLE = "IP 주소가 '어느 나라 어느 도시'로 바뀌어 화면에 나오기까지의 코드 흐름도"

FILE_ROLES = {
    "helpers/request_utils.py": "로그인 시도 목록에 위치를 붙이는 _attach_locations() 가 있는 공용 도구 파일.",
    "services/geoip.py": "ip-api.com 이라는 외부 서비스와의 통신만 전담하는 부품. 캐시를 먼저 보는 것이 핵심 설계.",
    "services/ip_utils.py": "IP 주소를 검증·정규화하는 순수 함수 모음. 외부 요청에 이상한 문자열이 섞이지 않게 막는다.",
    "db/geoip_cache.py": "한 번 조회한 IP 위치를 ip_locations 표에 저장·재사용하는 저장소 파일(캐시).",
}

s1 = Scenario("lookup", "위치가 붙는 과정",
              "로그인 시도 목록을 화면에 그릴 때마다 외부 서비스에 물어보면 무료 한도(분당 45건)를 금방 넘깁니다. 그래서 '저장해 둔 값(캐시)'을 먼저 보고, 모르는 IP만 새로 물어봅니다.")
s1.screen("로그인 시도 목록을 그린다", "회원 '내 로그인 기록'과 관리자 대시보드가 시도 목록을 만들 때, 각 줄에 위치를 붙이려고 이 함수를 부릅니다.",
          fn="helpers._attach_locations", hl=("ips = [attempt", "locations = geoip.get_locations(ips)"))
s1.step("① 중복 제거 + 저장된 값 먼저 확인", "같은 IP가 여러 번 나오는 건 흔해서 중복을 없앤 뒤, 이미 아는 IP들을 DB에서 한 번에 가져옵니다.",
        fn="services/geoip.py:get_locations", hl=("unique_ips = list", "cached = db.get_cached_ip_locations"),
        calls=[call("db.get_cached_ip_locations", "저장된 위치 한꺼번에 읽기", "ip_locations 표에서 이 IP들을 쿼리 한 번으로 가져옵니다(IP마다 따로 묻지 않음).")])
s1.step("② 아는 IP는 그대로 재사용", "캐시에 있으면 외부에 묻지 않고 저장된 값을 씁니다. 조회에 실패했던 IP도 저장되어 있어 헛수고를 반복하지 않습니다.",
        fn="services/geoip.py:get_locations", hl=("for ip in unique_ips:", "continue"))
s1.step("③ 모르는 IP만 새로 묻고 저장", "캐시에 없는 IP만 외부 서비스에 묻고, 결과(실패 포함)를 저장해서 다음부터는 묻지 않습니다.",
        fn="services/geoip.py:get_locations", hl=("location = _fetch_location(ip)", "result[ip] = location"),
        calls=[call("services/geoip.py:_fetch_location", "외부 서비스에 위치 묻기", "ip-api.com에 실제로 요청합니다(캐시는 신경 쓰지 않음)."),
               call("db.save_ip_location", "위치 저장(캐시)", "ip_locations 표에 저장합니다. 이미 있으면 덮어씁니다(upsert).")])
s1.step("④ 사람이 읽을 문장으로 바꾸기", "{국가, 도시} 를 \"South Korea · Seoul\" 같은 문자열로 바꿔 각 시도 기록에 붙입니다. 실패면 '위치 확인 불가'.",
        fn="helpers._attach_locations", hl=("for attempt in attempts:", 'geoip.format_location'),
        calls=[call("services/geoip.py:format_location", "화면용 문자열 만들기", "국가·도시를 ' · '로 이어 붙이고, 없으면 '위치 확인 불가'를 돌려줍니다.")])

s2 = Scenario("safe", "외부 호출 안전장치 (SSRF 방지)",
              "외부 주소에 IP를 그대로 끼워 넣어 요청하기 때문에, IP 자리에 이상한 문자열이 들어오면 외부 요청이 조작될 수 있습니다. 그래서 '진짜 IP 형식'일 때만 요청을 보냅니다.")
s2.screen("외부 위치 조회 함수", "캐시에 없는 IP를 실제로 조회하는 함수입니다. 캐시를 볼지는 이 함수를 부르는 쪽이 정합니다.",
          fn="services/geoip.py:_fetch_location", hl="def _fetch_location(ip: str)")
s2.step("① 진짜 IP 형식인가?", "IP면 그대로, IPv6 대역(/64)이면 대표 주소로, 둘 다 아니면 요청 자체를 보내지 않고 '조회 실패'로 처리합니다.",
        fn="services/geoip.py:_fetch_location", hl=("lookup_ip = lookup_address(ip)", '"lookup_failed": True}'), reject="조회 실패 (외부로 요청을 보내지 않음)",
        calls=[call("services/ip_utils.py:lookup_address", "조회에 쓸 실제 주소 확인", "IP·IP 대역이 아니면 None을 돌려줍니다.")])
s2.step("② 외부 서비스에 묻기 (5초 제한)", "ip-api.com에 국가·지역·도시만 요청합니다. 5초 안에 답이 없으면 포기합니다.",
        fn="services/geoip.py:_fetch_location", hl=("try:", "data = response.json()"))
s2.step("③ 네트워크 문제·예약 IP도 '실패'로", "인터넷이 안 되거나, 127.0.0.1 같은 사설 IP라 위치가 없을 때도 모두 값 없음(None)으로 채워 돌려줍니다.",
        fn="services/geoip.py:_fetch_location", hl=("except requests.RequestException:", 'if data.get("status") != "success"'))
s2.step("④ 성공하면 국가·지역·도시", "정상 응답이면 국가·지역·도시를 담아 돌려줍니다.",
        fn="services/geoip.py:_fetch_location", hl=('"country": data.get("country")', '"lookup_failed": False,'))

SCENARIOS = [s1.build(), s2.build()]
