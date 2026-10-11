# 7단원 — API 엔드포인트 매크로/봇 탐지 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "07-macro-bot"
TITLE = "7. API 엔드포인트 매크로/봇 탐지"
SUBTITLE = "서로 다른 /api/* 경로를 기계적으로 훑는 스크립트를 잡아내는 코드 흐름도"

FILE_ROLES = {
    "helpers/hooks.py": "요청마다 자동으로 끼어드는 훅 모음. track_api_access() 가 /api/* 요청을 관찰한다.",
    "security/detector.py": "판사 역할. 서로 다른 API 경로 개수로 매크로/봇 여부를 판정만 한다.",
    "security/soar/observe.py": "잠그지 않고 알림 + 기록만 하는 관찰형 조치 파일.",
    "notify/alert.py": "Slack 알림 전송 전담 파일.",
    "db/api_access_log.py": "/api/* 요청(POST 포함)을 메서드와 함께 기록하고, 서로 다른 경로 수를 세는 저장소 파일.",
}

s1 = Scenario("macro", "서로 다른 API를 훑는 패턴",
              "기존 '반복 페이지 접근'(6단원)은 GET 한 경로의 반복만 봅니다. 스크립트가 POST를 섞거나 여러 API를 옮겨 다니면 피해갈 수 있어서, 메서드를 가리지 않고 '서로 다른 /api/* 경로 개수'를 세는 탐지를 따로 둡니다.")
s1.screen("/api/* 요청이 들어올 때마다", "메서드와 상관없이(POST 포함) 라우팅이 끝난 뒤 실제 함수가 실행되기 직전에 훅이 호출됩니다.",
          fn="helpers/hooks.py:register_request_hooks", hl="app.before_request(track_api_access)")
s1.step("① 관찰 대상 거르기", "/api/ 로 시작하지 않거나, 자동 폴링 엔드포인트(대시보드·게시판)는 제외합니다. 폴링은 경로 하나만 반복하므로 어차피 이 탐지에 안 걸리지만 표를 불리지 않으려고 기록하지 않습니다.",
        fn="helpers/hooks.py:track_api_access", hl=('if request.url_rule is None or not request.path.startswith("/api/")', "if request.endpoint in PAGE_ACCESS_EXCLUDED_ENDPOINTS:"))
s1.step("② API 호출 한 줄 기록", "누가(IP) 어떤 경로를 어떤 방식(GET/POST…)으로 불렀는지 남깁니다.",
        fn="helpers/hooks.py:track_api_access", hl=("ip = get_request_ip()", "db.log_api_access(ip, request.path, request.method)"),
        calls=[call("db.log_api_access", "API 호출 한 줄 저장", "api_access_log 표에 IP·경로·메서드를 추가합니다.")])
s1.step("③ 서로 다른 경로가 몇 개인가? (판정)", "최근 60초 안에 호출한 '서로 다른 경로'가 5개를 초과하고, 정확히 6번째 경로일 때만 알립니다.",
        fn="helpers/hooks.py:track_api_access", hl=("suspicious, count, is_first_over_threshold = detector.is_macro_pattern_suspicious", "if suspicious and is_first_over_threshold:"),
        calls=[call("detector.is_macro_pattern_suspicious", "매크로/봇 판정", "(수상한가, 경로 개수, 지금 막 넘겼나)를 돌려줍니다.",
                    then=[call("db.count_recent_distinct_api_paths", "서로 다른 경로 개수 세기", "해당 IP의 최근 경로를 가져와 중복을 없애고(set) 개수를 셉니다.")])])
s1.step("④ 알림 + MEDIUM 기록 (잠그지 않음)", "여러 경로에 걸친 패턴이라 잠글 단일 대상이 없어서 관찰(알림 + 기록)까지만 자동화합니다.",
        fn="helpers/hooks.py:track_api_access", hl="soar.notify_macro_pattern(ip, count)",
        calls=[call("soar.notify_macro_pattern", "매크로 알림 + 기록", "Slack 알림 후 API_MACRO_PATTERN(MEDIUM)으로 기록합니다.",
                    then=[call("notify/alert.py:send_macro_pattern_alert", "Slack 알림", "횟수를 담아 보냅니다.")])])
s1.step("⑤ 기준치 코앞이면 AI 조기 경보 검토", "5개 직전(예: 3~5개)이면 LLM에게 조기 경보 여부를 묻습니다.",
        fn="helpers/hooks.py:track_api_access", hl=("elif not suspicious and count >=", '"API_MACRO_PATTERN", "ALERT_ONLY"'),
        calls=[call("soar.consider_early_warning", "조기 경보 판단", "LLM이 사전 조치를 제안합니다.", later="11단원")])

SCENARIOS = [s1.build()]
