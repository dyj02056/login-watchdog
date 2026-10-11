# 6단원 — 공격 유형별 탐지 매트릭스 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "06-detection-matrix"
TITLE = "6. 공격 유형별 탐지 매트릭스"
SUBTITLE = "404 반복·미인증 API·반복 접근·도배 같은 '관찰형' 탐지가 어디서 호출되고 무엇을 하는지 보는 코드 흐름도"

FILE_ROLES = {
    "helpers/hooks.py": "요청마다 자동으로 끼어드는 훅(404 처리, 반복 접근 관찰, 보안 헤더)을 모아둔 파일.",
    "helpers/auth.py": "관리자·회원 문지기와 '미인증 접근' 기록을 담당하는 파일.",
    "security/detector.py": "판사 역할. 각 공격 유형이 '수상한가?'를 True/False로 판정만 한다.",
    "security/soar/observe.py": "잠그지 않고 '알림 + 기록'만 하는 관찰형 조치와, 도배 요청 거부 기록을 담당한다.",
    "notify/alert.py": "Slack 알림 전송 전담 파일.",
    "db/access_logs.py": "404·미인증·페이지 접근 요청을 기록하고 최근 횟수를 세는 저장소 파일.",
    "routes/auth.py": "회원가입·로그인 입구 파일. 가입 도배 판정이 여기서 호출된다.",
    "routes/board.py": "게시판 입구 파일. 글·댓글 도배 판정이 여기서 호출된다.",
}

# ---------------------------------------------------------------- 1) 404 반복
s1 = Scenario("scan", "Web Scanning (404 반복)",
              "없는 주소를 계속 두드리는 것은 '숨은 페이지를 찾는 스캐닝'일 수 있습니다. 잠글 대상이 없어서 '기록 + 알림'만 하고, 임계값을 막 넘긴 순간에 딱 한 번만 알립니다.")
s1.screen("존재하지 않는 주소 요청 (404)", "Flask가 404를 만들면 등록된 404 처리기가 실행됩니다. 화면과 상관없이 기록·탐지가 항상 먼저 돌아갑니다.",
          fn="helpers/hooks.py:handle_not_found", hl="def handle_not_found")
s1.step("① 404 요청을 기록", "누가(IP) 어떤 경로를 두드렸는지 한 줄 남깁니다.",
        fn="helpers/hooks.py:handle_not_found", hl=("ip = get_request_ip()", "db.log_not_found_attempt(ip, request.path)"),
        calls=[call("db.log_not_found_attempt", "404 한 줄 저장", "not_found_attempts 표에 IP·경로를 추가합니다.")])
s1.step("② 임계값을 '막 넘긴 순간'인가?", "최근 60초 404가 10회 초과이고 정확히 11번째일 때만 True. 그 뒤 요청에는 알림을 반복하지 않습니다(알림 피로 방지).",
        fn="helpers/hooks.py:handle_not_found", hl=("suspicious, count, is_first_over_threshold = detector.is_web_scanning(ip)", "if suspicious and is_first_over_threshold:"),
        calls=[call("detector.is_web_scanning", "스캐닝 판정", "(수상한가, 횟수, 지금 막 넘겼나) 세 값을 돌려줍니다.",
                    then=[call("db.count_recent_not_found_attempts", "최근 404 횟수 세기", "이 IP의 최근 60초 404를 셉니다.")])])
s1.step("③ 알림 + MEDIUM 기록 (잠그지 않음)", "존재하지 않는 경로를 두드린 것이라 잠글 대상이 없고, IP를 잠그면 정상 이용까지 막기 때문에 관찰만 합니다.",
        fn="helpers/hooks.py:handle_not_found", hl="soar.notify_web_scanning(ip, count, request.path)",
        calls=[call("soar.notify_web_scanning", "스캐닝 알림 + 기록", "Slack 알림을 보내고 MEDIUM 이벤트로 기록합니다.",
                    then=[call("notify/alert.py:send_web_scanning_alert", "Slack 알림", "횟수와 경로를 담아 보냅니다.")])])
s1.step("④ 기준치 코앞이면 AI 조기 경보 검토", "아직 안 넘었지만 8~10회처럼 코앞이면 LLM에게 조기 경보 여부를 묻습니다.",
        fn="helpers/hooks.py:handle_not_found", hl=("elif not suspicious and count >=", "path=request.path,"),
        calls=[call("soar.consider_early_warning", "조기 경보 판단", "LLM이 사전 조치를 제안합니다.", later="11단원")])
s1.step("⑤ 404 화면 응답", "일반 페이지 요청이면 Next.js 404 화면, 그 외에는 기본 404 응답을 돌려줍니다.",
        fn="helpers/hooks.py:handle_not_found", hl="return spa.not_found_page() or error.get_response()")

# ---------------------------------------------------------------- 2) 미인증 API
s2 = Scenario("unauth", "Unauthorized Access (세션 없이 관리자 API)",
              "로그인 없이 관리자 API(/api/*)를 반복 호출하는 시도를 잡습니다. 다만 '세션은 있는데 만료된' 관리자는 공격이 아니므로 기록하지 않습니다.")
s2.screen("관리자 API 호출 → 문지기", "관리자 전용 API는 @login_required 문지기가 지킵니다. 문지기를 통과 못 하면 이 흐름이 시작됩니다.",
          fn="helpers/auth.py:login_required", hl=("if _load_current_admin() is None:", "return _reject_admin_request()"))
s2.step("① 세션은 있는데 무효 → 기록 안 함", "삭제·만료된 관리자 세션은 '다시 로그인해야 하는 사람'입니다. 기록하면 그 관리자의 대시보드 자동 폴링이 공격으로 오탐됩니다.",
        fn="helpers/auth.py:_reject_admin_request", hl=('if "admin_username" in session:', 'return redirect(url_for("admin.admin_login"))'),
        reject="세션이 만료되었습니다. 다시 로그인해주세요. (401)")
s2.step("② 세션이 아예 없음 → 기록 + 판정", "로그인 없이 /api/ 를 두드린 시도를 기록하고, 반복되면 알림 대상으로 봅니다.",
        fn="helpers/auth.py:_reject_admin_request", hl=("db.log_unauthorized_attempt(ip, request.path)", "if suspicious and is_first_over_threshold:"),
        calls=[call("db.log_unauthorized_attempt", "미인증 시도 한 줄 저장", "unauthorized_attempts 표에 추가합니다."),
               call("detector.is_unauthorized_access_suspicious", "미인증 접근 판정", "임계값 초과 + 지금 막 넘겼나를 돌려줍니다.",
                    then=[call("db.count_recent_unauthorized_attempts", "최근 미인증 시도 세기", "이 IP의 최근 60초 시도를 셉니다.")])])
s2.step("③ 알림 + 기록만 (잠그지 않는 이유)", "관리자 대시보드가 세션 만료 직후에도 자동 폴링을 보내서, 잠가버리면 관리자 본인이 재로그인도 못 하는 자충수가 됩니다.",
        fn="helpers/auth.py:_reject_admin_request", hl="soar.notify_unauthorized_access(ip, count, request.path)",
        calls=[call("soar.notify_unauthorized_access", "미인증 접근 알림 + 기록", "Slack 알림 후 MEDIUM 이벤트로 기록합니다.")])
s2.step("④ 401 응답", "API 요청에는 화면 이동 대신 JSON 401을 돌려줍니다.",
        fn="helpers/auth.py:_reject_admin_request", hl='return jsonify({"error": "로그인이 필요합니다."}), 401')

# ---------------------------------------------------------------- 3) 반복 페이지 접근
s3 = Scenario("page", "반복 페이지 접근",
              "같은 페이지 하나를 스크립트로 계속 요청하는 패턴(같은 경로 20회 초과)을 잡습니다. 여러 페이지를 둘러보는 정상 사용과 구분하기 위해 '이 경로를 몇 번 요청했나'를 셉니다.")
s3.screen("모든 GET 요청 직전에 실행되는 훅", "라우팅이 끝난 뒤, 실제 화면 함수가 실행되기 직전에 매번 호출됩니다.",
          fn="helpers/hooks.py:register_request_hooks", hl="app.before_request(track_page_access)")
s3.step("① 관찰 대상 좁히기", "존재하지 않는 경로(404)·GET이 아닌 요청·정적 파일·자동 폴링 API는 제외합니다. 안 빼면 정상 사용자가 항상 '수상'으로 잡힙니다.",
        fn="helpers/hooks.py:track_page_access", hl=('if request.method != "GET"', "if request.endpoint in PAGE_ACCESS_EXCLUDED_ENDPOINTS:"))
s3.step("② 접근 기록", "IP와 경로를 한 줄 남깁니다.",
        fn="helpers/hooks.py:track_page_access", hl=("ip = get_request_ip()", "db.log_page_access_attempt(ip, request.path)"),
        calls=[call("db.log_page_access_attempt", "페이지 접근 한 줄 저장", "page_access_attempts 표에 추가합니다.")])
s3.step("③ 같은 경로 반복 판정 → 알림", "이 IP가 이 경로를 20회 초과 요청한 순간에 한 번 알립니다. 잠그지 않는 이유는 새로고침하며 기다리던 정상 사용자를 막을 수 있어서입니다.",
        fn="helpers/hooks.py:track_page_access", hl=("suspicious, count, is_first_over_threshold = detector.is_page_access_suspicious", "soar.notify_page_access(ip, count, request.path)"),
        calls=[call("detector.is_page_access_suspicious", "반복 접근 판정", "이 경로의 최근 요청 횟수로 판정합니다.",
                    then=[call("db.count_recent_page_access_attempts", "이 경로 최근 요청 세기", "IP + 경로로 셉니다.")]),
               call("soar.notify_page_access", "반복 접근 알림 + 기록", "Slack 알림 후 MEDIUM 이벤트로 기록합니다.")])

# ---------------------------------------------------------------- 4) 도배
s4 = Scenario("spam", "도배 (가입 · 글 · 댓글)",
              "가입·글쓰기·댓글은 정상 사용자가 짧은 시간에 여러 번 반복할 이유가 거의 없어서, 기준치에 '도달'하면 곧바로 요청을 거부하고 HIGH 등급으로 기록합니다.")
s4.screen("가입 · 글쓰기 · 댓글 요청", "세 요청 모두 같은 패턴(먼저 판정 → 시도 기록)을 씁니다.",
          fn="routes/auth.py:signup_submit", hl=("rate_limited, signup_count = detector.is_signup_rate_limited(ip)", "if rate_limited:"),
          calls=[call("detector.is_signup_rate_limited", "가입 도배 판정 (60초 5회)", "횟수가 기준치 '이상'이면 True.")])
s4.step("① 글쓰기 도배 (60초 5회)", "글쓰기·글 수정이 같은 시도 기록을 공유합니다.",
        fn="routes/board.py:board_new_submit", hl=("if detector.is_post_rate_limited(ip):", "post=None)"), reject="너무 많은 게시글 작성 시도가 감지되었습니다.",
        calls=[call("detector.is_post_rate_limited", "글쓰기 도배 판정", "최근 시도 횟수가 기준치 이상인지.")])
s4.step("② 댓글 도배 (60초 10회)", "정상 대화에서는 댓글이 더 자주 달리므로 기준치가 더 넉넉합니다.",
        fn="routes/board.py:board_comment_submit", hl=("if detector.is_comment_rate_limited(ip):", "return redirect"), reject="너무 많은 댓글 작성 시도가 감지되었습니다.",
        calls=[call("detector.is_comment_rate_limited", "댓글 도배 판정", "최근 시도 횟수가 기준치 이상인지.")])
s4.step("③ 거부 사실을 HIGH로 기록 (중복 방지)", "이미 열린 미해결 이벤트가 있으면 새 행을 만들지 않고 횟수만 1 올립니다. 봇 한 대가 이벤트 표를 도배하지 못하게 하기 위해서입니다.",
        fn="soar.record_rejection", hl=("existing = db.get_unresolved_security_event", "db.insert_security_event_or_bump"),
        calls=[call("db.get_unresolved_security_event", "미해결 이벤트 찾기", "같은 IP·유형의 열린 이벤트가 있는지 봅니다."),
               call("db.insert_security_event_or_bump", "새로 기록하거나 횟수 증가", "동시 요청이 겹쳐도 유니크 인덱스가 중복 삽입을 막아줍니다.")])
s4.step("④ 상관분석 훅", "거부 이벤트도 여러 신호를 묶어 보는 상관분석(9단원)으로 넘깁니다.",
        fn="soar.record_rejection", hl="correlate.check_and_correlate(ip, event_type",
        calls=[call("security/correlate.py:check_and_correlate", "상관분석", "짧은 시간에 여러 유형이 겹치면 사건(incident)으로 묶습니다.", later="9단원")])

SCENARIOS = [s1.build(), s2.build(), s3.build(), s4.build()]
