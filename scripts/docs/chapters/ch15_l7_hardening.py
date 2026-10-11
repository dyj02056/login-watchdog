# 15단원 — L7 공격 방어 보강 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "15-l7-hardening"
TITLE = "15. L7 공격 방어 보강"
SUBTITLE = "IP 잠금만으로는 못 막는 공격(클릭재킹·대량 요청·봇·타이밍·SSRF·오픈 리다이렉트)을 메우는 방어들의 코드 흐름도"

FILE_ROLES = {
    "helpers/hooks.py": "모든 응답에 보안 헤더를 붙이는 등, 요청마다 걸리는 공용 훅 파일.",
    "app.py": "Flask 앱을 조립하는 시작 파일. 전역 요청 한도(Limiter)와 CSRF 오류 처리가 여기에 있다.",
    "helpers/request_utils.py": "봇 함정(허니팟) 확인과 요청 IP 확인을 담당하는 공용 도구.",
    "security/soar/observe.py": "알림·기록 조치 파일. 봇 감지·요청 거부(HIGH)를 기록한다.",
    "db/users.py": "회원 비밀번호 확인. 아이디가 없어도 같은 시간이 걸리게 '더미 해시'와 비교한다.",
    "db/admin.py": "관리자 비밀번호 확인. 회원과 같은 타이밍 방어를 쓴다.",
    "services/geoip.py": "IP 위치 조회 부품. IP 형식이 아니면 외부 요청을 보내지 않는다(SSRF 방지).",
    "services/ip_utils.py": "IP 주소를 검증·정규화하는 순수 함수 모음.",
    "templates/signup.html": "회원가입 화면. 사람 눈에 안 보이는 허니팟 입력칸이 들어 있다.",
}

# ---------------------------------------------------------------- HIGH
s1 = Scenario("high", "HIGH — 클릭재킹 방어 · 대량 요청 방어",
              "화면을 다른 사이트에 투명하게 겹쳐 클릭을 유도하는 공격(클릭재킹)과, 폼이 아닌 일반 페이지에 요청을 쏟아붓는 공격을 막습니다.")
s1.screen("모든 응답이 나가기 직전", "after_request 훅으로 '모든 응답'에 보안 헤더를 붙입니다.",
          fn="helpers/hooks.py:register_request_hooks", hl="app.after_request(set_security_headers)")
s1.step("① 다른 사이트의 iframe 에 못 들어가게", "X-Frame-Options(옛 브라우저용)와 CSP frame-ancestors(최신 표준)를 함께 씁니다. '즉시 해제'·'회원 삭제' 같은 파괴적 버튼이 있는 관리자 대시보드일수록 중요합니다.",
        fn="helpers/hooks.py:set_security_headers", hl=('response.headers["X-Frame-Options"] = "DENY"', '"form-action \'self\'"'))
s1.step("② 이 사이트가 주지 않은 스크립트는 실행하지 않게", "CSP 의 script-src 'self' — 인라인 스크립트와 외부 스크립트를 막습니다. 폰트만 Google Fonts 도메인을 예외로 엽니다.",
        fn="helpers/hooks.py:set_security_headers", hl=('"script-src \'self\'; "', '"font-src \'self\' https://fonts.gstatic.com; "'))
s1.step("③ 파일 형식을 추측하지 않게 · 이동 시 전체 주소를 숨기게", "MIME 스니핑 방지(nosniff)와 Referrer-Policy.",
        fn="helpers/hooks.py:set_security_headers", hl=('response.headers["X-Content-Type-Options"] = "nosniff"', 'response.headers["Referrer-Policy"]'))
s1.step("④ 전역 요청 한도 (1분 120회)", "기존 *_RATE_LIMIT 은 '특정 폼 제출'에만 걸려 있어서 /board 같은 일반 페이지는 무제한이었습니다. 같은 IP 가 1분에 한도를 넘기면 429 로 거절합니다. 자동 폴링 API 는 예외입니다.",
        snippet=("app.py", "limiter = Limiter(", "re:^\\)"), label="app.py Limiter",
        calls=[call(snippet=("config.py", "GLOBAL_RATE_LIMIT_PER_MINUTE =", "GLOBAL_RATE_LIMIT_PER_MINUTE ="), title="전역 한도 (120회/분)", plain="환경변수로 바꿀 수 있습니다.", label="GLOBAL_RATE_LIMIT_PER_MINUTE")])
s1.step("⑤ 한도를 넘기면 HTTP_FLOOD 로 기록", "거절하면서 HIGH 이벤트로 남깁니다. 같은 IP 가 계속 도배해도 미해결 이벤트 하나의 횟수만 올립니다.",
        fn="app.py:handle_rate_limit_exceeded", hl='soar.record_rejection("HTTP_FLOOD"',
        calls=[call("soar.record_rejection", "요청 거부 기록 (HIGH)", "상태 기반 중복 방지로 이벤트 표 도배를 막습니다.", later="8단원")])

# ---------------------------------------------------------------- MEDIUM
s2 = Scenario("medium", "MEDIUM — 허니팟 · 타이밍 · SSRF",
              "봇이 폼을 자동으로 채우는 것, 응답 시간 차이로 아이디 존재 여부를 알아내는 것, 서버가 대신 외부에 요청을 보내는 기능을 악용하는 것을 막습니다.")
s2.screen("허니팟: 사람 눈에 안 보이는 입력칸", "CSS 로 숨긴 'website' 칸입니다. 사람은 못 보니 비워 두지만, 폼의 모든 칸을 기계적으로 채우는 스크립트만 여기까지 채웁니다.",
          snippet=("templates/signup.html", '<div class="hp-field"', "</div>"), label="signup.html 허니팟 칸")
s2.step("① 칸이 채워져 있으면 봇으로 판정", "로그인·가입·글쓰기·댓글 등 폼에서 재사용됩니다. 외부 CAPTCHA 서비스 없이(API 키 불필요) 쓰는 무료 방식입니다.",
        fn="helpers/request_utils.py:is_bot_submission", hl="return bool(request.form.get(HONEYPOT_FIELD_NAME",
        calls=[call(snippet=("helpers/request_utils.py", "HONEYPOT_FIELD_NAME =", "HONEYPOT_FIELD_NAME ="), title="허니팟 칸 이름 'website'", plain="화면 쪽 칸 이름과 같아야 합니다.", label="HONEYPOT_FIELD_NAME")])
s2.step("② 즉시 거부 + MEDIUM 기록 (확인·기록 없이)", "로그인이라면 비밀번호 확인도 시도 기록도 없이 거부합니다. 잠그지는 않고 BOT_DETECTED(MEDIUM)로만 남깁니다.",
        fn="routes/auth.py:login_submit", hl=("if is_bot_submission():", 'return render_template("login_form.html"'),
        calls=[call("soar.notify_bot_detected", "봇 감지 기록", "Slack 알림 없이 MEDIUM 로 기록합니다.")])
s2.step("③ 타이밍 사이드채널: 아이디가 없어도 같은 시간", "비밀번호 비교는 일부러 느린 연산입니다. 없는 아이디일 때 이 계산을 건너뛰면 '즉시 실패 = 없는 아이디'라는 시간 차이로 존재 여부가 샐 수 있어, 미리 만든 더미 해시와 똑같이 비교합니다.",
        fn="db.verify_user_credentials", hl=("user = get_user_by_username(username)", "return result if user else False"),
        calls=[call(snippet=("db/users.py", "_DUMMY_PASSWORD_HASH =", "_DUMMY_PASSWORD_HASH ="), title="더미 해시 (모듈 로드 때 1번만 계산)", plain="요청마다 새로 계산하면 그 계산 자체가 또 다른 시간차를 만듭니다.", label="_DUMMY_PASSWORD_HASH")])
s2.step("④ 관리자 로그인도 같은 원칙", "관리자 아이디 존재 여부도 시간 차이로 알 수 없게 합니다.",
        fn="db.verify_admin_credentials", hl=("password_hash = res.data[0][\"password_hash\"] if res.data else _DUMMY_PASSWORD_HASH", "return result if res.data else False"))
s2.step("⑤ SSRF: IP 형식이 아니면 외부 요청을 보내지 않는다", "서버가 외부 주소에 값을 끼워 요청하는 기능은, 그 값에 이상한 문자열이 들어오면 조작될 수 있습니다. 진짜 IP(또는 IP 대역)일 때만 요청합니다(4단원).",
        fn="services/geoip.py:_fetch_location", hl=("lookup_ip = lookup_address(ip)", '"lookup_failed": True}'),
        calls=[call("services/ip_utils.py:lookup_address", "진짜 IP 인가?", "아니면 None → 외부 요청 없음.")])

# ---------------------------------------------------------------- LOW
s3 = Scenario("low", "LOW — 오픈 리다이렉트",
              "CSRF 오류가 났을 때 '이전 화면(referrer)'으로 돌려보내는데, 그 값은 요청한 쪽이 마음대로 정할 수 있어 공격자 사이트로 유도하는 데 악용될 수 있었습니다.")
s3.screen("CSRF 토큰이 없거나 틀린 요청", "세션이 오래돼 토큰이 만료된 것이 실제 사용자에게 가장 흔한 원인입니다.",
          fn="app.py:handle_csrf_error", hl="def handle_csrf_error(error):")
s3.step("① 안내 메시지", "다른 화면과 똑같이 flash 메시지로 안내합니다.",
        fn="app.py:handle_csrf_error", hl='flash("보안 토큰이 만료되었거나 올바르지 않습니다. 다시 시도해주세요.")')
s3.step("② 이 사이트로 돌아가는 주소일 때만 되돌려 보낸다", "referrer 의 도메인이 이 사이트(request.host)와 같을 때만 그 주소로 보내고, 아니거나 없으면 로그인 화면으로 고정합니다.",
        fn="app.py:handle_csrf_error", hl=("referrer = request.referrer", 'return redirect(url_for("auth.login")), 400'))

SCENARIOS = [s1.build(), s2.build(), s3.build()]
