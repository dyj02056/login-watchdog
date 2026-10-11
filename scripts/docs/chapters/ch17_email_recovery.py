# 17단원 — 이메일 인증 복구 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "17-email-recovery"
TITLE = "17. 이메일 인증 복구"
SUBTITLE = "영구 잠긴 사용자가 본인 이메일로 스스로 잠금을 푸는 과정과, 그 과정을 악용하지 못하게 하는 안전장치의 코드 흐름도"

FILE_ROLES = {
    "routes/recovery.py": "복구 화면 4개(요청 폼 · 메일 요청 · 확인 화면 · 완료)의 입구 파일. 계정 존재 여부를 숨기는 것이 핵심 원칙.",
    "helpers/timing.py": "응답 시간을 항상 같게 맞추는 도구. 응답이 빠르냐 느리냐로 아이디 존재 여부가 새지 않게 한다.",
    "security/lockdown.py": "복구가 끝나면 계정 잠금 해제(+보호관찰) 또는 IP '본인 + 본인 기기' 예외 발급을 실제로 반영한다.",
    "notify/mailer.py": "복구·완료 메일 발송과, 발송 실패 원인 분류 후 관리자 알림을 담당한다.",
    "db/recovery.py": "복구 요청(recovery_requests 표)을 만들고, 토큰·코드를 해시로 비교·1회 소비하는 저장소 파일.",
    "db/ip_exemptions.py": "영구 잠금 IP 에서 본인 기기만 통과시키는 예외(출입증) 표를 다루는 저장소 파일.",
    "routes/auth.py": "로그인 입구 파일. 영구 잠긴 IP 에서 '회원 + 기기'가 맞는 예외만 통과시킨다.",
    "helpers/device.py": "복구를 요청한 브라우저를 구분하는 기기 쿠키를 다루는 도구.",
}

REC = "routes/recovery.py"

# ---------------------------------------------------------------- 1) 복구 요청
s1 = Scenario("request", "복구 메일 요청 (항상 같은 응답)",
              "영구 잠금이 관리자만 풀 수 있으면 억울하게 잠긴 사용자는 기다리기만 해야 합니다. 본인 이메일로 인증해 스스로 풀 수 있게 하되, 아이디가 있는지·잠겼는지가 응답으로 새지 않게 항상 똑같이 답합니다.")
s1.screen("복구 요청 (POST /recovery/request)", "로그인 화면의 '본인 인증으로 잠금 해제'에서 아이디를 입력합니다.",
          fn=f"{REC}:recovery_request_submit", hl=('@recovery_bp.route("/recovery/request", methods=["POST"])', "def recovery_request_submit"))
s1.step("① 기기 쿠키를 (재)발급", "복구를 요청한 브라우저를 구분하는 무작위 쿠키입니다. 항상 발급해서 응답이 계정 존재 여부와 무관하게 똑같이 보이게 합니다.",
        fn=f"{REC}:recovery_request_submit", hl=("started = time.monotonic()", "device_token = request.cookies.get(config.DEVICE_COOKIE_NAME) or new_device_token()"),
        calls=[call("helpers/device.py:new_device_token", "기기 토큰 만들기", "예측할 수 없는 무작위 값을 만듭니다."),
               call("helpers/device.py:set_device_cookie", "기기 쿠키 심기", "HttpOnly, 운영 환경에서는 Secure 로 설정합니다.")])
s1.step("② 봇이면 같은 문구로 종료", "허니팟이 채워져 있어도 '등록된 이메일이 있다면…'이라는 같은 안내를 돌려줍니다.",
        fn=f"{REC}:recovery_request_submit", hl=("if is_bot_submission():", "message = GENERIC_SENT_MESSAGE"),
        calls=[call("soar.notify_bot_detected", "봇 감지 기록", "MEDIUM 으로 기록합니다.", later="15단원")])
s1.step("③ 처리 시간을 5초로 고정", "아이디가 없으면 DB 조회 한두 번으로 끝나고, 실제 복구 메일은 조회 여러 번 + SMTP 까지 거쳐서 그냥 두면 응답 시간 차이로 아이디 존재가 드러납니다. 빨리 끝나도 5초까지 기다립니다. 메일 발송까지 응답 전에 끝냅니다(서버리스는 응답을 보내면 함수를 멈추기 때문).",
        fn=f"{REC}:recovery_request_submit", hl=("result = {}", "message = result.get(\"message\", GENERIC_SENT_MESSAGE)"),
        calls=[call("helpers/timing.py:run_with_fixed_response_time", "고정 응답 시간", "목표 시간까지 남은 만큼 기다린 뒤 응답합니다. 처리 중 예외는 로그만 남기고 삼킵니다(500 이 새면 존재 여부가 드러남).")])
s1.step("④ IP 당 시간당 한도", "같은 IP 가 1시간에 너무 많이 요청하면 다른 문구로 거절합니다. IP 기준이라 계정 존재 여부와 무관합니다.",
        fn=f"{REC}:recovery_request_submit", hl=("if ip_count >= config.RECOVERY_MAX_PER_IP_PER_HOUR:", "return RATE_LIMITED_MESSAGE"),
        calls=[call("db.count_recovery_requests_by_ip", "최근 1시간 요청 수", "이 IP 의 복구 요청 개수.")])
s1.step("⑤ 하루 한도 · 60초 쿨다운 확인 + 잠금 조회 (동시에)", "서로 무관한 조회 3개를 동시에 보내서 서버리스의 함수 시간 제한 안에 끝냅니다.",
        fn=f"{REC}:_issue_recovery", hl=("with ThreadPoolExecutor(max_workers=3) as executor:", "return"),
        calls=[call(refs=["db.get_recovery_activity", "db.get_active_account_lockout", "db.get_active_lockout"], title="이력 · 계정 잠금 · IP 잠금 동시 조회", plain="최근 24시간 요청 이력, 이 계정의 잠금, 이 IP 의 잠금을 한꺼번에 가져옵니다.")])
s1.step("⑥ 풀 수 있는 대상인지 결정", "계정이 영구 잠금이고 복구 방식이 SELF 면 '계정', 아니면 IP 가 영구 잠금이고 EXEMPTION 이면 'IP(예외만 발급)'. 이메일을 신뢰할 수 없는 계정(UNDELIVERABLE)은 제외합니다. 대상이 없으면 메일 없이 조용히 끝납니다.",
        fn=f"{REC}:_eligible_target", hl=("if (", "return None"), reject="(대상 없음 — 메일 없이 같은 안내만)")
s1.step("⑦ 토큰 + 6자리 코드를 만들어 '해시만' 저장", "원문은 메일에만 있고 DB 에는 SHA-256 지문만 남아서, DB 가 유출돼도 링크를 만들 수 없습니다. 기기 쿠키도 해시로 저장합니다.",
        fn=f"{REC}:_issue_recovery", hl=("kind, value = target", "if created is None:"),
        calls=[call("db.create_recovery_request", "복구 요청 저장", "토큰·코드·기기 해시와 만료 시각(15분)을 PENDING 으로 저장합니다."),
               call("helpers/device.py:hash_secret", "SHA-256 해시", "원문 대신 지문만 저장하기 위한 함수입니다.")])
s1.step("⑧ 메일 발송 — 실패하면 요청 취소", "링크는 Host 헤더(공격자가 조작 가능)가 아니라 PUBLIC_BASE_URL 로만 만듭니다. 메일이 못 나가면 쓸 수 없는 요청이라 취소하고, 서버가 수신자를 영구 거부(REFUSED)했다면 그 계정을 UNDELIVERABLE 로 표시해 관리자 전용으로 올립니다.",
        fn=f"{REC}:_issue_recovery", hl=('link = f"{base_url}/recovery/verify?t={token}"', "_flag_undeliverable(user, ip)"),
        calls=[call("notify/mailer.py:send_recovery_email", "복구 메일 발송", "링크와 6자리 코드를 보냅니다. 실패 원인은 CONFIG/AUTH/CONNECT/OTHER/INTERNAL 로 분류해 관리자에게 알리고, 같은 원인은 1시간에 한 번만 보냅니다."),
               call(f"{REC}:_flag_undeliverable", "존재하지 않는 이메일 표시", "email_status=UNDELIVERABLE + 이메일 복구 불가(ADMIN_ONLY)로 올립니다.")])

# ---------------------------------------------------------------- 2) 확인 + 완료
s2 = Scenario("verify", "링크 · 코드로 복구 완료",
              "메일 링크(GET)는 확인 화면만 보여주고 토큰을 소모하지 않습니다. 메일 보안 스캐너가 링크를 먼저 열어도 사용자가 나중에 정상 사용할 수 있어야 하기 때문입니다. 실제 소비는 버튼(POST)에서 한 번만 일어납니다.")
s2.screen("메일 링크 열기 (GET /recovery/verify?t=…)", "토큰을 소비하지 않고 '해제할까요?' 확인 화면만 보여줍니다.",
          fn=f"{REC}:recovery_verify_form", hl=('@recovery_bp.route("/recovery/verify", methods=["GET"])', "def recovery_verify_form"))
s2.step("① 확인 버튼 (POST) — IP 복구는 요청한 기기에서만", "공격자가 피해자 아이디로 복구를 요청하고 피해자가 메일 링크를 눌러도, 공격자 기기에는 예외가 발급되지 않습니다. 다른 기기에서 누른 확인은 소비하지 않고 거부합니다.",
        fn=f"{REC}:recovery_verify_submit", hl=('token = request.form.get("t", "")', "return _finish(req)"), reject="이 링크는 복구를 요청한 기기에서만 사용할 수 있습니다.",
        calls=[call(f"{REC}:_device_matches", "요청한 기기인가?", "쿠키 해시와 저장된 해시를 타이밍 안전 비교(hmac.compare_digest)합니다.")])
s2.step("② 6자리 코드 경로 — 비교하기 '전에' 시도권부터 예약", "코드는 5회까지만 틀릴 수 있는 것이 핵심 방어선입니다. 비교한 뒤에 횟수를 올리면 동시에 수백 개를 보냈을 때 전부 비교되어 버려서, 비교 전에 시도권을 예약하고 예약에 실패하면 맞는 코드여도 통과시키지 않습니다(20단원).",
        fn=f"{REC}:recovery_verify_submit", hl=("attempt = db.reserve_recovery_code_attempt(", "return _finish(req)"), reject="코드가 올바르지 않습니다. (남은 시도 N회)",
        calls=[call("db.reserve_recovery_code_attempt", "시도권 예약 (조건부 UPDATE)", "읽은 횟수 그대로일 때만 +1 해서, 경쟁에서 진 요청은 예약에 실패합니다.", later="20단원")])
s2.step("③ 1회만 소비 (PENDING → VERIFIED)", "조건부 UPDATE 로 한 번만 소비합니다. 이미 소비된 링크는 거부됩니다.",
        fn=f"{REC}:_finish", hl=("consumed = db.consume_recovery_request(req[\"id\"])", "return render_template"),
        calls=[call("db.consume_recovery_request", "요청 소비", "status=PENDING 일 때만 VERIFIED 로 바꿉니다.")])
s2.step("④ 실제 조치 반영", "계정 복구면 영구 잠금 해제 + 24시간 보호관찰. IP 복구면 IP 는 계속 잠가 둔 채 '요청한 회원 + 요청한 기기'에게만 30일 예외(출입증)를 발급합니다.",
        fn="security/lockdown.py:apply_recovery", hl=('target_kind = recovery_request["target_kind"]', "return True"),
        calls=[call("db.release_permanent_account_lockout", "계정 영구 잠금 해제", "복구 방식이 SELF 인 것만 풉니다(ADMIN_ONLY 는 안 풂)."),
               call("db.set_account_probation", "보호관찰 시작", "24시간 안에 다시 잠기면 관리자 전용 영구 잠금이 됩니다."),
               call("db.insert_ip_exemption", "IP 예외(출입증) 발급", "회원 번호 + 기기 해시 + 만료일(30일)을 저장합니다.")])
s2.step("⑤ 완료 메일 + 이메일 인증으로도 인정", "복구 링크·코드를 썼다는 것은 그 메일함의 주인이라는 증거이므로, 이메일 인증으로도 칩니다(23단원).",
        fn=f"{REC}:_finish", hl=("try:", "return render_template(\"recovery_done.html\", success=True"),
        calls=[call("notify/mailer.py:send_recovery_done_notice", "복구 완료 안내 메일", "본인이 한 일이 아니면 즉시 비밀번호를 바꾸라고 안내합니다.")])

# ---------------------------------------------------------------- 3) 예외로 로그인
s3 = Scenario("login", "예외로 로그인 (영구 잠긴 IP)",
              "IP 는 여러 사람이 함께 쓸 수 있어서, 이메일로 'IP 를 풀지' 않고 '그 회원 + 그 기기'만 통과시킵니다. 같은 IP 의 다른 기기는 계속 차단됩니다.")
s3.screen("영구 잠긴 IP 에서 로그인", "로그인 입구가 영구 잠금을 보고 예외 여부를 확인합니다.",
          fn="routes/auth.py:login_submit", hl=("exemption = None", "# 예외가 있으면 IP 잠금 안내 없이"))
s3.step("① 회원 + 기기 쿠키가 모두 맞아야 예외", "기기 쿠키가 없거나 그 회원이 없으면 항상 None 입니다. 공격자는 둘 다 갖지 못합니다.",
        fn="routes/auth.py:_find_ip_exemption", hl=("device_hash = get_device_hash()", "return db.get_active_ip_exemption"),
        calls=[call("db.get_active_ip_exemption", "유효한 예외 찾기", "IP · 회원 번호 · 기기 해시 · 만료일이 모두 맞는 ACTIVE 한 줄.")])
s3.step("② 예외로 들어온 회원이 연달아 틀리면 예외 회수", "예외는 '본인이 비밀번호를 아는 상황'을 전제로 한 출입증이라, 계속 틀리면 도용 신호로 보고 회수합니다.",
        fn="routes/auth.py:login_submit", hl=("if exemption is not None:", "return _login_form()"),
        calls=[call("db.revoke_ip_exemption", "예외 회수", "사유와 함께 REVOKED 로 바꿉니다.")])

SCENARIOS = [s1.build(), s2.build(), s3.build()]
