# 24단원 — 비밀번호 찾기 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "24-password-reset"
TITLE = "24. 비밀번호 찾기"
SUBTITLE = "비밀번호를 잊은 회원이 '인증된 이메일'로 스스로 재설정하는 과정의 코드 흐름도"

FILE_ROLES = {
    "routes/password.py": "비밀번호 찾기 화면 4개(요청 폼·메일 요청·새 비밀번호 화면·재설정)의 입구 파일.",
    "services/email_verification.py": "'이메일 담당'. 인증된 주소로만 재설정 링크를 보내고, 토큰을 1회 소비해 비밀번호를 바꾼다.",
    "helpers/timing.py": "응답 시간을 항상 같게 맞추는 도구(17·25단원).",
    "db/email_tokens.py": "email_tokens 표 저장소. 재설정 토큰도 같은 표에 해시로 저장한다.",
    "db/users.py": "회원 표 저장소. 비밀번호 해시 저장 + 세션 세대 번호 증가.",
    "notify/mailer.py": "메일 발송 파일. 재설정 링크 메일과 완료 알림 메일을 보낸다.",
}

SVC = "services/email_verification.py"
PW = "routes/password.py"

s1 = Scenario("forgot", "재설정 메일 요청",
              "비밀번호를 잊은 회원은 스스로 해결할 방법이 없어 관리자가 처리해야 했습니다. 23단원에서 '확인된 이메일'과 '세션만으로는 바뀌지 않는 이메일'을 만들어 두었으므로, 그 이메일로 재설정하게 했습니다. 아이디가 없든, 미인증이든, 한도에 걸렸든 화면 응답과 응답 시간은 같습니다.")
s1.screen("비밀번호 찾기 요청 (POST /password/forgot)", "로그인 화면의 '비밀번호 찾기' 또는 프로필의 '이메일로 재설정'에서 아이디를 입력합니다.",
          fn=f"{PW}:password_forgot_submit", hl=('@password_bp.route("/password/forgot", methods=["POST"])', "def password_forgot_submit"))
s1.step("① 봇이면 같은 안내로 종료", "허니팟이 채워져 있어도 같은 안내 문구를 돌려줍니다.",
        fn=f"{PW}:password_forgot_submit", hl=("if is_bot_submission():", "return render_template"),
        calls=[call("soar.notify_bot_detected", "봇 감지 기록", "MEDIUM 으로 기록합니다.", later="15단원")])
s1.step("② IP 당 시간당 5회 + 고정 응답 시간", "IP 한도에 걸렸을 때만 다른 문구를 보여줍니다(IP 기준이라 가입 여부와 무관). 처리가 빨리 끝나도 5초 뒤에 응답합니다.",
        fn=f"{PW}:password_forgot_submit", hl=("def work():", "message = result.get(\"message\", GENERIC_SENT_MESSAGE)"), reject="요청이 너무 많습니다. (IP 한도)",
        calls=[call("db.count_email_tokens_by_ip", "최근 1시간 요청 수", "이 IP 가 재설정을 요청한 횟수."),
               call("helpers/timing.py:run_with_fixed_response_time", "고정 응답 시간", "남은 시간만큼 기다린 뒤 응답합니다.", later="25단원")])
s1.step("③ 인증된(VERIFIED) 이메일에만 보낸다", "아이디 형식이 맞고, 가입돼 있고, 이메일이 VERIFIED 일 때만 진행합니다. 그 외에는 아무 것도 하지 않고 조용히 끝납니다.",
        fn=f"{SVC}:request_password_reset", hl=("if not config.USERNAME_PATTERN.match(username):", 'if user is None or user.get("email_status") != "VERIFIED":'), reject="(조용히 종료 — 같은 안내만)",
        calls=[call("db.get_user_by_username", "회원 찾기", "아이디로 회원을 찾습니다.")])
s1.step("④ 회원별 하루 한도 후 링크 발송", "링크(15분, 1회용)는 PUBLIC_BASE_URL 로만 만들고, 6자리 코드는 쓰지 않습니다 — 링크를 가진 사람이 곧 메일함 주인이라 기기 제한이 필요 없고, 코드 무차별 대입이라는 공격 면을 만들지 않기 위해서입니다.",
        fn=f"{SVC}:request_password_reset", hl=("purpose = db.email_tokens.PURPOSE_PASSWORD_RESET", "_after_send(user[\"id\"], row, mailer.send_password_reset_email(user[\"email\"], link))"),
        calls=[call(f"{SVC}:_issue", "토큰 만들고 해시만 저장", "23단원과 같은 함수를 씁니다.", later="23단원"),
               call("notify/mailer.py:send_password_reset_email", "재설정 링크 메일", "링크가 들어 있는 메일을 보냅니다.")])

s2 = Scenario("reset", "새 비밀번호 설정",
              "링크(GET)는 입력 화면만 보여주고 토큰을 소비하지 않습니다. 새 비밀번호 형식을 먼저 검사하고 통과해야 토큰을 소비합니다 — 입력 실수로 링크가 닳지 않게 하기 위해서입니다.")
s2.screen("메일 링크 열기 (GET /password/reset?t=…)", "소비하지 않고 새 비밀번호 입력 화면만 보여줍니다.",
          fn=f"{PW}:password_reset_form", hl=('@password_bp.route("/password/reset", methods=["GET"])', "def password_reset_form"))
s2.step("① 링크가 유효한가 (이메일이 그대로인가)", "유효한 PASSWORD_RESET 토큰이고, 그 회원의 이메일이 메일을 보낸 그 주소 그대로일 때만 통과합니다. 메일을 보낸 뒤 이메일을 바꿨다면 옛 주소로 간 링크는 쓸 수 없습니다.",
        fn=f"{SVC}:get_reset_target", hl=("row = get_pending_token(token)", "return row, user"), reject="만료되었거나 이미 사용된 링크입니다.",
        calls=[call("db.get_pending_email_token", "토큰 해시로 대기 중 토큰 찾기", "소비하지 않고 조회만 합니다.")])
s2.step("② 새 비밀번호 형식을 먼저 검사", "길이·확인칸 일치를 통과해야 다음으로 갑니다. 실패하면 토큰은 그대로여서 다시 입력할 수 있습니다.",
        fn=f"{PW}:password_reset_submit", hl=('new_password = request.form.get("new_password", "")', "새 비밀번호와 확인이 일치하지 않습니다."), reject="비밀번호는 최소 8자 이상이어야 합니다. / 확인칸 불일치")
s2.step("③ 토큰 1회 소비 → 비밀번호 변경 → 모든 기기 로그아웃", "비밀번호를 바꾸면 세션 세대 번호가 올라가 모든 기기의 로그인이 끊깁니다(18단원). 알림 메일이 가고, 재설정은 잠금을 풀지 않습니다(영구 잠금은 17단원 복구로 풉니다).",
        fn=f"{SVC}:reset_password", hl=("target = get_reset_target(token)", "return RESET_DONE, user"),
        calls=[call("db.consume_email_token", "조건부 UPDATE 로 1회 소비", "먼저 온 요청만 성공합니다."),
               call("db.update_user_password", "해시 저장 + 세션 세대 번호 +1", "다른 기기의 로그인이 모두 끊깁니다.", later="18단원"),
               call("notify/mailer.py:send_password_reset_notice", "재설정 완료 알림", "본인이 한 일이 아니면 즉시 알리라고 안내합니다.")])

SCENARIOS = [s1.build(), s2.build()]
