# 23단원 — 이메일 인증 + 이메일 변경 보호 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "23-email-verification"
TITLE = "23. 이메일 인증 + 이메일 변경 보호"
SUBTITLE = "가입 이메일을 인증하고, 이메일 변경을 '현재 비밀번호 + 새 주소 확인 링크'로 보호하는 코드 흐름도"

FILE_ROLES = {
    "services/email_verification.py": "'이메일 담당'. 인증·변경 확인 링크를 만들고 처리한다. 결과를 예외 대신 값으로 돌려준다.",
    "routes/email.py": "메일 링크가 여는 확인 화면 2개. GET 은 화면만, POST 에서 토큰을 1회 소비한다. 로그인 불필요.",
    "routes/member.py": "회원 화면 입구 파일. 이메일 변경 요청이 여기 있다.",
    "routes/auth.py": "회원가입 입구 파일. 가입 직후 인증 메일을 보낸다.",
    "db/email_tokens.py": "email_tokens 표 저장소. 토큰은 해시만 저장하고 조건부 UPDATE 로 1회 소비한다.",
    "db/users.py": "회원 표 저장소. 이메일 변경·인증 표시를 담당한다.",
    "notify/mailer.py": "메일 발송 파일. 인증·변경 확인·알림 메일을 만든다.",
}

SVC = "services/email_verification.py"

s1 = Scenario("verify", "가입 이메일 인증",
              "비밀번호 찾기(24단원)는 '계정을 되찾는 메일'이라 그 메일이 가는 주소가 확실히 본인 것이어야 합니다. 그래서 가입 이메일로 인증 링크(15분, 1회용)를 보냅니다. 가입·로그인은 인증 없이도 바로 됩니다.")
s1.screen("가입 직후 / 대시보드 '인증 메일 보내기'", "가입이 끝나면 인증 메일을 보냅니다. 메일이 실패해도 가입은 유지됩니다.",
          fn="routes/auth.py:signup_submit", hl=("try:", "verification = email_verification.UNAVAILABLE"),
          calls=[call("routes/member.py:member_email_verify_resend", "'다시 보내기' 버튼", "대시보드·프로필에서 다시 요청합니다.", later="2단원")])
s1.step("① 이미 인증됐나? · 쿨다운 60초 · 하루 5회", "이미 VERIFIED 면 보내지 않고, 너무 자주·많이 요청하면 거절합니다.",
        fn=f"{SVC}:send_verification", hl=('if user.get("email_status") == "VERIFIED":', "return RATE_LIMITED"), reject="요청이 너무 잦습니다.",
        calls=[call(f"{SVC}:_rate_limited", "쿨다운·하루 한도", "최근 이력을 보고 판정합니다.",
                    then=[call("db.get_email_token_activity", "최근 24시간 발급 이력", "발급 횟수와 가장 최근 시각을 돌려줍니다.")])])
s1.step("② 토큰을 만들고 해시만 저장", "링크는 Host 헤더가 아니라 PUBLIC_BASE_URL 로만 만듭니다. 토큰 원문은 메일에만 있고 DB 에는 해시만 남습니다.",
        fn=f"{SVC}:_issue", hl=("base_url = public_base_url()", 'return row, f"{base_url}{path}?t={token}"'),
        calls=[call("db.create_email_token", "토큰 행 저장", "용도(EMAIL_VERIFY/EMAIL_CHANGE/PASSWORD_RESET)·주소·해시·만료(15분)를 저장합니다.")])
s1.step("③ 메일 발송 — 못 보냈으면 토큰 취소", "수신자 영구 거부(REFUSED)면 그 주소를 UNDELIVERABLE(반송)로 표시합니다.",
        fn=f"{SVC}:_after_send", hl=("if result == mailer.SENT:", "return UNAVAILABLE"),
        calls=[call("notify/mailer.py:send_email_verification", "인증 메일 발송", "링크가 들어 있는 메일을 보냅니다."),
               call("db.revoke_email_token", "토큰 취소", "메일이 못 나갔다면 쓸 수 없는 토큰이므로 취소합니다.")])

s2 = Scenario("confirm", "링크로 확인 (GET 은 화면만, POST 에서 소비)",
              "메일 링크를 누르면 확인 화면만 보이고 토큰은 닳지 않습니다. 메일 보안 스캐너가 링크를 먼저 열어도 사용자가 나중에 정상 사용할 수 있어야 하기 때문입니다. 확인 버튼(POST)에서 조건부 UPDATE 로 한 번만 소비합니다. 로그인은 요구하지 않습니다 — 메일은 휴대폰에서 여는 경우가 많고, 추측할 수 없는 토큰을 가진 사람이 곧 메일함 주인이기 때문입니다.")
s2.screen("메일 링크 열기 (GET /email/confirm?t=…)", "소비하지 않고 '인증할까요?' 화면만 보여줍니다.",
          fn="routes/email.py:email_confirm_form", hl=('@email_bp.route("/email/confirm", methods=["GET"])', "def email_confirm_form"))
s2.step("① 확인 버튼 (POST /email/confirm)", "IP 당 분당 한도가 따로 걸려 있습니다(app.py).",
        fn="routes/email.py:email_confirm_submit", hl="result, _user = email_verification.confirm(",
        calls=[call(f"{SVC}:confirm", "토큰 소비 + 용도별 반영", "(결과, 회원 행)을 돌려줍니다.")])
s2.step("② 토큰을 1회만 소비", "status=PENDING 인 행만 USED 로 바꾸므로, 같은 링크를 두 번 눌러도 두 번째는 '이미 사용된 링크'입니다.",
        fn=f"{SVC}:confirm", hl=("row = get_pending_email_token(token)", "return CONFIRM_INVALID, None"), reject="만료되었거나 이미 사용된 링크입니다.",
        calls=[call("db.consume_email_token", "조건부 UPDATE 로 1회 소비", "동시에 두 요청이 와도 먼저 온 쪽만 성공합니다.")])
s2.step("③ 인증 링크면 VERIFIED 로 표시", "메일을 보낸 뒤 이메일을 바꿨다면 옛 주소로 간 링크는 새 주소를 인증하지 못합니다(STALE).",
        fn=f"{SVC}:confirm", hl=("if consumed[\"purpose\"] == db.email_tokens.PURPOSE_EMAIL_VERIFY:", "return CONFIRMED_VERIFIED, user"),
        calls=[call("db.mark_user_email_verified", "email_status = VERIFIED", "그 주소가 아직 같을 때만 표시합니다.")])

s3 = Scenario("change", "이메일 변경 보호",
              "예전에는 이메일 변경이 로그인 세션만 있으면 비밀번호 확인 없이 바로 됐습니다. 세션 탈취 → 이메일 변경 → 비밀번호 재설정 → 계정 탈취가 가능했습니다.")
s3.screen("프로필에서 이메일 변경 요청", "현재 비밀번호를 먼저 확인합니다(2단원). 틀리면 로그인 실패와 똑같이 기록·잠금됩니다.",
          fn="routes/member.py:member_email_change_submit", hl=("result = email_verification.request_email_change(user, new_email, ip)", "return redirect(url_for(\"member.member_profile\"))"))
s3.step("① 새 주소로 '확인 링크'만 보낸다", "바로 바꾸지 않습니다. 새 주소로 간 링크를 눌러야 반영됩니다.",
        fn=f"{SVC}:request_email_change", hl=("purpose = db.email_tokens.PURPOSE_EMAIL_CHANGE", "return _after_send"),
        calls=[call("notify/mailer.py:send_email_change_confirmation", "변경 확인 메일", "새 주소로 확인 링크를 보냅니다.")])
s3.step("② 다른 계정이 쓰는 주소여도 화면 응답은 같다", "토큰 행은 똑같이 만들고(한도·처리 시간도 비슷하게) 호출부에는 똑같이 SENT 를 돌려줍니다. 그 주소로는 '이미 등록된 주소' 안내 메일만 갑니다. 화면으로는 남의 이메일 가입 여부를 알 수 없습니다.",
        fn=f"{SVC}:request_email_change", hl=("if db.is_email_taken(new_email, exclude_user_id=user[\"id\"]):", "return SENT"),
        calls=[call("notify/mailer.py:send_email_in_use_notice", "'이미 등록된 주소' 안내", "주소 주인에게만 알립니다.")])
s3.step("③ 링크를 눌러야 반영 + 기존 주소로 알림", "그사이 다른 계정이 그 주소를 차지했다면 변경하지 않습니다. 바뀌면 기존 주소로 알림이 가서 세션을 탈취한 사람이 바꿨다면 원래 주인이 알아챕니다.",
        fn=f"{SVC}:confirm", hl=("if consumed[\"purpose\"] == db.email_tokens.PURPOSE_EMAIL_CHANGE:", "return CONFIRMED_CHANGED"), reject="그사이 다른 계정이 이 주소를 등록해 변경할 수 없습니다.",
        calls=[call("db.change_user_email", "이메일 변경 (조건부)", "다른 계정이 쓰는 주소면 False."),
               call("notify/mailer.py:send_email_changed_notice", "기존 주소로 변경 알림", "새 주소는 가려서(a***e@…) 알려줍니다.")])

SCENARIOS = [s1.build(), s2.build(), s3.build()]
