# 18단원 — 비밀번호 변경 + 다른 기기 로그인 해제 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "18-password-change"
TITLE = "18. 비밀번호 변경 + 다른 기기 로그인 해제"
SUBTITLE = "비밀번호를 바꾸면 다른 기기의 로그인이 모두 끊기는 '세션 세대 번호' 방식의 코드 흐름도"

FILE_ROLES = {
    "routes/member.py": "회원 전용 화면의 입구 파일. 비밀번호 변경(member_password_submit)이 여기에 있다.",
    "routes/auth.py": "로그인 입구 파일. 로그인 성공 시 세션에 '세대 번호'를 함께 저장한다.",
    "helpers/auth.py": "회원 문지기. 요청마다 세션의 세대 번호와 DB 번호를 비교한다.",
    "db/users.py": "회원 표. 비밀번호 해시 저장과 세션 세대 번호 증가(조건부 UPDATE)를 담당한다.",
    "notify/mailer.py": "메일 발송 담당 파일. 비밀번호 변경 알림 메일을 보낸다.",
}

MEM = "routes/member.py:member_password_submit"

s1 = Scenario("change", "비밀번호 변경",
              "복구 완료 메일은 '본인이 아니면 비밀번호를 바꾸세요'라고 안내하는데, 비밀번호만 바꾸고 이미 로그인된 세션을 그대로 두면 세션을 훔친 사람은 계속 로그인 상태로 남습니다. 그래서 바꾸는 순간 다른 기기의 세션을 모두 끊습니다.")
s1.screen("비밀번호 변경 폼 제출 (POST /dashboard/password)", "내 프로필 화면의 비밀번호 변경 카드입니다. 회원 문지기를 통과해야 합니다.",
          fn=MEM, hl=('@member_bp.route("/dashboard/password", methods=["POST"])', "@member_login_required"))
s1.step("① 봇 · 계정 잠금 확인", "허니팟이 채워져 있거나 이미 잠긴 계정이면 세션을 정리하고 돌려보냅니다.",
        fn=MEM, hl=("if is_bot_submission():", 'flash("잠긴 계정입니다. 잠시 후 다시 로그인해주세요.")'), reject="일시적인 오류 / 잠긴 계정입니다.",
        calls=[call("detector.is_account_locked", "계정 잠금 여부", "5단원.", later="5단원")])
s1.step("② 새 비밀번호 형식 검사 (실패 횟수에는 안 넣음)", "길이 8자 이상·확인칸 일치·'현재와 같지 않음'. 이건 본인 확인과 무관한 입력 실수라서 로그인 실패 횟수에 넣지 않습니다.",
        fn=MEM, hl=('current_password = request.form.get("current_password"', "새 비밀번호가 현재 비밀번호와 같습니다."), reject="규칙에 맞는 안내 문구")
s1.step("③ 현재 비밀번호 확인 — 틀리면 로그인 실패와 똑같이 처리", "세션만 훔친 사람이 비밀번호를 바꾸지 못하게 하는 장치입니다. 틀리면 기록하고 같은 기준으로 잠가서, 이 화면이 '잠금 없이 비밀번호를 무한히 맞춰보는 우회로'가 되지 않게 합니다.",
        fn=MEM, hl=("if not db.verify_user_credentials(username, current_password):", "현재 비밀번호가 올바르지 않습니다."), reject="현재 비밀번호가 올바르지 않습니다.",
        calls=[call("db.verify_user_credentials", "현재 비밀번호 확인", "저장된 해시와 비교합니다."),
               call("db.log_attempt", "실패 기록", "로그인 실패와 같은 표에 기록합니다."),
               call("routes/member.py:_lock_if_suspicious", "수상하면 잠금", "IP·계정 기준으로 판정하고 잠급니다. 이미 잠긴 IP 는 다시 잠그지 않아 알림이 중복되지 않습니다.")])
s1.step("④ 비밀번호 저장 + 세션 세대 번호 +1 (이 기기만 새 번호 유지)", "새 해시를 저장하면서 번호를 1 올리고, 이 기기 세션에만 새 번호를 적어 이 기기는 로그인 상태를 유지합니다(다른 기기는 번호가 달라져 곧 끊깁니다). 번호는 1 올립니다. '읽은 값 그대로일 때만' 올리는 조건부 UPDATE 라서, 두 기기에서 거의 동시에 바꿔도 번호가 덜 올라가 옛 세션이 살아남는 일이 없습니다(경쟁에서 지면 다시 읽어 최대 3번 시도).",
        fn=MEM, hl='session["session_version"] = db.update_user_password',
        calls=[call("db.update_user_password", "해시 저장 + 번호 증가", "새 번호를 돌려줍니다."),
               call("db.get_user_session_version", "현재 세대 번호 읽기", "조건부 UPDATE 의 기준값입니다.")])
s1.step("⑤ 변경 알림 메일", "가입 이메일로 '비밀번호가 변경되었습니다' 알림을 보냅니다. 본인이 한 일이 아니면 바로 알 수 있게 하기 위해서입니다.",
        fn=MEM, hl=("mailer.send_password_changed_notice(user[\"email\"])", 'flash("비밀번호가 변경되었습니다.'),
        calls=[call("notify/mailer.py:send_password_changed_notice", "변경 알림 메일", "본인이 아니면 관리자에게 알리라고 안내합니다.")])

s2 = Scenario("guard", "다른 기기는 어떻게 끊기나",
              "로그인 때 세션에 '세대 번호'를 적어 두고, 회원 화면 요청마다 DB 의 번호와 비교합니다. 번호가 다르면 그 세션은 무효입니다.")
s2.screen("로그인 성공 — 세션에 번호 저장", "계정의 현재 세대 번호를 세션에 함께 적습니다.",
          fn="routes/auth.py:login_submit", hl=('session["username"] = username', 'session["session_version"] = user.get("session_version") or 0'))
s2.step("① 회원 화면 요청마다 번호 비교", "세션의 번호와 DB 의 번호가 다르거나, 회원이 삭제되어 번호를 못 찾으면(None) 회원 세션만 지우고 로그인 화면으로 보냅니다.",
        fn="helpers/auth.py:member_login_required", hl=("current = db.get_user_session_version", 'return redirect(url_for("auth.login"))'),
        reject="비밀번호가 변경되었거나 계정 정보가 바뀌어 로그아웃되었습니다.",
        calls=[call("db.get_user_session_version", "DB 의 현재 번호", "회원이 없으면 None 을 돌려줍니다."),
               call("helpers/auth.py:clear_member_session", "회원 세션만 지우기", "같은 브라우저의 관리자 세션은 그대로 둡니다.")])

SCENARIOS = [s1.build(), s2.build()]
