# 2단원 — 회원 대시보드 흐름도 명세 (문법 설명은 scripts/docs/dsl.py 참고)

from scripts.docs.dsl import Scenario, call

SLUG = "02-member-dashboard"
TITLE = "2. 회원 대시보드"
SUBTITLE = "로그인한 회원이 자기 정보를 보고 고치는 화면들이 어떤 함수를 거치는지 보는 코드 흐름도"

FILE_ROLES = {
    "routes/member.py": "회원 전용 화면(/dashboard …)의 입구 파일. 모든 화면이 '회원 문지기'로 보호된다.",
    "helpers/auth.py": "관리자·회원 문지기(로그인 확인 장치)와 세션 정리 함수 모음.",
    "helpers/request_utils.py": "요청에서 IP를 알아내고, 시도 기록에 위치(국가·도시)를 붙이는 공용 도구.",
    "db/users.py": "회원(users 표) 조회·수정·비밀번호 확인을 담당하는 저장소 파일.",
    "db/attempts.py": "로그인 시도 기록을 쓰고 읽는 저장소 파일.",
    "services/geoip.py": "IP 주소를 국가·도시로 바꿔주는 파일. (4단원)",
    "services/email_verification.py": "인증 메일·이메일 변경 확인 메일을 다루는 파일. (23단원)",
    "notify/mailer.py": "메일 발송 담당 파일. (17·18단원)",
    "security/detector.py": "'수상한가?'를 판정만 하는 판사 역할 파일. (5단원)",
    "security/soar/lockouts.py": "판정 결과대로 IP·계정을 실제로 잠그는 집행관 파일. (10단원)",
}

DASH = "member.member_dashboard"

# ---------------------------------------------------------------- 시나리오 1: 첫 화면 + 문지기
s1 = Scenario("home", "첫 화면 + 문지기",
              "/dashboard 에 들어오면 화면을 그리기 전에 '회원 문지기'가 먼저 로그인 여부와 세션이 아직 유효한지를 확인합니다. "
              "통과해야 인사말 화면이 그려집니다.")
s1.screen("/dashboard 접속", "로그인한 회원이 대시보드 주소로 들어옵니다. 이 주소는 문지기(@member_login_required)가 지키고 있습니다.",
          fn=DASH, hl=('@member_bp.route("/dashboard"', "@member_login_required"))
s1.step("① 문지기: 로그인했나?", "세션에 아이디가 없으면 화면을 보여주지 않고 로그인 화면으로 돌려보냅니다.",
        fn="helpers.member_login_required", hl=('if "username" not in session', 'return redirect(url_for("auth.login"))'),
        reject="로그인 화면(/login)으로 이동")
s1.step("② 문지기: 세션이 아직 유효한가?", "세션에 적힌 '세대 번호'가 DB 값과 같은지 봅니다. 다른 기기에서 비밀번호를 바꿨거나 계정이 삭제됐다면 번호가 달라 이 세션이 끊깁니다.",
        fn="helpers.member_login_required", hl=("current = db.get_user_session_version", 'return redirect(url_for("auth.login"))'),
        reject="비밀번호가 변경되었거나 계정 정보가 바뀌어 로그아웃되었습니다.",
        calls=[call("db.get_user_session_version", "세션 세대 번호 읽기", "users 표에서 이 회원의 세션 세대 번호를 가져옵니다."),
               call("helpers.clear_member_session", "회원 세션만 지우기", "회원용 키(username 등)만 지웁니다. 같은 브라우저의 관리자 세션은 그대로 둡니다.")])
s1.step("③ 내 정보 읽기", "세션에 저장된 회원 번호(user_id)로 본인 행을 가져옵니다. 그 사이 계정이 사라졌다면 세션을 정리합니다.",
        fn=DASH, hl=("user = db.get_user_by_id", "return _logout_missing_member()"),
        reject="계정 정보를 찾을 수 없습니다. 다시 로그인해주세요.",
        calls=[call("db.get_user_by_id", "회원 번호로 회원 찾기", "users 표에서 번호(id)로 한 명을 찾습니다."),
               call("routes/member.py:_logout_missing_member", "사라진 계정 처리", "계정이 없으면 세션을 정리하고 로그인 화면으로 보냅니다.")])
s1.step("④ 인사말 이름 정하고 화면 그리기", "'표시 이름'이 있으면 그 이름, 없으면 로그인 아이디로 인사합니다. 이메일 미인증이면 안내 배너도 함께 보여줍니다.",
        fn=DASH, hl=("display_name = user", "email_status=user.get"))

# ---------------------------------------------------------------- 시나리오 2: 로그인 기록 + 위치
s2 = Scenario("history", "내 로그인 기록",
              "'내가 언제 어디서 로그인했나'를 보여주는 화면입니다. 핵심은 권한을 확인한 뒤 전체에서 걸러내는 게 아니라, "
              "처음부터 내 아이디로만 데이터를 물어본다는 점입니다.")
s2.screen("/dashboard/history 접속", "문지기를 통과한 회원만 들어올 수 있는 주소입니다.",
          fn="member.member_history", hl=('@member_bp.route("/dashboard/history"', "@member_login_required"))
s2.step("① 내 아이디로만 조회", "session[\"username\"] 을 넘겨 본인 기록 20건만 가져옵니다. 다른 회원 기록은 쿼리 대상에 아예 없습니다.",
        fn="member.member_history", hl="db.list_attempts_by_username(session",
        calls=[call("db.list_attempts_by_username", "내 로그인 시도 20건", "login_attempts 표에서 내 아이디의 기록만 최신순으로 가져옵니다.")])
s2.step("② 시도마다 접속 위치 붙이기", "각 기록의 IP를 국가·도시 문자열로 바꿔 'location' 칸을 추가합니다.",
        fn="member.member_history", hl="attempts = _attach_locations(",
        calls=[call("helpers._attach_locations", "기록에 위치 붙이기", "IP 목록을 한 번에 넘겨 위치를 받아 각 줄에 붙입니다.",
                    then=[call("services/geoip.py:get_locations", "IP → 국가·도시", "캐시에 있는 IP는 저장된 값을, 없는 것만 외부에 물어봅니다.", later="4단원")])])
s2.step("③ 화면에 표시", "위치가 붙은 기록을 member_history.html 에 넘겨 표로 그립니다.",
        fn="member.member_history", hl='return render_template("member_history.html"')

# ---------------------------------------------------------------- 시나리오 3: 프로필 · 이메일 · 비밀번호
s3 = Scenario("profile", "프로필 · 이메일 · 비밀번호",
              "프로필 화면에는 세 가지 변경이 있습니다. 표시 이름은 바로 바뀌지만, 이메일과 비밀번호는 '현재 비밀번호'를 먼저 확인합니다. "
              "세션만 훔친 사람이 계정을 가로채지 못하게 하기 위해서입니다.")
s3.screen("표시 이름 저장 (POST)", "프로필 폼에서 '표시 이름'을 바꾸고 저장합니다.",
          fn="member.member_profile_submit", hl=('@member_bp.route("/dashboard/profile", methods=["POST"])', "@member_login_required"))
s3.step("① 이름 저장 후 다시 방문", "이름을 DB에 저장하고, 화면을 바로 그리지 않고 프로필 주소로 '다시 방문(redirect)'시킵니다. 새로고침해도 폼이 중복 제출되지 않습니다.",
        fn="member.member_profile_submit", hl=('name = request.form.get("name"', 'return redirect(url_for("member.member_profile"))'),
        calls=[call("db.update_user_name", "표시 이름 저장", "users 표의 name 칸만 고칩니다.")])
s3.step("② 이메일 변경: 입력 확인", "봇 함정(허니팟)·빈칸·형식·'지금 쓰는 주소와 같은지'를 먼저 확인합니다.",
        fn="member.member_email_change_submit", hl=("if is_bot_submission():", "지금 쓰고 있는 이메일과 같습니다."),
        reject="입력 문제에 맞는 안내 문구와 함께 프로필 화면으로")
s3.step("③ 현재 비밀번호 확인", "틀리면 '로그인 실패'와 똑같이 기록하고 같은 기준으로 잠급니다. 이 화면이 비밀번호를 무한히 맞춰보는 우회로가 되지 않게 하기 위해서입니다.",
        fn="member.member_email_change_submit", hl=("if not db.verify_user_credentials(username, current_password)", "현재 비밀번호가 올바르지 않습니다."),
        reject="현재 비밀번호가 올바르지 않습니다. (반복되면 잠금)",
        calls=[call("db.verify_user_credentials", "비밀번호 확인", "저장된 해시와 비교합니다."),
               call("db.log_attempt", "실패 기록", "로그인 실패와 같은 표에 기록해 탐지 대상이 됩니다."),
               call("routes/member.py:_lock_if_suspicious", "수상하면 잠금", "실패가 기준치를 넘었는지 판정하고 필요하면 잠급니다.",
                    then=[call("detector.is_suspicious", "수상한가? 판정", "최근 실패 횟수를 보고 판정만 합니다.", later="5단원"),
                          call("soar.enforce_lockout", "IP 잠금 집행", "판정 결과대로 실제로 잠급니다.", later="10단원")])])
s3.step("④ 새 주소로 확인 링크 발송", "바로 바꾸지 않고 새 주소로 확인 링크만 보냅니다. 링크를 눌러야 변경되고, 바뀌면 기존 주소로 알림이 갑니다.",
        fn="member.member_email_change_submit", hl=("result = email_verification.request_email_change", "return redirect(url_for(\"member.member_profile\"))"),
        calls=[call("email_verification.request_email_change", "이메일 변경 요청", "확인 링크를 만들어 새 주소로 보냅니다.", later="23단원")])
s3.step("⑤ 비밀번호 변경: 새 비밀번호 규칙", "새 비밀번호 길이·확인칸 일치·'현재와 같은지'를 봅니다. 이건 입력 실수라서 실패 횟수에 넣지 않습니다.",
        fn="member.member_password_submit", hl=("if len(new_password) < config.MIN_PASSWORD_LENGTH", "새 비밀번호가 현재 비밀번호와 같습니다."),
        reject="규칙에 맞는 안내 문구와 함께 프로필 화면으로")
s3.step("⑥ 비밀번호 변경: 저장 + 다른 기기 로그아웃", "현재 비밀번호를 확인한 뒤 새 비밀번호를 저장합니다. 이때 세션 세대 번호가 올라가 다른 기기의 로그인이 모두 끊기고(이 기기는 유지), 본인에게 알림 메일이 갑니다.",
        fn="member.member_password_submit", hl=('session["session_version"] = db.update_user_password', "다른 기기의 로그인은 모두 해제되었습니다."),
        calls=[call("db.update_user_password", "비밀번호 저장 + 세대 번호 증가", "새 비밀번호를 해시로 저장하고 세션 세대 번호를 1 올립니다."),
               call("notify/mailer.py:send_password_changed_notice", "변경 알림 메일", "'비밀번호가 바뀌었습니다' 알림을 계정 이메일로 보냅니다.", later="18단원")])

SCENARIOS = [s1.build(), s2.build(), s3.build()]
