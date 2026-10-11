# 22단원 — 계정 존재 여부 노출 방지 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "22-account-enumeration"
TITLE = "22. 계정 존재 여부 노출 방지"
SUBTITLE = "화면 문구·응답 시간 차이로 '이 아이디가 가입돼 있다'가 새지 않게 막는 장치들의 코드 흐름도"

FILE_ROLES = {
    "routes/auth.py": "로그인 입구 파일. 계정 잠금 안내를 임시·영구 구분 없이 한 문구로 통일한다.",
    "routes/recovery.py": "복구 화면 입구 파일. 6자리 코드 경로의 실패 문구를 하나로 통일한다.",
    "db/recovery.py": "복구 요청 표 저장소. 아이디로 요청을 찾는 조회를 한 번의 inner join 으로 한다.",
    "helpers/device.py": "복구를 요청한 기기를 구분하는 쿠키·해시 도구.",
}

s1 = Scenario("msg", "잠금 안내 문구를 하나로",
              "공격자가 아이디 목록을 넣어 보며 응답 차이로 '가입된 아이디'를 알아내면, 가입된 아이디만 골라 비밀번호 대입이나 피싱을 할 수 있습니다. 영구 승격은 '가입된 아이디'에만 일어나서, '영구 잠금'이라는 문구 자체가 가입 여부를 알려주고 있었습니다.")
s1.screen("계정이 잠긴 아이디로 로그인", "임시 잠금이든 영구 잠금이든 같은 방식으로 처리합니다.",
          fn="routes/auth.py:login_submit", hl=("if detector.is_account_locked(username):", "return _login_form(recovery_link=True)"))
s1.step("① 임시·영구 구분 없이 같은 문구", "'영구 잠금'이라고 따로 알려주면 그 아이디가 실제로 가입돼 있다는 사실이 드러납니다. 그래서 모든 계정 잠금에 같은 문구를 씁니다.",
        snippet=("routes/auth.py", "ACCOUNT_LOCKED_MESSAGE = (", "re:^\\)"), label="ACCOUNT_LOCKED_MESSAGE",
        calls=[call("detector.is_account_locked", "계정 잠금 여부", "임시든 영구든 같은 함수로 같은 판정을 합니다.", later="5단원")])
s1.step("② 복구 링크도 항상 같이", "링크를 영구 잠금에만 보여주면 링크 유무로 다시 구분되므로, 모든 계정 잠금에 보여줍니다. 복구 화면은 원래 항상 같은 응답입니다.",
        fn="routes/auth.py:_login_form", hl="recovery_link=recovery_link")

s2 = Scenario("code", "6자리 코드는 요청한 기기에서만",
              "코드 화면의 '남은 시도 N회'가 '이 아이디에 진행 중인 복구가 있다(= 가입된 아이디)'를 알려주고 있었습니다. 복구 종류와 무관하게 '복구를 요청한 기기'에서만 코드를 받고, 그 외에는 모두 같은 문구로 답합니다.")
s2.screen("코드 입력 (POST /recovery/verify)", "아이디 + 6자리 코드를 보냅니다.",
          fn="routes/recovery.py:recovery_verify_submit", hl=("username = request.form.get(\"username\"", "code = request.form.get(\"code\""))
s2.step("① 아이디로 요청을 한 번에 찾는다", "예전에는 '아이디로 회원 조회 → 그 id 로 요청 조회' 두 번 왕복했습니다. 없는 아이디는 한 번에 끝나고 있는 아이디는 한 번 더 왕복해서 응답 시간 차이로 가입 여부가 드러났습니다. 이제 inner join 한 번이라 어느 쪽이든 한 번입니다.",
        fn="routes/recovery.py:recovery_verify_submit", hl=("req = (", "else None"),
        calls=[call("db.get_latest_pending_recovery_for_username", "users 와 inner join 으로 한 번에", "아이디로 가장 최근의 유효한 복구 요청을 찾습니다.",
                    hl=('.select("*, users!inner(username)")', '.eq("users.username", username)'))])
s2.step("② 없음 · 다른 기기 · 코드 틀림을 구분하지 않는다", "아이디 없음 / 진행 중인 요청 없음 / 요청한 기기가 아님을 같은 문구로 답하고 시도권도 쓰지 않습니다. 그래서 다른 기기에서는 ① 이 아이디에 복구가 진행 중인지 알 수 없고 ② 틀린 코드를 넣어 남의 복구 요청을 취소시킬 수도 없습니다.",
        fn="routes/recovery.py:recovery_verify_submit", hl=("if req is None or not _device_matches(req):", "CODE_GENERIC_FAILURE_MESSAGE)"), reject="아이디 또는 코드가 올바르지 않거나 만료되었습니다.",
        calls=[call("routes/recovery.py:_device_matches", "요청한 기기인가?", "기기 쿠키 해시를 타이밍 안전하게 비교합니다.")])
s2.step("③ 한계: 회원가입은 여전히 알려준다", "'이미 사용 중인 아이디 또는 이메일입니다'는 가입 여부를 알려줍니다. 가입은 IP 당 빈도 제한(1분 5회)으로 대량 조회를 막습니다. PC 에서 요청하고 휴대폰 브라우저에 코드를 넣으면 거절되고, 휴대폰에서는 메일 링크를 누르면 됩니다.",
        fn="routes/auth.py:signup_submit", hl=("created = db.create_user(username, email, password)", "이미 사용 중인 아이디 또는 이메일입니다."), reject="이미 사용 중인 아이디 또는 이메일입니다.")

SCENARIOS = [s1.build(), s2.build()]
