# ============================================================================
# 1단원 — 인증 (회원가입 / 로그인) 흐름도 명세
#
# 노드(상자) 한 칸 = 화면에서 클릭 가능한 한 장의 카드.
#   col : 0 화면·도착지 / 1 routes(입구) / 2 판단(security·helpers·services) / 3 db(저장소)·config(설정값)
#   row : 위에서 아래로 실행되는 순서
#   items : 이 카드를 누르면 오른쪽에 보여줄 실제 코드
#     {"ref": "db.create_user"}                 → db/__init__.py 가 다시 내보낸 이름을 실제 파일로 풀어서 함수 전체를 보여줌
#     {"ref": "routes/auth.py:login_submit", "hl": ("시작 문구", "끝 문구")}  → 함수 전체 + 이 카드가 담당하는 줄을 강조
#     {"snippet": "templates/x.html", "from": "...", "to": "..."}  → 파일 일부분
#   hl 는 줄 번호가 아니라 "그 줄에 들어있는 문구"로 지정한다(코드가 밀려도 안 어긋남).
# ============================================================================

SLUG = "01-auth"
TITLE = "1. 인증 (회원가입 / 로그인)"
SUBTITLE = "회원가입과 로그인 요청이 어떤 파일의 어떤 함수를 거쳐 가는지 한눈에 보는 코드 흐름도"

COLUMNS = ["화면 · 도착지", "routes/ (입구)", "판단 (security · helpers)", "db/ · config.py (저장소 · 설정값)"]

FILE_ROLES = {
    "templates/signup.html": "회원가입 화면. 아이디·이메일·비밀번호 입력칸과 '가입하기' 버튼이 있다.",
    "templates/login_form.html": "로그인 화면. 회원 로그인과 관리자 로그인이 같은 화면 틀을 같이 쓴다.",
    "routes/auth.py": "회원가입(/signup)과 로그인(/login) 요청을 받아 처리 순서를 지휘하는 '입구' 파일.",
    "routes/member.py": "로그인한 회원이 보는 화면(대시보드·프로필 등)의 입구. (2단원에서 자세히)",
    "helpers/request_utils.py": "요청에서 IP 주소를 알아내거나 봇 함정(허니팟)을 확인하는 공용 도구.",
    "security/detector.py": "'수상한가?'를 판정만 하는 판사 역할 파일. 조치는 하지 않는다. (5·6단원에서 자세히)",
    "security/soar/lockouts.py": "판정 결과를 받아 IP·계정을 실제로 잠그거나 푸는 집행관 파일. (10단원)",
    "security/soar/observe.py": "잠그지 않고 알림·기록만 남기는 집행관 파일. (10단원)",
    "security/soar/early_warning.py": "기준치 코앞일 때 AI에게 조기 경보 여부를 묻는 파일. (11단원)",
    "services/email_verification.py": "가입 이메일로 인증 링크를 보내는 파일. (23단원)",
    "db/settings.py": "앱 설정값(회원가입 허용 여부)과 가입 시도 기록·집계를 다루는 저장소 파일.",
    "db/lockouts.py": "IP 잠금 현재 상태를 읽고 쓰는 저장소 파일.",
    "db/account_lockouts.py": "계정 단위 잠금 상태를 읽고 쓰는 저장소 파일.",
    "db/users.py": "회원(users 표) 가입·조회·비밀번호 확인을 담당하는 저장소 파일.",
    "db/attempts.py": "로그인 시도(login_attempts 표)를 기록·집계하는 저장소 파일.",
    "config.py": "아이디·이메일·비밀번호 규칙, 임계값 등 프로젝트 공용 설정값 모음.",
}

SIGNUP_FN = "routes/auth.py:signup_submit"
LOGIN_FN = "routes/auth.py:login_submit"
RET_TRUE = 'return render_template("signup.html", signup_enabled=True)'

SCENARIOS = [
    # ------------------------------------------------------------------ 회원가입
    {
        "id": "signup",
        "name": "회원가입",
        "intro": "사용자가 '가입하기'를 누르면 서버는 아래 순서로 검문한 뒤에야 계정을 저장합니다. 위에서 아래로 따라가 보세요. "
                 "카드를 누르면 실제 코드가 오른쪽에 열립니다.",
        "steps": ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"],
        "nodes": [
            {"id": "s0", "col": 0, "row": 0, "kind": "screen", "title": "가입 폼 제출",
             "plain": "아이디·이메일·비밀번호를 적고 '가입하기'를 누르면 /signup 주소로 POST 요청이 전송됩니다.",
             "items": [{"snippet": "templates/signup.html", "from": "<form method=\"post\"", "to": "</form>",
                        "label": "signup.html 폼", "hl": ("<form method=\"post\"", "<button type=\"submit\">가입하기")}]},

            {"id": "s1", "col": 1, "row": 1, "kind": "route", "title": "① 가입 접수가 열려 있나?",
             "plain": "관리자가 가입을 꺼둔 상태인지 서버에서 한 번 더 확인합니다(화면만 숨기면 직접 요청으로 뚫릴 수 있어서).",
             "reject": "현재 회원가입이 잠시 중단되어 있습니다.",
             "items": [{"ref": SIGNUP_FN, "hl": ("if not db.get_signup_enabled()", 'signup_enabled=False)')}]},
            {"id": "s1d", "col": 3, "row": 1, "kind": "db", "title": "가입 허용 여부 읽기",
             "plain": "app_settings 표에서 '가입 허용' 값을 읽어옵니다.",
             "items": [{"ref": "db.get_signup_enabled"}]},

            {"id": "s2", "col": 1, "row": 2, "kind": "route", "title": "② 사람이 맞나? (허니팟 함정)",
             "plain": "사람 눈에는 안 보이는 숨은 입력칸이 채워져 있으면 자동 프로그램(봇)으로 보고 바로 돌려보냅니다.",
             "reject": "일시적인 오류가 발생했습니다. 다시 시도해주세요.",
             "items": [{"ref": SIGNUP_FN, "hl": ("# 허니팟 필드가 채워져", RET_TRUE)}]},
            {"id": "s2h", "col": 2, "row": 2, "kind": "helper", "title": "봇 여부 확인",
             "plain": "숨은 입력칸(website)에 값이 들어 있는지만 봅니다.",
             "items": [{"ref": "helpers.is_bot_submission"}]},
            {"id": "s2n", "col": 2, "row": 2, "kind": "later", "title": "봇 감지 알림", "later": "10단원",
             "plain": "관리자에게 알림만 보내고 기록합니다.",
             "items": [{"ref": "soar.notify_bot_detected"}]},

            {"id": "s3", "col": 1, "row": 3, "kind": "route", "title": "③ 영구 차단된 네트워크인가?",
             "plain": "영구 잠금된 IP는 가입도 막습니다. 새 계정을 만들어 예외를 받아내는 우회로를 막기 위해서입니다.",
             "reject": "현재 이 네트워크에서는 회원가입을 할 수 없습니다.",
             "items": [{"ref": SIGNUP_FN, "hl": ("# 영구 잠금된 IP는 가입도", RET_TRUE)}]},
            {"id": "s3d", "col": 2, "row": 3, "kind": "later", "title": "IP 잠금 상태 판정", "later": "16단원",
             "plain": "NONE / TEMPORARY / PERMANENT 중 하나로 알려줍니다.",
             "items": [{"ref": "detector.get_ip_lock_state"}]},
            {"id": "s3b", "col": 3, "row": 3, "kind": "db", "title": "IP 잠금 기록 조회",
             "plain": "lockouts 표에서 지금 유효한 잠금이 있는지 찾습니다.",
             "items": [{"ref": "db.get_active_lockout"}]},

            {"id": "s4", "col": 1, "row": 4, "kind": "route", "title": "④ 너무 빨리, 많이 가입하나?",
             "plain": "같은 IP가 1분 안에 5번 이상 시도하면 막습니다. 기준치 코앞이면 AI 조기 경보도 판단합니다(11단원).",
             "reject": "너무 많은 가입 시도가 감지되었습니다.",
             "items": [{"ref": SIGNUP_FN, "hl": ("rate_limited, signup_count = detector", "if rate_limited:")}]},
            {"id": "s4d", "col": 2, "row": 4, "kind": "helper", "title": "가입 도배 판정",
             "plain": "최근 시도 횟수가 기준치 이상인지 True/False로 답합니다.",
             "items": [{"ref": "detector.is_signup_rate_limited"}]},
            {"id": "s4b", "col": 3, "row": 4, "kind": "db", "title": "최근 가입 시도 횟수 세기",
             "plain": "signup_attempts 표에서 이 IP의 최근 60초 시도 수를 셉니다.",
             "items": [{"ref": "db.count_recent_signup_attempts"}]},

            {"id": "s5", "col": 1, "row": 5, "kind": "route", "title": "⑤ 이번 시도 기록하기",
             "plain": "성공·실패와 상관없이 '가입을 시도했다'는 사실을 한 줄 남깁니다. 위 ④의 횟수가 여기서 쌓입니다.",
             "items": [{"ref": SIGNUP_FN, "hl": "db.log_signup_attempt(ip)"}]},
            {"id": "s5b", "col": 3, "row": 5, "kind": "db", "title": "가입 시도 한 줄 저장",
             "plain": "signup_attempts 표에 IP를 새 줄로 추가합니다.",
             "items": [{"ref": "db.log_signup_attempt"}]},

            {"id": "s6", "col": 1, "row": 6, "kind": "route", "title": "⑥ 입력값 규칙 검사",
             "plain": "빈칸·아이디 모양(영문/숫자/_ 3~20자)·이메일 모양·비밀번호 8자 이상·비밀번호 확인 일치를 차례로 확인합니다.",
             "reject": "규칙에 어긋난 항목마다 안내 문구를 보여주고 다시 입력 화면으로.",
             "items": [{"ref": SIGNUP_FN, "hl": ('username = request.form.get("username"', '비밀번호와 비밀번호 확인이 일치하지 않습니다')}]},
            {"id": "s6c", "col": 3, "row": 6, "kind": "config", "title": "규칙값 모음",
             "plain": "허용하는 아이디·이메일 모양과 최소 비밀번호 길이가 정의된 곳입니다.",
             "items": [{"snippet": "config.py", "from": "USERNAME_PATTERN =", "to": "EMAIL_PATTERN =",
                        "label": "config.py 규칙값", "hl": ("USERNAME_PATTERN =", "EMAIL_PATTERN =")}]},

            {"id": "s7", "col": 1, "row": 7, "kind": "route", "title": "⑦ 계정 저장",
             "plain": "아이디·이메일이 이미 쓰이는지 보고, 없으면 비밀번호를 해시(복원 불가능한 암호문)로 바꿔 저장합니다.",
             "reject": "이미 사용 중인 아이디 또는 이메일입니다.",
             "items": [{"ref": SIGNUP_FN, "hl": ("created = db.create_user", "이미 사용 중인 아이디 또는 이메일입니다")}]},
            {"id": "s7d", "col": 3, "row": 7, "kind": "db", "title": "회원 행 만들기",
             "plain": "중복 확인 → generate_password_hash 로 암호화 → users 표에 저장.",
             "items": [{"ref": "db.create_user", "hl": ("# 3) 문제 없으면", ".execute()")}]},

            {"id": "s8", "col": 1, "row": 8, "kind": "route", "title": "⑧ 인증 메일 보내고 로그인 화면으로",
             "plain": "가입 이메일로 인증 링크를 보냅니다. 메일이 실패해도 가입은 유지하고, /login 으로 이동시킵니다.",
             "items": [{"ref": SIGNUP_FN, "hl": ("# 가입 이메일로 인증 링크를", 'return redirect(url_for("auth.login"))')}]},
            {"id": "s8m", "col": 2, "row": 8, "kind": "later", "title": "인증 메일 발송", "later": "23단원",
             "plain": "인증 토큰을 만들어 메일로 보냅니다.",
             "items": [{"ref": "email_verification.send_verification"}]},
            {"id": "s8l", "col": 0, "row": 8, "kind": "screen", "title": "로그인 화면으로 이동",
             "plain": "가입 완료 후 /login 화면이 열립니다.",
             "items": [{"ref": "auth.login"}]},
        ],
        "edges": [
            ("s0", "s1", "POST /signup"),
            ("s1", "s1d", "db.get_signup_enabled()", "call"),
            ("s1", "s2"),
            ("s2", "s2h", "is_bot_submission()", "call"),
            ("s2", "s2n", "soar.notify_bot_detected()", "call"),
            ("s2", "s3"),
            ("s3", "s3d", "detector.get_ip_lock_state()", "call"),
            ("s3d", "s3b", "db.get_active_lockout()", "call"),
            ("s3", "s4"),
            ("s4", "s4d", "detector.is_signup_rate_limited()", "call"),
            ("s4d", "s4b", "db.count_recent_signup_attempts()", "call"),
            ("s4", "s5"),
            ("s5", "s5b", "db.log_signup_attempt()", "call"),
            ("s5", "s6"),
            ("s6", "s6c", "config.USERNAME_PATTERN 등", "call"),
            ("s6", "s7"),
            ("s7", "s7d", "db.create_user()", "call"),
            ("s7", "s8"),
            ("s8", "s8m", "send_verification()", "call"),
            ("s8", "s8l", "redirect", "call"),
        ],
    },

    # ------------------------------------------------------------------ 로그인
    {
        "id": "login",
        "name": "로그인",
        "intro": "로그인은 '비밀번호가 맞나?'를 보기 전에 먼저 잠금·봇 여부를 검문합니다. 확인 뒤에는 성공·실패를 반드시 기록하고, "
                 "실패하면 이 기록을 바탕으로 '수상한가?' 판정이 이어집니다(5단원).",
        "steps": ["l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8", "l9"],
        "nodes": [
            {"id": "l0", "col": 0, "row": 0, "kind": "screen", "title": "로그인 폼 제출",
             "plain": "아이디·비밀번호를 적고 '로그인'을 누르면 /login 주소로 POST 요청이 전송됩니다.",
             "items": [{"snippet": "templates/login_form.html", "from": "<form method=\"post\"", "to": "</form>",
                        "label": "login_form.html 폼", "hl": ("<form method=\"post\"", "<button type=\"submit\">로그인")}]},

            {"id": "l1", "col": 1, "row": 1, "kind": "route", "title": "① 만료된 잠금 먼저 청소",
             "plain": "시간이 지나 풀려야 할 IP 잠금·계정 잠금을 로그인 처리 전에 정리합니다.",
             "items": [{"ref": LOGIN_FN, "hl": ("soar.try_release_expired_lockouts()", "soar.try_release_expired_account_lockouts()")}]},
            {"id": "l1s", "col": 2, "row": 1, "kind": "later", "title": "만료 잠금 자동 해제", "later": "10단원",
             "plain": "5분이 지난 잠금을 풀어줍니다.",
             "items": [{"ref": "soar.try_release_expired_lockouts"}, {"ref": "soar.try_release_expired_account_lockouts"}]},

            {"id": "l2", "col": 1, "row": 2, "kind": "route", "title": "② 사람이 맞나? (허니팟 함정)",
             "plain": "회원가입과 같은 숨은 입력칸 검사입니다. 채워져 있으면 비밀번호 확인도 기록도 없이 거부합니다.",
             "reject": "아이디 또는 비밀번호가 올바르지 않습니다. (일부러 같은 문구)",
             "items": [{"ref": LOGIN_FN, "hl": ("# 허니팟 필드가 채워져", 'return render_template("login_form.html"')}]},
            {"id": "l2h", "col": 2, "row": 2, "kind": "helper", "title": "봇 여부 확인",
             "plain": "숨은 입력칸(website)에 값이 있는지 봅니다.",
             "items": [{"ref": "helpers.is_bot_submission"}]},
            {"id": "l2n", "col": 2, "row": 2, "kind": "later", "title": "봇 감지 알림", "later": "10단원",
             "plain": "알림과 기록만 남깁니다.",
             "items": [{"ref": "soar.notify_bot_detected"}]},

            {"id": "l3", "col": 1, "row": 3, "kind": "route", "title": "③ 이 IP가 잠겨 있나?",
             "plain": "잠긴 IP는 비밀번호를 보지도 않고 거부합니다. 영구 잠금 IP는 이메일 복구로 예외를 받은 '본인 + 본인 기기'만 통과합니다.",
             "reject": "잠긴 계정입니다. 잠시 후 다시 시도해주세요.",
             "items": [{"ref": LOGIN_FN, "hl": ("exemption = None", "# 예외가 있으면 IP 잠금 안내 없이")}]},
            {"id": "l3d", "col": 2, "row": 3, "kind": "helper", "title": "IP 잠금 여부 판정",
             "plain": "잠금 기록이 있는지(True/False)와 임시·영구 구분을 알려줍니다.",
             "items": [{"ref": "detector.is_locked"}, {"ref": "detector.get_ip_lock_state"}]},
            {"id": "l3b", "col": 3, "row": 3, "kind": "db", "title": "IP 잠금 기록 조회",
             "plain": "lockouts 표에서 지금 유효한 잠금 한 줄을 찾습니다.",
             "items": [{"ref": "db.get_active_lockout"}]},

            {"id": "l4", "col": 1, "row": 4, "kind": "route", "title": "④ 이 계정이 잠겨 있나?",
             "plain": "여러 IP가 나눠서 한 계정을 공격하는 경우를 대비한 '계정 단위' 잠금 확인입니다.",
             "reject": "잠긴 계정입니다. … '본인 인증으로 잠금 해제' 안내",
             "items": [{"ref": LOGIN_FN, "hl": ("if detector.is_account_locked(username)", "return _login_form(recovery_link=True)")}]},
            {"id": "l4d", "col": 2, "row": 4, "kind": "helper", "title": "계정 잠금 여부 판정",
             "plain": "잠금 기록이 있으면 True.",
             "items": [{"ref": "detector.is_account_locked"}]},
            {"id": "l4b", "col": 3, "row": 4, "kind": "db", "title": "계정 잠금 기록 조회",
             "plain": "account_lockouts 표에서 유효한 잠금을 찾습니다.",
             "items": [{"ref": "db.get_active_account_lockout"}]},

            {"id": "l5", "col": 1, "row": 5, "kind": "route", "title": "⑤ 아이디·비밀번호 확인",
             "plain": "저장된 해시와 입력한 비밀번호를 비교합니다. 아이디가 없어도 같은 시간이 걸리도록 '더미 해시'와 비교합니다.",
             "items": [{"ref": LOGIN_FN, "hl": "success = db.verify_user_credentials"}]},
            {"id": "l5d", "col": 3, "row": 5, "kind": "db", "title": "자격 증명 확인",
             "plain": "users 표에서 아이디로 회원을 찾고 check_password_hash 로 비교합니다.",
             "items": [{"ref": "db.verify_user_credentials"}, {"ref": "db.get_user_by_username"}]},

            {"id": "l6", "col": 1, "row": 6, "kind": "route", "title": "⑥ 시도 기록 남기기 (성공·실패 모두)",
             "plain": "CCTV처럼 누가 어떤 IP에서 시도했는지를 항상 한 줄 남깁니다. 탐지(5단원)는 이 기록을 보고 동작합니다.",
             "items": [{"ref": LOGIN_FN, "hl": "db.log_attempt(ip, username, success)"}]},
            {"id": "l6b", "col": 3, "row": 6, "kind": "db", "title": "로그인 시도 한 줄 저장",
             "plain": "login_attempts 표에 IP·아이디·성공 여부를 추가합니다.",
             "items": [{"ref": "db.log_attempt"}]},

            {"id": "l7", "col": 1, "row": 7, "kind": "route", "title": "⑦ 성공했나?",
             "plain": "⑤의 결과로 길이 둘로 갈라집니다.",
             "items": [{"ref": LOGIN_FN, "hl": "if success:"}]},

            {"id": "l8", "col": 1, "row": 8, "kind": "route", "title": "✅ 성공 → 세션 만들고 대시보드로",
             "plain": "브라우저에 '로그인된 상태'를 기억시키는 세션을 만들고 회원 대시보드로 보냅니다. 관리자 세션과는 다른 키를 씁니다.",
             "items": [{"ref": LOGIN_FN, "hl": ("user = db.get_user_by_username(username)", 'return redirect(url_for("member.member_dashboard"))')}]},
            {"id": "l8d", "col": 3, "row": 8, "kind": "db", "title": "회원 정보 조회",
             "plain": "세션에 담을 회원 번호(id)와 세션 세대 번호를 읽어옵니다.",
             "items": [{"ref": "db.get_user_by_username"}]},
            {"id": "l8m", "col": 0, "row": 8, "kind": "later", "title": "회원 대시보드", "later": "2단원",
             "plain": "로그인한 회원의 첫 화면.",
             "items": [{"ref": "member.member_dashboard"}]},

            {"id": "l9", "col": 1, "row": 9, "kind": "route", "title": "❌ 실패 → 같은 문구 + 위험 판정",
             "plain": "'아이디 없음'과 '비밀번호 틀림'을 구분해 알려주면 공격자에게 힌트가 되므로 항상 같은 문구로 안내합니다. "
                      "이어서 이 IP·계정의 실패가 기준치를 넘었는지 판정하고 필요하면 잠급니다.",
             "reject": "아이디 또는 비밀번호가 올바르지 않습니다.",
             "items": [{"ref": LOGIN_FN, "hl": ("# 실패했다면, 먼저 이 IP가", 'flash("아이디 또는 비밀번호가 올바르지 않습니다.")')}]},
            {"id": "l9d", "col": 2, "row": 9, "kind": "later", "title": "수상한가? 판정", "later": "5단원",
             "plain": "최근 실패 횟수가 기준치를 넘었는지 판정만 합니다.",
             "items": [{"ref": "detector.is_suspicious"}, {"ref": "detector.is_account_suspicious"}]},
            {"id": "l9s", "col": 2, "row": 9, "kind": "later", "title": "IP·계정 잠금 집행", "later": "10단원",
             "plain": "판정 결과대로 실제로 잠그고 알림을 보냅니다.",
             "items": [{"ref": "soar.enforce_lockout"}, {"ref": "soar.enforce_account_lockout"}]},
            {"id": "l9e", "col": 2, "row": 9, "kind": "later", "title": "AI 조기 경보", "later": "11단원",
             "plain": "기준치 코앞이면 AI에게 조기 경보 여부를 묻습니다.",
             "items": [{"ref": "soar.consider_early_warning"}]},
        ],
        "edges": [
            ("l0", "l1", "POST /login"),
            ("l1", "l1s", "soar.try_release_expired_*()", "call"),
            ("l1", "l2"),
            ("l2", "l2h", "is_bot_submission()", "call"),
            ("l2", "l2n", "soar.notify_bot_detected()", "call"),
            ("l2", "l3"),
            ("l3", "l3d", "detector.is_locked()", "call"),
            ("l3d", "l3b", "db.get_active_lockout()", "call"),
            ("l3", "l4"),
            ("l4", "l4d", "detector.is_account_locked()", "call"),
            ("l4d", "l4b", "db.get_active_account_lockout()", "call"),
            ("l4", "l5"),
            ("l5", "l5d", "db.verify_user_credentials()", "call"),
            ("l5", "l6"),
            ("l6", "l6b", "db.log_attempt()", "call"),
            ("l6", "l7"),
            ("l7", "l8", "성공"),
            ("l7", "l9", "실패"),
            ("l8", "l8d", "db.get_user_by_username()", "call"),
            ("l8", "l8m", "redirect", "call"),
            ("l9", "l9d", "detector.is_suspicious() 등", "call"),
            ("l9", "l9s", "soar.enforce_*()", "call"),
            ("l9", "l9e", "soar.consider_early_warning()", "call"),
        ],
    },
]
