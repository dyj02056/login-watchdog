# 25단원 — 복구 요청 한도 + 처리 시간 기록 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "25-recovery-limit"
TITLE = "25. 복구 요청 한도 + 처리 시간 기록"
SUBTITLE = "'항상 같은 시간 뒤에 응답'하는 요청이 서버 함수를 오래 붙잡지 못하게 한도를 걸고, 실제 처리 시간을 기록하는 코드 흐름도"

FILE_ROLES = {
    "app.py": "Flask 앱 조립 파일. 복구 요청 등에 좁은 요청 한도(Flask-Limiter)를 따로 걸고, 초과는 429 로 처리한다.",
    "helpers/timing.py": "응답 시간 고정 도구. 처리 시간을 [timing] 로그로 남긴다.",
    "routes/recovery.py": "복구 요청 입구 파일. 고정 응답 시간 도구를 쓴다.",
    "routes/password.py": "비밀번호 찾기 입구 파일. 같은 도구를 쓴다.",
    "security/soar/observe.py": "한도 초과 요청을 HTTP_FLOOD(HIGH)로 기록한다.",
}

s1 = Scenario("limit", "복구 요청 한도",
              "복구 요청과 비밀번호 찾기 요청은 가입 여부가 응답 시간으로 드러나지 않게 '항상 고정 시간 뒤에' 응답합니다. 그동안 서버리스 함수 하나가 묶여 있는데, /recovery/request 에는 화면 단위 한도가 없어 IP 하나가 분당 120번 함수를 묶어 둘 수 있었습니다.")
s1.screen("POST /recovery/request", "한도를 넘긴 요청은 뷰 함수가 실행되기 전에 거절됩니다. 고정 대기 없이 바로 끝납니다.",
          snippet=("app.py", 'app.view_functions["recovery.recovery_request_submit"]', "re:^\\)\\(app.view_functions"), label="app.py 복구 요청 한도",
          calls=[call(snippet=("config.py", "RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE =", "RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE ="), title="복구 요청 한도 (분당 5회)", plain="IP 당 분당 횟수.", label="RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE")])
s1.step("① 한도를 넘으면 대기 없이 429", "Flask-Limiter 가 뷰 실행 전에 거절합니다. 같은 IP 가 계속 두드려도 함수가 5초씩 묶이지 않습니다.",
        fn="app.py:handle_rate_limit_exceeded", hl=("ip = get_request_ip()", "return error.get_response()"), reject="429 Too Many Requests",
        calls=[call("soar.record_rejection", "HTTP_FLOOD 로 기록 (HIGH)", "복구·이메일 확인·비밀번호 찾기의 좁은 한도도 같은 예외로 여기에 옵니다.", later="8단원")])
s1.step("② 한도 안이라면 고정 시간 안에서 처리", "빨리 끝나든 오래 걸리든 응답 시점은 같습니다(17단원).",
        fn="helpers/timing.py:run_with_fixed_response_time", hl=("target = config.RECOVERY_MIN_RESPONSE_SECONDS", "path = request.path if has_request_context() else \"-\""),
        calls=[call(snippet=("config.py", "RECOVERY_MIN_RESPONSE_SECONDS =", "RECOVERY_MIN_RESPONSE_SECONDS ="), title="고정 응답 시간 (5초)", plain="처음 8초였으나 운영 실측(메일 발송 3.04초)을 근거로 5초로 줄였습니다.", label="RECOVERY_MIN_RESPONSE_SECONDS")])

s2 = Scenario("timing", "처리 시간 기록 ([timing] 로그)",
              "고정 시간(처음 8초)에는 실측 근거가 없었습니다. 실제 처리 시간을 한 줄씩 기록해서 고정 시간을 실측으로 조정할 수 있게 했습니다. 아이디·IP 는 기록하지 않습니다.")
s2.screen("work() 실행 직후", "처리가 끝난 시점까지 걸린 시간을 잽니다.",
          fn="helpers/timing.py:run_with_fixed_response_time", hl="def run_with_fixed_response_time(work, started: float)")
s2.step("① 처리 시간을 한 줄로 기록", "'[timing] /recovery/request work=0.61s target=5.0s' 형태입니다. 처리가 고정 시간을 넘기면 그 요청만 응답이 늦어져 계정 존재 여부가 드러날 수 있으므로 'overrun' 을 붙입니다.",
        fn="helpers/timing.py:_log_timing", hl=('overrun = " overrun" if work_seconds > target else ""', 'print(f"[timing]'))
s2.step("② 남은 시간만큼 기다렸다가 응답", "기본은 요청 안에서 처리(메일 발송 포함)를 끝낸 뒤 남은 시간만 기다립니다. 서버리스는 응답을 보내는 순간 함수를 멈추기 때문에, 메일 발송을 응답 뒤로 미루면 끝나기 전에 끊길 수 있습니다.",
        fn="helpers/timing.py:run_with_fixed_response_time", hl=("if target <= 0:", "return"))
s2.step("③ overrun 이 자주 보이면", "환경변수 RECOVERY_MIN_RESPONSE_SECONDS 를 6~8 로 올립니다(코드 수정 불필요).",
        fn="helpers/timing.py:_log_timing", hl="def _log_timing(path: str, work_seconds: float, target: float)")

SCENARIOS = [s1.build(), s2.build()]
