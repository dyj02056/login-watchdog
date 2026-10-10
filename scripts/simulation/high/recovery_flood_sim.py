# ============================================================================
# recovery_flood_sim.py — 복구·비밀번호 찾기·이메일 확인 같은 "메일을 보내거나 코드를 확인하는" 엔드포인트를
# 짧은 시간에 두드려 폭주시키는 공격을 흉내 내서, 엔드포인트별 좁은 요청 한도(429)가 걸리는지 확인하는 검증
# 스크립트 (guide37 / guide40 / guide41 / guide43)
#
# 이 엔드포인트들은 전역 한도(분당 120회)보다 훨씬 좁은 한도를 따로 가진다. 복구 요청은 응답마다 고정 시간
# 함수를 붙잡고, 이메일·비밀번호 재설정은 남의 주소로 메일을 계속 보내게 만드는 "메일 폭탄"에 쓰일 수 있어서다.
# 한도를 넘기면 429로 거절하고 HTTP_FLOOD(HIGH) 이벤트로 남긴다.
#
#   --target recovery        POST /recovery/request   분당 5회  (RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE)
#   --target recovery-verify POST /recovery/verify    분당 10회 (RECOVERY_VERIFY_RATE_LIMIT_PER_MINUTE)
#   --target password-forgot POST /password/forgot    분당 10회 (PASSWORD_RESET_RATE_LIMIT_PER_MINUTE)
#   --target password-reset  POST /password/reset     분당 10회 (PASSWORD_RESET_RATE_LIMIT_PER_MINUTE)
#   --target email-confirm   POST /email/confirm      분당 10회 (EMAIL_CONFIRM_RATE_LIMIT_PER_MINUTE)
#
# 동작 요약:
#   1) 가짜 IP 하나로 선택한 엔드포인트에 폼을 --attempts번(기본: 한도 + 3번) 연속 제출한다.
#   2) 한도를 넘은 요청이 429로 거절되면 성공. 처음 429가 나온 번째를 보여준다.
#
# 안전 원칙: 로컬 서버만 대상. 존재하지 않는 아이디/가짜 토큰만 보내므로 실제로 메일이 나가거나 계정이 바뀌지
# 않는다(429 이전의 일반 응답도 "처리했다"는 고정 문구만 돌려준다). 가짜 IP는 TRUST_FORWARDED_FOR=true일 때만 반영된다.
# ============================================================================

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import fetch_csrf, new_session, post_form, random_test_ip, require_local_or_exit  # noqa: E402

# 대상 이름 → (제출 경로, 기본 한도, 보낼 폼)
TARGETS = {
    "recovery": ("/recovery/request", 5, {"username": "no-such-user-sim"}),
    "recovery-verify": ("/recovery/verify", 10, {"token": "fake-token", "code": "000000"}),
    "password-forgot": ("/password/forgot", 10, {"username": "no-such-user-sim"}),
    "password-reset": ("/password/reset", 10, {"token": "fake-token", "password": "Aa1!aaaaaaaa", "password_confirm": "Aa1!aaaaaaaa"}),
    "email-confirm": ("/email/confirm", 10, {"token": "fake-token"}),
}


def run(base_url: str, target: str, attempts: int | None, ip: str) -> bool:
    path, limit, form = TARGETS[target]
    attempts = attempts or limit + 3
    session = new_session(ip)
    token = fetch_csrf(session, base_url, "/login")  # CSRF 토큰은 세션에 묶여 있어 아무 폼 화면에서 받아도 된다
    print(f"[*] POST {base_url}{path} | 가짜 IP {ip} | {attempts}회 연속 제출 (한도 분당 {limit}회)")
    statuses = []
    for i in range(1, attempts + 1):
        response = post_form(session, base_url, path, dict(form), token, referer_path="/login")
        statuses.append(response.status_code)
        print(f"    요청 {i:>2}/{attempts} | 상태 {response.status_code}{' | 한도 초과' if response.status_code == 429 else ''}")

    blocked = statuses.count(429)
    if blocked:
        print(f"[OK] {statuses.index(429) + 1}번째 요청부터 429로 거절됐습니다. 좁은 요청 한도가 정상 동작합니다.")
        print("  확인 위치: 대시보드 security_events의 event_type=HTTP_FLOOD, severity=HIGH")
        return True
    print("[FAIL] 429가 한 번도 나오지 않았습니다. --attempts가 한도보다 적었거나 한도가 꺼져 있습니다.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="복구/비밀번호 찾기/이메일 확인 요청 폭주(좁은 요청 한도) 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--target", choices=sorted(TARGETS), default="recovery", help="두드릴 엔드포인트 (기본 recovery)")
    parser.add_argument("--attempts", type=int, default=None, help="제출 횟수 (생략하면 해당 한도 + 3)")
    parser.add_argument("--ip", default=None, help="가짜 공격자 IP (생략하면 문서용 대역에서 무작위)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    ok = run(args.host.rstrip("/"), args.target, args.attempts, args.ip or random_test_ip())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
