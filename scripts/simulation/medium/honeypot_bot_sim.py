# ============================================================================
# honeypot_bot_sim.py — 폼의 모든 칸을 기계적으로 채우는 "봇"을 흉내 내서, 허니팟(BOT_DETECTED)이
# 걸러내는지 확인하는 검증 스크립트 (Tier 3)
#
# 허니팟이란? 로그인·가입·글쓰기 폼에 CSS로 화면에서 안 보이게 숨겨둔 입력칸("website")이다. 사람은 보이지
# 않으니 항상 비워 두지만, 폼의 모든 칸을 채우는 자동화 스크립트는 이 칸까지 채운다. 값이 들어 있으면 서버는
# 자격 증명을 확인하거나 실패 횟수에 넣지도 않고 곧바로 거절하며 BOT_DETECTED(MEDIUM) 이벤트로 남긴다.
#
# 동작 요약:
#   1) 가짜 IP 하나로 /login에 허니팟 칸을 채운 폼을 --login-attempts번(기본 8번) 제출한다.
#      진짜 틀린 비밀번호였다면 6번째에 IP가 잠겼겠지만, 허니팟이 먼저 걸러내면 실패로 세지 않으므로
#      8번을 보내도 잠금 문구가 한 번도 나오지 않아야 한다.
#   2) 같은 방식으로 /signup에 --signup-attempts번(기본 3번) 제출한다. 허니팟에 걸리면 가입 한도를 쓰지 않고
#      "일시적인 오류가 발생했습니다" 안내만 돌려준다(이 문구는 허니팟에서만 나온다).
#   3) 두 조건이 모두 맞으면 성공.
#
# 안전 원칙: 로컬 서버만 대상. 실제 계정이 만들어지거나 로그인되지 않는다(전부 거절). 가짜 IP는 서버의
# TRUST_FORWARDED_FOR=true일 때만 반영된다.
# ============================================================================

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import (  # noqa: E402
    LOCK_MESSAGE, fetch_csrf, new_session, post_form, random_test_ip, require_local_or_exit,
)

HONEYPOT_FIELD = "website"
SIGNUP_BOT_MESSAGE = "일시적인 오류가 발생했습니다"


def run(base_url: str, login_attempts: int, signup_attempts: int, ip: str) -> bool:
    session = new_session(ip)
    ok = True

    token = fetch_csrf(session, base_url, "/login")
    print(f"[*] POST {base_url}/login | 가짜 IP {ip} | 허니팟 칸을 채운 제출 {login_attempts}회")
    locked = False
    for i in range(1, login_attempts + 1):
        response = post_form(session, base_url, "/login",
                             {"username": "bot-user", "password": "bot-password", HONEYPOT_FIELD: "http://spam.example"},
                             token)
        locked = locked or LOCK_MESSAGE in response.text
        print(f"    제출 {i}/{login_attempts} | 상태 {response.status_code}")
    if locked:
        print("[FAIL] 허니팟 제출이 로그인 실패로 집계되어 잠금이 걸렸습니다. 허니팟이 먼저 걸러내지 못했습니다.")
        ok = False
    else:
        print("[OK] 잠금 문구가 한 번도 나오지 않았습니다. 허니팟 제출은 실패 횟수로 세지 않고 걸러졌습니다.")

    token = fetch_csrf(session, base_url, "/signup")
    print(f"[*] POST {base_url}/signup | 허니팟 칸을 채운 제출 {signup_attempts}회")
    caught = 0
    for i in range(1, signup_attempts + 1):
        response = post_form(session, base_url, "/signup",
                             {"username": f"bot{i}", "password": "Bot-password-1!", "password_confirm": "Bot-password-1!",
                              "email": f"bot{i}@example.com", HONEYPOT_FIELD: "http://spam.example"}, token)
        caught += SIGNUP_BOT_MESSAGE in response.text
        print(f"    제출 {i}/{signup_attempts} | 상태 {response.status_code}"
              f"{' | 허니팟 거절 문구 확인' if SIGNUP_BOT_MESSAGE in response.text else ''}")
    if caught == signup_attempts:
        print("[OK] 가입 폼 제출이 전부 허니팟 거절 문구로 돌아왔습니다.")
    else:
        print(f"[FAIL] 허니팟 거절 문구가 {caught}/{signup_attempts}회만 나왔습니다.")
        ok = False

    if ok:
        print("  확인 위치: 대시보드 security_events의 event_type=BOT_DETECTED, severity=MEDIUM")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description="허니팟(BOT_DETECTED) 봇 탐지 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--login-attempts", type=int, default=8, help="/login 제출 횟수 (기본 8, IP 잠금 기준 5를 넘겨야 의미 있음)")
    parser.add_argument("--signup-attempts", type=int, default=3, help="/signup 제출 횟수 (기본 3, 가입 한도 5 미만)")
    parser.add_argument("--ip", default=None, help="가짜 공격자 IP (생략하면 문서용 대역에서 무작위)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    ok = run(args.host.rstrip("/"), args.login_attempts, args.signup_attempts, args.ip or random_test_ip())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
