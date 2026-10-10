# ============================================================================
# admin_bruteforce_sim.py — 관리자 로그인(/admin/login)에 대한 브루트포스(ADMIN_BRUTE_FORCE)를
# 흉내 내서, IP 잠금이 걸리는지 확인하는 검증 스크립트
#
# 관리자 계정이 뚫리면 회원 삭제·잠금 해제 등 전부 장악당하므로 /admin/login도 /login과 같은 IP 잠금
# (60초 안에 5회 "초과" 실패 → 잠금)을 적용한다. 영구 잠금까지 올라가면 이메일 복구 없이 관리자만 풀 수 있다.
#
# 동작 요약:
#   1) 가짜 IP 하나로 /admin/login에 틀린 비밀번호를 --attempts번(기본 6번) 연속 제출한다.
#   2) 잠금이 걸렸다면 그다음 시도(--attempts + 1번째)는 비밀번호 확인도 없이 잠금 문구로 거절된다 → 성공.
#
# 안전 원칙: 로컬 서버만 대상으로 한다. 이 시뮬레이션이 잠그는 것은 가짜 IP뿐이라 관리자 본인은 영향이 없다
# (서버의 TRUST_FORWARDED_FOR=true일 때). 꺼져 있으면 실제 접속 IP가 잠기니, 그때는 unlock_ip.py로 풀어야 한다.
# ============================================================================

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import (  # noqa: E402
    LOCK_MESSAGE, fetch_csrf, new_session, post_form, random_test_ip, require_local_or_exit,
)

LOGIN_PATH = "/admin/login"


def run(base_url: str, username: str, attempts: int, ip: str) -> bool:
    session = new_session(ip)
    token = fetch_csrf(session, base_url, LOGIN_PATH)
    print(f"[*] {base_url}{LOGIN_PATH} | 아이디 '{username}' | 가짜 IP {ip} | 틀린 비밀번호 {attempts}회")
    for i in range(1, attempts + 1):
        response = post_form(session, base_url, LOGIN_PATH,
                             {"username": username, "password": "wrong-password-on-purpose"}, token)
        print(f"    시도 {i}/{attempts} | 상태 {response.status_code}"
              f"{' | 잠금 문구 확인' if LOCK_MESSAGE in response.text else ''}")

    response = post_form(session, base_url, LOGIN_PATH,
                         {"username": username, "password": "wrong-password-on-purpose"}, token)
    print(f"[*] 확인 시도 {attempts + 1}회째 | 상태 {response.status_code}")
    if LOCK_MESSAGE in response.text:
        print("[OK] 관리자 로그인 IP 잠금이 정상 동작합니다.")
        print("  확인 위치: 대시보드 security_events의 event_type=ADMIN_BRUTE_FORCE, severity=CRITICAL")
        return True
    print("[FAIL] 잠금 문구를 찾지 못했습니다. 관리자 로그인 잠금이 걸리지 않았습니다.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="관리자 로그인 브루트포스(IP 잠금) 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--username", default="admin-target", help="시도할 관리자 아이디 (없어도 된다)")
    parser.add_argument("--attempts", type=int, default=6, help="연속 시도 횟수 (기본 6 = 임계값 5 + 1)")
    parser.add_argument("--ip", default=None, help="가짜 공격자 IP (생략하면 문서용 대역에서 무작위)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    return 0 if run(args.host.rstrip("/"), args.username, args.attempts, args.ip or random_test_ip()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
