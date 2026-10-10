# ============================================================================
# admin_distributed_bruteforce_sim.py — 관리자 계정에 대한 분산 브루트포스
# (ADMIN_DISTRIBUTED_BRUTE_FORCE)를 흉내 내서, 관리자 "계정 단위" 잠금이 걸리는지 확인하는 검증 스크립트
# (guide38)
#
# distributed_bruteforce_sim.py(회원)의 관리자 버전이다. 한 관리자 아이디를 여러 IP에서 나눠 시도하면
# IP당 실패는 5회 이하라 IP 잠금은 피하지만, 15분(ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS) 안의 총 실패가
# ADMIN_ACCOUNT_FAILURE_THRESHOLD(기본 8회)를 "초과"하면 그 아이디가 5분간 계정 단위로 잠긴다.
# 아이디가 실제로 있든 없든 같은 기준·같은 문구로 잠가서 관리자 아이디 존재 여부가 드러나지 않는다.
#
# 동작 요약:
#   1) 가짜 IP --ips개(기본 3개)가 같은 관리자 아이디에 틀린 비밀번호를 --per-ip번(기본 3번)씩 번갈아 시도한다.
#   2) 한 번도 실패한 적 없는 새 IP로 같은 아이디를 한 번 더 시도한다. 깨끗한 IP인데도 잠금 문구가
#      나오면 IP가 아니라 아이디가 잠긴 것이다 → 성공.
#
# 안전 원칙: 로컬 서버만 대상. 가짜 IP는 서버의 TRUST_FORWARDED_FOR=true일 때만 반영된다. 허용 목록
# (PERMANENT_LOCK_IP_ALLOWLIST, 관리자 PC) IP는 계정 잠금을 건너뛰므로 가짜 IP(문서용 대역)를 쓴다.
# ============================================================================

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import (  # noqa: E402
    LOCK_MESSAGE, fetch_csrf, new_session, post_form, random_test_ip, require_local_or_exit,
)

LOGIN_PATH = "/admin/login"


def run(base_url: str, username: str, ips: int, per_ip: int) -> bool:
    attackers = []
    while len(attackers) < ips + 1:
        ip = random_test_ip()
        if ip not in attackers:
            attackers.append(ip)
    fresh_ip = attackers.pop()
    sessions = {ip: new_session(ip) for ip in attackers}
    tokens = {ip: fetch_csrf(sessions[ip], base_url, LOGIN_PATH) for ip in attackers}

    total = ips * per_ip
    print(f"[*] {base_url}{LOGIN_PATH} | 관리자 아이디 '{username}' | 가짜 IP {ips}개 x {per_ip}회 = {total}회")
    locked_early = False
    for i in range(total):
        ip = attackers[i % ips]
        response = post_form(sessions[ip], base_url, LOGIN_PATH,
                             {"username": username, "password": "wrong-password-on-purpose"}, tokens[ip])
        print(f"    시도 {i + 1:>2}/{total} | IP {ip:<15} | 상태 {response.status_code}"
              f"{' | 잠금 문구 확인' if LOCK_MESSAGE in response.text else ''}")
        # 마지막 시도 전에 잠금이 보이면 가짜 IP가 무시되어 한 IP로 보인 것이다(IP당 per_ip회는 IP 잠금 기준 이하).
        locked_early = locked_early or (i < total - 1 and LOCK_MESSAGE in response.text)

    if locked_early:
        print("[FAIL] 마지막 시도 전에 이미 잠겼습니다. 서버가 X-Forwarded-For를 무시해 모든 요청을 한 IP로 보고 있습니다")
        print("       (IP 잠금이 먼저 걸림). 서버를 TRUST_FORWARDED_FOR=true로 띄운 뒤 다시 실행하세요.")
        return False

    session = new_session(fresh_ip)
    token = fetch_csrf(session, base_url, LOGIN_PATH)
    response = post_form(session, base_url, LOGIN_PATH,
                         {"username": username, "password": "wrong-password-on-purpose"}, token)
    print(f"[*] 확인: 한 번도 실패한 적 없는 새 IP {fresh_ip}로 같은 관리자 아이디를 시도")
    if LOCK_MESSAGE in response.text:
        print("[OK] 깨끗한 IP인데도 잠금 문구가 나왔습니다. 관리자 계정 단위 잠금이 정상 동작합니다.")
        print("  확인 위치: security_events의 event_type=ADMIN_DISTRIBUTED_BRUTE_FORCE(또는 DISTRIBUTED_BRUTE_FORCE), CRITICAL")
        return True
    print("[FAIL] 새 IP에서 잠금 문구가 나오지 않았습니다. 관리자 계정 단위 잠금이 걸리지 않았습니다.")
    print("       서버가 TRUST_FORWARDED_FOR=true인지, 합계가 ADMIN_ACCOUNT_FAILURE_THRESHOLD(기본 8)를 넘는지 확인하세요.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="관리자 분산 브루트포스(계정 단위 잠금) 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--username", default="admin-target", help="공격 대상 관리자 아이디 (없어도 된다)")
    parser.add_argument("--ips", type=int, default=3, help="번갈아 쓸 가짜 IP 개수 (기본 3)")
    parser.add_argument("--per-ip", type=int, default=3, help="IP당 시도 횟수, IP 잠금 기준(5) 이하로 (기본 3)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    return 0 if run(args.host.rstrip("/"), args.username, args.ips, args.per_ip) else 1


if __name__ == "__main__":
    raise SystemExit(main())
