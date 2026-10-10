# ============================================================================
# distributed_bruteforce_sim.py — "분산 브루트포스(DISTRIBUTED_BRUTE_FORCE)"를 흉내 내서,
# IP가 아니라 "계정 단위" 잠금이 걸리는지 확인하는 검증 스크립트 (Tier 1: 분산/저속 대응)
#
# 분산 브루트포스란? 한 계정만 노리되 IP를 계속 바꿔가며 시도하는 공격이다(봇넷·프록시 로테이션).
# 각 IP는 몇 번 틀리지 않아 "IP당 5회 초과" 규칙(bruteforce_sim.py가 확인하는 IP 잠금)을 피해 가지만,
# 서버는 IP와 무관하게 "그 계정이 총 몇 번 틀렸는가"(ACCOUNT_FAILURE_THRESHOLD, 기본 8회 초과)도
# 세기 때문에 결국 계정이 잠긴다.
#
# 동작 요약:
#   1) 가짜 IP --ips개(기본 3개) 각각이 같은 아이디에 틀린 비밀번호를 --per-ip번(기본 3번)씩 번갈아 시도한다.
#      IP당 횟수는 IP 잠금 기준(5회) 아래로 유지하고, 전체 합(기본 9회)만 계정 기준(8회)을 넘긴다.
#   2) 마지막에 "한 번도 실패한 적 없는 새 IP"로 같은 아이디를 한 번 더 시도한다.
#      그 IP는 깨끗한데도 계정 잠금 안내가 나오면 IP가 아니라 "계정"이 잠긴 것이다 → 성공.
#
# 안전 원칙: 로컬 서버(기본 http://127.0.0.1:5000)만 대상으로 한다. 가짜 IP는 서버의
# TRUST_FORWARDED_FOR=true일 때만 반영된다(꺼져 있으면 모든 요청이 한 IP로 보여 IP 잠금이 먼저 걸린다).
# ============================================================================

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import (  # noqa: E402
    ACCOUNT_LOCK_MARKER, LOCK_MESSAGE, fetch_csrf, new_session, post_form, random_test_ip,
    require_local_or_exit,
)


def run(base_url: str, username: str, ips: int, per_ip: int, path: str = "/login") -> bool:
    attackers = []
    while len(attackers) < ips + 1:  # 마지막 하나는 "새 IP" 확인용으로 아껴둔다
        ip = random_test_ip()
        if ip not in attackers:
            attackers.append(ip)
    fresh_ip = attackers.pop()
    sessions = {ip: new_session(ip) for ip in attackers}
    tokens = {ip: fetch_csrf(sessions[ip], base_url, path) for ip in attackers}

    total = ips * per_ip
    print(f"[*] {base_url}{path} | 아이디 '{username}' | 가짜 IP {ips}개 x {per_ip}회 = {total}회")
    for i in range(total):
        ip = attackers[i % ips]
        response = post_form(sessions[ip], base_url, path,
                             {"username": username, "password": "wrong-password-on-purpose"}, tokens[ip])
        print(f"    시도 {i + 1:>2}/{total} | IP {ip:<15} | 상태 {response.status_code}"
              f"{' | 잠금 문구 확인' if LOCK_MESSAGE in response.text else ''}")

    session = new_session(fresh_ip)
    token = fetch_csrf(session, base_url, path)
    response = post_form(session, base_url, path,
                         {"username": username, "password": "wrong-password-on-purpose"}, token)
    print(f"[*] 확인: 한 번도 실패한 적 없는 새 IP {fresh_ip}로 같은 아이디를 시도")
    if ACCOUNT_LOCK_MARKER in response.text:
        print("[OK] 깨끗한 IP인데도 계정 잠금 안내가 나왔습니다. 계정 단위 잠금이 정상 동작합니다.")
        print("  확인 위치: 대시보드 security_events의 event_type=DISTRIBUTED_BRUTE_FORCE, severity=CRITICAL")
        return True
    print("[FAIL] 새 IP에서 계정 잠금 안내가 나오지 않았습니다. 계정 단위 잠금이 걸리지 않았습니다.")
    print("       서버가 TRUST_FORWARDED_FOR=true인지, 합계가 ACCOUNT_FAILURE_THRESHOLD(기본 8)를 넘는지 확인하세요.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="분산 브루트포스(계정 단위 잠금) 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--username", default="dist-target-user", help="공격 대상 아이디 (없는 아이디여도 된다)")
    parser.add_argument("--ips", type=int, default=3, help="번갈아 쓸 가짜 IP 개수 (기본 3)")
    parser.add_argument("--per-ip", type=int, default=3, help="IP당 시도 횟수, IP 잠금 기준(5) 이하로 (기본 3)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    return 0 if run(args.host.rstrip("/"), args.username, args.ips, args.per_ip) else 1


if __name__ == "__main__":
    raise SystemExit(main())
