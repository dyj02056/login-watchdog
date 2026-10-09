# ============================================================================
# http_flood_sim.py — "HTTP 플러딩(대량 요청 도배, HTTP_FLOOD)"을 흉내 내서, 전역 요청 한도가
# 정말로 429(요청이 너무 많음)로 막아주는지 확인하는 검증 스크립트 (Tier 2)
#
# 로그인·가입·글쓰기 같은 "폼 제출"에는 각자의 한도가 있지만, 일반 GET 페이지는 예전에 아무리 요청이 쏟아져도
# 다 받아줬다. 그래서 같은 IP가 1분(GLOBAL_RATE_LIMIT_PER_MINUTE, 기본 120회)에 전체 요청을 합쳐서 한도를
# 넘기면 429로 거절하고 HTTP_FLOOD(HIGH) 이벤트로 남긴다.
#
# 동작 요약:
#   1) 가짜 IP 하나로 --path(기본 /login)에 GET을 --requests번(기본 130번, 한도 120 + 여유) 최대한 빠르게 보낸다.
#   2) 어느 순간부터 429가 돌아오면 성공. 처음 429가 나온 번째와 총 429 개수를 보여준다.
#
# 안전 원칙: 로컬 서버만 대상. 가짜 IP는 서버의 TRUST_FORWARDED_FOR=true일 때만 반영된다(꺼져 있으면 실제 IP가
# 1분간 막힌다). 요청은 가볍지만 한도가 1분 단위이므로, 같은 IP로 반복 실행하면 1분 뒤에 다시 하는 게 좋다.
# ============================================================================

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import REQUEST_TIMEOUT, new_session, random_test_ip, require_local_or_exit  # noqa: E402


def run(base_url: str, path: str, requests_count: int, ip: str) -> bool:
    session = new_session(ip)
    print(f"[*] GET {base_url}{path} | 가짜 IP {ip} | {requests_count}회 연속 요청")
    statuses = []
    started = time.monotonic()
    for _ in range(requests_count):
        statuses.append(session.get(f"{base_url}{path}", timeout=REQUEST_TIMEOUT, allow_redirects=False).status_code)
    elapsed = time.monotonic() - started

    blocked = statuses.count(429)
    first_block = statuses.index(429) + 1 if blocked else None
    print(f"[*] 소요 {elapsed:.1f}초 | 200 계열 {sum(1 for s in statuses if s < 400)}회 | 429 {blocked}회"
          f"{f' | 처음 429는 {first_block}번째 요청' if first_block else ''}")
    if blocked:
        print("[OK] 전역 요청 한도가 429로 요청을 막았습니다.")
        print("  확인 위치: 대시보드 security_events의 event_type=HTTP_FLOOD, severity=HIGH")
        return True
    print("[FAIL] 429가 한 번도 나오지 않았습니다. 요청 횟수가 GLOBAL_RATE_LIMIT_PER_MINUTE보다 적었거나 한도가 꺼져 있습니다.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP 플러딩(전역 요청 한도) 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--path", default="/login", help="반복 요청할 경로 (기본 /login)")
    parser.add_argument("--requests", type=int, default=130, help="요청 횟수 (기본 130 = 한도 120 + 10)")
    parser.add_argument("--ip", default=None, help="가짜 공격자 IP (생략하면 문서용 대역에서 무작위)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    ok = run(args.host.rstrip("/"), args.path, args.requests, args.ip or random_test_ip())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
