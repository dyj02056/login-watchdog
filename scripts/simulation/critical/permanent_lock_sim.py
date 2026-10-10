# ============================================================================
# permanent_lock_sim.py — 상습 공격자가 임시 잠금을 반복해서 받다가 "영구 잠금(PERMANENT)"으로 올라가는
# 에스컬레이션(T1: REPEAT_OFFENDER)을 흉내 내서, 서버가 실제로 영구 차단하는지 확인하는 검증 스크립트
# (guide33)
#
# 임시 잠금(기본 5분)은 시간이 지나면 풀린다. 그런데 같은 IP가 30일(PERMANENT_LOCK_STRIKE_WINDOW_DAYS) 안에
# 임시 잠금을 PERMANENT_LOCK_STRIKE_COUNT번(기본 2번) 받으면 서버는 "상습범"으로 보고 자동 만료가 없는
# 영구 잠금으로 올린다. 허용 목록(PERMANENT_LOCK_IP_ALLOWLIST) IP는 절대 영구 잠그지 않으므로 가짜 IP를 쓴다.
#
# 동작 요약:
#   1) 가짜 IP로 /login에 틀린 비밀번호를 6번 보내 첫 번째 임시 잠금을 건다.
#   2) 임시 잠금이 자동으로 풀릴 때까지 기다린다(--wait-seconds, 기본 LOCKOUT_DURATION_SECONDS 300초 + 여유 5초).
#   3) 다시 6번 보내 두 번째 임시 잠금을 건다 → 서버가 상습범으로 판단해 영구 잠금으로 올린다.
#   4) 한 번 더 시도했을 때 "이 네트워크는 차단되어 있습니다"(영구 잠금 문구)가 나오면 성공.
#
# 안전 원칙: 로컬 서버만 대상. 가짜 IP는 서버의 TRUST_FORWARDED_FOR=true일 때만 반영된다. 영구 잠금은
# 자동으로 풀리지 않으니 시연 뒤에는 `python scripts/management/unlock_ip.py --ip <IP> --permanent`로 푼다.
# 5분 넘게 기다리기 싫으면 서버를 LOCKOUT_DURATION_SECONDS=10 같은 값으로 띄우고 --wait-seconds 12를 쓴다.
# ============================================================================

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import (  # noqa: E402
    LOCK_MESSAGE, PERMANENT_BLOCK_MESSAGE, fetch_csrf, new_session, post_form, random_test_ip,
    require_local_or_exit,
)

LOGIN_PATH = "/login"


def trigger_temporary_lock(session, token, base_url: str, username: str, attempts: int) -> bool:
    """틀린 비밀번호를 최대 attempts번 보내 잠금을 건다. 잠금(임시 또는 이미 올라간 영구) 문구가 보이면 멈추고 True.

    1차 잠금 직후 60초 안에 2차를 시작하면 이전 실패가 아직 집계 창에 남아 있어 첫 시도에 곧바로 다시 잠길 수 있다.
    """
    for i in range(1, attempts + 1):
        response = post_form(session, base_url, LOGIN_PATH,
                             {"username": username, "password": "wrong-password-on-purpose"}, token)
        blocked = LOCK_MESSAGE in response.text or PERMANENT_BLOCK_MESSAGE in response.text
        print(f"    시도 {i}/{attempts} | 상태 {response.status_code}{' | 잠금 문구 확인' if blocked else ''}")
        if blocked:
            return True
    return False


def run(base_url: str, username: str, ip: str, wait_seconds: float, attempts: int) -> bool:
    session = new_session(ip)
    token = fetch_csrf(session, base_url, LOGIN_PATH)
    print(f"[*] 가짜 IP {ip} | 아이디 '{username}' | 1차 임시 잠금 유발 ({attempts}회)")
    if not trigger_temporary_lock(session, token, base_url, username, attempts):
        print("[FAIL] 1차 임시 잠금이 걸리지 않았습니다. 서버가 TRUST_FORWARDED_FOR=true인지 확인하세요.")
        return False

    print(f"[*] 임시 잠금이 풀리기를 {wait_seconds:.0f}초 기다립니다...", flush=True)
    time.sleep(wait_seconds)

    print("[*] 2차 임시 잠금 유발 (같은 IP가 두 번째로 잠기면 상습범으로 영구 잠금)")
    token = fetch_csrf(session, base_url, LOGIN_PATH)
    if not trigger_temporary_lock(session, token, base_url, username, attempts):
        print("[FAIL] 2차 임시 잠금이 걸리지 않았습니다. 1차 잠금이 아직 안 풀렸을 수 있습니다(--wait-seconds를 늘리세요).")
        return False

    response = post_form(session, base_url, LOGIN_PATH,
                         {"username": username, "password": "wrong-password-on-purpose"}, token)
    print(f"[*] 확인 시도 | 상태 {response.status_code}")
    if PERMANENT_BLOCK_MESSAGE in response.text:
        print("[OK] 영구 잠금 문구가 나왔습니다. 상습범 에스컬레이션이 정상 동작합니다.")
        print("  확인 위치: security_events의 event_type=PERMANENT_LOCK, severity=CRITICAL, lock_history의 REPEAT_OFFENDER")
        print(f"  뒷정리: python scripts/management/unlock_ip.py --ip {ip} --permanent --note \"시뮬레이션 뒷정리\"")
        return True
    print("[FAIL] 영구 잠금 문구가 나오지 않았습니다. 임시 잠금까지만 걸렸습니다.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="상습 공격자 영구 잠금(REPEAT_OFFENDER) 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--username", default="repeat-offender", help="시도할 아이디 (없어도 된다)")
    parser.add_argument("--ip", default=None, help="가짜 공격자 IP (생략하면 문서용 대역에서 무작위)")
    parser.add_argument("--attempts", type=int, default=6, help="잠금 1회를 유발하는 시도 횟수 (기본 6 = 임계값 5 + 1)")
    parser.add_argument("--wait-seconds", type=float, default=305.0,
                        help="1차 임시 잠금이 풀리길 기다리는 시간 (기본 305 = LOCKOUT_DURATION_SECONDS 300 + 5)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    ok = run(args.host.rstrip("/"), args.username, args.ip or random_test_ip(), args.wait_seconds, args.attempts)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
