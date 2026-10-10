# ============================================================================
# incident_correlation_sim.py — 한 IP가 정찰 → 침투 시도 → 브루트포스를 차례로 벌이는 "다단계 공격"을
# 흉내 내서, 서버가 흩어진 이벤트를 하나의 사건(incident)으로 묶고 영구 차단까지 하는지 확인하는 검증 스크립트
# (guide27 SIEM 상관분석 / guide28 SOAR 플레이북 / guide33 T3)
#
# 서버는 같은 IP가 5분(INCIDENT_CORRELATION_WINDOW_MINUTES) 안에 서로 다른 종류의 이벤트를 2개 이상 남기면
# 사건으로 묶고, 최고 위험등급이 CRITICAL이면서 종류가 3개 이상이면 에스컬레이션 알림(CRITICAL_MULTI_STAGE)을
# 보낸다. CRITICAL 사건이 되면 그 IP를 즉시 영구 잠금으로 올린다(T3).
#
# 동작 요약 (모두 같은 가짜 IP):
#   1) 정찰: 없는 경로를 11번 요청 → WEB_SCANNING (MEDIUM)
#   2) 침투 시도: 로그인 없이 /api/status를 11번 요청 → UNAUTHORIZED_ACCESS (MEDIUM)
#   3) 공격: /login에 틀린 비밀번호 6번 → BRUTE_FORCE (CRITICAL)
#   4) 한 번 더 시도했을 때 "이 네트워크는 차단되어 있습니다"(영구 잠금 문구)가 나오면 성공.
#
# 안전 원칙: 로컬 서버만 대상. 가짜 IP는 서버의 TRUST_FORWARDED_FOR=true일 때만 반영된다. 시연 뒤에는
# `python scripts/management/unlock_ip.py --ip <IP> --permanent`로 영구 잠금을 푼다.
# ============================================================================

import argparse
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _sim_common import (  # noqa: E402
    LOCK_MESSAGE, PERMANENT_BLOCK_MESSAGE, REQUEST_TIMEOUT, fetch_csrf, new_session, post_form,
    random_test_ip, require_local_or_exit,
)

SCAN_TARGETS = (
    "admin.php", ".env", "wp-login.php", "wp-admin", "phpmyadmin", ".git/config",
    "backup.sql", "config.php", "xmlrpc.php", "server-status", "vendor/phpunit/eval-stdin.php",
)


def stage_scanning(session, base_url: str) -> list[int]:
    run_id = uuid.uuid4().hex[:8]
    statuses = []
    for target in SCAN_TARGETS:
        statuses.append(session.get(f"{base_url}/{target}/__scan_{run_id}", timeout=REQUEST_TIMEOUT,
                                    allow_redirects=False).status_code)
    return statuses


def stage_unauthorized(session, base_url: str) -> list[int]:
    return [session.get(f"{base_url}/api/status", timeout=REQUEST_TIMEOUT, allow_redirects=False).status_code
            for _ in range(11)]


def stage_bruteforce(session, base_url: str, username: str, attempts: int) -> bool:
    token = fetch_csrf(session, base_url, "/login")
    locked = False
    for _ in range(attempts):
        response = post_form(session, base_url, "/login",
                             {"username": username, "password": "wrong-password-on-purpose"}, token)
        locked = LOCK_MESSAGE in response.text
    return locked


def run(base_url: str, username: str, ip: str) -> bool:
    session = new_session(ip)
    print(f"[*] 가짜 IP {ip} | 다단계 공격 3단계")

    statuses = stage_scanning(session, base_url)
    print(f"[1/3] 정찰 (웹 스캐닝): 404 {statuses.count(404)}/{len(statuses)}회")

    statuses = stage_unauthorized(session, base_url)
    print(f"[2/3] 침투 시도 (인증 없는 API 접근): 401 {statuses.count(401)}/{len(statuses)}회")

    locked = stage_bruteforce(session, base_url, username, 6)
    print(f"[3/3] 브루트포스 6회: 임시 잠금 문구 {'확인' if locked else '없음'}")

    token = fetch_csrf(session, base_url, "/login")
    response = post_form(session, base_url, "/login",
                         {"username": username, "password": "wrong-password-on-purpose"}, token)
    print(f"[*] 확인 시도 | 상태 {response.status_code}")
    if PERMANENT_BLOCK_MESSAGE in response.text:
        print("[OK] 영구 잠금 문구가 나왔습니다. 상관분석(사건화) → 영구 차단 흐름이 정상 동작합니다.")
        print("  확인 위치: security_incidents(severity_max=CRITICAL, event_types 3개, escalated=true),")
        print("            security_events의 PERMANENT_LOCK, Slack/로그의 다단계 공격 에스컬레이션 알림")
        print(f"  뒷정리: python scripts/management/unlock_ip.py --ip {ip} --permanent --note \"시뮬레이션 뒷정리\"")
        return True
    print("[FAIL] 영구 잠금 문구가 나오지 않았습니다. 이벤트가 사건으로 묶여 승격되지 않았습니다.")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="다단계 공격 사건화(상관분석) + 영구 차단 검증 시뮬레이터")
    parser.add_argument("--host", default="http://127.0.0.1:5000", help="테스트 대상 서버 (기본 로컬)")
    parser.add_argument("--username", default="multi-stage-target", help="브루트포스에 쓸 아이디 (없어도 된다)")
    parser.add_argument("--ip", default=None, help="가짜 공격자 IP (생략하면 문서용 대역에서 무작위)")
    parser.add_argument("--i-know-what-im-doing", action="store_true", help="로컬이 아닌 --host를 허용")
    args = parser.parse_args()
    require_local_or_exit(args.host, args.i_know_what_im_doing)
    return 0 if run(args.host.rstrip("/"), args.username, args.ip or random_test_ip()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
