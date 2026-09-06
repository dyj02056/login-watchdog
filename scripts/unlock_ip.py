# ============================================================================
# unlock_ip.py — 지금 잠겨있는 IP를 관리자가 터미널에서 즉시 풀어주는 유지보수 스크립트
#
# 관리자 로그인(/admin/login)도 감시 대상 로그인(/login)과 같은 lockouts 표를
# "IP" 기준으로 함께 쓴다(19단계 보안 점검에서 관리자 로그인에도 잠금을 적용하도록
# 보완했기 때문). 그래서 같은 컴퓨터에서 브루트포스 시뮬레이션(bruteforce_sim.py)을
# 테스트하다 보면 그 IP를 쓰는 관리자 계정까지 함께 잠기는 일이 생긴다.
#
# 문제는 이때 관리자 대시보드의 "즉시 해제" 버튼도 쓸 수 없다는 점이다 — 그 버튼을
# 누르려면 먼저 관리자로 로그인해야 하는데, 로그인 자체가 잠겨서 막혀버리기
# 때문이다(닭이 먼저냐 달걀이 먼저냐 문제). 이 스크립트는 웹 화면을 거치지 않고
# db.py를 통해 Supabase의 lockouts 표를 직접 갱신한다 — 관리자 대시보드의
# "즉시 해제" 버튼이 서버 안에서 하는 일(db.release_lockout)을, 서버·로그인 없이
# 터미널에서 곧바로 실행하는 것과 같다.
#
# 안전 원칙: 이 스크립트는 .env에 적힌 SUPABASE_KEY(이 프로젝트 전용 비밀 키)가
# 있어야만 실제로 동작한다. 즉 이 파일 자체를 남이 읽거나 복사해가는 것만으로는
# 아무도 남의 프로젝트를 풀 수 없다 — 열쇠(.env)는 여전히 각자 따로 가지고
# 있어야 한다.
# ============================================================================

import argparse
import os
import sys

from dotenv import load_dotenv

# daily_report.py와 동일한 이유: scripts/ 폴더 밖(프로젝트 루트)에 있는 db.py를
# "python scripts/unlock_ip.py"로 실행해도 항상 찾을 수 있도록 경로를 추가해준다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import db  # noqa: E402  (load_dotenv()가 SUPABASE_URL 등을 먼저 읽어들인 뒤에 import 해야 함)


def show_active_lockouts() -> list[dict]:
    """지금 잠겨있는 IP 전체를 화면에 보여준다.

    아무것도 바꾸지 않는 "조회 전용" 동작이다 — 뭘 풀지 결정하기 전에
    먼저 현재 상태부터 확인할 수 있도록 만들었다.
    """
    lockouts = db.list_active_lockouts()
    if not lockouts:
        print("[*] 현재 활성 잠금이 없습니다.")
        return lockouts

    print(f"[*] 현재 활성 잠금 {len(lockouts)}건:")
    for lockout in lockouts:
        print(
            f"    - {lockout['ip_address']} "
            f"(실패 {lockout['failure_count']}회, "
            f"{lockout['locked_at']} 잠금 -> {lockout['unlock_at']} 자동 해제 예정)"
        )
    return lockouts


def unlock_one(ip: str) -> bool:
    """특정 IP 하나만 골라서 잠금을 해제한다.

    아무 확인 없이 바로 release_lockout을 부르지 않고, 먼저 get_active_lockout으로
    "정말 지금 잠겨있는지"부터 확인한다 — 이미 안 잠긴 IP에 실행해도 결과적으로는
    문제가 없지만, 사용자가 "내가 방금 뭘 풀었는지"를 화면에서 명확히 알 수 있게
    하기 위해서다.
    """
    lockout = db.get_active_lockout(ip)
    if lockout is None:
        print(f"[*] {ip}는 이미 잠겨있지 않습니다. 할 일이 없습니다.")
        return False

    print(
        f"[*] {ip} 잠금 해제 중... "
        f"(실패 {lockout['failure_count']}회, {lockout['locked_at']} 잠금됨)"
    )
    db.release_lockout(ip)
    print(f"[OK] {ip} 잠금을 해제했습니다.")
    return True


def unlock_all(lockouts: list[dict]) -> None:
    """조회된 모든 활성 잠금을 순서대로 해제한다."""
    for lockout in lockouts:
        db.release_lockout(lockout["ip_address"])
        print(f"[OK] {lockout['ip_address']} 잠금을 해제했습니다.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="로그인 워치독에서 잠긴 IP를 조회하거나 즉시 해제하는 유지보수 스크립트."
    )
    parser.add_argument(
        "--ip",
        help="이 IP 하나만 잠금 해제한다 (예: --ip 127.0.0.1). 생략하면 목록만 조회한다.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="현재 활성 상태인 잠금을 전부 해제한다. --ip와 함께 쓸 수 없다.",
    )
    args = parser.parse_args()

    if args.ip and args.all:
        parser.error("--ip와 --all은 동시에 쓸 수 없습니다. 하나만 선택하세요.")

    if args.all:
        lockouts = show_active_lockouts()
        if lockouts:
            unlock_all(lockouts)
        return

    if args.ip:
        unlock_one(args.ip)
        return

    # 아무 옵션도 주지 않으면 "조회만" 하고 끝낸다 — 실수로 뭔가를 풀어버리는
    # 사고를 막기 위해, 실제 해제는 반드시 --ip 또는 --all을 명시했을 때만 실행된다.
    show_active_lockouts()


if __name__ == "__main__":
    main()
