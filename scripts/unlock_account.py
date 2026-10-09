# ============================================================================
# unlock_account.py — 지금 잠겨있는 "계정"을 관리자가 터미널에서 즉시 풀어주는
# 유지보수 스크립트 (unlock_ip.py의 계정 잠금 버전)
#
# lockouts(IP 단위)와 별개로 account_lockouts(계정 단위) 표가 있다 — 공격자가
# 여러 IP로 나눠서(또는 느린 속도로) 같은 계정만 노리면 IP당 실패 횟수는
# 임계값을 넘지 않아 IP 잠금으로는 못 잡는다. soar.enforce_account_lockout()이
# 이때 IP가 아니라 "계정 자체"를 잠근다(L7 공격 보강 계획 Tier 1: 분산/저속
# 브루트포스 대응). 관리자 대시보드에는 이 계정 잠금을 풀어주는 화면이 따로
# 없으므로(현재 잠긴 IP 카드는 IP 잠금만 보여준다), unlock_ip.py와 동일한 방식으로
# 웹 화면을 거치지 않고 db 패키지를 통해 Supabase의 account_lockouts 표를 직접
# 갱신하는 스크립트를 별도로 둔다.
#
# --admin을 붙이면 회원 계정이 아니라 관리자 계정 잠금(admin_account_lockouts, guide38)을
# 다룬다 — super_admin 본인이 잠겼고 허용 목록 밖에 있어 대시보드에 들어갈 수 없을 때 쓰는
# 비상 해제 수단이다. 관리자 계정 잠금은 항상 임시 잠금이라 --permanent와 함께 쓸 수 없다.
#
# 안전 원칙: unlock_ip.py와 동일하게, 아무 옵션 없이 실행하면 지금 잠긴 계정
# 목록만 조회하고 아무것도 바꾸지 않는다. 실제 해제는 --username 또는 --all을
# 명시했을 때만 일어난다.
# ============================================================================

import argparse
import os
import sys

from dotenv import load_dotenv

# daily_report.py/unlock_ip.py와 동일한 이유: scripts/ 폴더 밖(프로젝트 루트)에
# 있는 db 패키지를 "python scripts/unlock_account.py"로 실행해도 항상 찾을 수
# 있도록 경로를 추가해준다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import db  # noqa: E402  (load_dotenv()가 SUPABASE_URL 등을 먼저 읽어들인 뒤에 import 해야 함)
from security import lockdown  # noqa: E402
from security import soar  # noqa: E402


# --permanent로 영구 잠금을 풀 때 lock_history에 남길 기본 사유(--note로 바꿀 수 있다).
DEFAULT_NOTE = "scripts/unlock_account.py --permanent 로 긴급 해제"


def show_active_lockouts() -> list[dict]:
    """지금 잠겨있는 계정 전체를 화면에 보여준다.

    아무것도 바꾸지 않는 "조회 전용" 동작이다 — 뭘 풀지 결정하기 전에
    먼저 현재 상태부터 확인할 수 있도록 만들었다.
    """
    lockouts = db.list_active_account_lockouts()
    if not lockouts:
        print("[*] 현재 활성 계정 잠금이 없습니다.")
        return lockouts

    print(f"[*] 현재 활성 계정 잠금 {len(lockouts)}건:")
    for lockout in lockouts:
        if lockout.get("lock_type") == "PERMANENT":
            print(
                f"    - {lockout['username']} [영구] "
                f"({lockout['locked_at']} 잠금, 해제하려면 --permanent 옵션 필요)"
            )
            continue
        print(
            f"    - {lockout['username']} "
            f"(실패 {lockout['failure_count']}회, "
            f"{lockout['locked_at']} 잠금 -> {lockout['unlock_at']} 자동 해제 예정)"
        )
    return lockouts


def unlock_one(username: str, permanent: bool = False, note: str = DEFAULT_NOTE) -> bool:
    """특정 계정 하나만 골라서 잠금을 해제한다. 영구 잠금(guide33)은 permanent=True일
    때만 lockdown.release()로 푼다(unlock_ip.py의 unlock_one()과 같은 방식).

    unlock_ip.py의 unlock_one()과 동일하게, 먼저 get_active_account_lockout으로
    "정말 지금 잠겨있는지"부터 확인한다 — 이미 안 잠긴 계정에 실행해도 결과적으로는
    문제가 없지만, 사용자가 "내가 방금 뭘 풀었는지"를 화면에서 명확히 알 수 있게
    하기 위해서다.
    """
    lockout = db.get_active_account_lockout(username)
    if lockout is None:
        print(f"[*] {username}은(는) 이미 잠겨있지 않습니다. 할 일이 없습니다.")
        return False

    if lockout.get("lock_type") == "PERMANENT":
        if not permanent:
            print(f"[!] {username}은(는) 영구 잠금입니다. 풀려면 --permanent 옵션을 함께 지정하세요.")
            return False
        released = lockdown.release("account", username, "script:unlock_account", note)
        print(
            f"[OK] {username} 영구 잠금을 해제했습니다."
            if released
            else f"[*] {username}은(는) 이미 영구 잠금이 아닙니다."
        )
        return released

    print(
        f"[*] {username} 잠금 해제 중... "
        f"(실패 {lockout['failure_count']}회, {lockout['locked_at']} 잠금됨)"
    )
    db.release_account_lockout(username)
    # soar.try_release_expired_account_lockouts()와 동일하게, 잠금을 풀 때는
    # 그 계정의 미해결 CRITICAL 보안 이벤트(DISTRIBUTED_BRUTE_FORCE)도 함께
    # 처리 완료로 표시한다. 이 스크립트로 풀 때만 빠뜨리면 대시보드의 "보안
    # 이벤트" 표에는 이미 오래 전에 풀린 계정이 "자동 해제 대기" 상태로
    # 영원히 남게 된다.
    db.resolve_security_events_for_username(username)
    print(f"[OK] {username} 잠금을 해제했습니다.")
    return True


def unlock_all(lockouts: list[dict], permanent: bool = False, note: str = DEFAULT_NOTE) -> None:
    """조회된 모든 활성 계정 잠금을 순서대로 해제한다. 영구 잠금은 permanent=True일 때만 푼다."""
    for lockout in lockouts:
        if lockout.get("lock_type") == "PERMANENT":
            if permanent:
                lockdown.release("account", lockout["username"], "script:unlock_account", note)
                print(f"[OK] {lockout['username']} 영구 잠금을 해제했습니다.")
            else:
                print(f"[!] {lockout['username']}은(는) 영구 잠금이라 건너뜁니다 (--permanent 필요).")
            continue
        db.release_account_lockout(lockout["username"])
        db.resolve_security_events_for_username(lockout["username"])
        print(f"[OK] {lockout['username']} 잠금을 해제했습니다.")


def show_active_admin_lockouts() -> list[dict]:
    """지금 잠겨 있는 관리자 계정(guide38)을 보여준다. 아무것도 바꾸지 않는다."""
    lockouts = db.list_active_admin_account_lockouts()
    if not lockouts:
        print("[*] 현재 활성 관리자 계정 잠금이 없습니다.")
        return lockouts

    print(f"[*] 현재 활성 관리자 계정 잠금 {len(lockouts)}건:")
    for lockout in lockouts:
        print(
            f"    - {lockout['username']} "
            f"(실패 {lockout['failure_count']}회, "
            f"{lockout['locked_at']} 잠금 -> {lockout['unlock_at']} 자동 해제 예정)"
        )
    return lockouts


def unlock_admin(username: str) -> bool:
    """관리자 계정 하나의 잠금을 푼다. 대시보드 "즉시 해제"와 같은 soar 함수를 써서 그 잠금의
    보안 이벤트만 함께 정리한다(같은 이름 회원의 이벤트는 그대로)."""
    released = soar.manual_release_admin_account(username)
    print(
        f"[OK] 관리자 계정 {username} 잠금을 해제했습니다."
        if released
        else f"[*] 관리자 계정 {username}은(는) 잠겨있지 않습니다. 할 일이 없습니다."
    )
    return released


def main() -> None:
    parser = argparse.ArgumentParser(
        description="로그인 워치독에서 잠긴 계정을 조회하거나 즉시 해제하는 유지보수 스크립트."
    )
    parser.add_argument(
        "--username",
        help="이 계정 하나만 잠금 해제한다 (예: --username jsw123). 생략하면 목록만 조회한다.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="현재 활성 상태인 계정 잠금을 전부 해제한다. --username과 함께 쓸 수 없다.",
    )
    parser.add_argument(
        "--permanent",
        action="store_true",
        help="영구 잠금(자동 만료 없음)도 함께 해제한다. 지정하지 않으면 영구 잠금은 건너뛴다.",
    )
    parser.add_argument(
        "--note",
        default=DEFAULT_NOTE,
        help="영구 잠금을 풀 때 해제 이력(lock_history)에 남길 사유.",
    )
    parser.add_argument(
        "--admin",
        action="store_true",
        help="회원 계정이 아니라 관리자 계정 잠금(guide38)을 조회·해제한다.",
    )
    args = parser.parse_args()

    if args.username and args.all:
        parser.error("--username과 --all은 동시에 쓸 수 없습니다. 하나만 선택하세요.")

    if args.admin:
        if args.permanent:
            parser.error("관리자 계정 잠금은 영구 잠금이 없어서 --permanent와 함께 쓸 수 없습니다.")
        if args.all:
            for lockout in show_active_admin_lockouts():
                unlock_admin(lockout["username"])
        elif args.username:
            unlock_admin(args.username)
        else:
            show_active_admin_lockouts()
        return

    if args.all:
        lockouts = show_active_lockouts()
        if lockouts:
            unlock_all(lockouts, args.permanent, args.note)
        return

    if args.username:
        unlock_one(args.username, args.permanent, args.note)
        return

    # 아무 옵션도 주지 않으면 "조회만" 하고 끝낸다 — 실수로 뭔가를 풀어버리는
    # 사고를 막기 위해, 실제 해제는 반드시 --username 또는 --all을 명시했을 때만 실행된다.
    show_active_lockouts()


if __name__ == "__main__":
    main()
