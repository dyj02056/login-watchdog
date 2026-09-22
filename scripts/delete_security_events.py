# ============================================================================
# delete_security_events.py — 보안 이벤트(security_events 표) 기록을 관리자가
# 터미널에서 영구 삭제하는 유지보수 스크립트
#
# 관리자 대시보드의 "보안 이벤트" 표에서 "처리 완료"를 눌러도 행 자체는 지워지지
# 않고 resolved_at 칸만 채워진 채 표에 계속 남는다(routes/admin.py의
# api_security_events_resolve → db.resolve_security_event 참고). 시간이 지나
# 처리 완료된 기록이 쌓이면 정리하고 싶을 수 있는데, 대시보드 화면에는 "삭제"
# 버튼이 없다 — 실수로 눌러 증적 자료를 날리는 사고를 막기 위해 일부러 넣지
# 않았다. 이 스크립트는 그 대신 unlock_ip.py와 같은 방식으로, 웹 화면을 거치지
# 않고 db.py를 통해 Supabase의 security_events 표를 직접 정리한다.
#
# 안전 원칙: unlock_ip.py처럼 --id/--resolved/--all 중 하나를 명시적으로 줘야만
# 실제 삭제가 일어난다(아무 옵션 없이 실행하면 지금 몇 건이 쌓여있는지 조회만
# 한다). 그중 --all은 미해결 이벤트까지 포함해 전부 지우는 가장 위험한 동작이라,
# 터미널에 "DELETE"를 직접 입력하는 확인 절차를 한 번 더 거친다(웹 화면의
# confirm() 팝업과 같은 목적 — public/js/dashboard/api.js의 deleteUser 등 참고).
# ============================================================================

import argparse
import os
import sys

from dotenv import load_dotenv

# daily_report.py/unlock_ip.py와 동일한 이유: scripts/ 폴더 밖(프로젝트 루트)에
# 있는 db 패키지를 "python scripts/delete_security_events.py"로 실행해도 항상
# 찾을 수 있도록 경로를 추가해준다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import db  # noqa: E402  (load_dotenv()가 SUPABASE_URL 등을 먼저 읽어들인 뒤에 import 해야 함)


def show_summary() -> dict:
    """지금 security_events 표에 총 몇 건이 있고, 그중 처리완료/미해결이 몇 건인지 보여준다.

    아무것도 지우지 않는 조회 전용 동작이다 — 뭘 지울지 결정하기 전에 먼저
    현재 상태부터 확인할 수 있도록 만들었다.
    """
    summary = db.count_security_events()
    print(
        f"[*] 보안 이벤트 총 {summary['total']}건 "
        f"(처리완료 {summary['resolved']}건 / 미해결 {summary['unresolved']}건)"
    )
    return summary


def delete_one(event_id: int) -> None:
    """이 id 하나만 골라서 영구 삭제한다."""
    deleted = db.delete_security_event(event_id)
    if deleted:
        print(f"[OK] 이벤트 #{event_id}를 삭제했습니다.")
    else:
        print(f"[*] 이벤트 #{event_id}를 찾을 수 없습니다. 할 일이 없습니다.")


def delete_resolved() -> None:
    """처리 완료된 이벤트만 골라서 영구 삭제한다. 미해결 이벤트는 건드리지 않는다."""
    count = db.delete_resolved_security_events()
    print(f"[OK] 처리완료 이벤트 {count}건을 삭제했습니다.")


def delete_all() -> None:
    """미해결 이벤트까지 포함해 표 전체를 영구 삭제한다.

    되돌릴 수 없는 가장 위험한 동작이므로, --all 플래그만으로는 실행하지 않고
    터미널에 "DELETE"를 정확히 입력했을 때만 실제로 삭제한다.
    """
    confirmed = input(
        '[!] 전체 보안 이벤트 기록을 영구 삭제합니다. 되돌릴 수 없습니다.\n'
        '    계속하려면 "DELETE"를 입력하세요: '
    )
    if confirmed != "DELETE":
        print("[*] 취소했습니다. 아무것도 삭제하지 않았습니다.")
        return

    count = db.delete_all_security_events()
    print(f"[OK] 보안 이벤트 {count}건을 전부 삭제했습니다.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="로그인 워치독의 보안 이벤트 기록을 조회하거나 영구 삭제하는 유지보수 스크립트."
    )
    parser.add_argument("--id", type=int, help="이 id의 이벤트 한 건만 삭제한다 (예: --id 42).")
    parser.add_argument(
        "--resolved",
        action="store_true",
        help="처리 완료(resolved_at이 채워진) 이벤트를 전부 삭제한다.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="미해결 이벤트까지 포함해 보안 이벤트 기록 전체를 삭제한다. 터미널에서 한 번 더 확인한다.",
    )
    args = parser.parse_args()

    chosen = [opt for opt in (args.id is not None, args.resolved, args.all) if opt]
    if len(chosen) > 1:
        parser.error("--id / --resolved / --all 중 하나만 선택하세요. 동시에 쓸 수 없습니다.")

    if args.id is not None:
        delete_one(args.id)
        return

    if args.resolved:
        delete_resolved()
        return

    if args.all:
        delete_all()
        return

    # 아무 옵션도 주지 않으면 "조회만" 하고 끝낸다 — 실수로 뭔가를 지워버리는
    # 사고를 막기 위해, 실제 삭제는 반드시 옵션을 명시했을 때만 실행된다.
    show_summary()


if __name__ == "__main__":
    main()
