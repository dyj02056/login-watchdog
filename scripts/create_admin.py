# ============================================================================
# create_admin.py — 새 관리자 계정을 role과 함께 만드는 유지보수 스크립트
# (Track B guide26, RBAC 기본 구조)
#
# 관리자 계정은 db/admin.py 설명대로 회원가입 화면이 없다 — 앱이 처음 켜질 때
# .env 값으로 딱 1개(super_admin으로 승격되는 최종 책임자 계정)만 자동 생성된다.
# security_viewer/security_admin 역할의 계정은 그 흐름을 타지 않으므로, 이
# 스크립트로 admin_users 표에 직접 행을 추가한다 — unlock_account.py 등과
# 동일하게 웹 화면을 거치지 않고 db 패키지를 직접 호출하는 구조다.
# ============================================================================

import argparse
import os
import sys

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import db  # noqa: E402  (load_dotenv()가 SUPABASE_URL 등을 먼저 읽어들인 뒤에 import 해야 함)
from werkzeug.security import generate_password_hash  # noqa: E402

MIN_PASSWORD_LENGTH = 8  # routes/auth.py의 회원가입 규칙과 동일하게 맞춤
VALID_ROLES = ("security_viewer", "security_admin", "super_admin")


def create_admin(username: str, password: str, role: str) -> bool:
    """admin_users 표에 새 관리자 계정 한 개를 role과 함께 추가한다.

    아이디가 이미 있으면(unique 제약) 아무것도 만들지 않고 False를 돌려준다 —
    ensure_bootstrap_admin()이 "이미 있으면 건너뛰기"로 중복 생성을 막는 것과
    같은 이유로, 이 스크립트도 실수로 두 번 실행해도 안전해야 한다.
    """
    existing = (
        db.get_client().table("admin_users").select("id").eq("username", username).limit(1).execute()
    )
    if existing.data:
        print(f"[*] {username}은(는) 이미 존재하는 관리자 계정입니다. 만들지 않았습니다.")
        return False

    db.get_client().table("admin_users").insert(
        {"username": username, "password_hash": generate_password_hash(password), "role": role}
    ).execute()
    print(f"[OK] {username} 계정을 role={role}로 생성했습니다.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="login-watchdog 관리자 계정을 role과 함께 생성하는 유지보수 스크립트."
    )
    parser.add_argument("--username", required=True, help="새 관리자 아이디")
    parser.add_argument("--password", required=True, help="새 관리자 비밀번호")
    parser.add_argument("--role", required=True, choices=VALID_ROLES, help="부여할 역할")
    args = parser.parse_args()

    if len(args.password) < MIN_PASSWORD_LENGTH:
        parser.error(f"비밀번호는 최소 {MIN_PASSWORD_LENGTH}자 이상이어야 합니다.")

    create_admin(args.username, args.password, args.role)


if __name__ == "__main__":
    main()
