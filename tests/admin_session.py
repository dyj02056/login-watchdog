# ============================================================================
# admin_session.py — 테스트에서 "로그인된 관리자"를 흉내내는 공용 헬퍼 (guide37)
#
# 관리자 문지기(helpers.login_required / require_permission)는 세션에 아이디·기본키·로그인
# 시각이 모두 있고, db.get_admin_by_id()가 같은 아이디의 계정을 돌려줘야 통과시킨다.
# 테스트마다 이 세 값을 직접 채우고 DB 조회를 가짜로 바꾸는 대신 아래 두 함수를 쓴다.
#   - login_admin_session(sess, username): session_transaction() 안에서 세션 값을 채운다
#   - stub_admin_role(monkeypatch, role): 세션의 관리자가 이 role을 가진 계정으로 조회되게 한다
# 기본 role(security_admin)은 conftest.py의 flask_app fixture가 미리 깔아둔다.
# ============================================================================

import time

from flask import session

import db

TEST_ADMIN_ID = 1


def login_admin_session(sess, username: str, admin_id: int = TEST_ADMIN_ID, login_at: float | None = None) -> None:
    sess["admin_username"] = username
    sess["admin_id"] = admin_id
    sess["admin_login_at"] = int(time.time()) if login_at is None else login_at


def stub_admin_role(monkeypatch, role: str) -> None:
    monkeypatch.setattr(
        db,
        "get_admin_by_id",
        lambda admin_id: {"id": admin_id, "username": session.get("admin_username"), "role": role},
    )
