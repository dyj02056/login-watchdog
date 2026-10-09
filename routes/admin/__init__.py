# ============================================================================
# routes/admin/ — 관리자 로그인/로그아웃(/admin/*) + 관리자 대시보드 화면 및 API
#
# 원래 routes/admin.py 한 파일(798줄)에 로그인, 대시보드 폴링, 잠금 조치, 사건 처리,
# 회원·게시판·관리자 계정 관리가 전부 들어 있었다. 기능 묶음별로 나눴다:
#   login.py      — /admin/login, /admin/logout
#   status.py     — /admin/dashboard, /api/status (대시보드 폴링)
#   locks.py      — 잠금 즉시 해제, 영구 잠금 승격/해제, IP 예외·복구 요청 회수
#   incidents.py  — AI 조기 경보 승인/반려, 보안 이벤트·연관 사건 처리
#   manage.py     — 회원 삭제, 회원가입 On/Off, 게시글·댓글 삭제, 관리자 계정 관리
#
# Blueprint는 여기서 하나만 만든다 — 하위 파일들이 같은 admin_bp에 라우트를 붙이므로
# 엔드포인트 이름(url_for("admin.api_status") 등)과 URL은 나누기 전과 완전히 같다.
# 하위 모듈 import는 admin_bp를 만든 "뒤"에 해야 한다(하위 모듈이 이 admin_bp를 가져다 쓰므로).
#
# docs/refactor/2026-10-09-module-plan.md — 이 분리 작업의 배경과 계획 문서.
# ============================================================================

from flask import Blueprint

admin_bp = Blueprint("admin", __name__)

from routes.admin import incidents, locks, login, manage, status  # noqa: E402,F401
