"""화면 확인용 데모 서버 — 가짜 데이터로 관제 화면을 띄운다. Supabase에 접속하지 않는다.

    python scripts/demo/demo_server.py            # http://127.0.0.1:5077

실제 DB·Slack·메일에는 아무것도 보내지 않는다(DB 클라이언트를 빈 응답을 돌려주는 가짜로 바꾸고,
Slack·메일은 보내지 않는다). 접속하면 관리자로 이미 로그인된 상태가 되어 /admin/dashboard가 바로 열린다.
IP는 문서용 대역(RFC 5737)만 쓴 가짜 값이고, 표시되는 숫자는 실행할 때마다 같은 난수 씨앗으로 만든다.

디자인 검토·스크린샷·프런트엔드 개발용이다. 운영에서는 쓰지 않는다.
"""

import os
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("SECRET_KEY", "demo-only-secret-key")
os.environ.setdefault("ADMIN_USERNAME", "demo-admin")
os.environ.setdefault("ADMIN_PASSWORD", "demo-admin-password")
os.environ["SUPABASE_URL"] = "http://supabase.invalid"
os.environ["SUPABASE_KEY"] = "demo-key"
os.environ["SLACK_WEBHOOK_URL"] = ""
os.environ["MAIL_BACKEND"] = "console"
os.environ.pop("FLASK_ENV", None)

import db  # noqa: E402
from db import stats as db_stats  # noqa: E402


class _Result:
    def __init__(self, data=None, count=0):
        self.data = data if data is not None else []
        self.count = count


class _Query:
    """.table().select().eq()... 어떤 순서로 불러도 빈 결과를 돌려주는 가짜 쿼리."""

    def __getattr__(self, _name):
        return lambda *args, **kwargs: self

    def execute(self):
        return _Result()


class _FakeClient:
    def table(self, _name):
        return _Query()


db._client = _FakeClient()
db.get_client = lambda: db._client

# 시드(분류 가능한 가짜 IP): 문서용 대역만 쓴다.
_RNG = random.Random(20261009)
_ATTACKERS = [
    ("203.0.113.57", "Russia", ["BRUTE_FORCE", "WEB_SCANNING", "UNAUTHORIZED_ACCESS", "PASSWORD_SPRAYING"], 38),
    ("198.51.100.23", "China", ["BRUTE_FORCE", "DISTRIBUTED_BRUTE_FORCE", "API_MACRO_PATTERN"], 29),
    ("192.0.2.144", "United States", ["WEB_SCANNING", "PAGE_ACCESS"], 21),
    ("203.0.113.9", "Germany", ["SIGNUP_RATE_LIMIT", "HTTP_FLOOD"], 14),
    ("198.51.100.201", "Vietnam", ["BRUTE_FORCE"], 11),
    ("192.0.2.88", "South Korea", ["UNAUTHORIZED_ACCESS", "WEB_SCANNING"], 9),
    ("203.0.113.130", "Brazil", ["POST_RATE_LIMIT", "COMMENT_RATE_LIMIT"], 7),
    ("198.51.100.77", "India", ["BRUTE_FORCE"], 5),
]
_SEVERITY = {
    "BRUTE_FORCE": "CRITICAL",
    "DISTRIBUTED_BRUTE_FORCE": "CRITICAL",
    "PASSWORD_SPRAYING": "CRITICAL",
    "SIGNUP_RATE_LIMIT": "HIGH",
    "HTTP_FLOOD": "HIGH",
    "POST_RATE_LIMIT": "HIGH",
    "COMMENT_RATE_LIMIT": "HIGH",
    "WEB_SCANNING": "MEDIUM",
    "UNAUTHORIZED_ACCESS": "MEDIUM",
    "PAGE_ACCESS": "MEDIUM",
    "API_MACRO_PATTERN": "MEDIUM",
}
_ACTION = {"CRITICAL": "LOCKED", "HIGH": "REJECTED", "MEDIUM": "ALERTED"}
# 실제 운영 기록처럼 계정·행위 단위 탐지(브루트포스·스프레이·API 매크로)는 경로가 비어 있다. 웹 스캐닝은 긴 경로를 남긴다.
_PATHS = {"BRUTE_FORCE": None, "DISTRIBUTED_BRUTE_FORCE": None, "PASSWORD_SPRAYING": None, "SIGNUP_RATE_LIMIT": "/signup",
          "HTTP_FLOOD": "/board", "POST_RATE_LIMIT": "/board/new", "COMMENT_RATE_LIMIT": "/board/12/comments",
          "WEB_SCANNING": "/.env/__scan_678ea07229d5453ba9624d2ea8f6c221", "UNAUTHORIZED_ACCESS": "/admin/dashboard", "PAGE_ACCESS": "/board", "API_MACRO_PATTERN": None}


def _times(now: datetime):
    """오늘 낮 시간대에 몰리고 지난 6일은 고르게 퍼지는 가짜 탐지 시각."""
    for _ in range(_RNG.randint(1, 4)):
        yield now - timedelta(days=_RNG.choice([0, 0, 0, 1, 1, 2, 3, 4, 5, 6]), hours=_RNG.randint(0, 23), minutes=_RNG.randint(0, 59))


def _fake_raw(now=None):
    now = (now or datetime.now(db_stats.KST)).astimezone(db_stats.KST)
    events, n = [], 0
    for ip, _country, types, weight in _ATTACKERS:
        for _ in range(weight):
            event_type = _RNG.choice(types)
            when = next(_times(now))
            if when > now:
                when -= timedelta(days=1)
            severity = _SEVERITY[event_type]
            n += 1
            events.append({
                "id": n, "event_type": event_type, "severity": severity, "ip_address": ip, "path": _PATHS[event_type],
                "count": _RNG.randint(3, 40), "action": _ACTION[severity], "username": None,
                "detected_at": when.isoformat(), "resolved_at": when.isoformat() if _RNG.random() < 0.55 else None,
            })
    sample = lambda hours: [(now - timedelta(days=_RNG.choice([0, 0, 1, 7]), hours=_RNG.randint(0, hours), minutes=_RNG.randint(0, 59))).isoformat() for _ in range(220)]
    today = now.date()
    summary = [
        {"day": (today - timedelta(days=d)).isoformat(), "source": s, "count": _RNG.randint(80, 900) + (400 if s == "page_access_attempts" else 0)}
        for d in range(1, 7)
        for s in db_stats.LOG_SOURCES
    ]
    incidents = [
        {"id": 1, "ip_address": "203.0.113.57", "event_types": ["BRUTE_FORCE", "WEB_SCANNING", "UNAUTHORIZED_ACCESS", "PASSWORD_SPRAYING"],
         "severity_max": "CRITICAL", "status": "OPEN", "first_event_at": (now - timedelta(hours=5)).isoformat(), "last_event_at": (now - timedelta(minutes=12)).isoformat()},
        {"id": 2, "ip_address": "198.51.100.23", "event_types": ["BRUTE_FORCE", "DISTRIBUTED_BRUTE_FORCE", "API_MACRO_PATTERN"],
         "severity_max": "CRITICAL", "status": "OPEN", "first_event_at": (now - timedelta(hours=9)).isoformat(), "last_event_at": (now - timedelta(hours=1)).isoformat()},
        {"id": 3, "ip_address": "192.0.2.144", "event_types": ["WEB_SCANNING", "HTTP_FLOOD"],
         "severity_max": "HIGH", "status": "IDLE", "first_event_at": (now - timedelta(days=2)).isoformat(), "last_event_at": (now - timedelta(days=1, hours=3)).isoformat()},
        {"id": 4, "ip_address": "203.0.113.9", "event_types": ["BRUTE_FORCE", "PASSWORD_SPRAYING"], "resolved_by": "system:permanent_lock",
         "severity_max": "CRITICAL", "status": "CLOSED", "first_event_at": (now - timedelta(days=3)).isoformat(), "last_event_at": (now - timedelta(days=2)).isoformat()},
        {"id": 5, "ip_address": "198.51.100.77", "event_types": ["WEB_SCANNING", "PAGE_ACCESS"], "resolved_by": "demo-admin",
         "severity_max": "MEDIUM", "status": "CLOSED", "first_event_at": (now - timedelta(days=3)).isoformat(), "last_event_at": (now - timedelta(days=2)).isoformat()},
    ]
    return {
        "now": now, "events": events, "summary": summary, "incidents": incidents,
        "failed_logins": [{"attempted_at": t} for t in sample(23)],
        "not_found": [{"attempted_at": t} for t in sample(23)[:80]],
        "unauthorized": [{"attempted_at": t} for t in sample(23)[:50]],
        "today_counts": {s: _RNG.randint(40, 700) for s in db_stats.LOG_SOURCES},
    }


db_stats.fetch_raw = _fake_raw
db.get_cached_ip_locations = lambda ips: {ip: {"country": country} for ip, country, _t, _w in _ATTACKERS if ip in ips}
db.list_active_lockouts = lambda: [{"ip_address": "203.0.113.57"}, {"ip_address": "198.51.100.23"}]
db.list_active_account_lockouts = lambda: [{"username": "kim_minjae"}]
db.list_active_admin_account_lockouts = lambda: []
db.list_pending_requests = lambda page, size: ([], 2)
db.ensure_bootstrap_admin = lambda: None
db.get_admin_by_id = lambda admin_id: {"id": admin_id, "username": "demo-admin", "role": "super_admin"}
db.log_page_access_attempt = lambda ip, path: None
db.log_api_access = lambda ip, path, method: None
db.log_not_found_attempt = lambda ip, path: None
db.log_unauthorized_attempt = lambda ip, path: None

# ---- 처리 작업대(/api/status)와 회원 화면용 가짜 데이터 ----------------------------------------
def _iso(**delta):
    return (datetime.now(db_stats.KST) - timedelta(**delta)).isoformat()


_USERS = [
    {"id": i + 1, "username": name, "email": f"{name}@example.com", "email_status": status, "created_at": _iso(days=i + 1)}
    for i, (name, status) in enumerate([("kim_minjae", "VERIFIED"), ("lee_seoyeon", "UNKNOWN"), ("park_dohyun", "VERIFIED"), ("choi_harin", "UNDELIVERABLE")])
]
_POSTS = [
    {"id": 3, "title": "점심 메뉴 추천 받습니다", "body": "회사 근처에서 먹을 만한 곳 있을까요? 매운 건 괜찮습니다.", "author_username": "kim_minjae", "created_at": _iso(hours=3)},
    {"id": 2, "title": "로그인이 잠겼을 때 해결한 방법", "body": "이메일 본인 인증으로 풀었습니다.", "author_username": "park_dohyun", "created_at": _iso(days=1)},
    {"id": 1, "title": "처음 인사드립니다", "body": "잘 부탁드립니다.", "author_username": "lee_seoyeon", "created_at": _iso(days=3)},
]
_COMMENTS = [
    {"id": 1, "post_id": 3, "body": "회사 앞 칼국수집 좋아요.", "author_username": "park_dohyun", "created_at": _iso(hours=2)},
    {"id": 2, "post_id": 3, "body": "저도 궁금합니다.", "author_username": "kim_minjae", "created_at": _iso(hours=1)},
]
_ATTEMPTS = [
    {"id": i, "ip_address": ip, "username": user, "success": ok, "attempted_at": _iso(minutes=7 * i + 2)}
    for i, (ip, user, ok) in enumerate([("192.0.2.14", "kim_minjae", True), ("203.0.113.57", "admin", False), ("203.0.113.57", "root", False), ("198.51.100.23", "kim_minjae", False), ("192.0.2.14", "kim_minjae", True), ("203.0.113.9", "test", False)])
]
_EVENTS = [
    {"id": 100 + i, "event_type": t, "severity": sev, "ip_address": ip, "username": None, "path": path, "count": n, "action": act, "detected_at": _iso(minutes=25 * i + 4), "resolved_at": None if i % 3 else _iso(minutes=5)}
    for i, (t, sev, ip, path, n, act) in enumerate([
        ("BRUTE_FORCE", "CRITICAL", "203.0.113.57", "/login", 6, "LOCKED"),
        ("WEB_SCANNING", "MEDIUM", "192.0.2.144", "/wp-login.php", 11, "ALERTED"),
        ("SIGNUP_RATE_LIMIT", "HIGH", "203.0.113.9", "/signup", 5, "REJECTED"),
        ("UNAUTHORIZED_ACCESS", "MEDIUM", "192.0.2.88", "/admin/dashboard", 4, "ALERTED"),
        ("DISTRIBUTED_BRUTE_FORCE", "CRITICAL", "198.51.100.23", "/login", 9, "ACCOUNT_LOCKED"),
    ])
]
_INCIDENTS = [
    {"id": 1, "ip_address": "203.0.113.57", "event_types": ["BRUTE_FORCE", "WEB_SCANNING", "UNAUTHORIZED_ACCESS"], "severity_max": "CRITICAL", "status": "OPEN", "first_event_at": _iso(hours=5), "last_event_at": _iso(minutes=12), "resolved_at": None, "resolved_by": None},
    {"id": 2, "ip_address": "198.51.100.23", "event_types": ["BRUTE_FORCE", "API_MACRO_PATTERN"], "severity_max": "HIGH", "status": "CLOSED", "first_event_at": _iso(days=2), "last_event_at": _iso(days=2, hours=-1), "resolved_at": _iso(days=1), "resolved_by": "demo-admin"},
]
_AI = [{"request_id": 7, "event_type": "BRUTE_FORCE", "target_kind": "ip", "target_value": "198.51.100.201", "count": 4, "threshold": 5, "llm_reason": "서로 다른 아이디 4개를 1분 안에 연달아 시도했고, 같은 사전 단어 패턴이 보입니다.", "requested_at": _iso(minutes=3)}]


def _page(rows, page, size):
    return rows[(page - 1) * size : page * size], len(rows)


db.list_recent_attempts = lambda page, size: _page(_ATTEMPTS, page, size)
db.list_users = lambda page, size: _page(_USERS, page, size)
db.list_posts = lambda page, size: _page(_POSTS, page, size)
db.list_comments_admin = lambda page, size: _page(_COMMENTS, page, size)
db.list_admin_login_log = lambda page, size: _page([{"attempted_at": _iso(hours=2), "username": "demo-admin", "ip_address": "192.0.2.14", "success": True}], page, size)
db.list_security_events = lambda page, size: _page(_EVENTS, page, size)
db.list_security_incidents = lambda page, size: _page(_INCIDENTS, page, size)
db.list_pending_requests = lambda page, size: _page(_AI, page, size)
db.list_active_lockouts = lambda: [
    {"ip_address": "203.0.113.57", "locked_at": _iso(minutes=2), "unlock_at": _iso(minutes=-3), "failure_count": 6, "lock_type": "TEMPORARY"},
    {"ip_address": "198.51.100.23", "locked_at": _iso(days=1), "unlock_at": None, "failure_count": 14, "lock_type": "PERMANENT", "permanent_reason": "REPEAT_OFFENDER", "recoverable": "SELF", "promoted_at": _iso(hours=20)},
]
db.list_active_account_lockouts = lambda: [{"username": "kim_minjae", "locked_at": _iso(minutes=1), "unlock_at": _iso(minutes=-4), "failure_count": 8, "lock_type": "TEMPORARY"}]
db.list_active_admin_account_lockouts = lambda: [{"username": "night_shift", "locked_at": _iso(minutes=9), "unlock_at": _iso(minutes=-1), "failure_count": 5}]
db.list_recent_recovery_requests = lambda n: [{"id": 1, "created_at": _iso(hours=3), "username": "park_dohyun", "target_kind": "account", "target_value": "park_dohyun", "requested_ip": "192.0.2.14", "status": "PENDING"}]
db.list_active_ip_exemptions = lambda n: [{"id": 1, "granted_at": _iso(days=1), "ip_address": "192.0.2.14", "username": "park_dohyun", "expires_at": _iso(days=-29)}]
db.get_signup_enabled = lambda: True
db.get_email_statuses = lambda names: {n: "UNKNOWN" for n in names}
_ALL = ["unlock_ip", "resolve_security_event", "resolve_incident", "toggle_signup", "delete_user", "delete_post", "delete_comment", "manage_admin_users", "approve_pending_action", "promote_permanent_lock", "release_permanent_lock", "revoke_ip_exemption", "revoke_recovery_request", "unlock_admin_account"]
db.list_role_permissions = lambda role: _ALL
db.has_permission = lambda role, action: True
db.list_admin_users = lambda: [{"id": 1, "username": "demo-admin", "role": "super_admin", "created_at": _iso(days=30)}, {"id": 2, "username": "night_shift", "role": "security_viewer", "created_at": _iso(days=4)}]
db.get_user_session_version = lambda user_id: 0
db.get_user_by_id = lambda user_id: {**_USERS[0], "name": "민재"}
db.get_pending_email_token_for_user = lambda user_id, purpose: None
db.list_attempts_by_username = lambda username, n: _ATTEMPTS
db.get_post = lambda post_id: next((p for p in _POSTS if p["id"] == post_id), None)
db.list_comments_by_post = lambda post_id: [c for c in _COMMENTS if c["post_id"] == post_id]
db.get_latest_comment_info = lambda post_id: {"count": len([c for c in _COMMENTS if c["post_id"] == post_id]), "latest_at": _COMMENTS[-1]["created_at"]}
_posts_page = lambda page, size: _page(_POSTS, page, size)

from security import detector  # noqa: E402

detector.is_page_access_suspicious = lambda ip, path: (False, 1, False)
detector.is_macro_pattern_suspicious = lambda ip: (False, 1, False)
detector.is_web_scanning = lambda ip: (False, 1, False)

import app as app_module  # noqa: E402
import routes.admin.status as _status  # noqa: E402
import routes.member as _member  # noqa: E402

_status._attach_locations = lambda rows: [{**r, "location": "Seoul, South Korea"} for r in rows]
_member._attach_locations = _status._attach_locations

app = app_module.app


@app.route("/__demo_member")
def demo_member():
    """데모 전용: 회원 세션을 바로 만들고 회원 대시보드로 보낸다."""
    from flask import redirect, session

    session["username"] = "kim_minjae"
    session["user_id"] = 1
    session["session_version"] = 0
    return redirect("/dashboard")


@app.route("/__demo_login")
def demo_login():
    """데모 전용: 관리자 세션을 바로 만들고 대시보드로 보낸다."""
    from flask import redirect, session

    session["admin_username"] = "demo-admin"
    session["admin_id"] = 1
    session["admin_login_at"] = int(time.time())
    return redirect("/admin/dashboard")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5077))
    print(f"데모 서버: http://127.0.0.1:{port}/__demo_login  (가짜 데이터, DB 접속 없음)")
    app.run(port=port, debug=False)
