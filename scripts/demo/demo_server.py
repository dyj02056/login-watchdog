"""화면 확인용 데모 서버 — generate_demo_logs.py가 만든 7일치 샘플 로그로 관제 화면을 띄운다. Supabase에 접속하지 않는다.

    python scripts/demo/generate_demo_logs.py     # 먼저 한 번: 샘플 로그 생성 (scripts/demo/output/demo_logs.json)
    python scripts/demo/demo_server.py            # http://127.0.0.1:5077/__demo_login

    python scripts/demo/demo_server.py --no-shift   # 기록 시각을 지금으로 옮기지 않고 생성 당시 그대로 보기

실제 DB·Slack·메일에는 아무것도 보내지 않는다(DB를 메모리에 올린 가짜로 바꾸고, IP 위치 조회 서비스도 부르지 않는다).
접속하면 관리자로 이미 로그인된 상태가 되어 /admin/dashboard가 바로 열린다. 기록의 시각은 열 때마다 "지금"을 기준으로
옮겨서(가장 최근 기록 ≈ 방금) 며칠 전에 만든 파일도 항상 최근 7일처럼 보인다.

디자인 검토·스크린샷·시연용이다. 운영에서는 쓰지 않는다.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEFAULT_LOGS = HERE / "output" / "demo_logs.json"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

os.environ.setdefault("SECRET_KEY", "demo-only-secret-key")
os.environ["ADMIN_USERNAME"] = "demo-admin"
os.environ["ADMIN_PASSWORD"] = "DemoAdmin#2026x"
os.environ["SUPABASE_URL"] = "http://supabase.invalid"
os.environ["SUPABASE_KEY"] = "demo-key"
os.environ["SLACK_WEBHOOK_URL"] = ""
os.environ["GROQ_API_KEY"] = ""
os.environ["MAIL_BACKEND"] = "console"
os.environ.pop("FLASK_ENV", None)

parser = argparse.ArgumentParser(description="샘플 로그로 대시보드를 띄우는 데모 서버")
parser.add_argument("--logs", default=str(DEFAULT_LOGS), help="generate_demo_logs.py가 만든 JSON 파일")
parser.add_argument("--no-shift", action="store_true", help="시각을 지금 기준으로 옮기지 않는다")
parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5077)))
args = parser.parse_args() if __name__ == "__main__" else parser.parse_args([])

import db  # noqa: E402
import demo_data as dd  # noqa: E402
from memory_supabase import MemoryClient  # noqa: E402

logs_path = Path(args.logs)
if not logs_path.exists():
    sys.exit(f"샘플 로그 파일이 없습니다: {logs_path}\n먼저 실행하세요:  python scripts/demo/generate_demo_logs.py")

dump = json.loads(logs_path.read_text(encoding="utf-8"))
if not args.no_shift:
    dd.shift_dump_to_now(dump)

if not args.no_shift:   # 아직 풀리지 않은 임시 잠금은 서버를 켠 시각부터 5분 뒤에 풀리게 해서, 켜자마자 "현재 잠긴 IP·계정"이 보이게 한다
    from datetime import datetime, timedelta, timezone

    _now = datetime.now(timezone.utc)
    for _table in ("lockouts", "account_lockouts", "admin_account_lockouts"):
        for _row in dump["tables"].get(_table, []):
            if _row.get("active") and _row.get("lock_type", "TEMPORARY") == "TEMPORARY" and _row.get("unlock_at"):
                if dd.parse_iso(_row["unlock_at"]) > _now:
                    _row["unlock_at"] = (_now + timedelta(minutes=5)).isoformat()

client = MemoryClient()
for name, rows in dump["tables"].items():
    client.store.tables[name] = rows
    # 이후 새로 생기는 행(대시보드 조작)이 기존 번호와 겹치지 않게 번호표를 이어 붙인다
    key = "request_id" if name == "access_requests" else "id"
    import itertools
    client.store._ids[name] = itertools.count(max([r.get(key) or 0 for r in rows], default=0) + 1)
db._client = client
db.get_client = lambda: client

# 이 데모 서버는 시각을 옮긴 기록을 읽기만 한다 — 위치 조회 서비스(ip-api.com)와 외부 전송은 막는다.
import services.geoip as geoip  # noqa: E402

geoip._fetch_location = lambda ip: {"country": None, "region_name": None, "city": None, "lookup_failed": True}

# 권한 표(roles/permissions)는 샘플 로그에 들어 있지 않다 — 데모 관리자는 모든 조작을 볼 수 있게 한다.
db.has_permission = lambda role, action: True
db.list_role_permissions = lambda role: [
    "unlock_ip", "resolve_security_event", "resolve_incident", "toggle_signup", "delete_user", "delete_post", "delete_comment",
    "manage_admin_users", "approve_pending_action", "promote_permanent_lock", "release_permanent_lock", "revoke_ip_exemption",
    "revoke_recovery_request", "unlock_admin_account",
]

import app as app_module  # noqa: E402

app = app_module.app


def _first_user_id() -> int:
    users = client.store.tables.get("users", [])
    return min((u["id"] for u in users), default=1)


@app.route("/__demo_member")
def demo_member():
    """데모 전용: 회원 세션을 바로 만들고 회원 대시보드로 보낸다."""
    from flask import redirect, session

    user = next((u for u in client.store.tables.get("users", []) if u["username"] == "kim_minjae"), None) or client.store.tables["users"][0]
    session["username"] = user["username"]
    session["user_id"] = user["id"]
    session["session_version"] = user.get("session_version", 0)
    return redirect("/dashboard")


@app.route("/__demo_login")
def demo_login():
    """데모 전용: 관리자 세션을 바로 만들고 대시보드로 보낸다."""
    from flask import redirect, session

    admin_id = db.get_admin_id_by_username("demo-admin") or 1
    session["admin_username"] = "demo-admin"
    session["admin_id"] = admin_id
    session["admin_login_at"] = int(time.time())
    return redirect("/admin/dashboard")


if __name__ == "__main__":
    print(f"데모 서버: http://127.0.0.1:{args.port}/__demo_login  (샘플 로그 {logs_path.name}, DB 접속 없음)")
    app.run(port=args.port, debug=False)
