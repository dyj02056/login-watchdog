"""시뮬레이션 점검기 — scripts/simulation/ 의 공격 시뮬레이션이 실제로 탐지를 일으키는지 한 번에 확인한다.

    python scripts/demo/check_simulations.py             # 전부 실행
    python scripts/demo/check_simulations.py honeypot    # 이름에 'honeypot'이 들어간 것만

메모리 DB(memory_supabase.py)를 붙인 서버를 127.0.0.1:5000에 띄우고, 시뮬레이션을 하나씩 실행한 뒤 두 가지를
확인한다: (1) 시뮬레이션이 성공(종료 코드 0)했는가, (2) 서버가 기대한 보안 이벤트(event_type + severity)를
security_events에 실제로 기록했는가. 진짜 Supabase·Slack·메일에는 아무것도 보내지 않고, 5000번 포트를 쓰므로
`python app.py`로 띄운 개발 서버가 켜져 있으면 먼저 끈다(signup_abuse_sim·unauthorized_access_sim이 5000번 고정이라서).

개발·점검용이다. 운영에서는 쓰지 않는다.
"""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SIM = ROOT / "scripts" / "simulation"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

HOST = "http://127.0.0.1:5000"
USER, PASSWORD = "simuser", "SimPass-1234!"
VIEWER, VIEWER_PASSWORD = "sim-viewer", "SimViewer-1234!"

# 서버를 띄우기 전에 환경을 덮어쓴다 — .env의 진짜 값이 섞이지 않게 모두 고정한다.
os.environ.update({
    "SECRET_KEY": "sim-check-only-secret-key-0123456789",
    "ADMIN_USERNAME": "sim-admin", "ADMIN_PASSWORD": "sim-admin-password-1234",
    "SUPABASE_URL": "http://supabase.invalid", "SUPABASE_KEY": "sim-check",
    "SLACK_WEBHOOK_URL": "", "GROQ_API_KEY": "", "MAIL_BACKEND": "console",
    "TRUST_FORWARDED_FOR": os.environ.get("TRUST_FORWARDED_FOR", "true"),  # 가짜 공격자 IP(X-Forwarded-For)를 믿는다
    "PERMANENT_LOCK_IP_ALLOWLIST": "127.0.0.1,::1",
    "LOCKOUT_DURATION_SECONDS": "3",        # permanent_lock_sim이 5분을 기다리지 않게 임시 잠금을 짧게
    "RECOVERY_MIN_RESPONSE_SECONDS": "0",   # 복구 요청의 고정 대기(5초)를 없앤다
    "SPA_ENABLED": "false",
})
os.environ.pop("FLASK_ENV", None)

import db  # noqa: E402
from memory_supabase import MemoryClient  # noqa: E402

client = MemoryClient()
db._client = client
db.get_client = lambda: client

import app as app_module  # noqa: E402

KEEP_TABLES = ("users", "admin_users", "settings", "role_permissions")


def seed():
    db.create_user(USER, f"{USER}@example.com", PASSWORD)
    db.create_admin_user(VIEWER, VIEWER_PASSWORD, "security_viewer")


def reset_between_runs():
    """시뮬레이션마다 깨끗한 상태에서 시작한다: 기록·잠금을 비우고 요청 한도 카운터를 초기화한다."""
    client.store.reset(keep=KEEP_TABLES)
    app_module.limiter.reset()


def events():
    return [(row.get("event_type"), row.get("severity")) for row in client.store.rows("security_events")]


# (이름, 시뮬레이션 파일, 인자, 기대 이벤트[(event_type, severity)], 추가 확인 표 이름)
CASES = [
    ("critical", "critical/bruteforce_sim.py", [], [("BRUTE_FORCE", "CRITICAL")]),
    ("critical", "critical/password_spraying_sim.py", ["--interval", "0.3"], [("PASSWORD_SPRAYING", "CRITICAL")]),
    ("critical", "critical/distributed_bruteforce_sim.py", [], [("DISTRIBUTED_BRUTE_FORCE", "CRITICAL")]),
    ("critical", "critical/admin_bruteforce_sim.py", [], [("ADMIN_BRUTE_FORCE", "CRITICAL")]),
    ("critical", "critical/admin_distributed_bruteforce_sim.py", [], [("ADMIN_DISTRIBUTED_BRUTE_FORCE", "CRITICAL")]),
    ("critical", "critical/permanent_lock_sim.py", ["--wait-seconds", "4"], [("PERMANENT_LOCK", "CRITICAL")]),
    ("critical", "critical/incident_correlation_sim.py", [],
     [("WEB_SCANNING", "MEDIUM"), ("UNAUTHORIZED_ACCESS", "MEDIUM"), ("BRUTE_FORCE", "CRITICAL"), ("PERMANENT_LOCK", "CRITICAL")]),
    ("high", "high/signup_abuse_sim.py", [], []),  # 기본 3회는 한도(5) 미만이라 이벤트가 없는 것이 정상
    ("high", "high/signup_abuse_sim.py", ["@attempts=6"], [("SIGNUP_RATE_LIMIT", "HIGH")]),
    ("high", "high/spam_sim.py", ["--username", USER, "--password", PASSWORD, "--attempts", "6", "--interval", "0.05"],
     [("POST_RATE_LIMIT", "HIGH")]),
    ("high", "high/comment_spam_sim.py", ["--username", USER, "--password", PASSWORD], [("COMMENT_RATE_LIMIT", "HIGH")]),
    ("high", "high/http_flood_sim.py", [], [("HTTP_FLOOD", "HIGH")]),
    ("high", "high/recovery_flood_sim.py", ["--target", "recovery"], [("HTTP_FLOOD", "HIGH")]),
    ("high", "high/recovery_flood_sim.py", ["--target", "recovery-verify"], [("HTTP_FLOOD", "HIGH")]),
    ("high", "high/recovery_flood_sim.py", ["--target", "password-forgot"], [("HTTP_FLOOD", "HIGH")]),
    ("high", "high/recovery_flood_sim.py", ["--target", "password-reset"], [("HTTP_FLOOD", "HIGH")]),
    ("high", "high/recovery_flood_sim.py", ["--target", "email-confirm"], [("HTTP_FLOOD", "HIGH")]),
    ("medium", "medium/web_scanning_sim.py", [], [("WEB_SCANNING", "MEDIUM")]),
    ("medium", "medium/unauthorized_access_sim.py", [], [("UNAUTHORIZED_ACCESS", "MEDIUM")]),
    ("medium", "medium/repeated_access_sim.py", [], [("PAGE_ACCESS", "MEDIUM")]),
    ("medium", "medium/macro_bot_sim.py", ["--username", VIEWER, "--password", VIEWER_PASSWORD], [("API_MACRO_PATTERN", "MEDIUM")]),
    ("medium", "medium/honeypot_bot_sim.py", [], [("BOT_DETECTED", "MEDIUM")]),
]


def command_for(path, args):
    # '@attempts=6'은 argparse가 없는 시뮬레이션의 run()을 직접 호출하라는 표시다.
    if args and args[0].startswith("@attempts="):
        attempts = int(args[0].split("=")[1])
        module_dir = str(SIM / Path(path).parent)
        code = (f"import sys; sys.path.insert(0, {module_dir!r}); import {Path(path).stem} as m; "
                f"raise SystemExit(0 if m.run(base_url={HOST!r}, attempts={attempts}, interval=0.05) else 1)")
        return [sys.executable, "-I", "-c", code]
    return [sys.executable, str(SIM / path), *args]


def serve():
    from werkzeug.serving import make_server
    server = make_server("127.0.0.1", 5000, app_module.app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    import logging
    keyword = sys.argv[1] if len(sys.argv) > 1 else ""
    # 서버 스레드가 찍는 요청 로그·Slack 대체 출력은 버리고, 점검 결과만 보여준다.
    sys.stdout.reconfigure(encoding="utf-8")
    report = sys.stdout
    rp = lambda *a, **k: print(*a, file=report, flush=True)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    seed()
    server = serve()
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
    time.sleep(0.3)
    rows, failures = [], 0
    for level, path, args, expected in CASES:
        label = f"{path} {' '.join(a for a in args if not a.startswith('--') or a == '--target')}".strip()
        if keyword and keyword not in label:
            continue
        reset_between_runs()
        started = time.monotonic()
        try:
            done = subprocess.run(command_for(path, args), capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=180, cwd=str(ROOT), env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            code, output = done.returncode, done.stdout + done.stderr
        except subprocess.TimeoutExpired as error:
            code, output = -1, f"시간 초과\n{error.stdout or ''}"
        recorded = events()
        missing = [e for e in expected if e not in recorded]
        ok = code == 0 and not missing
        failures += not ok
        rows.append((ok, level, label, code, time.monotonic() - started, missing, sorted(set(recorded))))
        rp(f"[{'PASS' if ok else 'FAIL'}] {level:<8} {label:<68} 종료코드={code} {time.monotonic() - started:5.1f}s")
        if not ok:
            rp(f"        누락된 이벤트: {missing}\n        기록된 이벤트: {sorted(set(recorded))}")
            rp("        --- 시뮬레이션 출력(끝 15줄) ---")
            rp("\n".join("        " + line for line in output.strip().splitlines()[-15:]))
    server.shutdown()
    rp(f"\n합계:{len(rows) - failures} PASS / {failures} FAIL / 총 {len(rows)}건")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
