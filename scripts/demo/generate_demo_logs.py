"""7일치 샘플 로그 생성기 — 실제 서버를 내 컴퓨터에 켜고, 회원가입·로그인·공격 시뮬레이션을 진짜로 돌려서 기록을 만든다.

    python scripts/demo/generate_demo_logs.py                # 7일치 생성 → scripts/demo/output/demo_logs.json
    python scripts/demo/generate_demo_logs.py --seed 7       # 같은 숫자면 같은 결과, 다른 숫자면 다른 순서·모양
    python scripts/demo/generate_demo_logs.py --use-groq     # AI 조기경보를 진짜 Groq API로 판정(.env의 GROQ_API_KEY 필요)
    python scripts/demo/generate_demo_logs.py --days 7 --members 12

흐름
  ① 메모리 DB(memory_supabase.py)를 붙인 서버를 127.0.0.1:5000에 켠다 (진짜 Supabase·Slack·메일에는 접속하지 않는다. --use-groq를 줄 때만 Groq API로 조기경보 판정 요청을 보낸다)
  ② 가짜 회원을 /signup 화면으로 실제 가입시킨다
  ③ 정상 접속(로그인·글·댓글)과 공격 시뮬레이션 21종을 "시각 순서"대로 실행한다. 각 묶음은 끝날 때마다 기록의 시각을
     미리 뽑아 둔 시각(지난 7일 안의 무작위)으로 옮기고, 공격자 IP를 여러 나라의 IP로 바꾼다
  ④ 일별 요약표·관리자 처리 이력을 채우고, 대시보드에 '-'로 보일 빈칸을 가능한 만큼 채운다
  ⑤ JSON 한 파일로 저장한다 → demo_server.py가 읽어서 보여주고, load_demo_to_supabase.py가 DB에 넣을 수 있다

개발·시연용이다. 운영 서버나 운영 DB에는 접속하지 않으며, 접속할 수도 없다(DB 주소를 존재하지 않는 값으로 덮어쓴다).
"""

import argparse
import copy
import itertools
import json
import os
import random
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SIM = ROOT / "scripts" / "simulation"
OUTPUT = HERE / "output" / "demo_logs.json"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

HOST = "http://127.0.0.1:5000"

# --use-groq: AI 조기경보를 로컬 판정기 대신 진짜 Groq API로 만든다. 이때만 .env의 GROQ_API_KEY를 읽는다(다른 .env 값은 읽지 않는다).
# 환경을 덮어쓰기 전에 키를 꺼내 둬야 해서 argparse보다 먼저 확인한다.
USE_GROQ = "--use-groq" in sys.argv
GROQ_KEY = ""
if USE_GROQ:
    from dotenv import dotenv_values

    GROQ_KEY = os.environ.get("GROQ_API_KEY") or dotenv_values(ROOT / ".env").get("GROQ_API_KEY") or ""
    if not GROQ_KEY:
        sys.exit("--use-groq: GROQ_API_KEY를 찾지 못했습니다. .env에 GROQ_API_KEY=발급받은키 를 넣거나 환경변수로 지정하세요.")

# 서버를 띄우기 전에 환경을 덮어쓴다 — .env의 진짜 값(Supabase 주소·키, Slack, Groq)이 섞이지 않게 모두 고정한다.
os.environ.update({
    "SECRET_KEY": "demo-generate-only-secret-key-0123456789",
    "ADMIN_USERNAME": "demo-admin", "ADMIN_PASSWORD": "DemoAdmin#2026x",
    "SUPABASE_URL": "http://supabase.invalid", "SUPABASE_KEY": "demo-generate",
    "SLACK_WEBHOOK_URL": "", "GROQ_API_KEY": GROQ_KEY, "MAIL_BACKEND": "console",
    "TRUST_FORWARDED_FOR": "true",            # 가짜 공격자 IP(X-Forwarded-For)를 접속 IP로 믿는다
    "PERMANENT_LOCK_IP_ALLOWLIST": "127.0.0.1,::1",
    "LOCKOUT_DURATION_SECONDS": "3",          # 영구 잠금 시뮬레이션이 5분을 기다리지 않게 (기록의 해제 시각은 나중에 5분으로 고친다)
    "RECOVERY_MIN_RESPONSE_SECONDS": "0",
    "SPA_ENABLED": "false",                   # 시뮬레이션이 읽는 건 서버가 그리는 HTML 화면이다
})
os.environ.pop("FLASK_ENV", None)

import requests  # noqa: E402

import db  # noqa: E402
from memory_supabase import MemoryClient  # noqa: E402

client = MemoryClient()
db._client = client
db.get_client = lambda: client
assert "supabase.invalid" in os.environ["SUPABASE_URL"], "운영 DB에 연결될 수 있는 설정입니다"

import app as app_module  # noqa: E402
from services import llm_client  # noqa: E402

import demo_data as dd  # noqa: E402

sys.path.insert(0, str(SIM))
from _sim_common import extract_csrf_token  # noqa: E402

LOCK_SECONDS = 300          # 기록에 남길 임시 잠금 시간(실제 설정 기본값)
RUN_TIMEOUT = 420

# 시뮬레이션이 만드는 이벤트 → 대시보드에 비어 보이지 않게 채워 둘 대표 경로
DEFAULT_PATH = {
    "BRUTE_FORCE": "/login", "DISTRIBUTED_BRUTE_FORCE": "/login", "PASSWORD_SPRAYING": "/login",
    "ADMIN_BRUTE_FORCE": "/admin/login", "ADMIN_DISTRIBUTED_BRUTE_FORCE": "/admin/login",
    "PERMANENT_LOCK": "/login", "BOT_DETECTED": "/login", "API_MACRO_PATTERN": "/api/unlock",
    "SIGNUP_RATE_LIMIT": "/signup", "POST_RATE_LIMIT": "/board/new", "COMMENT_RATE_LIMIT": "/board/1/comments",
    "HTTP_FLOOD": "/login",
}
LOGIN_EVENT_TYPES = {"BRUTE_FORCE", "DISTRIBUTED_BRUTE_FORCE", "PASSWORD_SPRAYING", "PERMANENT_LOCK", "BOT_DETECTED"}
ADMIN_EVENT_TYPES = {"ADMIN_BRUTE_FORCE", "ADMIN_DISTRIBUTED_BRUTE_FORCE"}
IP_COLUMNS = ("ip_address", "requested_ip", "context_ip", "triggering_ip")
COMMON_USERNAMES = ["admin", "root", "test", "administrator", "guest", "user", "support", "webmaster"]


# ---------------------------------------------------------------------------
# 서버와 도우미
# ---------------------------------------------------------------------------

class _InjectIp:
    """X-Forwarded-For가 없는 요청에 '지금 묶음의 공격자 IP'를 붙여 준다 — IP 옵션이 없는 시뮬레이션도 그 나라에서 온 것처럼."""

    current_ip = "127.0.0.1"

    def __init__(self, wsgi):
        self.wsgi = wsgi

    def __call__(self, environ, start_response):
        if not environ.get("HTTP_X_FORWARDED_FOR"):
            environ["HTTP_X_FORWARDED_FOR"] = _InjectIp.current_ip
        return self.wsgi(environ, start_response)


def serve():
    from werkzeug.serving import make_server
    app_module.app.wsgi_app = _InjectIp(app_module.app.wsgi_app)
    server = make_server("127.0.0.1", 5000, app_module.app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


REASONS = {
    "BRUTE_FORCE": "서로 다른 아이디를 짧은 시간에 연달아 시도했고, 임계값({t})까지 {r}회 남았습니다. 사전 단어 대입 패턴으로 보입니다.",
    "DISTRIBUTED_BRUTE_FORCE": "같은 계정을 여러 IP가 번갈아 시도하고 있습니다. 실패 {c}회로 계정 잠금 기준({t})에 거의 닿았습니다.",
    "SIGNUP_RATE_LIMIT": "같은 IP에서 가입 요청이 {c}번 이어졌고 자동 생성 도구의 간격과 비슷합니다. 한도({t})까지 {r}회 남았습니다.",
    "WEB_SCANNING": "존재하지 않는 경로를 {c}번 연달아 요청했습니다. 관리자·설정 파일을 찾는 스캐너 패턴입니다.",
    "UNAUTHORIZED_ACCESS": "로그인 없이 관리자 전용 API를 {c}번 두드렸습니다. 기준({t})을 곧 넘길 것으로 보입니다.",
    "PAGE_ACCESS": "같은 페이지를 {c}번 반복 요청했습니다. 사람의 새로고침보다 일정한 간격입니다.",
    "API_MACRO_PATTERN": "서로 다른 관리 API를 {c}개 연속 호출했습니다. 매크로·봇의 접근 순서와 같습니다.",
}


from security.soar.early_warning import _EARLY_WARNING_LABELS  # noqa: E402

_LABEL_TO_TYPE = {label: kind for kind, label in _EARLY_WARNING_LABELS.items()}


def fake_judge(label, target_kind, target_value, count, threshold, path=None, context_count=None, prior_occurrences=0):
    """Groq 호출 대신 쓰는 로컬 판정기 — 인터넷·API 키 없이 조기경보 요청이 만들어지게 한다(대부분 위험, 일부는 정상으로 판정)."""
    if random.random() < 0.15:
        return {"risky": False, "reason": "정상 사용자의 오타로 보입니다."}
    event_type = _LABEL_TO_TYPE.get(label, "BRUTE_FORCE")
    text = REASONS.get(event_type, "임계값에 가까운 비정상 패턴입니다.").format(c=count, t=threshold, r=max(threshold - count, 0))
    if prior_occurrences:
        text += f" 같은 대상이 최근 {prior_occurrences}번 더 보고되었습니다."
    return {"risky": True, "reason": text}


GROQ_STATS = {"calls": 0, "risky": 0, "safe": 0, "failed": 0}


def counted_groq_judge(*args, **kwargs):
    """진짜 Groq 판정을 그대로 쓰되, 몇 번 불렀고 결과가 어땠는지 센다(실패하면 서버는 조용히 넘어가므로 따로 알려야 한다)."""
    GROQ_STATS["calls"] += 1
    judgment = _real_judge(*args, **kwargs)
    if judgment is None:
        GROQ_STATS["failed"] += 1
    else:
        GROQ_STATS["risky" if judgment.get("risky") else "safe"] += 1
    return judgment


_real_judge = llm_client.judge_early_warning
llm_client.judge_early_warning = counted_groq_judge if USE_GROQ else fake_judge


# ---------------------------------------------------------------------------
# 기록 묶음의 사후 처리: 무엇이 새로 생겼는지 찾고 → IP 바꾸기 → 시각 옮기기
# ---------------------------------------------------------------------------

def snapshot() -> dict:
    with client.store.lock:
        return {name: copy.deepcopy(rows) for name, rows in client.store.tables.items()}


def changed_rows(before: dict):
    """(행, 바뀐 칸 목록 또는 None=새 행)을 돌려준다."""
    with client.store.lock:
        for name, rows in client.store.tables.items():
            old = before.get(name, [])
            for index, row in enumerate(rows):
                if index >= len(old):
                    yield name, row, None
                elif row != old[index]:
                    yield name, row, [k for k in row if row.get(k) != old[index].get(k)]


@dataclass
class Context:
    rng: random.Random
    pool: dd.IpPool
    now: datetime
    members: list = field(default_factory=list)   # [{username, email, password, ip, created_at}]
    log: list = field(default_factory=list)


def remap_foreign_ips(ctx: Context, rows) -> dict:
    """시뮬레이션이 스스로 만든 IP(문서용 대역 등)를 여러 나라의 IP로 바꾼다."""
    foreign = []
    for _name, row, keys in rows:
        for column in IP_COLUMNS:
            value = row.get(column)
            if isinstance(value, str) and dd.IPV4.fullmatch(value) and value not in ctx.pool.country_of and value not in foreign:
                if keys is None or column in keys:
                    foreign.append(value)
        if row.get("target_kind") == "ip" and dd.IPV4.fullmatch(str(row.get("target_value", ""))):
            value = row["target_value"]
            if value not in ctx.pool.country_of and value not in foreign:
                foreign.append(value)
    mapping = {}
    for ip, new_ip in zip(foreign, ctx.pool.pick_mixed(len(foreign)) if foreign else []):
        mapping[ip] = new_ip
    if mapping:
        for _name, row, keys in rows:
            for key, value in list(row.items()):
                if isinstance(value, str) and (keys is None or key in keys):
                    for old, new in mapping.items():
                        if old in value:
                            row[key] = value = value.replace(old, new)
    return mapping


def move_to(rows, when: datetime) -> None:
    """묶음 안에서 가장 이른 시각이 when이 되도록, 묶음 전체의 시각을 같은 만큼 옮긴다(앞뒤 순서는 그대로)."""
    times = []
    for _name, row, keys in rows:
        for key in keys if keys is not None else row:
            if dd.is_time_string(row.get(key)):
                times.append(dd.parse_iso(row[key]))
    if not times:
        return
    delta = when - min(times)
    for _name, row, keys in rows:
        dd.shift_row_times(row, delta, keys)


def normalize_locks(rows, live: bool, rng: random.Random) -> None:
    """3초짜리 임시 잠금을 실제 설정(5분)처럼 고친다. 방금 일어난 공격(live)의 임시 잠금은 아직 풀리지 않은 채로 둔다."""
    for name, row, keys in rows:
        if name in ("lockouts", "account_lockouts", "admin_account_lockouts") and row.get("unlock_at") and row.get("locked_at"):
            if row.get("lock_type", "TEMPORARY") == "TEMPORARY" and (keys is None or "unlock_at" in keys or "locked_at" in keys):
                row["unlock_at"] = (dd.parse_iso(row["locked_at"]) + timedelta(seconds=LOCK_SECONDS)).isoformat()
                if live:
                    row["unlock_at"] = (datetime.now(timezone.utc) + timedelta(seconds=rng.randint(120, 240))).isoformat()


def settle_locks(now: datetime) -> None:
    """풀릴 시각이 지난 임시 잠금을 앱과 같은 방식으로 풀고, 그때 정리되는 이벤트·이력에 풀린 시각을 적는다."""
    with client.store.lock:
        t = client.store.tables
        for table, key, kind in (("lockouts", "ip_address", "ip"), ("account_lockouts", "username", "account"), ("admin_account_lockouts", "username", "admin_account")):
            for lock in t.get(table, []):
                if lock.get("lock_type") == "PERMANENT" or not lock.get("unlock_at"):
                    continue
                unlock = dd.parse_iso(lock["unlock_at"])
                if unlock > now:
                    continue
                lock["active"] = False
                target = lock[key]
                for event in t.get("security_events", []):
                    matches = event.get("ip_address") == target if kind == "ip" else event.get("username") == target
                    if matches and event.get("resolved_at") is None and dd.parse_iso(event["detected_at"]) <= unlock:
                        event["resolved_at"] = unlock.isoformat()
                for hist in t.get("lock_history", []):
                    if hist.get("target_value") == target and hist.get("lock_type") == "TEMPORARY" and hist.get("target_kind") == kind:
                        if dd.parse_iso(hist["locked_at"]) <= unlock and (hist.get("released_at") is None or dd.parse_iso(hist["released_at"]) < unlock):
                            hist["released_at"] = unlock.isoformat()
                            hist["released_by"] = "AUTO_EXPIRE"


def finish_batch(ctx: Context, before: dict, when: datetime, live: bool) -> dict:
    rows = list(changed_rows(before))
    mapping = remap_foreign_ips(ctx, rows)
    move_to(rows, when)
    normalize_locks(rows, live, ctx.rng)
    settle_locks(datetime.now(timezone.utc))
    return {"rows": len(rows), "remapped": len(mapping)}


# ---------------------------------------------------------------------------
# 정상 접속 (회원가입·로그인·글·댓글) — requests로 실제 화면에 접속한다
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]


def web_session(ctx: Context, ip: str) -> requests.Session:
    session = requests.Session()
    session.headers["X-Forwarded-For"] = ip
    session.headers["User-Agent"] = ctx.rng.choice(USER_AGENTS)
    return session


def post_form(session, path, data, csrf):
    return session.post(f"{HOST}{path}", data={**data, "csrf_token": csrf, "website": ""},
                        headers={"Referer": f"{HOST}{path}"}, allow_redirects=False, timeout=10)


def csrf_for(session, path) -> str:
    return extract_csrf_token(session.get(f"{HOST}{path}", timeout=10).text, path)


def signup(ctx: Context, member: dict) -> bool:
    session = web_session(ctx, member["ip"])
    response = post_form(session, "/signup", {
        "username": member["username"], "email": member["email"],
        "password": member["password"], "password_confirm": member["password"],
    }, csrf_for(session, "/signup"))
    return response.status_code in (301, 302, 303) and "/login" in response.headers.get("Location", "")


def member_login(session, member, password=None) -> bool:
    response = post_form(session, "/login", {"username": member["username"], "password": password or member["password"]},
                         csrf_for(session, "/login"))
    return response.status_code in (301, 302, 303) and "/dashboard" in response.headers.get("Location", "")


def member_session(ctx: Context, member: dict) -> dict:
    """회원 한 명의 접속: (가끔 비밀번호 오타) → 로그인 → 게시판 → (가끔) 글·댓글."""
    rng = ctx.rng
    session = web_session(ctx, member["ip"])
    done = {"login": False, "posts": 0, "comments": 0}
    if rng.random() < 0.25:
        member_login(session, member, password="wrong-" + member["password"])
    if not member_login(session, member):
        return done
    done["login"] = True
    board = session.get(f"{HOST}/board", timeout=10)
    session.get(f"{HOST}/dashboard", timeout=10)
    if rng.random() < 0.35:
        token = csrf_for(session, "/board/new")
        title = rng.choice(["점심 메뉴 추천 받습니다", "로그인이 잠겼을 때 해결한 방법", "이번 주 스터디 일정", "보안 공지 확인했어요",
                            "비밀번호 바꾸는 방법 공유", "새 기능 써봤는데 좋네요", "주말 모임 장소 투표"])
        body = rng.choice(["다들 어떻게 생각하세요? 의견 부탁드립니다.", "도움이 됐으면 좋겠습니다.", "자세한 내용은 댓글로 남겨 주세요.", "잘 부탁드립니다."])
        response = post_form(session, "/board/new", {"title": f"{title}", "body": body}, token)
        if response.status_code in (301, 302, 303):
            done["posts"] += 1
    ids = sorted({int(x) for x in __import__("re").findall(r"/board/(\d+)", board.text)})
    if ids and rng.random() < 0.55:
        post_id = rng.choice(ids)
        detail = session.get(f"{HOST}/board/{post_id}", timeout=10)
        try:
            token = extract_csrf_token(detail.text, "게시글")
            comment = rng.choice(["저도 궁금했어요.", "좋은 정보 감사합니다.", "회사 앞 칼국수집 좋아요.", "동의합니다!", "확인했습니다."])
            response = post_form(session, f"/board/{post_id}/comments", {"body": comment}, token)
            done["comments"] += response.status_code in (301, 302, 303)
        except RuntimeError:
            pass
    return done


def admin_session(ctx: Context, username: str, ip: str, fail_first: bool) -> bool:
    """관리자가 대시보드를 여는 접속 (가끔 비밀번호 오타). 관리자 로그인 기록과 API 사용 기록이 남는다."""
    session = web_session(ctx, ip)
    if fail_first:
        post_form(session, "/admin/login", {"username": username, "password": "wrong-password"}, csrf_for(session, "/admin/login"))
    response = post_form(session, "/admin/login", {"username": username, "password": dd.ADMIN_PASSWORD}, csrf_for(session, "/admin/login"))
    if response.status_code not in (301, 302, 303):
        return False
    for _ in range(ctx.rng.randint(2, 4)):
        session.get(f"{HOST}/api/status", timeout=10)
    return True


# ---------------------------------------------------------------------------
# 공격 시뮬레이션 21종 (+ 조기경보를 노린 임계값 직전 변형)
# ---------------------------------------------------------------------------

def py_run(module_path, call):
    """argparse가 없는 시뮬레이션의 run()을 직접 부른다."""
    module_dir = str(SIM / Path(module_path).parent)
    code = (f"import sys; sys.path.insert(0, {module_dir!r}); import {Path(module_path).stem} as m; "
            f"raise SystemExit(0 if {call} else 1)")
    return [sys.executable, "-I", "-c", code]


def any_member(ctx):
    return ctx.rng.choice(ctx.members)


def common_or_member(ctx):
    return ctx.rng.choice(COMMON_USERNAMES + [m["username"] for m in ctx.members])


# 키 → (위험도, 명령을 만드는 함수(ctx, ip) → list, 이 시뮬레이션이 스스로 여러 IP를 쓰는가)
ATTACKS = {
    "bruteforce": ("critical", lambda c, ip: [str(SIM / "critical/bruteforce_sim.py"), "--username", common_or_member(c), "--ip", ip], False),
    "password_spraying": ("critical", lambda c, ip: [str(SIM / "critical/password_spraying_sim.py"), "--interval", "0.3",
                                                     "--usernames", ",".join(c.rng.sample([m["username"] for m in c.members] + COMMON_USERNAMES, 6))], False),
    "distributed_bruteforce": ("critical", lambda c, ip: [str(SIM / "critical/distributed_bruteforce_sim.py"),
                                                          "--username", any_member(c)["username"]], True),
    "admin_bruteforce": ("critical", lambda c, ip: [str(SIM / "critical/admin_bruteforce_sim.py"), "--ip", ip,
                                                    "--username", c.rng.choice(["admin", "superadmin", "sysadmin", "administrator"])], False),
    "admin_distributed_bruteforce": ("critical", lambda c, ip: [str(SIM / "critical/admin_distributed_bruteforce_sim.py"),
                                                                "--username", c.rng.choice(["admin", "root", "manager"])], True),
    "permanent_lock": ("critical", lambda c, ip: [str(SIM / "critical/permanent_lock_sim.py"), "--ip", ip, "--wait-seconds", "4",
                                                  "--username", common_or_member(c)], False),
    "incident_correlation": ("critical", lambda c, ip: [str(SIM / "critical/incident_correlation_sim.py"), "--ip", ip,
                                                        "--username", common_or_member(c)], False),
    "signup_abuse": ("high", lambda c, ip: py_run("high/signup_abuse_sim.py", f"m.run(base_url={HOST!r}, attempts=6, interval=0.05, ip={ip!r})"), False),
    "post_spam": ("high", lambda c, ip: [str(SIM / "high/spam_sim.py"), "--username", (m := any_member(c))["username"], "--password", m["password"],
                                         "--attempts", "6", "--interval", "0.05"], False),
    "comment_spam": ("high", lambda c, ip: [str(SIM / "high/comment_spam_sim.py"), "--username", (m := any_member(c))["username"], "--password", m["password"]], False),
    "http_flood": ("high", lambda c, ip: [str(SIM / "high/http_flood_sim.py"), "--ip", ip, "--path", c.rng.choice(["/login", "/board", "/signup"])], False),
    "recovery_flood": ("high", lambda c, ip: [str(SIM / "high/recovery_flood_sim.py"), "--ip", ip, "--target", "recovery"], False),
    "recovery_verify_flood": ("high", lambda c, ip: [str(SIM / "high/recovery_flood_sim.py"), "--ip", ip, "--target", "recovery-verify"], False),
    "password_forgot_flood": ("high", lambda c, ip: [str(SIM / "high/recovery_flood_sim.py"), "--ip", ip, "--target", "password-forgot"], False),
    "password_reset_flood": ("high", lambda c, ip: [str(SIM / "high/recovery_flood_sim.py"), "--ip", ip, "--target", "password-reset"], False),
    "email_confirm_flood": ("high", lambda c, ip: [str(SIM / "high/recovery_flood_sim.py"), "--ip", ip, "--target", "email-confirm"], False),
    "web_scanning": ("medium", lambda c, ip: [str(SIM / "medium/web_scanning_sim.py")], False),
    "unauthorized_access": ("medium", lambda c, ip: [str(SIM / "medium/unauthorized_access_sim.py")], False),
    "repeated_access": ("medium", lambda c, ip: [str(SIM / "medium/repeated_access_sim.py"), "--ip", ip], False),
    "macro_bot": ("medium", lambda c, ip: [str(SIM / "medium/macro_bot_sim.py"), "--username", "night_shift", "--password", dd.ADMIN_PASSWORD], False),
    "honeypot_bot": ("medium", lambda c, ip: [str(SIM / "medium/honeypot_bot_sim.py"), "--ip", ip], False),
}
# 임계값 바로 아래까지만 두드려서 "AI 조기경보" 승인 대기 요청이 생기게 하는 변형
EARLY_WARNING = {
    "ew_bruteforce": lambda c, ip: [str(SIM / "critical/bruteforce_sim.py"), "--username", common_or_member(c), "--ip", ip, "--attempts", "4"],
    "ew_signup": lambda c, ip: py_run("high/signup_abuse_sim.py", f"m.run(base_url={HOST!r}, attempts=4, interval=0.05, ip={ip!r})"),
    "ew_distributed": lambda c, ip: [str(SIM / "critical/distributed_bruteforce_sim.py"), "--ips", "3", "--per-ip", "2",
                                     "--username", any_member(c)["username"]],
}


@dataclass(order=True)
class Batch:
    when: datetime
    kind: str = field(compare=False)
    ip: str = field(compare=False, default="")
    live: bool = field(compare=False, default=False)
    payload: dict = field(compare=False, default_factory=dict)


def attack_time(rng: random.Random, now: datetime, days: int, live=False, day=None) -> datetime:
    if live:
        return now - timedelta(minutes=rng.randint(4, 85))
    for _ in range(200):
        day = rng.randint(0, days - 1) if day is None else day
        hour = rng.choice([0, 1, 2, 3, 4, 5]) if rng.random() < 0.6 else rng.randint(0, 23)
        base = now.astimezone(dd.KST).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=day)
        when = base + timedelta(hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        if now - timedelta(days=days) < when < now - timedelta(hours=3):
            return when.astimezone(timezone.utc)
    return attack_time(rng, now, days)   # 그 날에 맞는 시각이 없으면(오늘 새벽 등) 아무 날이나


def build_plan(ctx: Context, days: int) -> list[Batch]:
    rng, pool, now = ctx.rng, ctx.pool, ctx.now
    plan: list[Batch] = []
    day_order = itertools.cycle(rng.sample(range(days), days))   # 공격이 7일에 고르게 퍼지도록 날짜를 돌아가며 배정한다
    spread = lambda: attack_time(rng, now, days, day=next(day_order))

    # 정상 회원: 가입 → 하루 한두 번 접속
    for member in ctx.members:
        plan.append(Batch(member["created_at"], "signup", member["ip"], payload={"member": member}))
        for day in range(days):
            if rng.random() < 0.7:
                base = now.astimezone(dd.KST).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=day)
                when = (base + timedelta(hours=rng.randint(8, 22), minutes=rng.randint(0, 59))).astimezone(timezone.utc)
                if member["created_at"] + timedelta(hours=2) < when < now - timedelta(minutes=30):
                    plan.append(Batch(when, "member", member["ip"], payload={"member": member}))
    # 관리자: 하루 한두 번 대시보드 확인
    for day in range(days):
        for username in rng.sample([a[0] for a in dd.ADMIN_ACCOUNTS], rng.randint(1, 2)):
            base = now.astimezone(dd.KST).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=day)
            when = (base + timedelta(hours=rng.randint(9, 18), minutes=rng.randint(0, 59))).astimezone(timezone.utc)
            if when < now - timedelta(minutes=30):
                plan.append(Batch(when, "admin", pool.pick("South Korea"), payload={"username": username, "fail": rng.random() < 0.2}))

    # 공격 21종: 한 번씩은 반드시, 시각은 지난 7일 안에서 무작위(새벽에 많이 몰림)
    for key in ATTACKS:
        plan.append(Batch(spread(), key, pool.pick()))
    # 같은 IP가 여러 날 돌아오는 반복 공격자 3명 (반복 위반 → 영구 잠금까지 이어지는 흐름)
    repeatable = [k for k, v in ATTACKS.items() if not v[2] and k not in ("permanent_lock", "incident_correlation", "honeypot_bot", "http_flood")]
    for _ in range(3):
        ip = pool.pick()
        for when, key in zip(sorted(attack_time(rng, now, days, day=d) for d in rng.sample(range(days), 4)),
                             rng.sample(["web_scanning", "unauthorized_access", "bruteforce", "repeated_access", "bruteforce"], 4)):
            plan.append(Batch(when, key, ip))
    # 같은 계정을 두 번 노리는 분산 공격 (계정 영구 잠금)
    target = any_member(ctx)["username"]
    for when in sorted(attack_time(rng, now, days) for _ in range(2)):
        plan.append(Batch(when, "distributed_bruteforce", pool.pick(), payload={"username": target}))
    # 무작위 추가 공격과 조기경보용 변형
    for _ in range(14):
        plan.append(Batch(spread(), rng.choice(repeatable + ["distributed_bruteforce"]), pool.pick()))
    for key in EARLY_WARNING:
        for _ in range(2):
            plan.append(Batch(spread(), key, pool.pick()))
    # 방금 일어난 공격(진행 중 사건·활성 잠금·승인 대기가 보이도록)
    for key in ("incident_correlation", "bruteforce", "web_scanning", "ew_bruteforce", "ew_signup"):
        plan.append(Batch(attack_time(rng, now, days, live=True), key, pool.pick(), live=True))

    plan.sort()
    return plan


def run_attack(ctx: Context, batch: Batch) -> tuple[bool, str]:
    builder = EARLY_WARNING.get(batch.kind) or ATTACKS[batch.kind][1]
    command = builder(ctx, batch.ip)
    if command[0] != sys.executable:
        command = [sys.executable, *command]
    if batch.payload.get("username") and "--username" in command:
        command[command.index("--username") + 1] = batch.payload["username"]
    _InjectIp.current_ip = batch.ip
    try:
        done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=RUN_TIMEOUT,
                              cwd=str(ROOT), env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        return done.returncode == 0, (done.stdout + done.stderr).strip()[-600:]
    except subprocess.TimeoutExpired:
        return False, "시간 초과"


# ---------------------------------------------------------------------------
# 마무리: 요약표, 관리자 처리 이력, 빈칸 채우기
# ---------------------------------------------------------------------------

def build_daily_summary(now: datetime, country_of: dict) -> tuple[list, list]:
    """log_daily_summary / log_daily_breakdown — 어제까지의 날을 로그 표에서 요약한다(guide47과 같은 모양)."""
    today = now.astimezone(dd.KST).date()
    sources = {"login_attempts": "attempted_at", "signup_attempts": "attempted_at", "not_found_attempts": "attempted_at",
               "unauthorized_attempts": "attempted_at", "page_access_attempts": "attempted_at", "api_access_log": "requested_at"}
    summary, breakdown = Counter(), Counter()
    ips, usernames, paths, countries = defaultdict(set), defaultdict(set), defaultdict(Counter), defaultdict(Counter)
    with client.store.lock:
        for source, column in sources.items():
            for row in client.store.tables.get(source, []):
                moment = dd.parse_iso(row[column]).astimezone(dd.KST)
                if moment.date() >= today:
                    continue
                day = moment.date().isoformat()
                category = ("success" if row.get("success") else "failure") if source == "login_attempts" else (row.get("method") or "request")
                summary[(day, moment.hour, source, str(category))] += 1
                key = (day, source)
                if row.get("ip_address"):
                    ips[key].add(row["ip_address"])
                if row.get("path"):
                    paths[key][row["path"]] += 1
                if source == "login_attempts":
                    if not row.get("success"):
                        usernames[key].add(row["username"])
                    countries[key][country_of.get(row["ip_address"], "알 수 없음")] += 1
    for key, values in ips.items():
        breakdown[(key[0], key[1], "distinct_ips", "")] = len(values)
    for key, values in usernames.items():
        breakdown[(key[0], key[1], "failed_usernames", "")] = len(values)
    for key, counter in paths.items():
        top = counter.most_common(5)
        for path, count in top:
            breakdown[(key[0], key[1], "top_path", path)] = count
        rest = sum(counter.values()) - sum(c for _p, c in top)
        if rest:
            breakdown[(key[0], key[1], "top_path", "(그 외)")] = rest
    for key, counter in countries.items():
        for country, count in counter.items():
            breakdown[(key[0], key[1], "country", country)] = count
    return (
        [{"day": d, "hour": h, "source": s, "category": c, "count": n} for (d, h, s, c), n in sorted(summary.items())],
        [{"day": d, "source": s, "dimension": dim, "value": v, "count": n} for (d, s, dim, v), n in sorted(breakdown.items())],
    )


def admin_decisions(ctx: Context, now: datetime) -> None:
    """오래된 사건·이벤트·AI 조기경보 중 일부를 관리자가 처리한 것으로 만든다(최근 것은 처리 대기로 남긴다)."""
    rng = ctx.rng
    admins = [a[0] for a in dd.ADMIN_ACCOUNTS if a[1] != "security_viewer"]
    with client.store.lock:
        t = client.store.tables
        # 같은 IP에는 열린(OPEN) 사건이 하나만 — 오래된 것은 IDLE, 사람이 확인한 것은 CLOSED
        by_ip = defaultdict(list)
        for incident in t.get("security_incidents", []):
            by_ip[incident["ip_address"]].append(incident)
        for incident in t.get("security_incidents", []):
            last = dd.parse_iso(incident["last_event_at"])
            age = now - last
            if incident["status"] == "OPEN" and age > timedelta(hours=3):
                incident["status"] = "IDLE"
            if incident["status"] in ("OPEN", "IDLE") and age > timedelta(hours=18) and rng.random() < 0.7:
                incident["status"] = "CLOSED"
                incident["resolved_by"] = rng.choice(admins)
                incident["resolved_at"] = (last + timedelta(minutes=rng.randint(20, 600))).isoformat()
            if incident["status"] == "CLOSED" and not incident.get("resolved_by"):
                incident["resolved_by"] = rng.choice(admins)
                incident["resolved_at"] = incident.get("resolved_at") or (last + timedelta(minutes=rng.randint(5, 120))).isoformat()
        for ips in by_ip.values():
            opened = sorted((i for i in ips if i["status"] == "OPEN"), key=lambda i: i["last_event_at"])
            for incident in opened[:-1]:
                incident["status"] = "IDLE"
        # 보안 이벤트: 하루 지난 것의 일부를 관리자가 처리 완료
        for event in t.get("security_events", []):
            detected = dd.parse_iso(event["detected_at"])
            if event.get("resolved_at") is None and now - detected > timedelta(hours=20) and event["severity"] != "CRITICAL" and rng.random() < 0.6:
                event["resolved_at"] = (detected + timedelta(minutes=rng.randint(10, 900))).isoformat()
        # 같은 IP·유형의 미해결 HIGH는 하나만 (DB의 부분 유니크 인덱스 조건)
        seen = set()
        for event in sorted(t.get("security_events", []), key=lambda e: e["detected_at"], reverse=True):
            if event["severity"] == "HIGH" and event.get("resolved_at") is None:
                key = (event["ip_address"], event["event_type"])
                if key in seen:
                    event["resolved_at"] = (dd.parse_iso(event["detected_at"]) + timedelta(minutes=30)).isoformat()
                seen.add(key)
        # AI 조기경보: 하루 넘게 지난 대기 요청은 승인/반려로 처리
        for request in t.get("access_requests", []):
            requested = dd.parse_iso(request["requested_at"])
            if request["status"] == "PENDING" and now - requested > timedelta(hours=14):
                request["status"] = "APPROVED" if rng.random() < 0.6 else "REJECTED"
                request["decided_by_admin_id"] = 1
                request["decided_at"] = (requested + timedelta(minutes=rng.randint(5, 240))).isoformat()


def fill_blanks(ctx: Context) -> None:
    """대시보드에 '-'로 보일 칸을 의미가 맞는 범위에서 채운다. 원래 비어야 정상인 칸(진행 중 사건의 처리자 등)은 건드리지 않는다."""
    with client.store.lock:
        t = client.store.tables
        attempts = t.get("login_attempts", [])
        admin_attempts = t.get("admin_login_log", [])
        for event in t.get("security_events", []):
            if not event.get("path") and event["event_type"] in DEFAULT_PATH:
                event["path"] = DEFAULT_PATH[event["event_type"]]
            if not event.get("username"):
                # 같은 IP가 그 무렵 시도하거나 로그인한 계정(로그인 기록·관리자 로그인 기록)이 있으면 그 계정을 적는다.
                moment = dd.parse_iso(event["detected_at"])
                names = Counter(a["username"] for a in attempts + admin_attempts
                                if a["ip_address"] == event["ip_address"]
                                and abs((dd.parse_iso(a["attempted_at"]) - moment).total_seconds()) < 3600)
                if names:
                    event["username"] = names.most_common(1)[0][0]
        for lock in t.get("lockouts", []) + t.get("account_lockouts", []):
            if lock.get("lock_type") == "PERMANENT":
                lock["permanent_reason"] = lock.get("permanent_reason") or "REPEAT_OFFENDER"
                lock["recoverable"] = lock.get("recoverable") or "EXEMPTION"
                lock["promoted_at"] = lock.get("promoted_at") or lock.get("locked_at")


def release_one_permanent(ctx: Context, now: datetime) -> None:
    """오래된 영구 잠금 하나를 관리자가 풀어 준 이력을 남긴다(잠금 해제 흐름도 화면에 보이게)."""
    with client.store.lock:
        old = [l for l in client.store.tables.get("lockouts", [])
               if l.get("lock_type") == "PERMANENT" and l.get("active") and now - dd.parse_iso(l["locked_at"]) > timedelta(days=2)]
        if not old:
            return
        lock = ctx.rng.choice(old)
        released = dd.parse_iso(lock["locked_at"]) + timedelta(hours=ctx.rng.randint(20, 40))
        lock["active"] = False
        for hist in client.store.tables.get("lock_history", []):
            if hist.get("target_kind") == "ip" and hist.get("target_value") == lock["ip_address"] and hist.get("lock_type") == "PERMANENT":
                hist["released_at"] = released.isoformat()
                hist["released_by"] = "admin:demo-admin"
                hist["release_note"] = "본인 확인 후 관리자가 해제"


def add_recovery_records(ctx: Context, now: datetime) -> None:
    """이메일 본인 인증 복구 흐름의 결과(복구 요청·IP 예외)를 채운다. 메일 인증은 사람이 코드를 입력해야 해서 직접 행으로 만든다."""
    rng = ctx.rng
    locks = [l for l in client.store.tables.get("lockouts", [])
             if l.get("lock_type") == "PERMANENT" and l.get("active") and l.get("recoverable") == "EXEMPTION"]
    users = {u["username"]: u for u in client.store.tables.get("users", [])}
    members = [users[m["username"]] for m in ctx.members if m["username"] in users]
    rand_hex = lambda: "%064x" % rng.getrandbits(256)
    for index, lock in enumerate(locks[:3]):
        user = rng.choice(members)
        requested = dd.parse_iso(lock["locked_at"]) + timedelta(hours=rng.randint(1, 6), minutes=rng.randint(0, 59))
        if requested > now - timedelta(minutes=40):
            requested = now - timedelta(minutes=rng.randint(40, 90))
        status = "VERIFIED" if index != 2 else "EXPIRED"
        row = {"user_id": user["id"], "target_kind": "ip", "target_value": lock["ip_address"], "token_hash": rand_hex(),
               "code_hash": rand_hex(), "device_hash": rand_hex(), "requested_ip": lock["ip_address"], "status": status,
               "code_attempts": 1 if status == "VERIFIED" else 0, "expires_at": (requested + timedelta(minutes=30)).isoformat(),
               "created_at": requested.isoformat(), "verified_at": (requested + timedelta(minutes=4)).isoformat() if status == "VERIFIED" else None}
        client.table("recovery_requests").insert(row).execute()
        if status == "VERIFIED":
            granted = requested + timedelta(minutes=4)
            client.table("ip_lock_exemptions").insert({
                "ip_address": lock["ip_address"], "user_id": user["id"], "device_hash": row["device_hash"], "granted_via": "EMAIL_RECOVERY",
                "status": "ACTIVE", "granted_at": granted.isoformat(), "expires_at": (granted + timedelta(days=30)).isoformat(), "revoked_reason": None,
            }).execute()
    # 방금 들어온 복구 요청 한 건(대기 중)
    if locks and members:
        pending = rng.choice(members)
        created = now - timedelta(minutes=6)
        client.table("recovery_requests").insert({
            "user_id": pending["id"], "target_kind": "ip", "target_value": locks[-1]["ip_address"], "token_hash": rand_hex(),
            "code_hash": rand_hex(), "device_hash": rand_hex(), "requested_ip": locks[-1]["ip_address"], "status": "PENDING",
            "code_attempts": 0, "expires_at": (created + timedelta(minutes=30)).isoformat(), "created_at": created.isoformat(), "verified_at": None,
        }).execute()


# ---------------------------------------------------------------------------
# 메인
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="7일치 샘플 로그 생성기 (내 컴퓨터에서만 실행)")
    parser.add_argument("--seed", type=int, default=20261009, help="같은 숫자면 같은 결과 (기본 20261009)")
    parser.add_argument("--days", type=int, default=7, help="기록할 기간(일), 기본 7")
    parser.add_argument("--members", type=int, default=12, help="가입시킬 가짜 회원 수 (최대 12)")
    parser.add_argument("--out", default=str(OUTPUT), help="저장할 JSON 파일")
    parser.add_argument("--use-groq", action="store_true",
                        help="AI 조기경보를 진짜 Groq API로 판정한다(.env의 GROQ_API_KEY 필요, 샘플 데이터가 Groq로 전송되고 호출 수만큼 시간이 걸린다)")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")
    out = sys.stdout
    say = lambda *a: print(*a, file=out, flush=True)
    random.seed(args.seed)
    rng = random.Random(args.seed)
    now = datetime.now(timezone.utc)
    pool = dd.IpPool(rng)
    ctx = Context(rng=rng, pool=pool, now=now)

    for username, role in dd.ADMIN_ACCOUNTS[1:]:
        db.create_admin_user(username, dd.ADMIN_PASSWORD, role)
    names = dd.MEMBER_NAMES[: max(1, min(args.members, len(dd.MEMBER_NAMES)))]
    for index, username in enumerate(names):
        recent = index < 3  # 세 명은 이번 주에 가입한 신규 회원
        created = now - (timedelta(days=rng.uniform(1.2, args.days - 0.5)) if recent else timedelta(days=rng.uniform(args.days + 1, 25)))
        ctx.members.append({
            "username": username, "email": f"{username}@example.com", "password": dd.MEMBER_PASSWORD,
            "ip": pool.pick(dd.MEMBER_COUNTRIES[index % len(dd.MEMBER_COUNTRIES)]), "created_at": created,
        })

    plan = build_plan(ctx, args.days)
    if USE_GROQ:
        say("AI 조기경보: 진짜 Groq API로 판정합니다 (샘플 IP·아이디·횟수가 Groq로 전송됩니다. 그 밖의 외부 접속은 없습니다)")
    say(f"계획: 묶음 {len(plan)}개 (회원 가입 {len(ctx.members)}, 공격 {sum(1 for b in plan if b.kind in ATTACKS or b.kind in EARLY_WARNING)}) — 서버를 켭니다")
    server = serve()
    time.sleep(0.5)
    real_stdout, devnull = sys.stdout, open(os.devnull, "w", encoding="utf-8")
    logging = __import__("logging")
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    failures, started, done_kinds = [], time.monotonic(), Counter()

    for number, batch in enumerate(plan, 1):
        for attempt in range(3):   # 윈도우 소켓 고갈 같은 일시 오류가 나면 이 묶음이 만든 행을 되돌리고 다시 시도한다
            app_module.limiter.reset()
            before = snapshot()
            sys.stdout = devnull   # 서버 스레드가 찍는 알림 출력은 버린다
            try:
                if batch.kind == "signup":
                    ok, note = signup(ctx, batch.payload["member"]), ""
                elif batch.kind == "member":
                    ok, note = member_session(ctx, batch.payload["member"])["login"], ""
                elif batch.kind == "admin":
                    ok, note = admin_session(ctx, batch.payload["username"], batch.ip, batch.payload["fail"]), ""
                else:
                    ok, note = run_attack(ctx, batch)
            except requests.RequestException as error:
                ok, note = False, str(error)
            finally:
                sys.stdout = real_stdout
            if ok or batch.kind in EARLY_WARNING or attempt == 2:
                break
            with client.store.lock:
                client.store.tables.clear()
                client.store.tables.update(before)
            time.sleep(3)
        if ok:
            done_kinds[batch.kind] += 1
        info = finish_batch(ctx, before, batch.when, batch.live)
        if not ok and batch.kind not in EARLY_WARNING:   # 조기경보용 변형은 일부러 잠금 직전까지만 두드려서 시뮬레이션 자체는 '실패'로 끝난다
            failures.append((batch.kind, note))
        say(f"[{number:>3}/{len(plan)}] {'OK  ' if ok else 'FAIL'} {batch.when.astimezone(dd.KST):%m-%d %H:%M} {batch.kind:<30} {batch.ip:<16} 행 {info['rows']}")
    server.shutdown()

    now = datetime.now(timezone.utc)
    settle_locks(now)
    admin_decisions(ctx, now)
    release_one_permanent(ctx, now)
    add_recovery_records(ctx, now)
    fill_blanks(ctx)
    summary, breakdown = build_daily_summary(now, pool.country_of)
    with client.store.lock:
        for member in ctx.members:   # 가입 시각을 계획한 시각으로 맞춘다
            for user in client.store.tables.get("users", []):
                if user["username"] == member["username"]:
                    user["created_at"] = member["created_at"].isoformat()
        for admin in client.store.tables.get("admin_users", []):   # 서버가 자동으로 만든 첫 관리자는 최고 관리자다
            if admin["username"] == dd.ADMIN_ACCOUNTS[0][0]:
                admin["role"] = dd.ADMIN_ACCOUNTS[0][1]
        client.store.tables["log_daily_summary"] = summary
        client.store.tables["log_daily_breakdown"] = breakdown
        client.store.tables["ip_locations"] = pool.location_rows(now.isoformat())
        used = {r.get("ip_address") for rows in client.store.tables.values() for r in rows if isinstance(r, dict)}
        client.store.tables["ip_locations"] = [r for r in client.store.tables["ip_locations"] if r["ip_address"] in used]
        dump = {"generated_at": now.isoformat(), "seed": args.seed, "tables": {n: r for n, r in client.store.tables.items() if r}}

    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dump, ensure_ascii=False, indent=1), encoding="utf-8")
    events = Counter(e["event_type"] for e in dump["tables"].get("security_events", []))
    say(f"\n완료: {time.monotonic() - started:.0f}초 · 저장 {path}")
    say("표별 행 수: " + ", ".join(f"{n} {len(r)}" for n, r in sorted(dump["tables"].items())))
    say("이벤트 유형: " + ", ".join(f"{k} {v}" for k, v in events.most_common()))
    say(f"IP {len(dump['tables'].get('ip_locations', []))}개 · 나라 {len({r['country'] for r in dump['tables'].get('ip_locations', [])})}곳")
    if USE_GROQ:
        say(f"Groq 판정: 호출 {GROQ_STATS['calls']}회 · 위험 {GROQ_STATS['risky']} · 정상 {GROQ_STATS['safe']} · 실패 {GROQ_STATS['failed']}"
            + (" (실패한 건은 조기경보가 만들어지지 않았습니다 — 한도·네트워크를 확인하세요)" if GROQ_STATS["failed"] else ""))
    ran = [k for k in ATTACKS if done_kinds[k]]
    say(f"공격 시뮬레이션 {len(ran)}/{len(ATTACKS)}종 실행 성공" + (f" (실패: {', '.join(k for k in ATTACKS if k not in ran)})" if len(ran) < len(ATTACKS) else ""))
    if failures:
        say(f"실패한 묶음 {len(failures)}개:")
        for kind, note in failures[:10]:
            say(f"  - {kind}: {note[-200:]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
