"""샘플 로그를 실제 Supabase 표에 넣거나(--apply), 넣었던 것만 지운다(--purge).

    python scripts/demo/load_demo_to_supabase.py            # 미리보기: 아무것도 쓰지 않고 무엇이 들어갈지만 보여준다
    python scripts/demo/load_demo_to_supabase.py --apply    # 실제 적재 (대상 DB 주소를 직접 입력해 확인)
    python scripts/demo/load_demo_to_supabase.py --purge    # 이 스크립트가 넣은 행만 삭제

주의 — 이 스크립트는 .env의 SUPABASE_URL/SUPABASE_KEY(진짜 DB)에 접속하는 유일한 데모 스크립트다.
  · 기본은 미리보기라 아무것도 바뀌지 않는다. 쓰기는 --apply + 주소 입력 확인이 있어야만 한다.
  · 넣은 행의 번호를 output/supabase_manifest.json에 남기고, --purge는 그 번호의 행만 지운다(기존 운영 데이터는 건드리지 않는다).
  · 회원 비밀번호는 로그인할 수 없는 값으로 바꿔서 넣는다. 관리자 계정·메일 토큰은 넣지 않는다.
  · 같은 아이디의 회원이나 같은 날짜의 일별 요약이 이미 있으면 그 부분은 넣지 않거나(요약·잠금·위치) 중단한다(회원).
기록의 시각은 넣는 순간을 기준으로 "최근 7일"로 옮긴다. 별도의 빈 Supabase 프로젝트에 넣는 것이 가장 안전하다.
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEFAULT_LOGS = HERE / "output" / "demo_logs.json"
MANIFEST = HERE / "output" / "supabase_manifest.json"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

import demo_data as dd  # noqa: E402

# 외래키 때문에 이 순서로 넣는다(지울 때는 거꾸로).
ORDER = [
    "users", "posts", "comments", "login_attempts", "signup_attempts", "not_found_attempts", "unauthorized_attempts",
    "page_access_attempts", "api_access_log", "post_attempts", "comment_attempts", "admin_login_log",
    "security_incidents", "security_events", "lockouts", "account_lockouts", "admin_account_lockouts", "lock_history",
    "access_requests", "recovery_requests", "ip_lock_exemptions", "ip_locations", "log_daily_summary", "log_daily_breakdown",
]
SKIP_TABLES = {"admin_users", "email_tokens"}          # 관리자 계정과 메일 인증 토큰은 넣지 않는다
NATURAL_KEY = {"lockouts": "ip_address", "account_lockouts": "username", "admin_account_lockouts": "username", "ip_locations": "ip_address"}
COMPOSITE_KEY = {"log_daily_summary": ("day", "hour", "source", "category"), "log_daily_breakdown": ("day", "source", "dimension", "value")}
ID_REMAPPED = ("users", "posts", "security_incidents")   # 다른 표가 이 표의 번호를 가리킨다
IDENTITY_KEY = {"access_requests": "request_id"}      # 나머지 표는 id
CHUNK = 100
DISABLED_HASH = "!demo-account-login-disabled"
MISSING_TABLE_CODES = {"42P01", "PGRST205", "PGRST204"}


def pk_of(table: str) -> str | None:
    if table in COMPOSITE_KEY:
        return None
    return NATURAL_KEY.get(table) or IDENTITY_KEY.get(table, "id")


def connect():
    import db

    return db.get_client()


def host_of() -> str:
    import os

    return urlparse(os.environ.get("SUPABASE_URL", "")).hostname or "(SUPABASE_URL 없음)"


def select_existing(client, table: str, column: str, values: list) -> set:
    found = set()
    for start in range(0, len(values), CHUNK):
        res = client.table(table).select(column).in_(column, values[start:start + CHUNK]).execute()
        found |= {row[column] for row in res.data}
    return found


def prepare(dump: dict, client, tables: list[str]) -> tuple[dict, list[str]]:
    """넣을 행을 준비한다: 번호 칸 제거, 비밀번호 무력화, 이미 있는 행 걸러내기. (표 → 행 목록, 안내 문구들)"""
    notes, prepared = [], {}
    for table in tables:
        rows = [dict(r) for r in dump["tables"].get(table, [])]
        if not rows:
            continue
        if table == "users":
            existing = select_existing(client, "users", "username", [r["username"] for r in rows])
            existing |= select_existing(client, "users", "email", [r["email"] for r in rows])
            clash = sorted({r["username"] for r in rows if r["username"] in existing or r["email"] in existing})
            if clash:
                raise SystemExit(f"중단: 이미 같은 아이디/이메일의 회원이 있습니다 ({', '.join(clash[:5])} …). 아무것도 넣지 않았습니다.")
            for row in rows:
                row["password_hash"] = DISABLED_HASH
        elif table in NATURAL_KEY:
            key = NATURAL_KEY[table]
            existing = select_existing(client, table, key, [r[key] for r in rows])
            if existing:
                notes.append(f"{table}: 이미 있는 {len(existing)}건은 넣지 않습니다")
                rows = [r for r in rows if r[key] not in existing]
        elif table in COMPOSITE_KEY:
            days = sorted({r["day"] for r in rows})
            found = set()
            for day in days:
                if client.table(table).select("day").eq("day", day).limit(1).execute().data:
                    found.add(day)
            if found:
                notes.append(f"{table}: 이미 요약이 있는 날짜 {len(found)}일은 넣지 않습니다(운영 요약을 덮어쓰지 않기 위해)")
                rows = [r for r in rows if r["day"] not in found]
        if table == "access_requests":
            for row in rows:
                row["decided_by_admin_id"] = None   # 관리자 계정은 넣지 않으므로 연결을 끊는다
        for row in rows:
            if table in ID_REMAPPED:
                row["_old_id"] = row.get("id")   # 다른 표의 외래키를 새 번호로 이어 붙일 때 쓴다(DB에는 보내지 않는다)
            row.pop("id", None)
            row.pop("request_id", None)
        if rows:
            prepared[table] = rows
    return prepared, notes


def apply_load(client, dump: dict, prepared: dict) -> dict:
    """표 순서대로 넣고, 넣은 행의 번호를 manifest로 남긴다. 외래키(글→댓글, 회원→복구 요청, 사건→잠금 이력)는 새 번호로 이어 붙인다."""
    manifest = {"host": host_of(), "tables": {}}
    new_ids: dict[str, dict] = {table: {} for table in ID_REMAPPED}
    try:
        for table in ORDER:
            rows = prepared.get(table)
            if not rows:
                continue
            key = pk_of(table)
            inserted = []
            for start in range(0, len(rows), CHUNK):
                chunk = rows[start:start + CHUNK]
                for row in chunk:
                    if table == "comments":
                        row["post_id"] = new_ids["posts"].get(row["post_id"])
                    elif table in ("recovery_requests", "ip_lock_exemptions"):
                        row["user_id"] = new_ids["users"].get(row["user_id"])
                    elif table == "lock_history":
                        row["incident_id"] = new_ids["security_incidents"].get(row.get("incident_id"))
                payload = [{k: v for k, v in row.items() if k != "_old_id"} for row in chunk]
                try:
                    data = client.table(table).insert(payload).execute().data
                except Exception as error:  # noqa: BLE001
                    code = getattr(error, "code", None)
                    if code in MISSING_TABLE_CODES:
                        print(f"  - {table}: 이 DB에 표(또는 칸)가 없어 건너뜁니다 ({code})")
                        break
                    raise
                inserted += data
            if not inserted:
                continue
            if table in new_ids:
                # 입력 순서 = 반환 순서. 원래 번호 → 새 번호
                for row, new in zip(rows, inserted):
                    new_ids[table][row["_old_id"]] = new["id"]
            if key:
                manifest["tables"][table] = [row[key] for row in inserted]
            else:
                manifest["tables"][table] = [{c: row[c] for c in COMPOSITE_KEY[table]} for row in inserted]
            print(f"  + {table}: {len(inserted)}건")
    except Exception as error:  # noqa: BLE001
        MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
        raise SystemExit(f"\n오류로 중단했습니다: {error}\n지금까지 넣은 행은 manifest에 기록했습니다. 정리하려면 --purge 를 실행하세요.")
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    return manifest


def purge(client) -> None:
    if not MANIFEST.exists():
        raise SystemExit("지울 기록이 없습니다 (manifest 파일이 없음).")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    print(f"대상 DB: {manifest['host']} (현재 .env: {host_of()})")
    if manifest["host"] != host_of():
        raise SystemExit("중단: manifest를 만든 DB와 현재 .env의 DB가 다릅니다.")
    for table in reversed(ORDER):
        keys = manifest["tables"].get(table)
        if not keys:
            continue
        if table in COMPOSITE_KEY:
            for item in keys:
                query = client.table(table).delete()
                for column, value in item.items():
                    query = query.eq(column, value)
                query.execute()
        else:
            key = pk_of(table)
            for start in range(0, len(keys), CHUNK):
                client.table(table).delete().in_(key, keys[start:start + CHUNK]).execute()
        print(f"  - {table}: {len(keys)}건 삭제")
    MANIFEST.unlink()
    print("완료: 이 스크립트가 넣은 행만 삭제했습니다.")


def main() -> int:
    parser = argparse.ArgumentParser(description="샘플 로그를 실제 Supabase에 넣거나 지운다")
    parser.add_argument("--logs", default=str(DEFAULT_LOGS), help="generate_demo_logs.py가 만든 JSON")
    parser.add_argument("--apply", action="store_true", help="실제로 넣는다(없으면 미리보기)")
    parser.add_argument("--purge", action="store_true", help="이 스크립트가 넣은 행만 지운다")
    parser.add_argument("--yes", action="store_true", help="주소 입력 확인을 건너뛴다(자동화용)")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    import os

    if not os.environ.get("SUPABASE_URL") or not os.environ.get("SUPABASE_KEY"):
        raise SystemExit(".env에 SUPABASE_URL / SUPABASE_KEY가 없습니다.")
    client = connect()
    print(f"대상 DB: {host_of()}")

    if args.purge:
        if not args.yes and input(f"{host_of()} 에서 샘플 기록을 삭제합니다. 계속하려면 주소를 입력하세요: ").strip() != host_of():
            raise SystemExit("취소했습니다.")
        purge(client)
        return 0

    path = Path(args.logs)
    if not path.exists():
        raise SystemExit(f"샘플 로그 파일이 없습니다: {path}\n먼저 실행하세요:  python scripts/demo/generate_demo_logs.py")
    if args.apply and MANIFEST.exists():
        raise SystemExit("이미 적재한 기록이 있습니다. 중복을 막으려면 먼저 --purge 로 지우세요.")
    dump = json.loads(path.read_text(encoding="utf-8"))
    dd.shift_dump_to_now(dump)
    tables = [t for t in ORDER if t not in SKIP_TABLES]
    prepared, notes = prepare(dump, client, tables)

    print("\n들어갈 행:")
    for table in ORDER:
        if table in prepared:
            print(f"  {table:<26}{len(prepared[table]):>6}건")
    for note in notes:
        print(f"  ※ {note}")
    if not args.apply:
        print("\n미리보기입니다 — 아무것도 쓰지 않았습니다. 실제로 넣으려면 --apply 를 붙이세요.")
        return 0

    if not args.yes and input(f"\n{host_of()} 에 위 행을 실제로 기록합니다. 계속하려면 주소를 입력하세요: ").strip() != host_of():
        raise SystemExit("취소했습니다. 아무것도 쓰지 않았습니다.")
    apply_load(client, dump, prepared)
    print("\n완료. 지우려면: python scripts/demo/load_demo_to_supabase.py --purge")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
