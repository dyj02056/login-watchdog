#!/usr/bin/env python3
# ============================================================================
# scripts/docs/build_flowcharts.py — 단원별 "클릭형 코드 흐름도(.html)" 생성기
#
# docs/feature-reference/02-layer-order/NN-xxx.html 을 만든다. 흐름도에 보이는 코드는
# 손으로 붙여넣지 않고, 이 스크립트가 실제 소스 파일에서 함수 이름으로 찾아 뽑아 넣는다
# (기존 문서의 "auth.py:64" 같은 줄 번호는 코드가 바뀌면 어긋나기 때문).
#
# 핵심 규칙
#   1) `db.create_user` 처럼 패키지 이름으로 적힌 호출은 db/__init__.py 의 재내보내기
#      (re-export) 표를 읽어 실제 파일(db/users.py)로 풀어서 연결한다.
#   2) 강조할 줄은 줄 번호가 아니라 "문구(anchor)"로 지정한다 → 코드가 밀려도 안 어긋난다.
#      찾지 못하면 에러를 내고 멈춘다(조용히 낡은 정보가 들어가지 않게).
#
# 사용법 (저장소 루트에서):
#   python scripts/docs/build_flowcharts.py 1        # 1단원만
#   python scripts/docs/build_flowcharts.py --all    # chapters/ 에 있는 전부
# ============================================================================

from __future__ import annotations

import argparse
import ast
import importlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT_DIR = REPO / "docs" / "feature-reference" / "02-layer-order"
TEMPLATE = Path(__file__).resolve().parent / "templates" / "flowchart.html"
GITHUB_BLOB = "https://github.com/dyj02056/login-watchdog/blob/main/"

# 코드에서 쓰는 짧은 이름(alias) → (파일, 패키지 재내보내기 파일인가?)
ALIASES: dict[str, tuple[str, bool]] = {
    "db": ("db/__init__.py", True),
    "soar": ("security/soar/__init__.py", True),
    "helpers": ("helpers/__init__.py", True),
    "detector": ("security/detector.py", False),
    "auth": ("routes/auth.py", False),
    "member": ("routes/member.py", False),
    "email_verification": ("services/email_verification.py", False),
}


class SpecError(Exception):
    pass


# ----------------------------------------------------------------------------
# 소스 읽기 / 함수 찾기
# ----------------------------------------------------------------------------

_file_cache: dict[str, list[str]] = {}
_reexport_cache: dict[str, dict[str, str]] = {}


def read_lines(path: str) -> list[str]:
    if path not in _file_cache:
        full = REPO / path
        if not full.is_file():
            raise SpecError(f"파일이 없습니다: {path}")
        _file_cache[path] = full.read_text(encoding="utf-8").split("\n")
    return _file_cache[path]


def reexport_table(init_path: str) -> dict[str, str]:
    """__init__.py 가 다시 내보내는 이름 → 그 이름이 실제로 정의된 파일 경로."""
    if init_path in _reexport_cache:
        return _reexport_cache[init_path]
    tree = ast.parse("\n".join(read_lines(init_path)))
    pkg_dir = Path(init_path).parent
    table: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if node.level >= 1:  # from .users import x  → 같은 폴더
            target = (pkg_dir / (node.module or "").replace(".", "/")).as_posix() + ".py"
        else:  # from security.soar.lockouts import x
            target = (node.module or "").replace(".", "/") + ".py"
        if not (REPO / target).is_file():
            continue
        for alias in node.names:
            table[alias.asname or alias.name] = target
    _reexport_cache[init_path] = table
    return table


def find_function(path: str, name: str) -> tuple[int, int]:
    """파일 맨 위 단계(top-level)의 함수 name 의 (시작줄, 끝줄). 데코레이터 포함, 1-based."""
    tree = ast.parse("\n".join(read_lines(path)))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            return start, node.end_lineno
    raise SpecError(f"{path} 안에서 함수 {name}() 를 찾지 못했습니다")


def find_line(lines: list[str], anchor: str, start: int, end: int, what: str) -> int:
    """lines[start-1:end] 구간(1-based, 양끝 포함)에서 anchor 가 들어있는 첫 줄 번호(1-based)."""
    for i in range(start - 1, end):
        if anchor in lines[i]:
            return i + 1
    raise SpecError(f"문구를 찾지 못했습니다 ({what}): {anchor!r}")


# ----------------------------------------------------------------------------
# 코드 블록 만들기
# ----------------------------------------------------------------------------

class Builder:
    def __init__(self) -> None:
        self.blocks: dict[str, dict] = {}
        self.used_files: dict[str, dict] = {}

    def _add_block(self, key: str, path: str, start: int, end: int, lang: str, alias: dict | None) -> None:
        if key in self.blocks:
            return
        lines = read_lines(path)
        self.blocks[key] = {
            "path": path,
            "start": start,
            "end": end,
            "lang": lang,
            "code": "\n".join(lines[start - 1:end]),
            "alias": alias,
        }

    def resolve_ref(self, ref: str) -> tuple[str, str, dict | None]:
        """'db.create_user' / 'routes/auth.py:login_submit' → (실제 파일, 함수 이름, 별칭 정보)."""
        if ":" in ref:
            path, name = ref.split(":", 1)
            return path, name, None
        alias, _, name = ref.partition(".")
        if alias not in ALIASES:
            raise SpecError(f"알 수 없는 별칭: {ref} (ALIASES 에 추가하거나 'path.py:func' 형식을 쓰세요)")
        entry_path, is_pkg = ALIASES[alias]
        if not is_pkg:
            return entry_path, name, None
        real = reexport_table(entry_path).get(name)
        if real is None:
            raise SpecError(f"{entry_path} 의 재내보내기 표에 {name} 이(가) 없습니다")
        return real, name, {"call": f"{ref}()", "via": entry_path, "real": real}

    def item(self, spec: dict) -> dict:
        """노드의 코드 항목 하나 → {block, hl:[시작,끝], call, label}."""
        if "ref" in spec:
            path, name, alias = self.resolve_ref(spec["ref"])
            start, end = find_function(path, name)
            key = f"{path}:{name}"
            self._add_block(key, path, start, end, "python", alias)
            label = f"{name}()"
        else:  # snippet: 파일의 일부분을 anchor 로 잘라 보여준다
            path = spec["snippet"]
            lines = read_lines(path)
            start = find_line(lines, spec["from"], 1, len(lines), f"{path} 시작")
            end = find_line(lines, spec["to"], start, len(lines), f"{path} 끝")
            key = f"{path}:{start}-{end}"
            lang = "html" if path.endswith((".html", ".htm")) else "python"
            self._add_block(key, path, start, end, lang, None)
            label = spec.get("label", Path(path).name)
        block = self.blocks[key]
        hl = None
        if "hl" in spec:
            hs, he = spec["hl"] if isinstance(spec["hl"], (tuple, list)) else (spec["hl"], None)
            lines = read_lines(block["path"])
            first = find_line(lines, hs, block["start"], block["end"], f"{key} 강조 시작")
            last = find_line(lines, he, first, block["end"], f"{key} 강조 끝") if he else first
            hl = [first, last]
        self.used_files.setdefault(block["path"], {})
        return {"block": key, "hl": hl, "label": label, "call": (block["alias"] or {}).get("call"),
                "snippet": "snippet" in spec}


# ----------------------------------------------------------------------------
# 파일 설명(맨 위 # 주석 블록)
# ----------------------------------------------------------------------------

def header_comment(path: str) -> str:
    if not path.endswith(".py"):
        return ""
    out: list[str] = []
    for line in read_lines(path):
        s = line.strip()
        if not s.startswith("#"):
            break
        text = s.lstrip("#").strip()
        if set(text) <= {"="}:
            continue
        out.append(text)
    return "\n".join(out).strip()


# ----------------------------------------------------------------------------
# 단원 명세 → 화면용 데이터
# ----------------------------------------------------------------------------

def build_chapter(spec) -> tuple[dict, str]:
    b = Builder()
    scenarios = []
    for sc in spec.SCENARIOS:
        nodes = []
        ids = set()
        for n in sc["nodes"]:
            if n["id"] in ids:
                raise SpecError(f"노드 id 중복: {n['id']}")
            ids.add(n["id"])
            items = [b.item(i) for i in n.get("items", [])]
            nodes.append({
                "id": n["id"], "col": n["col"], "row": n["row"], "kind": n["kind"],
                "title": n["title"], "plain": n.get("plain", ""), "reject": n.get("reject", ""),
                "later": n.get("later", ""), "items": items,
            })
        edges = []
        for e in sc["edges"]:
            for end in (e[0], e[1]):
                if end not in ids:
                    raise SpecError(f"간선이 없는 노드를 가리킵니다: {end}")
            edges.append({"from": e[0], "to": e[1], "label": e[2] if len(e) > 2 else "", "kind": e[3] if len(e) > 3 else "flow"})
        for sid in sc["steps"]:
            if sid not in ids:
                raise SpecError(f"steps 에 없는 노드: {sid}")
        scenarios.append({"id": sc["id"], "name": sc["name"], "intro": sc["intro"],
                          "nodes": nodes, "edges": edges, "steps": sc["steps"]})

    files = {}
    for path in b.used_files:
        files[path] = {
            "role": spec.FILE_ROLES.get(path, ""),
            "header": header_comment(path),
            "github": GITHUB_BLOB + path,
        }
        if not files[path]["role"]:
            raise SpecError(f"FILE_ROLES 에 {path} 설명이 없습니다")

    data = {
        "title": spec.TITLE,
        "subtitle": spec.SUBTITLE,
        "mdFile": spec.SLUG + ".md",
        "github": GITHUB_BLOB,
        "columns": spec.COLUMNS,
        "scenarios": scenarios,
        "blocks": b.blocks,
        "files": files,
    }
    return data, spec.SLUG


def render(data: dict) -> str:
    raw = json.dumps(data, ensure_ascii=False)
    # <script> 안에 넣어도 태그가 깨지지 않게 위험한 문자열을 이스케이프
    safe = raw.replace("</", "<\\/").replace("<!--", "<\\u0021--")
    html = TEMPLATE.read_text(encoding="utf-8")
    return html.replace("__TITLE__", data["title"]).replace("__DATA__", safe)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("chapters", nargs="*", type=int, help="만들 단원 번호 (예: 1 2 3)")
    ap.add_argument("--all", action="store_true", help="chapters/ 안의 모든 단원")
    args = ap.parse_args()

    chap_dir = Path(__file__).resolve().parent / "chapters"
    if args.all:
        nums = sorted(int(p.name[2:4]) for p in chap_dir.glob("ch[0-9][0-9]_*.py"))
    else:
        nums = args.chapters
    if not nums:
        ap.error("단원 번호를 주거나 --all 을 쓰세요")

    sys.path.insert(0, str(REPO))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rc = 0
    for num in nums:
        matches = list(chap_dir.glob(f"ch{num:02d}_*.py"))
        if not matches:
            print(f"[{num}단원] 명세 파일이 없습니다 (chapters/ch{num:02d}_*.py)")
            rc = 1
            continue
        spec = importlib.import_module(f"scripts.docs.chapters.{matches[0].stem}")
        try:
            data, slug = build_chapter(spec)
        except SpecError as e:
            print(f"[{num}단원] 실패: {e}")
            rc = 1
            continue
        out = OUT_DIR / f"{slug}.html"
        out.write_text(render(data), encoding="utf-8")
        n_nodes = sum(len(s["nodes"]) for s in data["scenarios"])
        print(f"[{num}단원] {out.relative_to(REPO)}  (노드 {n_nodes}개, 코드 블록 {len(data['blocks'])}개)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
