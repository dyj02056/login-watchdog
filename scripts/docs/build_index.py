#!/usr/bin/env python3
# ============================================================================
# scripts/docs/build_index.py — 32개 단원 흐름도의 "목차 페이지(index.html)" 생성기
#
# docs/feature-reference/02-layer-order/index.html 을 만든다. 웹(GitHub Pages)에 올렸을 때
# 첫 화면이 되는 페이지로, 단원 제목·설명은 scripts/docs/chapters/chNN_*.py 의
# TITLE / SUBTITLE 을 그대로 읽어 쓴다(그래서 단원 이름을 고치면 목차도 같이 바뀐다).
#
# 사용법 (저장소 루트에서):
#   python3 -I scripts/docs/build_index.py
# ============================================================================

from __future__ import annotations

import html
import importlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "docs" / "feature-reference" / "02-layer-order" / "index.html"
CHAP_DIR = Path(__file__).resolve().parent / "chapters"

# 단원 번호 범위 → 계층 이름 (docs/feature-reference/02-layer-order.md 의 계층 구분과 같다)
LAYERS = [
    (1, 4, "Layer 1. 기반 기능", "사용자가 직접 쓰는 화면 — 감시 대상"),
    (5, 7, "Layer 2. 탐지", "\"이거 수상한가?\"를 판단만 하는 판사"),
    (8, 11, "Layer 3. 대응", "실제로 잠그고·알리고·엮는 집행관·형사"),
    (12, 14, "Layer 4. 관리", "자동 대응을 사람이 보고 되돌리는 최종 판단"),
    (15, 31, "Layer 5. 방어 강화 · 확장", "개별 취약점 보강, 영구 잠금, 복구, 이메일 인증, 화면 어댑터 등"),
    (32, 32, "Layer 6. 부록", "프로젝트 전체를 찾아보는 지도"),
]

PAGE = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>login-watchdog 코드 흐름도</title>
<style>
  :root{
    --bg:#f4f6f3; --surface:#ffffff; --ink:#12201c; --ink-muted:#5a6b63; --border:#d9e0da;
    --accent:#0f6f66; --accent-soft:#e2ede9; --shadow:0 1px 2px rgba(18,32,28,.06), 0 6px 20px rgba(18,32,28,.07);
    --sans:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR","Segoe UI",sans-serif;
  }
  @media (prefers-color-scheme: dark){
    :root:not([data-theme="light"]){
      --bg:#0d1512; --surface:#141e1a; --ink:#e7efe9; --ink-muted:#93a49c; --border:#28352e;
      --accent:#4fc9b8; --accent-soft:#17332d; --shadow:0 1px 2px rgba(0,0,0,.4), 0 6px 20px rgba(0,0,0,.35);
    }
  }
  :root[data-theme="dark"]{
    --bg:#0d1512; --surface:#141e1a; --ink:#e7efe9; --ink-muted:#93a49c; --border:#28352e;
    --accent:#4fc9b8; --accent-soft:#17332d; --shadow:0 1px 2px rgba(0,0,0,.4), 0 6px 20px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.6}
  .wrap{max-width:1040px;margin:0 auto;padding:40px 16px 64px}
  header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:8px}
  h1{margin:0 0 6px;font-size:28px;line-height:1.25}
  .lead{margin:0;color:var(--ink-muted);max-width:62ch}
  .theme{border:1px solid var(--border);background:var(--surface);color:var(--ink);border-radius:8px;
    width:40px;height:40px;font-size:18px;cursor:pointer;flex:none}
  .theme:hover{border-color:var(--accent)}
  .howto{margin:20px 0 8px;padding:14px 16px;background:var(--accent-soft);border-radius:10px;color:var(--ink)}
  .howto b{color:var(--accent)}
  section{margin-top:32px}
  h2{margin:0;font-size:18px}
  .layer-desc{margin:2px 0 12px;color:var(--ink-muted);font-size:13.5px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:12px}
  a.card{display:block;background:var(--surface);border:1px solid var(--border);border-radius:12px;
    padding:14px 16px;text-decoration:none;color:inherit;box-shadow:var(--shadow);
    transition:border-color .15s,transform .15s}
  a.card:hover,a.card:focus-visible{border-color:var(--accent);transform:translateY(-2px);outline:none}
  a.card:focus-visible{box-shadow:0 0 0 3px var(--accent-soft),var(--shadow)}
  .card .t{font-weight:700;margin-bottom:4px}
  .card .d{color:var(--ink-muted);font-size:13px;line-height:1.5}
  footer{margin-top:40px;color:var(--ink-muted);font-size:13px}
  footer a{color:var(--accent)}
  @media (max-width:520px){ h1{font-size:23px} }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>login-watchdog 코드 흐름도</h1>
      <p class="lead">로그인 감시 시스템의 32개 기능이 <b>어떤 파일의 어떤 함수를 거쳐 가는지</b>를 그림으로 보는 안내서입니다.</p>
    </div>
    <button class="theme" id="theme" type="button" aria-label="밝게/어둡게 전환" title="밝게/어둡게 전환">🌓</button>
  </header>
  <p class="howto">단원 카드를 열면 흐름도가 나옵니다. 흐름도의 <b>카드(파일·함수 이름)를 누르면 실제 코드</b>가 오른쪽에 열리고, 코드 패널의 너비는 경계선을 끌어서 조절할 수 있습니다.</p>
__SECTIONS__
  <footer>코드 원본: <a href="https://github.com/dyj02056/login-watchdog">github.com/dyj02056/login-watchdog</a></footer>
</div>
<script>
  (function(){
    var root=document.documentElement, KEY="lw-theme";
    try{var s=localStorage.getItem(KEY); if(s==="light"||s==="dark") root.setAttribute("data-theme",s);}catch(e){}
    document.getElementById("theme").addEventListener("click",function(){
      var dark=root.getAttribute("data-theme")==="dark" ||
        (!root.getAttribute("data-theme") && matchMedia("(prefers-color-scheme: dark)").matches);
      var next=dark?"light":"dark"; root.setAttribute("data-theme",next);
      try{localStorage.setItem(KEY,next);}catch(e){}
    });
  })();
</script>
</body>
</html>
"""


def load_chapters() -> dict[int, tuple[str, str, str]]:
    """단원 번호 → (slug, 제목, 설명)."""
    sys.path.insert(0, str(REPO))
    out: dict[int, tuple[str, str, str]] = {}
    for p in sorted(CHAP_DIR.glob("ch[0-9][0-9]_*.py")):
        spec = importlib.import_module(f"scripts.docs.chapters.{p.stem}")
        out[int(p.name[2:4])] = (spec.SLUG, spec.TITLE, spec.SUBTITLE)
    return out


def main() -> int:
    chapters = load_chapters()
    sections = []
    for lo, hi, name, desc in LAYERS:
        cards = []
        for num in range(lo, hi + 1):
            if num not in chapters:
                print(f"[경고] {num}단원 명세가 없어 목차에서 뺍니다")
                continue
            slug, title, sub = chapters[num]
            cards.append(
                f'<a class="card" href="{html.escape(slug)}.html">'
                f'<div class="t">{html.escape(title)}</div><div class="d">{html.escape(sub)}</div></a>'
            )
        if cards:
            sections.append(
                f"  <section>\n    <h2>{html.escape(name)}</h2>\n    <p class=\"layer-desc\">{html.escape(desc)}</p>\n"
                f"    <div class=\"grid\">\n      " + "\n      ".join(cards) + "\n    </div>\n  </section>"
            )
    OUT.write_text(PAGE.replace("__SECTIONS__", "\n".join(sections)), encoding="utf-8")
    print(f"{OUT.relative_to(REPO)}  (단원 {len(chapters)}개)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
