# ============================================================================
# scripts/docs/dsl.py — 단원 명세를 짧게 쓰기 위한 도우미
#
# 1단원처럼 노드마다 col/row/id/간선을 손으로 적는 대신, "단계(step)" 하나에 "그 단계가
# 부르는 함수들(calls)"을 매달아 적으면 좌표와 화살표를 자동으로 만든다.
#
#   sc = Scenario("login", "로그인", intro="...")
#   sc.screen("로그인 폼 제출", "설명", snippet=("templates/x.html", "<form", "</form>"))
#   sc.step("① 제목", "설명", fn="routes/auth.py:login_submit", hl=("시작 문구", "끝 문구"),
#           reject="막히면 보이는 문구",
#           calls=[call("db.log_attempt", "시도 기록", "설명"),
#                  call("detector.is_locked", "잠금 판정", "설명",
#                       then=[call("db.get_active_lockout", "잠금 기록 조회", "설명")]),
#                  call("soar.enforce_lockout", "잠금 집행", "설명", later="10단원")])
#   SCENARIOS = [sc.build()]
#
# 열(col)은 호출되는 파일 종류로 자동 결정된다:
#   화면(templates/…) 0 · routes 1 · 판단(security/helpers/services/notify…) 2 · db/·config 3
# 필요하면 call(..., kind="db"|"helper"|"screen"|"route"|"config"|"later") 로 직접 지정한다.
# ============================================================================

from __future__ import annotations

KIND_COL = {"screen": 0, "route": 1, "helper": 2, "later": 2, "db": 3, "config": 3}


def _kind_for(item: dict) -> str:
    path = item.get("snippet") or ""
    ref = item.get("ref") or ""
    if ref and ":" in ref:
        path = ref.split(":", 1)[0]
    elif ref.startswith("db."):
        return "db"
    elif ref.startswith(("auth.", "member.")):
        return "route"
    if path.startswith("db/"):
        return "db"
    if path in ("config.py",) or path.startswith("config"):
        return "config"
    if path.startswith("templates/") or path.startswith("spa/") or path.endswith(".html"):
        return "screen"
    if path.startswith("routes/"):
        return "route"
    return "helper"


def call(ref=None, title="", plain="", *, refs=None, snippet=None, hl=None, label=None,
         later="", kind=None, then=None, reject="") -> dict:
    """호출되는 함수(또는 파일 일부) 하나. ref 대신 refs=[...] 로 같은 카드에 여러 함수를 묶을 수 있다."""
    items = []
    if snippet is not None:
        it = {"snippet": snippet[0], "from": snippet[1], "to": snippet[2]}
        if label:
            it["label"] = label
        if hl is not None:
            it["hl"] = hl
        items.append(it)
    for r in ([ref] if ref else []) + list(refs or []):
        it = {"ref": r}
        if hl is not None and len(items) == 0:
            it["hl"] = hl
        items.append(it)
    if not items:
        raise ValueError("call() 에는 ref/refs/snippet 중 하나가 필요합니다")
    k = "later" if later else (kind or _kind_for(items[0]))
    if k == "route" and kind is None:
        k = "helper"  # 호출되는 routes 안의 보조 함수는 입구 열이 아니라 판단 열에 둔다
    return {"items": items, "title": title, "plain": plain, "kind": k, "later": later,
            "then": then or [], "reject": reject}


def later(ref=None, title="", plain="", chapter="", **kw) -> dict:
    return call(ref, title, plain, later=chapter, **kw)


class Scenario:
    def __init__(self, sid: str, name: str, intro: str):
        self.sid, self.name, self.intro = sid, name, intro
        self.nodes: list[dict] = []
        self.edges: list[tuple] = []
        self.steps: list[str] = []
        self.row = 0
        self.prev: str | None = None
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{self.sid}_{prefix}{self._n}"

    def _add(self, kind: str, title: str, plain: str, items: list[dict], row: int, reject="", later_="", col=None):
        nid = self._id("n")
        self.nodes.append({"id": nid, "col": KIND_COL[kind] if col is None else col, "row": row, "kind": kind, "title": title,
                           "plain": plain, "reject": reject, "later": later_, "items": items})
        return nid

    def screen(self, title: str, plain: str, *, snippet=None, fn=None, hl=None, label=None, calls=None, edge_label: str = ""):
        """흐름의 시작(보통 화면에서 폼 제출). 코드는 snippet(파일 일부) 또는 fn(함수)."""
        item = {}
        if snippet:
            item = {"snippet": snippet[0], "from": snippet[1], "to": snippet[2]}
            if label:
                item["label"] = label
        else:
            item = {"ref": fn}
        if hl is not None:
            item["hl"] = hl
        nid = self._add("screen", title, plain, [item], self.row)
        self.steps.append(nid)
        self.prev = nid
        self.row += 1
        self._pending_label = edge_label
        for c in calls or []:
            self._attach(nid, c, self.row - 1)
        return nid

    def step(self, title: str, plain: str, *, fn: str | None = None, hl=None, reject: str = "",
             calls=None, items=None, edge_label: str = "", kind: str = "route", snippet=None, label=None, col=None):
        """경로가 따라가는 한 단계(보통 라우트 함수 안의 한 덩어리). hl 은 이 단계가 담당하는 줄."""
        its = items
        if its is None:
            if snippet:
                it = {"snippet": snippet[0], "from": snippet[1], "to": snippet[2]}
                if label:
                    it["label"] = label
            else:
                it = {"ref": fn}
            if hl is not None:
                it["hl"] = hl
            its = [it]
        row = self.row
        nid = self._add(kind, title, plain, its, row, reject=reject, col=col if col is not None else (1 if kind in ("route", "helper", "later") else None))
        self.steps.append(nid)
        if self.prev:
            self.edges.append((self.prev, nid, edge_label or getattr(self, "_pending_label", "")))
        self._pending_label = ""
        self.prev = nid
        self.row += 1
        for c in calls or []:
            self._attach(nid, c, row)
        return nid

    def _attach(self, parent: str, c: dict, row: int):
        nid = self._add(c["kind"], c["title"], c["plain"], c["items"], row, reject=c.get("reject", ""), later_=c["later"])
        self.edges.append((parent, nid, "", "call"))
        for sub in c["then"]:
            self._attach(nid, sub, row)

    def build(self) -> dict:
        return {"id": self.sid, "name": self.name, "intro": self.intro, "nodes": self.nodes,
                "edges": self.edges, "steps": self.steps}
