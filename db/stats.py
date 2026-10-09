# ============================================================================
# db/stats.py — 관제 대시보드(차트·히트맵·흐름도)용 집계
#
# 관리자 대시보드의 화면 A(위협 현황)·B(공격 상세)가 쓰는 숫자를 한 번에 계산한다.
# 표에서 원본 줄을 가져와 파이썬에서 묶는다 — 이 프로젝트의 로그는 하루 수천 줄 규모라
# 별도 집계 쿼리·뷰를 DB에 새로 만들 필요가 없고, 새 마이그레이션 없이 배포할 수 있다.
#
# 구조는 둘로 나눴다.
#   fetch_raw()           — Supabase에서 원본 줄을 가져온다(여러 쿼리를 동시에).
#   build_threat_stats()  — 가져온 줄로 화면용 숫자를 계산한다. DB 없이 테스트할 수 있는 순수 함수.
#
# 시각은 전부 한국 시간(KST, UTC+9)으로 묶는다 — 관제 화면의 "오늘"은 한국 날짜 기준이고,
# 일별 요약표(log_daily_summary)도 같은 기준으로 만들어진다. 한국은 서머타임이 없어 고정 오프셋이다.
#
# L3/L4(네트워크·전송 계층) 공격은 아직 수집하지 않는다 — README "알려진 제한사항" 참고.
# 그래서 응답의 network_layer는 항상 빈 목록이고, 화면은 이를 "데이터 없음" 상태로 그린다.
# ============================================================================

import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

import config
import db

KST = timezone(timedelta(hours=9))

# log_daily_summary(guide47)가 요약하는 "요청 로그" 표들. 하루 로그 발생량 막대에 쓴다.
LOG_SOURCES = (
    "login_attempts",
    "signup_attempts",
    "not_found_attempts",
    "unauthorized_attempts",
    "page_access_attempts",
    "api_access_log",
)
_LOG_TIME_COLUMN = {"api_access_log": "requested_at"}

EVENT_WINDOW_DAYS = 30  # 신규/반복 공격자 판정에 쓰는 이벤트 조회 기간
RECENT_DAYS = 7
_PAGE = 1000  # Supabase 한 번에 가져올 수 있는 최대 줄 수
_MAX_ROWS = 20000  # 한 표에서 가져올 최대 줄 수(폭주 시 응답이 무한정 느려지지 않게)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(KST)


def _fetch_rows(table: str, columns: str, time_column: str, since: datetime, **filters) -> list[dict]:
    """`since` 이후의 줄을 최신순으로 페이지 단위로 모아 온다(최대 _MAX_ROWS줄)."""
    rows: list[dict] = []
    start = 0
    while start < _MAX_ROWS:
        query = (
            db.get_client()
            .table(table)
            .select(columns)
            .gte(time_column, since.isoformat())
            .order(time_column, desc=True)
            .range(start, start + _PAGE - 1)
        )
        for column, value in filters.items():
            query = query.eq(column, value)
        page = query.execute().data
        rows.extend(page)
        if len(page) < _PAGE:
            break
        start += _PAGE
    return rows


def _count_since(table: str, time_column: str, since: datetime) -> int:
    res = (
        db.get_client()
        .table(table)
        .select("*", count="exact", head=True)
        .gte(time_column, since.isoformat())
        .execute()
    )
    return res.count or 0


def _summary_rows(since_day: date) -> list[dict]:
    """일별 요약표. 마이그레이션(guide47)을 아직 안 돌린 DB에서는 비어 있는 것으로 취급한다."""
    try:
        res = (
            db.get_client()
            .table("log_daily_summary")
            .select("day,source,count")
            .gte("day", since_day.isoformat())
            .in_("source", list(LOG_SOURCES))
            .execute()
        )
        return res.data
    except Exception:  # noqa: BLE001 — 표가 없거나 접근 불가면 "요약 없음"으로 계속한다
        return []


def fetch_raw(now: datetime | None = None) -> dict:
    """대시보드 집계에 필요한 원본 줄을 동시에 가져온다."""
    now = (now or datetime.now(KST)).astimezone(KST)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago_start = today_start - timedelta(days=RECENT_DAYS)  # 지난주 같은 요일 포함
    events_since = today_start - timedelta(days=EVENT_WINDOW_DAYS)
    incidents_since = today_start - timedelta(days=RECENT_DAYS - 1)

    jobs = {
        "events": lambda: _fetch_rows(
            "security_events",
            "id,event_type,severity,ip_address,path,count,action,username,detected_at,resolved_at",
            "detected_at",
            events_since,
        ),
        "failed_logins": lambda: _fetch_rows(
            "login_attempts", "attempted_at", "attempted_at", week_ago_start, success=False
        ),
        "not_found": lambda: _fetch_rows("not_found_attempts", "attempted_at", "attempted_at", week_ago_start),
        "unauthorized": lambda: _fetch_rows(
            "unauthorized_attempts", "attempted_at", "attempted_at", week_ago_start
        ),
        "incidents": lambda: _fetch_rows(
            "security_incidents",
            "id,ip_address,event_types,severity_max,status,first_event_at,last_event_at",
            "last_event_at",
            incidents_since,
        ),
        "summary": lambda: _summary_rows((today_start - timedelta(days=RECENT_DAYS - 1)).date()),
    }
    for source in LOG_SOURCES:
        column = _LOG_TIME_COLUMN.get(source, "attempted_at")
        jobs[f"today:{source}"] = lambda s=source, c=column: _count_since(s, c, today_start)

    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        futures = {name: executor.submit(job) for name, job in jobs.items()}
        raw = {name: future.result() for name, future in futures.items()}

    raw["today_counts"] = {source: raw.pop(f"today:{source}") for source in LOG_SOURCES}
    raw["now"] = now
    return raw


# ---------------------------------------------------------------------------
# 순수 계산
# ---------------------------------------------------------------------------

def _hourly(times: list[datetime], day: date, until_hour: int | None) -> list[int | None]:
    """`day` 하루를 0~23시 24칸으로 센다. until_hour 이후(아직 오지 않은 시간)는 None으로 둔다."""
    buckets = [0] * 24
    for t in times:
        if t.date() == day:
            buckets[t.hour] += 1
    if until_hour is not None:
        return [value if hour <= until_hour else None for hour, value in enumerate(buckets)]
    return buckets


def _day_labels(today: date) -> list[date]:
    return [today - timedelta(days=offset) for offset in range(RECENT_DAYS - 1, -1, -1)]


def _top(counter: Counter, n: int) -> list[dict]:
    return [{"name": name, "count": count} for name, count in counter.most_common(n)]


def build_threat_stats(raw: dict, *, active_locks: int, pending_ai: int, locations: dict[str, dict]) -> dict:
    """원본 줄 → 화면용 숫자. `locations`는 {IP: {"country": ...}} (ip_locations 캐시)."""
    now: datetime = raw["now"]
    today = now.date()
    days = _day_labels(today)
    day_set = set(days)

    events = []
    for row in raw["events"]:
        detected = _parse(row["detected_at"])
        if detected is not None:
            events.append({**row, "_t": detected, "_d": detected.date()})
    recent_events = [e for e in events if e["_d"] in day_set]

    # 1) 시간대별 탐지량 — 보안 이벤트 + 로그인 실패 + 404 + 미인증 접근을 한 줄로 합친다.
    detection_times = [e["_t"] for e in events if e["_d"] >= today - timedelta(days=RECENT_DAYS)]
    for key in ("failed_logins", "not_found", "unauthorized"):
        detection_times += [t for t in (_parse(r["attempted_at"]) for r in raw[key]) if t is not None]
    hourly = {
        "today": _hourly(detection_times, today, now.hour),
        "yesterday": _hourly(detection_times, today - timedelta(days=1), None),
        "last_week": _hourly(detection_times, today - timedelta(days=RECENT_DAYS), None),
    }

    # 2) 최근 7일 로그 발생량 — 지난 날은 일별 요약표, 오늘은 원본 표 개수.
    summary_by_day: dict[str, int] = defaultdict(int)
    for row in raw["summary"]:
        summary_by_day[row["day"]] += row["count"]
    log_volume = [
        {
            "day": d.isoformat(),
            "count": sum(raw["today_counts"].values()) if d == today else summary_by_day.get(d.isoformat(), 0),
            "live": d == today,
        }
        for d in days
    ]

    # 3) 공격자 IP × 날짜 히트맵 — 7일간 이벤트가 많은 IP 상위 8개.
    per_ip: Counter = Counter(e["ip_address"] for e in recent_events)
    heat_ips = [ip for ip, _ in per_ip.most_common(8)]
    per_ip_day: Counter = Counter((e["ip_address"], e["_d"]) for e in recent_events)
    heatmap = {
        "days": [d.isoformat() for d in days],
        "ips": heat_ips,
        "cells": [[per_ip_day.get((ip, d), 0) for d in days] for ip in heat_ips],
    }

    # 4) 흐름도: IP → 공격 유형 → 조치 (상위 IP 6개만, 나머지는 '그 외')
    flow_ips = [ip for ip, _ in per_ip.most_common(6)]
    flow_links: Counter = Counter()
    for e in recent_events:
        ip = e["ip_address"] if e["ip_address"] in flow_ips else "(그 외)"
        flow_links[(ip, e["event_type"], e["action"])] += 1
    sankey_links = []
    for (ip, event_type, action), n in flow_links.items():
        sankey_links.append({"source": ip, "target": event_type, "value": n})
    action_links: Counter = Counter()
    for (ip, event_type, action), n in flow_links.items():
        action_links[(event_type, action)] += n
    sankey_links += [{"source": t, "target": f"조치:{a}", "value": n} for (t, a), n in action_links.items()]

    # 5) 신규 공격자 / 반복 공격자 / 미처리 / 복합 공격
    first_seen: dict[str, date] = {}
    days_seen: dict[str, set] = defaultdict(set)
    last_seen: dict[str, datetime] = {}
    types_by_ip: dict[str, set] = defaultdict(set)
    count_by_ip: Counter = Counter()
    for e in events:
        ip = e["ip_address"]
        first_seen[ip] = min(first_seen.get(ip, e["_d"]), e["_d"])
        days_seen[ip].add(e["_d"])
        last_seen[ip] = max(last_seen.get(ip, e["_t"]), e["_t"])
        types_by_ip[ip].add(e["event_type"])
        if e["_d"] in day_set:
            count_by_ip[ip] += 1

    new_cutoff = today - timedelta(days=RECENT_DAYS - 1)
    new_attackers = sorted(
        (ip for ip, d in first_seen.items() if d >= new_cutoff and count_by_ip[ip] > 0),
        key=lambda ip: last_seen[ip],
        reverse=True,
    )
    repeat_attackers = sorted(
        (ip for ip in count_by_ip if len({d for d in days_seen[ip] if d in day_set}) >= 3),
        key=lambda ip: count_by_ip[ip],
        reverse=True,
    )

    def _ip_row(ip: str, **extra) -> dict:
        return {
            "ip": ip,
            "country": (locations.get(ip) or {}).get("country"),
            "count": count_by_ip[ip],
            "types": sorted(types_by_ip[ip]),
            "last_seen": last_seen[ip].isoformat(),
            **extra,
        }

    unresolved = sorted(
        (e for e in events if e["resolved_at"] is None),
        key=lambda e: (SEVERITY_ORDER.get(e["severity"], 9), -e["_t"].timestamp()),
    )
    compound = [
        {
            "ip": i["ip_address"],
            "types": i["event_types"],
            "type_count": len(i["event_types"]),
            "severity": i["severity_max"],
            "status": i["status"],
            "last_event_at": i["last_event_at"],
            "country": (locations.get(i["ip_address"]) or {}).get("country"),
        }
        for i in raw["incidents"]
        if len(i["event_types"]) >= 3
    ]

    # 6) 상세 모니터링: Top 5들과 나라별 흐름
    today_events = [e for e in events if e["_d"] == today]
    yesterday_events = [e for e in events if e["_d"] == today - timedelta(days=1)]
    top_sources = _top(Counter(e["ip_address"] for e in recent_events), 5)
    top_types = _top(Counter(e["event_type"] for e in recent_events), 5)
    top_paths = _top(Counter(e["path"] or "(경로 없음)" for e in recent_events), 5)
    severity_counts = Counter(e["severity"] for e in recent_events)

    country_flow: Counter = Counter()
    for e in recent_events:
        country = (locations.get(e["ip_address"]) or {}).get("country") or "위치 미확인"
        country_flow[(country, e["event_type"])] += 1
    country_links = [{"source": c, "target": t, "value": n} for (c, t), n in country_flow.items()]

    live_events = [
        {
            "id": e["id"],
            "detected_at": e["detected_at"],
            "severity": e["severity"],
            "event_type": e["event_type"],
            "ip": e["ip_address"],
            "country": (locations.get(e["ip_address"]) or {}).get("country"),
            "path": e["path"],
            "count": e["count"],
            "action": e["action"],
            "resolved": e["resolved_at"] is not None,
        }
        for e in sorted(events, key=lambda e: e["_t"], reverse=True)[:30]
    ]

    failed_today = sum(
        1 for t in (_parse(r["attempted_at"]) for r in raw["failed_logins"]) if t is not None and t.date() == today
    )

    return {
        "generated_at": now.isoformat(),
        "kpi": {
            "events_today": len(today_events),
            "events_yesterday": len(yesterday_events),
            "failed_logins_today": failed_today,
            "blocked_today": sum(1 for e in today_events if any(k in (e["action"] or "").upper() for k in ("LOCK", "REJECT"))),
            "active_locks": active_locks,
            "pending_ai": pending_ai,
            "unresolved_critical": sum(1 for e in unresolved if e["severity"] == "CRITICAL"),
            "unresolved_total": len(unresolved),
            "severity_7d": {k: severity_counts.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM")},
        },
        "hourly": hourly,
        "log_volume": log_volume,
        "summary_available": bool(raw["summary"]),
        "heatmap": heatmap,
        "flow": {"links": sankey_links},
        "new_attackers": [_ip_row(ip) for ip in new_attackers[:6]],
        "repeat_attackers": [
            _ip_row(ip, days=len({d for d in days_seen[ip] if d in day_set})) for ip in repeat_attackers[:6]
        ],
        "unresolved": [
            {
                "id": e["id"],
                "severity": e["severity"],
                "event_type": e["event_type"],
                "ip": e["ip_address"],
                "country": (locations.get(e["ip_address"]) or {}).get("country"),
                "path": e["path"],
                "detected_at": e["detected_at"],
            }
            for e in unresolved[:8]
        ],
        "compound": compound[:6],
        "top_sources": top_sources,
        "top_types": top_types,
        "top_paths": top_paths,
        "country_flow": {"links": country_links},
        "events": live_events,
        # L3/L4 센서는 아직 없다 — 화면은 이 빈 목록을 "수집 전" 상태로 그린다.
        "network_layer": [],
    }


# 같은 집계를 여러 관리자 탭이 동시에 요청해도 DB 조회는 한 번만 한다(단일 비행 + 짧은 보관).
_cache_lock = threading.Lock()
_cache: dict = {"at": None, "key": None, "value": None}


def _compute(active_locks: int, pending_ai: int) -> dict:
    raw = fetch_raw()
    ips = {e["ip_address"] for e in raw["events"]} | {i["ip_address"] for i in raw["incidents"]}
    locations = db.get_cached_ip_locations(sorted(ips)) if ips else {}
    return build_threat_stats(raw, active_locks=active_locks, pending_ai=pending_ai, locations=locations)


def get_threat_stats(active_locks: int, pending_ai: int) -> dict:
    """관리자 화면이 부르는 진입점: 원본을 가져와 계산하고, 상위 IP의 나라 정보를 붙인다.

    config.ADMIN_STATS_CACHE_SECONDS 안에 같은 요청이 또 오면 계산해 둔 값을 돌려준다. 락을 잡은 채로
    계산하므로, 동시에 들어온 다른 탭은 기다렸다가 같은 결과를 받는다(DB를 N번 두드리지 않는다).
    """
    ttl = config.ADMIN_STATS_CACHE_SECONDS
    if ttl <= 0:
        return _compute(active_locks, pending_ai)
    key = (active_locks, pending_ai)
    with _cache_lock:
        fresh = _cache["at"] is not None and time.monotonic() - _cache["at"] < ttl and _cache["key"] == key
        if not fresh:
            _cache.update(value=_compute(active_locks, pending_ai), key=key, at=time.monotonic())
        return _cache["value"]
