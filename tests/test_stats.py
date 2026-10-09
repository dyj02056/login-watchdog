# ============================================================================
# test_stats.py — 관제 대시보드 집계(db/stats.py)의 순수 계산 부분
# ============================================================================

from datetime import datetime, timedelta

from db import stats

NOW = datetime(2026, 10, 9, 15, 30, tzinfo=stats.KST)


def _event(i, days_ago, hour, ip, event_type="BRUTE_FORCE", severity="CRITICAL", action="LOCK_IP", resolved=False):
    when = (NOW - timedelta(days=days_ago)).replace(hour=hour, minute=5)
    return {
        "id": i, "event_type": event_type, "severity": severity, "ip_address": ip, "path": "/login",
        "count": 6, "action": action, "username": None, "detected_at": when.isoformat(),
        "resolved_at": when.isoformat() if resolved else None,
    }


def _raw(events=(), summary=(), incidents=(), today_counts=None, failed=(), nf=(), ua=()):
    return {
        "now": NOW, "events": list(events), "summary": list(summary), "incidents": list(incidents),
        "failed_logins": [{"attempted_at": t} for t in failed],
        "not_found": [{"attempted_at": t} for t in nf],
        "unauthorized": [{"attempted_at": t} for t in ua],
        "today_counts": today_counts or {s: 0 for s in stats.LOG_SOURCES},
    }


def build(raw, locations=None, active=0, pending=0):
    return stats.build_threat_stats(raw, active_locks=active, pending_ai=pending, locations=locations or {})


def test_empty_database_gives_zeroes_and_empty_network_layer():
    result = build(_raw())
    assert result["kpi"]["events_today"] == 0
    assert result["network_layer"] == []
    assert len(result["hourly"]["today"]) == 24
    assert len(result["log_volume"]) == 7
    assert result["summary_available"] is False


def test_hourly_series_stops_at_the_current_hour_for_today_only():
    result = build(_raw(events=[_event(1, 0, 9, "1.1.1.1"), _event(2, 1, 22, "1.1.1.1"), _event(3, 7, 3, "1.1.1.1")]))
    today = result["hourly"]["today"]
    assert today[9] == 1 and today[15] == 0 and today[16] is None and today[23] is None
    assert result["hourly"]["yesterday"][22] == 1
    assert result["hourly"]["last_week"][3] == 1


def test_failed_logins_and_404s_count_as_detections():
    stamp = NOW.replace(hour=10).isoformat()
    result = build(_raw(failed=[stamp, stamp], nf=[stamp], ua=[stamp]))
    assert result["hourly"]["today"][10] == 4
    assert result["kpi"]["failed_logins_today"] == 2


def test_log_volume_uses_summary_for_past_days_and_live_counts_for_today():
    yesterday = (NOW - timedelta(days=1)).date().isoformat()
    summary = [{"day": yesterday, "source": "login_attempts", "count": 7}, {"day": yesterday, "source": "api_access_log", "count": 5}]
    counts = {s: 0 for s in stats.LOG_SOURCES} | {"login_attempts": 3, "not_found_attempts": 2}
    result = build(_raw(summary=summary, today_counts=counts))
    by_day = {d["day"]: d for d in result["log_volume"]}
    assert by_day[yesterday]["count"] == 12 and by_day[yesterday]["live"] is False
    assert by_day[NOW.date().isoformat()]["count"] == 5 and by_day[NOW.date().isoformat()]["live"] is True
    assert result["summary_available"] is True


def test_heatmap_ranks_ips_and_new_vs_repeat_attackers():
    events = [
        _event(1, 0, 8, "9.9.9.9"), _event(2, 1, 8, "9.9.9.9"), _event(3, 2, 8, "9.9.9.9"), _event(7, 25, 8, "9.9.9.9"),  # 최근 3일에 걸쳐 → 반복(예전부터 있었으니 신규 아님)
        _event(4, 0, 9, "8.8.8.8"),                                                          # 오늘 처음 → 신규
        _event(5, 20, 9, "7.7.7.7"), _event(6, 0, 9, "7.7.7.7"),                              # 20일 전부터 있었음 → 신규 아님
    ]
    result = build(_raw(events=events))
    assert result["heatmap"]["ips"][0] == "9.9.9.9"
    assert result["heatmap"]["cells"][0] == [0, 0, 0, 0, 1, 1, 1]
    assert [r["ip"] for r in result["new_attackers"]] == ["8.8.8.8"]
    assert [r["ip"] for r in result["repeat_attackers"]] == ["9.9.9.9"]
    assert result["repeat_attackers"][0]["days"] == 3


def test_unresolved_sorted_by_severity_and_kpi_counts():
    events = [
        _event(1, 0, 8, "1.1.1.1", severity="MEDIUM"),
        _event(2, 0, 9, "2.2.2.2", severity="CRITICAL"),
        _event(3, 0, 10, "3.3.3.3", severity="HIGH", resolved=True),
    ]
    result = build(_raw(events=events), active=2, pending=1)
    assert [u["severity"] for u in result["unresolved"]] == ["CRITICAL", "MEDIUM"]
    assert result["kpi"]["unresolved_critical"] == 1
    assert result["kpi"]["blocked_today"] == 3
    assert result["kpi"]["active_locks"] == 2 and result["kpi"]["pending_ai"] == 1


def test_compound_attackers_need_three_event_types_and_country_is_attached():
    incidents = [
        {"id": 1, "ip_address": "5.5.5.5", "event_types": ["A", "B", "C"], "severity_max": "CRITICAL", "status": "OPEN",
         "first_event_at": NOW.isoformat(), "last_event_at": NOW.isoformat()},
        {"id": 2, "ip_address": "6.6.6.6", "event_types": ["A", "B"], "severity_max": "HIGH", "status": "OPEN",
         "first_event_at": NOW.isoformat(), "last_event_at": NOW.isoformat()},
    ]
    result = build(_raw(incidents=incidents), locations={"5.5.5.5": {"country": "Russia"}})
    assert [c["ip"] for c in result["compound"]] == ["5.5.5.5"]
    assert result["compound"][0]["country"] == "Russia"


def test_flow_and_country_links_aggregate_counts():
    events = [_event(1, 0, 8, "1.1.1.1"), _event(2, 0, 9, "1.1.1.1"), _event(3, 0, 9, "2.2.2.2", event_type="WEB_SCANNING", action="ALERT_ONLY")]
    result = build(_raw(events=events), locations={"1.1.1.1": {"country": "Korea"}})
    links = {(l["source"], l["target"]): l["value"] for l in result["flow"]["links"]}
    assert links[("1.1.1.1", "BRUTE_FORCE")] == 2
    assert links[("BRUTE_FORCE", "조치:LOCK_IP")] == 2
    countries = {(l["source"], l["target"]): l["value"] for l in result["country_flow"]["links"]}
    assert countries[("Korea", "BRUTE_FORCE")] == 2 and countries[("위치 미확인", "WEB_SCANNING")] == 1


def _incident(i, status, severity="HIGH", resolved_by=None, minutes_ago=5):
    stamp = (NOW - timedelta(minutes=minutes_ago)).isoformat()
    return {"id": i, "ip_address": f"7.7.7.{i}", "event_types": ["A", "B"], "severity_max": severity, "status": status,
            "first_event_at": stamp, "last_event_at": stamp, "resolved_by": resolved_by}


def test_open_incidents_list_unresolved_idle_and_system_closed_but_not_admin_closed():
    incidents = [
        _incident(1, "CLOSED", resolved_by="admin1"),
        _incident(2, "IDLE", "CRITICAL"),
        _incident(3, "OPEN", "MEDIUM"),
        _incident(4, "CLOSED", resolved_by="system:permanent_lock"),
        _incident(5, "OPEN", "CRITICAL"),
    ]
    result = build(_raw(incidents=incidents))
    assert [i["id"] for i in result["open_incidents"]] == [5, 3, 2, 4]  # 상태(OPEN→IDLE→자동 종료) 순, 같은 상태는 등급순
    assert result["open_incidents_total"] == 4
    assert [i["auto_closed"] for i in result["open_incidents"]] == [False, False, False, True]


def test_build_locks_merges_ip_account_admin_with_permanent_first():
    locks = stats.build_locks(
        [{"ip_address": "1.1.1.1", "locked_at": "2026-10-09T10:00:00+00:00", "lock_type": "TEMPORARY"}],
        [{"username": "kim", "locked_at": "2026-10-09T09:00:00+00:00", "lock_type": "PERMANENT"}],
        [{"username": "root", "locked_at": "2026-10-09T11:00:00+00:00"}],
    )
    assert [(l["kind"], l["target"], l["permanent"]) for l in locks["locks"]] == [
        ("account", "kim", True), ("admin", "root", False), ("ip", "1.1.1.1", False)]
    assert locks["locks_total"] == 3 and locks["locks_permanent"] == 1


def test_pathless_events_are_split_by_type_and_kept_out_of_top_paths():
    def ev(i, event_type, path):
        stamp = (NOW - timedelta(minutes=i)).isoformat()
        return {"id": i, "event_type": event_type, "severity": "MEDIUM", "ip_address": "9.9.9.9", "path": path, "count": 1,
                "action": "ALERTED", "username": None, "detected_at": stamp, "resolved_at": None}

    events = [ev(1, "WEB_SCANNING", "/.env"), ev(2, "WEB_SCANNING", "/.env"), ev(3, "BRUTE_FORCE", None), ev(4, "BRUTE_FORCE", None),
              ev(5, "BRUTE_FORCE", None), ev(6, "API_MACRO_PATTERN", None), ev(7, "PASSWORD_SPRAYING", None),
              ev(8, "DISTRIBUTED_BRUTE_FORCE", None), ev(9, "UNAUTHORIZED_ACCESS", None), ev(10, "UNAUTHORIZED_ACCESS", None)]
    result = build(_raw(events=events))
    assert result["top_paths"] == [{"name": "/.env", "count": 2}]
    assert result["pathless_total"] == 8
    names = [t["name"] for t in result["pathless_types"]]
    assert names[:2] == ["BRUTE_FORCE", "UNAUTHORIZED_ACCESS"] and names[-1] == "기타"
    assert len(result["pathless_types"]) == stats.PATHLESS_TYPE_LIMIT + 1
    assert sum(t["count"] for t in result["pathless_types"]) == 8


def test_no_pathless_events_means_no_other_bucket():
    result = build(_raw())
    assert result["pathless_types"] == [] and result["pathless_total"] == 0
