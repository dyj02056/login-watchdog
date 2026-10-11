# 10단원 — SOAR 플레이북 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "10-soar"
TITLE = "10. SOAR 플레이북"
SUBTITLE = "심각한 복합 공격에만 한 번 더 강조 알림을 보내는 플레이북과, 집행관(soar) 함수 지도"

FILE_ROLES = {
    "security/correlate.py": "사건을 보고 '이 정도면 에스컬레이션'을 판단하고 PLAYBOOKS(대응 매뉴얼)를 실행한다.",
    "notify/alert.py": "Slack 알림 전송 전담 파일. 에스컬레이션 알림 메시지가 여기서 만들어진다.",
    "db/incidents.py": "사건 표를 다루는 저장소 파일. '이미 알렸다'(escalated) 표시도 여기서 한다.",
    "security/soar/__init__.py": "집행관 패키지의 '창구'. 하위 파일의 함수를 다시 내보내 soar.xxx() 로 쓰게 해준다.",
    "security/soar/lockouts.py": "잠금 집행(IP·회원·관리자 계정)과 자동·수동 해제.",
    "security/soar/observe.py": "잠그지 않고 알림 + 기록만 하는 관찰형 조치와 요청 거부 기록.",
    "security/soar/early_warning.py": "LLM 조기 경보와 관리자 승인/반려. (11단원)",
}

s1 = Scenario("escalate", "복합 공격 에스컬레이션",
              "사건이 여러 개 쌓이는 것과 '정말 심각한 복합 공격'인 것은 다릅니다. 모든 사건에 긴급 알림을 보내면 알림 피로가 생기므로, 세 가지 조건을 모두 통과할 때 사건당 딱 한 번만 강조 알림을 보냅니다.")
s1.screen("사건이 갱신된 직후", "상관분석이 사건을 열거나 병합한 바로 뒤에 호출됩니다.",
          fn="security/correlate.py:check_and_correlate", hl=("incident = db.record_incident(ip, distinct_types, severity)", "_maybe_escalate(ip, incident)"),
          calls=[call("db.record_incident", "사건 열기 / 병합", "9단원에서 다뤘습니다.", later="9단원")])
s1.step("① 이미 알렸나?", "한 사건에 이벤트가 하나씩 붙을 때마다 알림이 반복되지 않도록, 이미 에스컬레이션된 사건은 건너뜁니다.",
        fn="security/correlate.py:_maybe_escalate", hl=('if incident["escalated"]:', "return"), reject="(조용히 종료 — 중복 알림 방지)")
s1.step("② 최고 위험등급이 CRITICAL 인가?", "잠금까지 일어난 사건만 대상입니다.",
        fn="security/correlate.py:_maybe_escalate", hl=('if incident["severity_max"] != "CRITICAL":', "return"), reject="(조용히 종료)")
s1.step("③ 서로 다른 공격 유형이 3개 이상인가?", "유형 하나짜리 사건은 5단원 알림으로 충분합니다. 여러 단계에 걸친 복합 공격일 때만 대상입니다.",
        fn="security/correlate.py:_maybe_escalate", hl=('if len(incident["event_types"]) < config.INCIDENT_ESCALATION_MIN_EVENT_TYPES:', "return"), reject="(조용히 종료)",
        calls=[call(snippet=("config.py", "INCIDENT_ESCALATION_MIN_EVENT_TYPES =", "INCIDENT_ESCALATION_MIN_EVENT_TYPES ="), title="필요 유형 수 (기본 3)", plain="에스컬레이션에 필요한 서로 다른 공격 유형 개수.", label="config.py 유형 수")])
s1.step("④ 플레이북 실행", "PLAYBOOKS 라는 '대응 매뉴얼' 목록의 함수를 이름으로 찾아 차례로 실행합니다. 대응이 늘어나도 목록에 이름만 추가하면 됩니다.",
        fn="security/correlate.py:_maybe_escalate", hl=("for action_name in PLAYBOOKS", "action(ip, incident"),
        calls=[call(snippet=("security/correlate.py", "PLAYBOOKS = {", "re:^}"), title="PLAYBOOKS (대응 매뉴얼)", plain="'이런 상황이면 이런 대응'을 선언적으로 나열한 딕셔너리.", label="PLAYBOOKS"),
               call("notify/alert.py:send_incident_escalation_alert", "복합 공격 Slack 알림", "IP·연관된 공격 유형 목록을 담아 강조된 알림을 보냅니다.")])
s1.step("⑤ 재발송 방지 표시", "이 사건에는 이미 알렸다고 표시합니다. 5유형·6유형으로 늘어나도 다시 알리지 않습니다.",
        fn="security/correlate.py:_maybe_escalate", hl="db.mark_incident_escalated(incident[\"id\"])",
        calls=[call("db.mark_incident_escalated", "escalated = True", "security_incidents 표에 '이미 알림' 표시를 남깁니다.")])

s2 = Scenario("map", "집행관(security/soar/) 함수 지도",
              "탐지(detector)가 '수상하다'고 판단만 하면, 실제로 잠그고 알리고 기록하는 일은 모두 soar 패키지가 합니다. 호출하는 쪽은 파일 위치를 몰라도 soar.함수() 하나로 부르고, 실제 파일은 아래처럼 나뉩니다.", chain=False)
s2.screen("호출하는 쪽 — soar.enforce_lockout(...)", "routes/auth.py 등은 soar 패키지 이름만 알고 있습니다. 어느 파일에 있는지는 몰라도 됩니다.",
          snippet=("security/soar/__init__.py", "from security.soar._events import _record_event", '    record_rejection,'), label="soar/__init__.py 재내보내기",
          calls=[])
s2.step("잠금 집행 · 해제 (lockouts.py)", "enforce_* 는 잠그고 알리고 기록합니다. try_release_expired_* 는 시간이 지난 잠금을 요청이 들어올 때마다 확인해 풀어줍니다(별도 타이머 없이).",
        kind="helper", items=[{"ref": "soar.enforce_lockout"}, {"ref": "soar.enforce_account_lockout"}, {"ref": "soar.enforce_admin_account_lockout"},
                              {"ref": "soar.try_release_expired_lockouts"}, {"ref": "soar.try_release_expired_account_lockouts"}, {"ref": "soar.manual_release"}])
s2.step("관찰 알림 (observe.py)", "잠그지 않고 알림 + 기록만 하는 조치. 잠글 대상이 없거나, 잠그면 정상 사용자가 피해를 볼 때 씁니다.",
        kind="helper", items=[{"ref": "soar.notify_bot_detected"}, {"ref": "soar.notify_web_scanning"}, {"ref": "soar.notify_unauthorized_access"},
                              {"ref": "soar.notify_page_access"}, {"ref": "soar.notify_macro_pattern"}, {"ref": "soar.record_rejection"}])
s2.step("LLM 조기 경보 (early_warning.py)", "기준치 코앞에서 AI에게 한 번 더 묻고, 관리자 승인으로 원래 조치를 실행합니다(11단원).",
        kind="helper", items=[{"ref": "soar.consider_early_warning"}, {"ref": "soar.execute_approved_request"}, {"ref": "soar.reject_pending_request"}])
s2.step("공통 기록 지점 (_events.py)", "위 모든 조치가 이벤트를 남길 때 지나는 함수(8단원).",
        kind="helper", items=[{"ref": "soar._record_event"}])

SCENARIOS = [s1.build(), s2.build()]
