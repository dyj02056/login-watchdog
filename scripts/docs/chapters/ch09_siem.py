# 9단원 — SIEM 상관분석 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "09-siem"
TITLE = "9. SIEM 상관분석"
SUBTITLE = "흩어진 이벤트들이 '하나의 공격 사건'으로 묶이고 닫히는 과정의 코드 흐름도"

FILE_ROLES = {
    "security/soar/_events.py": "이벤트를 저장한 직후 상관분석을 호출하는 공통 기록 지점.",
    "security/correlate.py": "형사 역할. 같은 IP 의 이벤트들을 보고 사건으로 묶을지 '판단'한다. 저장·병합은 db 에 맡긴다.",
    "db/incidents.py": "security_incidents 표(사건)를 열고, 병합하고, 닫는 저장소 파일.",
    "db/security_events.py": "security_events 표(개별 이벤트)를 읽고 쓰는 저장소 파일.",
    "routes/admin/incidents.py": "관리자 대시보드의 '해결' 버튼이 호출하는 API 입구 파일.",
    "config.py": "상관분석 시간 창(5분)·유휴 기준(30분) 같은 설정값.",
}

s1 = Scenario("correlate", "사건 묶기",
              "같은 IP 가 '웹 스캐닝(정찰) → 브루트포스(공격)'처럼 움직이면 우연이 아니라 하나의 공격 흐름일 가능성이 큽니다. 이벤트를 기록할 때마다 '최근 5분 안에 서로 다른 유형이 2개 이상인가?'를 확인합니다.")
s1.screen("이벤트가 기록된 직후", "_record_event() 가 이벤트를 저장하고 나면 항상 상관분석을 부릅니다.",
          fn="security/soar/_events.py:_record_event", hl="correlate.check_and_correlate(ip, event_type, severity)")
s1.step("① 최근 5분 안에 서로 다른 유형이 몇 개?", "같은 IP 의 최근 이벤트 유형 목록(중복 없이)을 가져옵니다. 방금 기록한 이벤트도 포함됩니다.",
        fn="security/correlate.py:check_and_correlate", hl=("distinct_types = db.get_recent_distinct_event_types(", "if len(distinct_types) < 2:"),
        calls=[call("db.get_recent_distinct_event_types", "최근 이벤트 유형 목록", "security_events 에서 이 IP 의 최근 N분 유형을 모아 중복을 없앱니다."),
               call(snippet=("config.py", "INCIDENT_CORRELATION_WINDOW_MINUTES =", "INCIDENT_CORRELATION_WINDOW_MINUTES ="), title="시간 창 설정 (5분)", plain="상관분석이 보는 시간 범위입니다.", label="config.py 시간 창")])
s1.step("② 2개 미만이면 사건으로 만들지 않는다", "단발성 이벤트까지 전부 사건으로 묶으면 사건 표가 이벤트 표와 다를 바 없어집니다.",
        fn="security/correlate.py:check_and_correlate", hl=("if len(distinct_types) < 2:", "return"))
s1.step("③ 사건을 열거나 갱신", "이 IP 에 열린 사건이 있으면 합치고, 없으면 새로 엽니다.",
        fn="security/correlate.py:check_and_correlate", hl="incident = db.record_incident(ip, distinct_types, severity)",
        calls=[call("db.record_incident", "사건 열기 / 병합", "열린 사건을 찾아 병합하거나 새 사건을 만듭니다.",
                    then=[call("db.get_open_incident", "열린 사건 찾기", "이 IP 의 OPEN 사건 한 건을 가져옵니다.")])])
s1.step("④ 오래 조용했던 사건은 IDLE 로 옮기고 새로 연다", "마지막 이벤트로부터 30분 넘게 조용했던 사건에 새 공격을 억지로 합치지 않습니다. 이미 알림이 나간 옛 사건이 새 공격의 알림을 삼키는 일을 막기 위해서입니다.",
        fn="db.record_incident", hl=("existing = get_open_incident(ip)", "existing = None"),
        calls=[call("db/incidents.py:_is_idle", "오래 조용했나?", "last_event_at 이 유휴 기준(30분)보다 오래됐는지 비교합니다."),
               call("db.mark_incident_idle", "OPEN → IDLE", "옛 사건을 '활동 없음'으로 옮깁니다(아직 관리자 미해결).")])
s1.step("⑤ 열린 사건이 있으면 병합, 없으면 새로 열기", "유형 목록은 합집합, 위험등급은 더 높은 쪽으로 갱신합니다. 동시 요청이 겹쳐도 DB 유니크 인덱스가 중복을 막습니다.",
        fn="db.record_incident", hl=("if existing:", "except APIError as e:"),
        calls=[call("db/incidents.py:_merge_into_existing", "기존 사건에 병합", "유형 합집합 + 더 높은 등급으로 갱신합니다."),
               call("db/incidents.py:_insert_incident", "새 사건 열기", "status=OPEN, escalated=False 로 시작합니다.")])
s1.step("⑥ 에스컬레이션 판단", "사건이 충분히 심각해졌는지 이어서 확인합니다(10단원).",
        fn="security/correlate.py:check_and_correlate", hl="_maybe_escalate(ip, incident)",
        calls=[call("security/correlate.py:_maybe_escalate", "복합 공격 에스컬레이션", "CRITICAL + 유형 3개 이상이면 추가 알림.", later="10단원")])

s2 = Scenario("close", "사건 해결 (관리자 버튼으로만)",
              "사건은 'IP 잠금 해제'와 별개입니다. 잠금은 접속 차단을 거두는 조치일 뿐이고, 사건은 관리자가 내용을 확인하고 '해결'을 눌러야만 닫힙니다.")
s2.screen("대시보드 '해결' 클릭 (POST)", "연관 사건 표의 '해결' 버튼이 이 API 를 호출합니다.",
          fn="routes/admin/incidents.py:api_security_incidents_resolve", hl=('@admin_bp.route("/api/security-incidents/resolve"', '@require_permission("resolve_incident")'))
s2.step("① 입력 확인", "incident_id 가 정수가 아니면 거부합니다. bool 도 정수처럼 보이지만 일부러 걸러냅니다.",
        fn="routes/admin/incidents.py:api_security_incidents_resolve", hl=('incident_id = data.get("incident_id")', "return jsonify"), reject="incident_id 값이 필요합니다. (400)")
s2.step("② 해결자는 세션에서 가져온다", "누가 해결했는지는 요청 본문이 아니라 로그인 세션에서 가져옵니다. 본문 값은 위조할 수 있기 때문입니다.",
        fn="routes/admin/incidents.py:api_security_incidents_resolve", hl='resolved = db.resolve_incident(incident_id, session["admin_username"])',
        calls=[call("db.resolve_incident", "CLOSED 로 변경 + 해결자·시각 기록", "OPEN 또는 IDLE 인 사건에만 적용돼서 이미 해결된 사건을 다시 눌러도 안전합니다.",
                    hl=('.update({"status": "CLOSED"', '.in_("status", ["OPEN", "IDLE"])'))])

SCENARIOS = [s1.build(), s2.build()]
