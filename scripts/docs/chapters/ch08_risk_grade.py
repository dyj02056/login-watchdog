# 8단원 — 통합 보안 위험등급 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "08-risk-grade"
TITLE = "8. 통합 보안 위험등급"
SUBTITLE = "서로 다른 이상행위가 CRITICAL / HIGH / MEDIUM 등급과 함께 하나의 표에 모이는 코드 흐름도"

FILE_ROLES = {
    "security/soar/_events.py": "모든 조치 함수가 지나가는 '공통 기록 지점'. 이벤트를 저장하고 상관분석 훅을 부른다.",
    "security/soar/lockouts.py": "잠금 집행 파일. 잠그는 순간 CRITICAL 이벤트를 기록한다.",
    "security/soar/observe.py": "관찰형 조치 파일. 알림만 하는 유형은 MEDIUM, 요청을 거부한 유형은 HIGH로 기록한다.",
    "db/security_events.py": "security_events 표(위험등급별 이벤트 목록)를 읽고 쓰는 저장소 파일.",
    "routes/admin/incidents.py": "관리자 대시보드의 '처리 완료'·'해결'·'승인' 버튼이 호출하는 API 입구 파일.",
}

# ---------------------------------------------------------------- 1) 기록
s1 = Scenario("record", "이벤트 기록 (공통 진입점)",
              "탐지·집행 파일이 제각각 이벤트를 저장하면 등급 기준이 흩어집니다. 그래서 모든 조치 함수가 _record_event() 한 곳을 지나가도록 모았습니다. 등급은 '대응 방식'으로 정해집니다.")
s1.screen("조치 함수가 이벤트를 남긴다", "잠금(enforce_*), 요청 거부(record_rejection), 관찰 알림(notify_*)이 각자 자기 등급으로 _record_event() 를 부릅니다.",
          fn="soar.enforce_lockout", hl='_record_event(event_type, "CRITICAL", ip, None, failure_count, "LOCKED")')
s1.step("① CRITICAL — 실제로 잠갔다", "IP·계정 잠금처럼 가장 강한 조치가 일어난 이벤트. 잠금이 풀릴 때 자동으로 처리됩니다.",
        fn="soar.enforce_lockout", hl=("if is_admin:", '_record_event(event_type, "CRITICAL", ip, None, failure_count, "LOCKED")'),
        calls=[call("soar.enforce_account_lockout", "계정 잠금도 CRITICAL", "DISTRIBUTED_BRUTE_FORCE 로 기록합니다.", later="5단원")])
s1.step("② HIGH — 요청을 거부했다", "가입·글·댓글 도배처럼 요청을 거부한 이벤트. 이미 열린 이벤트가 있으면 새 행 대신 횟수만 올립니다.",
        fn="soar.record_rejection", hl=("existing = db.get_unresolved_security_event", "db.insert_security_event_or_bump"),
        calls=[call("db.get_unresolved_security_event", "미해결 이벤트 찾기", "같은 IP·유형의 열린 이벤트가 있는지 봅니다."),
               call("db.update_security_event_count", "횟수만 1 올리기", "새 행을 만들지 않고 count 를 올립니다."),
               call("db.insert_security_event_or_bump", "새로 기록", "동시 요청이 겹쳐도 유니크 인덱스가 중복 삽입을 막습니다.")])
s1.step("③ MEDIUM — 관찰만 했다", "Web Scanning·미인증 접근·매크로처럼 알림과 기록만 한 이벤트.",
        fn="soar.notify_web_scanning", hl='_record_event("WEB_SCANNING", "MEDIUM", ip, path, count, "ALERTED")',
        calls=[call("soar.notify_unauthorized_access", "UNAUTHORIZED_ACCESS", "MEDIUM 으로 기록합니다."),
               call("soar.notify_macro_pattern", "API_MACRO_PATTERN", "MEDIUM 으로 기록합니다.")])
s1.step("④ 공통 기록 지점 _record_event()", "모든 조치 함수가 결국 여기를 통과합니다. 새 조치 함수를 만들 때 상관분석 호출을 빠뜨리지 않도록 한 곳으로 모았습니다.",
        fn="security/soar/_events.py:_record_event", hl=("if username is not None:", "db.insert_security_event(event_type, severity, ip, path, count, action)"),
        calls=[call("db.insert_security_event", "security_events 표에 저장", "유형·등급·IP·경로·횟수·조치를 한 줄로 저장합니다.")])
s1.step("⑤ 상관분석 훅 자동 호출", "저장 직후 항상 상관분석(9단원)을 부릅니다. 같은 IP의 이벤트들이 하나의 공격 흐름인지 보기 위해서입니다.",
        fn="security/soar/_events.py:_record_event", hl="correlate.check_and_correlate(ip, event_type, severity)",
        calls=[call("security/correlate.py:check_and_correlate", "사건 묶기", "5분 안에 서로 다른 유형이 2개 이상이면 사건으로 묶습니다.", later="9단원")])

# ---------------------------------------------------------------- 2) 처리
s2 = Scenario("resolve", "관리자 '처리 완료'",
              "HIGH·MEDIUM 이벤트는 관리자가 확인한 뒤 '처리 완료'를 누릅니다. CRITICAL 은 이 버튼으로 지울 수 없고, 잠금이 풀릴 때 자동으로만 처리됩니다.")
s2.screen("대시보드 '처리 완료' 클릭 (POST)", "브라우저가 이 API 를 호출합니다. 권한 있는 관리자만 들어옵니다.",
          fn="routes/admin/incidents.py:api_security_events_resolve", hl=('@admin_bp.route("/api/security-events/resolve"', '@require_permission("resolve_security_event")'))
s2.step("① 권한 확인 후 해결 요청", "require_permission 문지기가 이미 '권한 있는 관리자'임을 보장하므로 바로 해결 처리합니다.",
        fn="routes/admin/incidents.py:api_security_events_resolve", hl=('event_id = data.get("event_id")', "resolved = db.resolve_security_event(event_id)"),
        reject="event_id 값이 필요합니다. (400)",
        calls=[call("db.resolve_security_event", "해결됨으로 표시", "resolved_at 을 채웁니다. 단, CRITICAL 은 제외합니다.", hl=(".neq(\"severity\", \"CRITICAL\")", ".is_(\"resolved_at\", \"null\")"))])
s2.step("② CRITICAL 은 서버가 막는다", "화면에서 버튼을 숨기는 것만으로는 API 직접 호출로 우회할 수 있어서, 서버 쪽 쿼리에서도 CRITICAL 을 제외합니다.",
        fn="db.resolve_security_event", hl=('.neq("severity", "CRITICAL")', '.is_("resolved_at", "null")'))
s2.step("③ CRITICAL 은 잠금이 풀릴 때 자동 처리", "잠금이 풀리는 순간(자동 만료든 수동 해제든) 그 IP 의 미해결 CRITICAL 이벤트도 함께 끝난 것으로 봅니다.",
        fn="db.resolve_security_events_for_ip", hl='.eq("severity", "CRITICAL")',
        calls=[call("soar.manual_release", "관리자 즉시 해제", "잠금을 풀고 이 IP 의 CRITICAL 이벤트를 정리합니다.", later="12단원"),
               call("soar.try_release_expired_lockouts", "만료 자동 해제", "5분이 지난 잠금을 풀고 이벤트를 정리합니다.", later="10단원")])

SCENARIOS = [s1.build(), s2.build()]
