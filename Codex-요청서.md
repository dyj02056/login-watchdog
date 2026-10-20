# 역할 B — Codex 요청서

> 읽는 법: [설명서.md](설명서.md)의 5장. **작업 하나 = Codex 실행 하나.** 최신 main을 받은 뒤 저장소 폴더에서 Codex를 열고, 아래 ` ```text ` 상자를 **통째로** 붙여 넣는다.
> Codex는 저장소 루트의 `AGENTS.md`(공통 규칙)와 `docs/track-d/contracts.md`(계약서)를 스스로 읽는다. 요청문에는 그 작업에 필요한 것만 적었다.
> **용어 — "계약서" = 저장소의 `docs/track-d/contracts.md`.** 팀 계획 폴더의 `02-연동-계약서.md`를 뼈대 PR이 저장소로 복사한 사본이고 내용이 같다. 요청문 안의 "계약서 K4"는 이 파일의 K4 절을 뜻한다. Codex가 저장소에서 스스로 읽으므로 따로 첨부하지 않는다. 각 요청문의 첫 "계약서"에도 경로를 붙여 두었다.
> 상위 계획서는 저장소 밖에 있다. B0-1~B1-3은 필요한 내용을 요청문에 직접 옮겨 적었고, **B2-1~B3-2는 같은 폴더의 [plan-excerpt.md](plan-excerpt.md)를 Codex 대화창에 첨부**해서 쓴다(규칙 표가 길어 요청문에 다시 적지 않음). 이 파일은 저장소 안으로 복사하지 않는다.

---

## B0-1 비밀 도장 검사 (10/20)

```text
[작업 B0-1] 내부 API 서명 검증 공용 함수 — 계약서(docs/track-d/contracts.md) K3

먼저 읽을 파일: AGENTS.md, docs/track-d/contracts.md(K1·K3), routes/internal/_hmac.py(뼈대 껍데기), routes/internal/ingest.py, tests/track_d/conftest.py, config.py의 "# === Track D ===" 구역
고칠 파일: routes/internal/_hmac.py, tests/track_d/test_b_hmac.py(새 파일)

요구사항
1. sign(key: str, timestamp: str, body: bytes) -> str : hmac.new(key.encode(), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
2. verify_request(allowed_senders: set[str]) -> str | None : 현재 flask.request를 검사해 성공 시 보낸이 이름, 실패 시 None.
   - X-LW-Sender가 allowed_senders에 없으면 None
   - 키: "shipper" → config.NET_INGEST_SECRET, "fw-agent" → config.NET_AGENT_SECRET. 키가 빈 문자열이면 None
   - X-LW-Timestamp가 정수가 아니거나 |지금 - 값| > config.NET_INTERNAL_MAX_SKEW_SECONDS면 None
   - 본문은 request.get_data(cache=True)로 읽어 뒤에서 get_json()을 다시 쓸 수 있게 한다
   - hmac.compare_digest로 비교
   - 실패 이유는 응답에 노출하지 않고, print 한 줄 로그(이유 종류만, 키·서명 값은 출력 금지)
3. 모듈 docstring에 왜 보낸이별 키를 나누는지(P7)와 재전송 방지(60초)를 한국어로 설명.

테스트(tests/track_d/test_b_hmac.py)
- tests/track_d/conftest.py의 signed_headers 헬퍼와 sign()이 같은 값을 만드는지(교차 검증)
- 기준값: sign("test-key", "1760930000", b'{"a":1}') == "2f744cec328f65506df5ad72df7fdd688c7a3cf3c6f90b1e0085849106179de2" (계약서 K3에 적힌 값)
- flask_app.test_request_context로: 올바른 서명 → 보낸이 반환 / 허용 안 된 보낸이 / 빈 키 / 61초 지난 시각 / 본문 한 글자 변조 / 헤더 누락 → None

완료 조건: pytest tests/ -q 통과. 기준값 테스트가 계약서 K3 값과 일치.
```

---

## B0-2 DB 구조 변경 SQL (10/20) — 모두가 기다림

```text
[작업 B0-2] Track D 마이그레이션 — 계약서(docs/track-d/contracts.md) K11

먼저 읽을 파일: AGENTS.md, docs/track-d/contracts.md(K5·K8·K9·K11·K12), docs/schema.sql, docs/migrations/guide33_permanent_lock.sql(형식 예시), docs/migrations/guide44_log_retention.sql
고칠 파일: docs/migrations/guide52_track_d.sql(새 파일), docs/schema.sql(같은 내용을 맨 아래 "Track D (guide52)" 구역에 반영)

guide52_track_d.sql에 아래를 모두 넣어라. 모든 문장은 여러 번 실행해도 안전해야 한다(create table if not exists, add column if not exists, create index if not exists, drop constraint if exists 후 add constraint, insert ... on conflict do nothing). 기존 칸 삭제·이름 변경 금지. RLS는 기존 표들처럼 쓰지 않는다.

1. network_events 표
   id bigint identity PK, event_id text not null unique, sensor text not null check in ('suricata','scapy'), layer text not null check in ('L3','L4','L7'), src_ip text not null, dst_port int, proto text, category text not null check in ('SYN_FLOOD','PORT_SCAN','SCANNER_UA','WEB_ATTACK','LOGIN_BURST','OTHER'), signature_id int, signature text, sensor_severity smallint, packet_count int not null default 1, window_start timestamptz not null, observed_at timestamptz not null, last_seen_at timestamptz not null, promoted boolean not null default false, received_at timestamptz not null default now()
   인덱스 (src_ip, observed_at desc), (observed_at desc)
2. network_blocks 표 (C 소유)
   ip_address text PK, reason text not null, evidence text not null check in ('SPOOFABLE','CONNECTED'), status text not null check in ('PENDING_APPLY','APPLIED','PENDING_REMOVE','REMOVED','FAILED'), expires_at timestamptz, requested_by text not null, requested_at timestamptz not null default now(), applied_at timestamptz, removed_at timestamptz, last_error text,
   constraint network_blocks_permanent_needs_connected check (expires_at is not null or evidence = 'CONNECTED')
   인덱스 (status)
3. agent_heartbeats 표 (C 소유, PC별) — 계약서 K11 변경분
   agent text not null check in ('fw-agent','shipper'), node text not null, last_seen_at timestamptz not null, detail jsonb, primary key (agent, node)
4. notification_cooldowns 표 (C 소유): key text PK, last_sent_at timestamptz not null
5. playbook_runs 표: id bigint identity PK, playbook text not null, trigger_ref text not null, step text not null, status text not null check in ('OK','FAILED','SKIPPED'), error text, ran_at timestamptz not null default now(); 인덱스 (ran_at desc)
6. security_events에 source text not null default 'APP' check in ('APP','NET'), layer text check in ('L3','L4','L7') 추가
7. security_incidents에 matched_rules text[] not null default '{}', app_severity_max text check in ('MEDIUM','HIGH','CRITICAL') 추가, 그리고
   update security_incidents set app_severity_max = severity_max where app_severity_max is null;
   (기존 사건은 모두 앱 이벤트뿐이므로, 영구 잠금 판단이 새 칸만 읽어도 기존 판단이 바뀌지 않는다)
8. access_requests의 check 제약 3개를 넓힌다: event_type에 'NET_REPEAT_FLOOD','NET_SUBNET_ATTACK', pending_action에 'BLOCK_L4_PERMANENT','BLOCK_SUBNET', target_kind에 'subnet'. 기존 허용값은 docs/schema.sql의 가장 마지막 정의를 그대로 유지하고 추가만 한다.
9. permissions_action_check에 'release_network_block' 추가(기존 값은 docs/schema.sql의 마지막 정의 유지), 그리고 'unlock_ip' 권한을 가진 모든 역할에 'release_network_block' insert ... select ... on conflict do nothing
10. security_incidents.status 제약은 건드리지 않는다.

파일 맨 위 주석: 목적, 실행 순서(Supabase SQL Editor에서 통합 담당자가 실행), 두 번 실행해도 안전함, 되돌리는 방법(drop table/column 문을 주석으로).

테스트: pytest 테스트는 필요 없다. 대신 tests/test_log_retention.py처럼 SQL 파일을 문자열로 읽어 검사하는 테스트가 있다면 그 방식으로 tests/track_d/test_b_migration.py를 만들어 "if not exists" 사용, 위 표 이름 5개 존재, update app_severity_max 문 존재를 확인하라. 그런 방식이 없으면 이 테스트는 만들지 마라.

완료 조건: pytest tests/ -q 통과. 마지막 보고에 "통합 담당자가 실행 전에 확인할 행 수 조회 SQL" 3줄(security_incidents, security_events, access_requests count)을 적어라.
```

---

## B1-1 경보 접수 창구 (10/22) — B0-1 머지 + DB 적용 후

```text
[작업 B1-1] 수집 API POST /api/internal/net-events — 계약서(docs/track-d/contracts.md) K4·K10

먼저 읽을 파일: AGENTS.md, docs/track-d/contracts.md(K1·K3·K4·K10), routes/internal/__init__.py, routes/internal/_hmac.py, routes/internal/ingest.py(껍데기), db/network_events.py(껍데기), db/security_events.py(23505 처리 예시), helpers/request_utils.py(normalize_ip가 어디서 오는지), app.py(internal.net_events에 건 한도와 rate_limit_key 사용 방식 — 읽기만), docs/migrations/guide52_track_d.sql
고칠 파일: routes/internal/ingest.py, db/network_events.py, tests/track_d/test_b_ingest.py(새 파일)
고치면 안 되는 파일: app.py(뼈대 PR이 이미 한도를 걸어 둠)

요구사항
1. net_events() 처리 순서: (a) request.content_length가 config.NET_INGEST_MAX_BODY_BYTES 초과면 413 (b) verify_request({"shipper"}) 실패면 401 (c) get_json(silent=True)이 dict가 아니면 400 (d) 계약서 K4 표대로 칸별 검증, 실패 시 400 {"error":"invalid","field":칸} (e) src_ip는 normalize_ip로 바꿔 저장.
2. 저장: db.insert_network_event(row) -> bool (event_id 충돌 23505면 False). False면 db.bump_network_event(event_id, packet_count, last_seen_at=observed_at)로 packet_count는 더 클 때만 갱신(.lt("packet_count", 새값) 조건), last_seen_at 갱신.
3. 응답: 새로 저장 {"status":"stored","promoted":false}, 이미 있음 {"status":"updated","promoted":false}. (보안 이벤트 승격은 다음 작업 B1-2에서 추가)
4. rate_limit_key() -> str : f"net-ingest:{X-LW-Sender 헤더 또는 'unknown'}" (보낸이별 분당 한도 — 계약서 K1의 NET_INGEST_RATE_LIMIT_PER_MINUTE. 헤더 값은 서명 검증 전이라 이름표로만 쓴다)
5. db/network_events.py에 계약서 K10의 조회 함수도 만든다:
   - list_recent_network_events(limit=50) -> list[dict] : id, observed_at, src_ip, layer, category, signature, packet_count, promoted, observed_at 최신순
   - count_network_events_by_category(since_iso: str) -> list[dict] : observed_at >= since_iso 인 행을 category·layer로 묶은 {"category","layer","count"} 목록(개수 많은 순). 행이 많을 수 있으니 db/stats.py의 페이지 반복 방식처럼 최대 20000행까지 읽어 Python에서 센다.
   - 모든 새 함수 이름을 __all__에 추가.

테스트: client fixture + tests/track_d/conftest.py의 signed_headers. config.NET_INGEST_SECRET을 monkeypatch, db.insert_network_event/bump_network_event는 가짜(raising=False). 확인: 정상 stored, 같은 event_id updated, 서명 없음 401, fw-agent 키로 보내면 401, 큰 본문 413, 잘못된 IP·category·packet_count·시각 형식 각 400(field 값 확인), src_ip 정규화.
db 함수 단위 테스트는 db.get_client 가짜로 insert 23505 → False, count 집계.

완료 조건: pytest tests/ -q 통과.
```

---

## B1-2 경보 → 보안 기록 + NET_BLOCKED 함수 (10/23) — C1-2가 기다림

```text
[작업 B1-2] NET 경보를 보안 이벤트로 승격 + NET_BLOCKED 기록·해결 — 계약서(docs/track-d/contracts.md) K5·K6

먼저 읽을 파일: AGENTS.md, docs/track-d/contracts.md(K5·K6), security/net_ingest.py(껍데기), security/soar/_events.py, security/soar/observe.py(record_rejection의 bump 경로), security/correlate.py, db/security_events.py, db/network_events.py, routes/internal/ingest.py, tests/test_soar.py, tests/test_correlate.py
고칠 파일: security/net_ingest.py, security/soar/_events.py, security/correlate.py(check_and_correlate에 source 인자 전달만), db/security_events.py(기존 insert 함수 2개에 선택 인자만), db/incidents.py(record_incident에 source 선택 인자만 — 사용은 B1-3), db/network_events.py(새 함수), routes/internal/ingest.py(승격 호출), tests/track_d/test_b_net_ingest.py(새 파일)

요구사항
1. _record_event(event_type, severity, ip, path, count, action, username=None, source="APP", layer=None): source·layer를 db.insert_security_event에 넘기고, correlate.check_and_correlate(ip, event_type, severity, source=source)를 부른다. 기존 호출부는 바꾸지 않아도 그대로 동작해야 한다.
2. db.insert_security_event와 db.insert_security_event_or_bump에 source="APP", layer=None 선택 인자를 추가해 insert 행에 넣는다(기존 인자 순서·동작 유지). check_and_correlate(ip, event_type, severity, source="APP")도 선택 인자만 추가하고 record_incident에 source를 넘긴다(record_incident는 지금은 source를 받기만 하고 쓰지 않아도 된다).
3. security/net_ingest.py
   - CATEGORY_MAP: 계약서 K5 표 그대로 (SYN_FLOOD→NET_SYN_FLOOD HIGH, PORT_SCAN→NET_PORT_SCAN MEDIUM, SCANNER_UA→NET_SCANNER_UA MEDIUM, WEB_ATTACK→NET_WEB_ATTACK HIGH, LOGIN_BURST→NET_LOGIN_BURST MEDIUM). OTHER는 승격 안 함.
   - promote(row: dict) -> bool : 매핑이 있으면 보안 이벤트로 기록하고 True. HIGH는 observe.record_rejection과 같은 bump 경로(db.insert_security_event_or_bump(..., source="NET", layer=row["layer"]) 뒤 correlate.check_and_correlate(..., source="NET")), MEDIUM은 _record_event(..., action="NET_ALERT", source="NET", layer=...). path=None, count=packet_count.
   - record_net_blocked(ip, reason) -> None : 같은 IP에 미해결 NET_BLOCKED가 있으면 아무것도 안 함(db.get_unresolved_security_event 사용). 없으면 _record_event("NET_BLOCKED","CRITICAL", ip, None, 1, "L4_BLOCKED", source="NET", layer="L4"). docstring에 reason은 로그·알림용이며 이벤트 칸에는 넣지 않는다고 적는다.
   - resolve_net_blocked(ip) -> None : 그 IP의 미해결 NET_BLOCKED만 해결 처리. 새 db 함수 db.resolve_net_blocked_events(ip)를 db/network_events.py에 만들어 쓴다(규칙: 기존 db 파일에 새 함수 금지).
4. db/network_events.py: mark_network_event_promoted(event_id), resolve_net_blocked_events(ip) 추가 + __all__.
5. routes/internal/ingest.py: 새로 저장된 경우에만 net_ingest.promote(row)를 부르고, True면 mark_network_event_promoted 후 응답 promoted true. "from security import net_ingest" 후 net_ingest.promote(...)처럼 모듈 이름을 거쳐 호출.

테스트: 각 category의 event_type·등급·source·layer, OTHER는 승격 안 함, HIGH는 bump 경로, updated(재전송)일 때 승격 안 함, record_net_blocked 두 번 불러도 이벤트 1개, resolve_net_blocked가 NET_BLOCKED만 해결. 기존 tests/test_soar.py·test_correlate.py가 그대로 통과해야 한다.

완료 조건: pytest tests/ -q 통과. 오늘(10/23) 통합일에 머지되도록 PR.
```

---

## B1-3 앱 등급 분리 app_severity_max (10/23) — C2-2가 기다림

```text
[작업 B1-3] 사건의 앱 이벤트 등급만으로 영구 잠금 판단 — 설계 원칙 P4, 위협 V1

먼저 읽을 파일: AGENTS.md, db/incidents.py, security/correlate.py, security/lockdown.py, tests/test_correlate.py, tests/test_permanent_lock.py, tests/conftest.py(consider_incident_promotion을 lambda ip, incident로 바꿔 끼우는 부분)
고칠 파일: db/incidents.py, security/lockdown.py(consider_incident_promotion 함수 안만), tests/track_d/test_b_app_severity.py(새 파일)
security/lockdown.py는 역할 C도 고친다(release 함수). consider_incident_promotion 말고는 한 글자도 바꾸지 마라.

배경: 네트워크 경보(source='NET')는 출발지 IP를 위조할 수 있다. 이것이 섞여 사건 severity_max가 올라가 L7 영구 잠금(T3/T4)이 걸리면 안 되고, 반대로 일부러 섞어서 기존 방어를 끄는 것도 막아야 한다.

요구사항
1. record_incident(ip, event_types, severity, source="APP"): 사건 행의 app_severity_max를 함께 관리한다. 새 사건이면 source=="APP"일 때 severity, 아니면 None. 병합이면 source=="APP"일 때 기존 app_severity_max와 severity 중 높은 것, 아니면 기존 값 유지. severity_max(전체)는 지금처럼 계속 갱신한다.
2. get_open_incident 등 사건을 읽는 select에 app_severity_max, matched_rules를 포함하고, record_incident가 돌려주는 dict에도 app_severity_max와 matched_rules를 넣는다(기존 키 유지).
3. consider_incident_promotion(ip, incident): 함수 모양(인자)은 그대로 두고, incident.get("severity_max") 대신 incident.get("app_severity_max")로 T3/T4를 판단한다. None이면 아무것도 하지 않는다. docstring에 이유(P4·V1)를 추가한다. tests/conftest.py의 가짜 함수(lambda ip, incident)는 그대로 두어야 하므로 인자를 늘리지 마라.

테스트: NET 이벤트만으로 열린 사건 → 영구 잠금 없음, 앱 HIGH + NET 이벤트 섞임 → 기존과 같은 T4 판단, 앱 CRITICAL → T3, 병합 시 NET 이벤트가 app_severity_max를 바꾸지 않음. 기존 tests/test_correlate.py·test_permanent_lock.py 통과.

완료 조건: pytest tests/ -q 통과. git diff security/lockdown.py가 consider_incident_promotion 안에만 있음. 10/23 통합일 머지.
```

---

## B2-1 교차 규칙 NET-01·CR-01·CR-02 (10/28) — plan-excerpt 첨부

> 붙여 넣기 전에 [plan-excerpt.md](plan-excerpt.md)를 Codex 대화창에 첨부한다. 규칙 내용은 첨부 파일에만 있다.

```text
[작업 B2-1] 교차 계층 규칙 엔진 — 계약서(docs/track-d/contracts.md) K1·K12, 첨부 plan-excerpt.md 2.4

첨부: plan-excerpt.md. 맨 위 "이 발췌보다 우선하는 것" 표를 먼저 읽어라. 규칙의 조건·창·증거 조건·우선순위·플레이북 이름은 첨부 2.4 ③ 표를 그대로 따른다.
먼저 읽을 파일: AGENTS.md, docs/track-d/contracts.md(K1·K5·K12), security/correlate.py, security/soar/_events.py, security/soar/observe.py(record_rejection — HTTP_FLOOD 기록 방식), security/playbooks.py(껍데기), db/incidents.py, db/network_events.py, app.py(handle_rate_limit_exceeded와 그 위의 라우트별 limiter.limit 부분만 — 읽기만), tests/conftest.py, tests/test_correlate.py, tests/test_permanent_lock.py
고칠 파일: security/correlate.py, db/incidents.py(기존 함수에 선택 인자만), db/network_events.py(새 조회 함수), tests/track_d/test_b_cross_layer.py(새 파일)

요구사항
1. 범위: 첨부 2.4 ③ 표의 NET-01·CR-01·CR-02만 CROSS_LAYER_RULES에 넣는다. CR-03은 B3-1, CR-04~06은 선택 과제라 넣지 않는다.
2. 호출 위치: 첨부 2.4 ① 스케치대로 check_cross_layer(ip, event_type)를 부른다. consider_incident_promotion 호출은 B1-3에서 정한 모양(인자 2개) 그대로 둔다.
   - 주의: 지금 check_and_correlate는 서로 다른 이벤트 유형이 2개 미만이면 맨 앞에서 return한다. 그 return 뒤에 규칙 검사를 두면 NET-01(SYN Flood 단독, 유형 1개)이 영영 실행되지 않는다. 기존 사건 처리 부분만 "유형 2개 이상일 때" 블록으로 감싸고, check_cross_layer는 유형 수와 상관없이(NET_BLOCKED만 빼고) 항상 부른다.
3. 규칙이 맞았을 때: 첨부 2.4 ② 세 항목 그대로.
   - "사건당 규칙당 1회" 확인은 db.get_open_incident(ip)의 matched_rules로 한다.
   - matched_rules 병합은 db.record_incident에 rule_id=None 선택 인자를 더해 처리한다. 새 사건이면 [rule_id], 병합이면 _merge_into_existing 안에서 기존 목록에 없을 때만 덧붙인다. 기존 호출부·기존 테스트는 그대로 동작해야 한다.
4. 플레이북 실행: "from security import playbooks" 후 playbooks.run(playbook, trigger_ref, ctx)로 부른다. trigger_ref는 계약서 K12대로 f"incident:{사건 id}:{규칙 ID}", ctx는 계약서 K8 모양(ip, incident_id, rule_id, priority, matched_rules, evidence; username·user_id·user_email은 None)으로 넣는다. B2-2 전이라 run이 껍데기여도 된다(테스트에서 가짜로 바꿈).
5. 창 안의 이벤트를 읽는 조회 함수는 db/network_events.py에 새로 만들고 __all__에 추가한다. 창 길이는 계약서 K1의 설정값, 시각 비교는 DB 시각(UTC).
6. check_cross_layer 안에서 난 예외는 잡아서 print 한 줄 로그만 남긴다. 원래 이벤트 기록·기존 사건 처리는 실패하면 안 된다.
7. 모듈 docstring에 규칙 ID별 한 줄 요약(이유 포함)을 한국어로 적는다. 첨부 표를 통째로 옮기지는 않는다.
8. CR-02의 HTTP_FLOOD는 전역 한도 초과만 센다(첨부 2.4 ③ CR-02 행 "라우트별 한도 경로 제외"). app.py의 429 처리기는 복구·이메일 확인·비밀번호 찾기의 라우트별 한도 초과도 같은 HTTP_FLOOD로 기록하고, 구분할 수 있는 단서는 security_events.path뿐이다. app.py에서 라우트별 한도가 걸린 엔드포인트의 경로를 확인해 correlate.py에 상수(CR02_EXCLUDED_FLOOD_PATHS)로 두고, 그 경로로 기록된 HTTP_FLOOD는 CR-02 조건에서 빼라. 상수 위에 "app.py의 라우트별 limiter.limit을 바꾸면 여기도 바꾼다"는 주석을 단다. app.py는 고치지 않는다.

테스트(tests/track_d/test_b_cross_layer.py) — db 함수와 playbooks.run은 monkeypatch 가짜(raising=False)
- 규칙마다: 맞는 경우 → 해당 플레이북 이름으로 run 1회 / 조건 하나가 빠진 경우 → run 안 부름
- CR-01 순서가 반대면 안 맞음, 창 밖 이벤트는 안 셈
- CR-02: path가 라우트별 한도 경로(예: 복구 코드 제출)인 HTTP_FLOOD + NET_SYN_FLOOD → 안 맞음, path가 /login인 HTTP_FLOOD + NET_SYN_FLOOD → 맞음
- 같은 사건에서 같은 규칙이 두 번 맞아도 run은 1회
- 사건이 없을 때 규칙이 맞으면 사건이 생기고 matched_rules에 규칙 ID
- 이 IP의 이벤트가 NET_SYN_FLOOD 하나뿐(유형 1개)이어도 NET-01이 맞아 run이 불림
- NET_BLOCKED가 들어오면 규칙 검사를 하지 않음
- check_cross_layer가 예외를 내도 check_and_correlate 호출이 예외 없이 끝남
- 기존 tests/test_correlate.py·test_permanent_lock.py 그대로 통과

완료 조건: pytest tests/ -q 통과. 마지막 보고에 바꾼 파일 목록과 record_incident의 새 인자 설명 한 줄. 10/28 통합일 머지.
```

---

## B2-2 플레이북 엔진 (10/29) — 통합 I2-2가 기다림 · plan-excerpt 첨부

> 붙여 넣기 전에 [plan-excerpt.md](plan-excerpt.md)를 Codex 대화창에 첨부한다.

```text
[작업 B2-2] 플레이북 레지스트리와 실행기 — 계약서(docs/track-d/contracts.md) K7·K8·K12, 첨부 plan-excerpt.md 2.5

첨부: plan-excerpt.md. 맨 위 "이 발췌보다 우선하는 것" 표를 먼저 읽어라. ACTIONS·PLAYBOOKS의 이름과 순서, 영구 잠금 인자(reason·recoverable), 차단 계층 결정표는 첨부 2.5 ①·③을 그대로 따른다.
먼저 읽을 파일: AGENTS.md, docs/track-d/contracts.md(K7·K8·K12), security/playbooks.py(껍데기), security/correlate.py, security/lockdown.py(promote_ip·promote_account 인자 확인 — 읽기만), security/netblock.py, db/playbook_runs.py(껍데기), docs/migrations/guide52_track_d.sql(playbook_runs 표), tests/conftest.py
고칠 파일: security/playbooks.py, db/playbook_runs.py(기록 함수), tests/track_d/test_b_playbooks.py(새 파일)
고치면 안 되는 파일: security/lockdown.py, security/netblock.py, notify/alert.py, notify/mailer.py(모두 읽기만)

요구사항
1. ACTIONS·PLAYBOOKS: 첨부 2.5 ①의 표 그대로. ACTIONS 값은 "모듈.함수" 문자열이고(모듈 이름은 실제 import 경로로 적는다: security.lockdown, security.netblock, db, notify.mailer, notify.alert), 실행할 때 importlib + getattr로 찾는다(테스트 monkeypatch가 먹도록 import 시점에 함수 객체를 잡지 않는다).
2. run(playbook, trigger_ref, ctx) -> list[dict]
   - 단계마다 try/except로 격리. 한 단계가 실패해도 다음 단계를 계속하고, 이미 실행된 차단은 되돌리지 않는다.
   - 단계 결과 {"step", "status": OK|FAILED|SKIPPED, "error"}를 db.insert_playbook_run(...)으로 playbook_runs에 남기고, 목록으로 돌려준다. 기록 자체가 실패해도 run은 예외를 내지 않는다.
   - 찾을 수 없는 함수(아직 없는 C 함수, 선택 과제 llm_postmortem)는 SKIPPED.
   - 마지막 단계 notify_slack에는 앞 단계 결과 목록을 함께 넘긴다(계약서 K8 alert.send_playbook_alert 인자).
3. 조치별 인자 만들기: ctx(계약서 K8 모양 — ip, incident_id, rule_id, priority, matched_rules, evidence, username, user_id, user_email)에서 계약서 K7·K8 함수 모양에 맞춰 인자를 만드는 작은 함수를 조치 이름별로 둔다. 필요한 값(사용자 메일 주소 등)이 ctx에 없으면 그 단계는 SKIPPED.
   L4 차단 두 단계는 아래 값으로 고정한다(ctx["evidence"]를 그대로 넘기지 않는다).
   - block_l4_ttl → netblock.request_block(ip, reason, evidence="SPOOFABLE", ttl_seconds=None, requested_by=f"playbook:{플레이북 이름}")
     · reason은 계약서 K12대로 NET_FLOOD_TTL·NET_FLOOD 플레이북 모두 "NET_FLOOD".
     · ttl_seconds를 넘기지 않는 이유: 기본 1시간 × 2^(최근 차단 횟수)와 6시간 상한은 C의 request_block이 계산한다(계약서 K7). 여기서 계산하면 반복 시 2배가 빠지거나 두 번 계산된다.
     · evidence를 "SPOOFABLE"로 고정하는 이유: CR-02는 HTTP_FLOOD라는 연결 완성 증거가 있지만, ctx의 "CONNECTED"를 ttl 없이 넘기면 request_block이 영구 차단으로 기록한다. 계획(첨부 2.5 ③)은 CR-02를 TTL 1시간, 영구 L4는 관리자 승인으로 정했다.
   - block_l4 → netblock.request_block(ip, "KILL_CHAIN", evidence="CONNECTED", ttl_seconds=None, requested_by="playbook:KILL_CHAIN") — CR-01 영구 L4. 이 단계가 다른 플레이북에 쓰이면 FAILED로 기록하고 부르지 않는다.
   - lock_ip_permanent → lockdown.promote_ip(ip, reason="NETWORK_IDS", recoverable=KILL_CHAIN은 "ADMIN_ONLY"·WEB_ATTACK은 "EXEMPTION", incident_id=ctx["incident_id"]) (첨부 2.5 ① 아래 메모).
4. 실행기는 판단하지 않는다. IP 형식·허용 목록 검사는 C의 조치 함수가 스스로 한다(P5). 여기서 중복 검사하지 않는다.
5. db/playbook_runs.py에 insert_playbook_run(playbook, trigger_ref, step, status, error=None) 추가 + __all__.
6. 기존 security/correlate.py의 PLAYBOOKS["CRITICAL_MULTI_STAGE"](복합 공격 알림)는 옮기지 않고 그대로 둔다(계약서 K12). playbooks.py는 Track D 플레이북만 담당한다. correlate.py는 이 작업에서 고치지 않는다.

테스트(tests/track_d/test_b_playbooks.py) — 모든 조치 함수는 monkeypatch 가짜(raising=False)
- 플레이북마다 부른 조치 순서가 PLAYBOOKS 표와 같음
- 중간 단계 예외 → 그 단계 FAILED, 다음 단계는 실행, 앞 단계는 되돌리지 않음
- 함수가 없으면 SKIPPED, 기록 함수가 예외를 내도 run은 정상 반환
- notify_slack 가짜가 앞 단계 결과 목록을 받음
- NET_FLOOD·NET_FLOOD_TTL의 block_l4_ttl 가짜가 evidence="SPOOFABLE", ttl_seconds=None, reason="NET_FLOOD", requested_by="playbook:<이름>"을 받음 — ctx evidence가 "CONNECTED"여도 같음
- KILL_CHAIN의 block_l4 가짜가 evidence="CONNECTED", ttl_seconds=None, reason="KILL_CHAIN"을 받음
- B2-1의 check_cross_layer가 부르는 run의 인자 모양과 맞는지(규칙 하나로 끝까지)

완료 조건: pytest tests/ -q 통과. 10/29까지 PR — 통합 담당자의 5초 측정(I2-2)이 이 작업을 기다린다.
```

---

## B3-1 CR-03 로그인 성공 훅 (11/2) — C3-1이 기다림 · plan-excerpt 첨부

> 붙여 넣기 전에 [plan-excerpt.md](plan-excerpt.md)를 Codex 대화창에 첨부한다. C2-1(조치 도구 3개)이 main에 머지된 뒤 시작한다.

```text
[작업 B3-1] 의심 로그인 성공 규칙 CR-03 — 계약서(docs/track-d/contracts.md) K8·K12, 첨부 plan-excerpt.md 2.4 ③·"CR-03 훅 위치", 2.5 ①, 2.9 S6

첨부: plan-excerpt.md. 맨 위 "이 발췌보다 우선하는 것" 표를 먼저 읽어라. CR-03의 조건·증거 조건·창·플레이북과 훅 위치는 첨부 2.4의 CR-03 행과 "CR-03 훅 위치" 항목을 그대로 따른다. 기대 결과는 첨부 2.9 S6 행이다.
먼저 읽을 파일: AGENTS.md, docs/track-d/contracts.md(K8·K12), routes/auth.py(login_submit 전체), security/correlate.py, security/playbooks.py, db/network_events.py, db/users.py(bump_session_version), tests/conftest.py, tests/test_app.py에서 로그인 성공을 시험하는 부분
고칠 파일: security/correlate.py(check_success_login 추가), routes/auth.py(login_submit 성공 분기에 호출 몇 줄만), db/network_events.py(필요하면 조회 함수), tests/track_d/test_b_success_login.py(새 파일)

요구사항
1. correlate.check_success_login(ip, username) -> bool : 맞으면 True. 근거로 세는 이벤트 유형은 첨부 CR-03 행의 증거 조건대로 연결이 완성된 NET 이벤트만이다.
2. 맞으면: 사건을 열거나 병합(rule_id="CR-03"), 사건당 1회 규칙(B2-1과 같은 방식)을 지킨 뒤 playbooks.run("SUSPICIOUS_SUCCESS_LOGIN", f"incident:{사건 id}:CR-03", ctx)를 부른다. ctx는 계약서 K8 모양으로, user_id·username·user_email(회원의 메일 주소)까지 채워 C의 조치 함수(세션 무효화·경고 메일)가 쓸 수 있게 한다.
3. routes/auth.py: 성공 분기에서 session[...]에 쓰기 전에 "from security import correlate" 후 correlate.check_success_login(ip, username)을 부른다. True면 세션을 만들지 않고, 기존 실패 문구와 같은 일반 안내만 보여 준다(규칙에 걸렸다는 사실을 화면에 드러내지 않음). 그 밖의 login_submit 줄은 바꾸지 않는다.
4. check_success_login 안의 예외는 잡아서 print 한 줄 로그를 남기고 False를 돌려준다(검사 오류로 정상 로그인을 막지 않는다).
5. 경고 메일 쿨다운은 C의 mailer가 지킨다. 여기서 따로 세지 않는다.

테스트(tests/track_d/test_b_success_login.py) — db 조회·playbooks.run은 monkeypatch 가짜
- 근거 이벤트가 있으면 True, 세션에 username이 없음, 응답에 일반 안내 문구
- 근거가 위조 가능 유형(SYN·포트 스캔)뿐이면 False, 정상 로그인
- 창 밖 이벤트면 False
- 같은 사건에서 두 번째 성공 시도 → run은 1회
- check_success_login이 예외를 내도 정상 로그인 진행
- 기존 tests/test_app.py 등 로그인 테스트 그대로 통과

완료 조건: pytest tests/ -q 통과. git diff routes/auth.py가 login_submit 성공 분기 몇 줄뿐. 11/2 통합일 머지(C3-1 시나리오 S6이 기다린다).
```

---

## B3-2 보존 SQL (11/2) — plan-excerpt 첨부

> 붙여 넣기 전에 [plan-excerpt.md](plan-excerpt.md)를 Codex 대화창에 첨부한다.

```text
[작업 B3-2] Track D 표 보존 기간 — 첨부 plan-excerpt.md 2.3 ⑦

첨부: plan-excerpt.md. 보존 기간과 지우지 않는 상태값은 첨부 2.3 ⑦ 표를 그대로 따른다.
먼저 읽을 파일: AGENTS.md, docs/migrations/guide44_log_retention.sql, docs/migrations/guide47_daily_log_summary.sql(cleanup_old_logs의 가장 최근 정의), docs/migrations/guide52_track_d.sql, docs/schema.sql, tests/test_log_retention.py
고칠 파일: docs/migrations/guide53_track_d_retention.sql(새 파일), docs/schema.sql(맨 아래 "Track D 보존 (guide53)" 구역), tests/track_d/test_b_retention.py(새 파일)
고치면 안 되는 파일: guide44·guide47·guide52 마이그레이션 파일

요구사항
1. guide47의 cleanup_old_logs(dry_run boolean default false) 정의를 그대로 가져와 create or replace로 다시 정의하고, Track D 표 3개의 삭제를 덧붙인다. 기존 표의 보존 동작·반환 모양·dry_run 동작·권한(revoke)·pg_cron 일정은 바꾸지 않는다.
2. dry_run=true면 Track D 표도 지울 건수만 돌려준다(기존 방식과 같은 모양).
3. 여러 번 실행해도 안전해야 한다(create or replace, 표·칸 변경 없음).
4. 파일 맨 위 주석: 목적, 실행 방법(통합 담당자가 Supabase SQL Editor에서), 미리보기 명령(select * from cleanup_old_logs(true);), 되돌리는 방법(guide47 정의를 다시 실행).

테스트: tests/test_log_retention.py처럼 SQL 파일을 문자열로 읽어 검사한다. 표 3개 이름, 각 보존 기간, network_blocks의 지우지 않는 상태값 3개가 삭제 조건에 들어가지 않음, guide47의 기존 표 삭제 문이 그대로 남아 있음.

완료 조건: pytest tests/ -q 통과. 마지막 보고에 "통합 담당자가 적용 전에 돌려 볼 미리보기 SQL 1줄"을 적어라. 11/2 통합일 머지 후 통합 담당자가 공용 DB에 적용.
```

---

## ~~B3-3 guide52·guide53 초안~~ — 통합 담당자로 이관 (2026-10-14)

> 가이드 guide52(수집·상관분석)·guide53(플레이북 엔진·보존)는 형식을 맞추기 위해 **통합 담당자가 전담**한다(`03-통합담당-점검서.md` 6.2, 작업 번호 I3-3). 이 작업의 Codex 요청문은 없다. 마이그레이션 SQL(`guide52_track_d.sql`, `guide53_track_d_retention.sql`)은 이름만 비슷할 뿐 문서가 아니므로 **그대로 B 담당**이다.
>
> **B가 할 일은 두 가지뿐이다.**
> 1. 작업 PR마다 본문 **"가이드·README용 메모"** 칸에 "왜 이렇게 만들었나" 3~5줄을 적는다(예: B1-3이라면 앱 등급을 따로 두는 이유, B2-1이라면 각 규칙이 무엇을 잡는지).
> 2. 통합 담당자가 쓴 guide52·53을 11/3~11/4에 읽고 **설명이 코드와 맞는지만** 확인한다(리허설의 상관분석 설명 준비 겸).
