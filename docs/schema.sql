-- login-watchdog Supabase 스키마
-- Supabase SQL 편집기에서 1회 실행. 이 저장소에서 직접 실행되는 마이그레이션 파일이 아니라 문서용 기록입니다.
-- 근거: plan.md 3-3절(로그/잠금/관리자 테이블) + 회원가입 기능 확장(users 테이블)
--
-- 이미 이 스키마로 테이블을 만들어둔 기존 Supabase 프로젝트라면, 이 파일 전체를
-- 다시 실행할 필요 없이 L7 공격 보강 계획(Tier 1)에서 추가된 아래 두 문장만
-- Supabase SQL 편집기에서 실행하면 된다:
--   create table account_lockouts (
--     username text primary key,
--     locked_at timestamptz not null default now(),
--     unlock_at timestamptz not null,
--     failure_count int not null,
--     active boolean not null default true
--   );
--   alter table security_events add column username text;

-- 감시 대상 /login 화면에 실제로 가입해 로그인하는 사용자 계정
-- name: 로그인 아이디(username)와 별개인 "표시 이름". 회원가입 때는 안 받고 기본값 ''(빈 문자열)로
-- 시작하며, 회원 대시보드의 프로필 수정 화면에서 나중에 채워 넣는다(12단계 참고).
create table users (
  id bigint generated always as identity primary key,
  username text not null unique,
  email text not null unique,
  name text not null default '',
  password_hash text not null,
  created_at timestamptz not null default now()
);

-- /login 시도 기록 (append-only 로그). username은 가입 여부와 무관하게 시도값을 그대로 저장하므로 FK를 걸지 않음
create table login_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  username text not null,
  success boolean not null,
  attempted_at timestamptz not null default now()
);
create index idx_login_attempts_ip_time on login_attempts (ip_address, attempted_at);

-- IP 단위 잠금 "현재 상태" (login_attempts와 분리 — research.md 5-2절 참고)
create table lockouts (
  ip_address text primary key,
  locked_at timestamptz not null default now(),
  unlock_at timestamptz not null,
  failure_count int not null,
  active boolean not null default true
);

-- 계정(아이디) 단위 잠금 "현재 상태" (lockouts와 짝을 이루는 표).
-- lockouts는 "이 IP가 얼마나 실패했는가"만 보므로, 공격자가 여러 IP로 나눠서
-- 같은 계정만 노리면 각 IP는 임계값을 넘지 않아 안 잠긴다. 이 표는 IP와
-- 무관하게 "이 계정이 총 몇 번 실패당했는가"를 기준으로 잠가서 분산/저속
-- 브루트포스(L7 공격 보강 계획 Tier 1)에 대응한다.
create table account_lockouts (
  username text primary key,
  locked_at timestamptz not null default now(),
  unlock_at timestamptz not null,
  failure_count int not null,
  active boolean not null default true
);

-- 관리자 계정 (앱 최초 기동 시 .env 값으로 1개만 자동 시드, 회원가입 화면 없음)
create table admin_users (
  id bigint generated always as identity primary key,
  username text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now()
);

-- 관리자 로그인 성공/실패 감사 로그 (대시보드에 노출)
create table admin_login_log (
  id bigint generated always as identity primary key,
  username text not null,
  success boolean not null,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);

-- 앱 전역 설정 (딱 1행만 사용). 로컬/Vercel 등 여러 곳에서 서버가 동시에 돌아도
-- "회원가입 켜짐/꺼짐" 같은 상태를 서버 메모리가 아니라 여기 저장해야
-- 모든 서버 인스턴스가 항상 같은 값을 보게 된다 (11단계 참고).
create table app_settings (
  id int primary key default 1,
  signup_enabled boolean not null default true,
  constraint app_settings_singleton check (id = 1)
);
insert into app_settings (id, signup_enabled) values (1, true);

-- IP → 국가/지역 조회 결과 캐시 (13단계). ip-api.com은 무료 사용 시 분당 45건까지만
-- 허용하는데, 같은 IP를 매번 다시 물어보면 순식간에 한도를 넘는다. 그래서 한 번
-- 조회한 IP는 여기 저장해두고, 다음부터는 외부 API 대신 이 표에서 바로 꺼내 쓴다.
create table ip_locations (
  ip_address text primary key,
  country text,
  region_name text,
  city text,
  lookup_failed boolean not null default false,
  looked_up_at timestamptz not null default now()
);

-- 회원가입(/signup) 요청 빈도 제한용 로그 (append-only). login_attempts와 별도 표로 둔
-- 이유: 회원가입은 아이디/성공 여부와 무관하게 "이 IP가 얼마나 자주 두드렸는가"만
-- 세면 되므로 더 가벼운 구조로 분리했다 (18단계 보안 점검 보완).
create table signup_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);
create index idx_signup_attempts_ip_time on signup_attempts (ip_address, attempted_at);

-- ============================================================================
-- 게시판/댓글 기능 (docs/board-comment/plan_board.md 참고)
-- ============================================================================

-- 게시판 글. login_attempts와 동일한 관례로 users와 FK를 걸지 않고 작성자를
-- 텍스트로만 저장한다 — 회원이 탈퇴해도 글은 흔적만 남기고 유지된다
-- (docs/board-comment/02-design-decisions.md 결정 #4).
create table posts (
  id bigint generated always as identity primary key,
  author_username text not null,
  title text not null,
  body text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index idx_posts_created_at on posts (created_at desc);

-- 댓글. 단일 depth(대댓글 없음, 결정 #3)라 자기참조 FK는 두지 않는다.
-- post_id는 posts를 FK로 참조하며 on delete cascade — "글이 지워지면 그 글의
-- 댓글도 함께 지워진다"는 자연스러운 종속 관계이지, 회원 탈퇴 cascade(하지
-- 않기로 함, 결정 #4)와는 별개의 문제다.
create table comments (
  id bigint generated always as identity primary key,
  post_id bigint not null references posts(id) on delete cascade,
  author_username text not null,
  body text not null,
  created_at timestamptz not null default now()
);
create index idx_comments_post_id_created_at on comments (post_id, created_at);

-- 게시글 작성 요청 빈도 제한 (signup_attempts와 완전히 동일한 구조, 결정 #7)
create table post_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);
create index idx_post_attempts_ip_time on post_attempts (ip_address, attempted_at);

-- 댓글 작성 요청 빈도 제한
create table comment_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  attempted_at timestamptz not null default now()
);
create index idx_comment_attempts_ip_time on comment_attempts (ip_address, attempted_at);

-- ============================================================================
-- 이상행위 탐지 보완 (21단계, attack_response_state.md 구현 대상 #1)
-- ============================================================================

-- 존재하지 않는 경로(404) 요청 기록 (append-only). signup_attempts와 동일한
-- 목적("이 IP가 얼마나 자주 두드렸는가")이지만, 어떤 경로를 두드렸는지도
-- 함께 남겨야 관리자가 나중에 "무엇을 스캔했는지" 확인할 수 있어 path를 추가로 저장한다.
create table not_found_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  attempted_at timestamptz not null default now()
);
create index idx_not_found_attempts_ip_time on not_found_attempts (ip_address, attempted_at);

-- 관리자 전용 API(/api/*)에 로그인 세션 없이 접근을 시도한 기록 (append-only).
-- not_found_attempts와 동일한 목적("이 IP가 얼마나 자주 두드렸는가" + 어떤
-- 경로였는지)이지만, "존재하지 않는 경로"가 아니라 "존재는 하는데 권한이
-- 없는 경로"를 두드린 것이라는 점이 다르다 (attack_response_state.md 구현 대상 #2).
create table unauthorized_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  attempted_at timestamptz not null default now()
);
create index idx_unauthorized_attempts_ip_time on unauthorized_attempts (ip_address, attempted_at);

-- 반복 페이지 접근(같은 IP가 같은 GET 경로를 반복 요청) 탐지용 로그.
-- not_found_attempts/unauthorized_attempts와 구조는 같지만, 카운트할 때
-- ip_address뿐 아니라 path까지 함께 걸러야 하므로(이 IP의 "전체" 요청이
-- 아니라 "이 경로" 요청 횟수를 센다) 인덱스에 path도 포함한다
-- (attack_response_state.md 구현 대상 #4).
create table page_access_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  attempted_at timestamptz not null default now()
);
create index idx_page_access_attempts_ip_path_time on page_access_attempts (ip_address, path, attempted_at);

-- ============================================================================
-- 통합 보안 위험등급 (security-risk-response-summary.md 5절 참고)
-- ============================================================================

-- MEDIUM/HIGH/CRITICAL 이상행위 이벤트를 등급과 함께 기록하는 공통 표.
-- LOW(임계치 미도달)는 여기 넣지 않는다 — 정상 트래픽만으로 이 표가 폭증하는 걸
-- 막기 위해, 기존 개별 테이블(login_attempts, not_found_attempts 등) 조회로만
-- 추세를 본다. resolved_at은 CRITICAL(IP 잠금)은 잠금 해제 시 자동으로,
-- HIGH/MEDIUM은 관리자가 대시보드에서 "처리 완료"를 눌러야 채워진다.
-- username: 계정 단위 이벤트(예: 분산 브루트포스로 인한 account_lockouts 잠금)에만
-- 채워지는 참고용 칸이다. IP 단위 이벤트(기존 BRUTE_FORCE 등)는 계속 비워둔다
-- (L7 공격 보강 계획 Tier 1) — 기존 행과 호환되도록 nullable로 추가했다.
create table security_events (
  id bigint generated always as identity primary key,
  event_type text not null,
  severity text not null check (severity in ('MEDIUM', 'HIGH', 'CRITICAL')),
  ip_address text not null,
  path text,
  count int not null,
  action text not null,
  username text,
  detected_at timestamptz not null default now(),
  resolved_at timestamptz
);
create index idx_security_events_detected_at on security_events (detected_at desc);
create index idx_security_events_ip_severity on security_events (ip_address, severity);

-- 같은 IP·이벤트 유형·HIGH 등급이면서 아직 처리되지 않은(resolved_at is null) 행은
-- 항상 최대 1건만 존재하도록 DB가 직접 강제한다. soar.record_rejection()이 삽입 전에
-- "미해결 이벤트가 있는지" 먼저 확인하지만, 그 확인과 실제 삽입 사이의 아주 짧은
-- 틈에 동시 요청 두 개가 겹치면 둘 다 통과해버릴 수 있다(경쟁 조건) — 이 인덱스가
-- 그 드문 경우에도 두 번째 삽입을 막아준다(db.insert_security_event_or_bump 참고).
-- CRITICAL/MEDIUM은 조건에서 제외한다 — CRITICAL은 애초에 같은 IP가 다시 잠기기 전에
-- resolve_security_events_for_ip()로 먼저 정리되고, MEDIUM(notify_web_scanning 등)은
-- "미해결이면 건너뛰기"가 아니라 임계값을 다시 넘길 때마다 새로 기록하는 구조라서
-- 이 제약을 걸면 정상적인 재알림이 막혀버린다.
create unique index idx_security_events_high_open_incident
  on security_events (ip_address, event_type)
  where resolved_at is null and severity = 'HIGH';

-- ============================================================================
-- RBAC 기본 구조 (Track B guide26 — login_watchdog_expansion_plan.md 참고)
-- ============================================================================

-- 관리자 역할 3종. security_viewer < security_admin < super_admin 순으로
-- 할 수 있는 일이 늘어나지만, 이 표 자체에는 "포함 관계"를 표현하지 않는다 —
-- 아래 permissions 표에 역할별로 할 수 있는 액션을 전부 한 줄씩 나열한다.
create table roles (
  role text primary key check (role in ('security_viewer', 'security_admin', 'super_admin'))
);
insert into roles (role) values ('security_viewer'), ('security_admin'), ('super_admin');

-- role이 할 수 있는 action 하나하나를 나열한 표. routes/admin.py의 쓰기 API
-- 6개(unlock_ip / resolve_security_event / toggle_signup / delete_user /
-- delete_post / delete_comment)에 1:1로 대응한다. require_permission()
-- 데코레이터가 요청마다 이 표를 조회해서 "지금 이 관리자의 역할이 이 액션을
-- 할 수 있는가"를 확인한다.
create table permissions (
  role text not null references roles(role),
  action text not null check (
    action in (
      'unlock_ip', 'resolve_security_event', 'toggle_signup',
      'delete_user', 'delete_post', 'delete_comment', 'manage_admin_users'
    )
  ),
  primary key (role, action)
);
insert into permissions (role, action) values
  ('security_admin', 'unlock_ip'),
  ('security_admin', 'resolve_security_event'),
  ('super_admin', 'unlock_ip'),
  ('super_admin', 'resolve_security_event'),
  ('super_admin', 'toggle_signup'),
  ('super_admin', 'delete_user'),
  ('super_admin', 'delete_post'),
  ('super_admin', 'delete_comment'),
  -- 대시보드 "관리자 계정 관리"(guide26 후속) — security_viewer/security_admin
  -- 계정을 생성·삭제하는 액션. super_admin만 가지며, 이 액션 자체로는
  -- super_admin 계정을 만들거나 지울 수 없다(routes/admin.py에서 role 검증).
  ('super_admin', 'manage_admin_users');
-- security_viewer는 어떤 액션도 없다 — 대시보드 조회(GET /admin/dashboard,
-- /api/status)는 지금처럼 login_required만으로 충분해서 permissions에
-- "view_dashboard" 같은 행을 따로 두지 않았다(세 역할 모두 어차피 볼 수 있으므로
-- 권한 구분의 의미가 없다).

-- 기존 admin_users 표에 역할 칸을 추가한다. 이미 있는 관리자 계정(예:
-- sktmaster123)도 이 ALTER 한 번으로 전부 기본값 'security_admin'을 갖게 된다 —
-- 그 중 최종 책임자 계정만 아래 UPDATE로 super_admin으로 올려준다.
alter table admin_users add column role text not null references roles(role) default 'security_admin';

-- 이미 있는 최종 책임자 계정을 super_admin으로 승격 (계정을 새로 만드는 게
-- 아니라 기존 행의 role 값만 바꾸는 것 — login_watchdog_expansion_plan.md 논의 참고).
-- 이 프로젝트의 실제 최종 책임자 계정 이름으로 바꿔서 한 번만 실행하면 된다.
update admin_users set role = 'super_admin' where username = 'sktmaster123';

-- ============================================================================
-- SIEM 상관분석 (Track C guide27 — login_watchdog_expansion_plan.md 참고)
-- ============================================================================

-- security_events가 개별 신고서 한 장 한 장이라면, 이 표는 "같은 IP가 짧은
-- 시간 안에 서로 다른 event_type을 2개 이상 남겼을 때" 그 신고들을 하나의
-- 사건으로 묶어두는 사건철이다. correlate.py가 soar.py를 통해 새 이벤트가
-- 기록될 때마다 이 표를 조회/갱신한다. 단발성 이벤트(신고 1장)는 여기 묶이지
-- 않고 지금처럼 security_events에만 남는다.
create table security_incidents (
  id bigint generated always as identity primary key,
  ip_address text not null,
  event_types text[] not null,
  severity_max text not null check (severity_max in ('MEDIUM', 'HIGH', 'CRITICAL')),
  status text not null check (status in ('OPEN', 'CLOSED')) default 'OPEN',
  first_event_at timestamptz not null,
  last_event_at timestamptz not null
);
create index idx_security_incidents_last_event_at on security_incidents (last_event_at desc);

-- 같은 IP는 OPEN 상태 사건이 항상 최대 1건만 존재하도록 DB가 직접 강제한다.
-- idx_security_events_high_open_incident와 같은 이유(확인과 삽입 사이의 짧은
-- 틈에 동시 요청이 겹치는 경쟁 조건 방지)로, db.record_incident()가 이 인덱스
-- 충돌(23505)을 붙잡아 새로 여는 대신 기존 사건에 병합하는 안전망을 둔다.
create unique index idx_security_incidents_open_ip
  on security_incidents (ip_address)
  where status = 'OPEN';

-- ============================================================================
-- SOAR 플레이북 고도화 (Track C guide28 — login_watchdog_expansion_plan.md 참고)
-- ============================================================================

-- 사건이 CRITICAL이면서 서로 다른 event_type이 config.INCIDENT_ESCALATION_MIN_EVENT_TYPES
-- (기본 3) 개 이상 쌓이면, correlate.py가 관리자에게 별도의 "복합 공격" 에스컬레이션
-- 알림을 보낸다. 이 컬럼은 그 알림을 이미 보낸 사건인지 표시해서, 사건이 갱신될
-- 때마다 같은 알림이 반복 발송되는 걸 막는다(soar.enforce_lockout의 "잠그는 순간에
-- 딱 한 번만" 알림 원칙과 동일). 사건이 닫혔거나(CLOSED) 오래 조용해 IDLE로 옮겨진 뒤 새로 열리면
-- 새 행이므로 자동으로 false에서 다시 시작한다.
alter table security_incidents add column escalated boolean not null default false;

-- ============================================================================
-- API 엔드포인트별 매크로/봇 탐지 (Track C guide29 — login_watchdog_expansion_plan.md 참고)
-- ============================================================================

-- not_found_attempts/unauthorized_attempts/page_access_attempts와 같은 목적의
-- 요청 로그다. 다만 이 표는 "/api/*" 요청 전체(POST 포함)를 메서드와 함께
-- 기록해서, 같은 IP가 짧은 시간에 서로 다른 API 여러 개를 옮겨 다니는
-- 패턴(매크로/봇 의심)을 잡는다 — track_page_access()는 GET만, "같은 경로
-- 하나"의 반복만 보므로 이 패턴은 잡지 못한다.
create table api_access_log (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  method text not null,
  requested_at timestamptz not null default now()
);
create index idx_api_access_log_ip_requested_at on api_access_log (ip_address, requested_at desc);

-- ============================================================================
-- LLM 조기 경보 (Track A guide31 — login_watchdog_expansion_plan.md 참고)
-- ============================================================================

-- 위의 모든 탐지 유형(로그인 브루트포스/계정 단위 분산 브루트포스/회원가입
-- 남용/Web Scanning/Unauthorized Access/반복 페이지 접근/매크로·봇)은 전부
-- "임계값을 넘었을 때"만 반응한다. 이 표는 그 반대 — "아직 임계값을 못
-- 넘었지만 코앞(config.EARLY_WARNING_BAND)인" 원래 아무 조치도 없던
-- 사각지대에서, Groq(LLM)가 "지켜볼 필요가 있다"고 판단한 건을 관리자
-- 승인 대기 목록으로 쌓아둔다 — soar.consider_early_warning()이 등록하고,
-- soar.execute_approved_request()/reject_pending_request()가 상태를 바꾼다.
create table access_requests (
  request_id bigint generated always as identity primary key,
  event_type text not null check (
    event_type in (
      'BRUTE_FORCE', 'DISTRIBUTED_BRUTE_FORCE', 'SIGNUP_RATE_LIMIT',
      'WEB_SCANNING', 'UNAUTHORIZED_ACCESS', 'PAGE_ACCESS', 'API_MACRO_PATTERN'
    )
  ),
  -- 승인됐을 때 실제로 실행할 조치. "그 유형이 원래 임계값을 넘었을 때 하던
  -- 조치"와 정확히 같다 — 로그인/계정 브루트포스만 잠그고(LOCK_IP/LOCK_ACCOUNT),
  -- 나머지 유형은 원래도 잠그지 않으므로 알림·기록만 한다(ALERT_ONLY).
  pending_action text not null check (pending_action in ('LOCK_IP', 'LOCK_ACCOUNT', 'ALERT_ONLY')),
  target_kind text not null check (target_kind in ('ip', 'account')),
  target_value text not null,
  -- Web Scanning/Unauthorized Access/반복 페이지 접근/회원가입 남용처럼 "어느
  -- 경로에서 관찰됐는지"가 있는 유형만 채워진다. 로그인 브루트포스·매크로/봇처럼
  -- 특정 경로 하나가 아니라 IP 전체의 패턴을 가리키는 유형은 null로 남긴다
  -- (soar.py의 notify_macro_pattern이 path=None을 쓰는 것과 같은 이유).
  path text,
  count int not null,
  threshold int not null,
  -- LOCK_IP는 distinct_usernames(Brute Force/Password Spraying 구분),
  -- LOCK_ACCOUNT는 distinct_ips(분산 정도)를 담는다. ALERT_ONLY 유형은 null.
  context_count int,
  -- LOCK_ACCOUNT(계정 잠금)를 승인 시 soar.enforce_account_lockout()에 넘길
  -- "이번 시도의 triggering_ip"를 담는다. 그 외 유형은 null.
  context_ip text,
  llm_reason text not null,
  status text not null check (status in ('PENDING', 'APPROVED', 'REJECTED')) default 'PENDING',
  requested_at timestamptz not null default now(),
  decided_by_admin_id bigint references admin_users(id),
  decided_at timestamptz
);
create index idx_access_requests_status_requested_at on access_requests (status, requested_at desc);

-- 같은 (event_type, target_kind, target_value)에는 PENDING 요청이 동시에
-- 최대 1건만 존재하도록 DB가 직접 강제한다 — idx_security_incidents_open_ip와
-- 같은 이유(확인과 삽입 사이의 짧은 틈에 동시 요청이 겹치는 경쟁 조건 방지)로,
-- db.insert_pending_request()가 이 인덱스 충돌(23505)을 붙잡아 조용히 무시한다.
create unique index idx_access_requests_open_target
  on access_requests (event_type, target_kind, target_value)
  where status = 'PENDING';

-- 승인/반려를 실행할 권한 — unlock_ip/resolve_security_event와 같은 급의
-- "IP·계정 관련 보안 조치"이므로 그 두 액션과 동일하게 security_admin/
-- super_admin 둘 다에게 부여한다(security_viewer는 여전히 조회만 가능).
-- permissions.action의 check 제약을 새 값 하나로 교체해야 한다(제약 자체를
-- "추가"하는 SQL 문법은 없고, 기존 것을 지우고 새로 만들어야 한다) — 제약
-- 이름은 Postgres가 자동으로 붙인 기본값(<표>_<칸>_check)을 그대로 쓴다.
alter table permissions drop constraint permissions_action_check;
alter table permissions add constraint permissions_action_check check (
  action in (
    'unlock_ip', 'resolve_security_event', 'toggle_signup',
    'delete_user', 'delete_post', 'delete_comment', 'manage_admin_users',
    'approve_pending_action'
  )
);
insert into permissions (role, action) values
  ('security_admin', 'approve_pending_action'),
  ('super_admin', 'approve_pending_action');

-- ============================================================================
-- 사건 해결을 잠금 해제와 분리 (관리자가 직접 "해결" — incident_resolution)
-- ============================================================================
-- 지금까지는 IP 잠금이 풀리면 그 IP의 사건이 자동으로 CLOSED 됐다. "접속 차단을
-- 푸는 조치"와 "관리자가 검토를 마쳤다는 판단"은 다른 일이므로, 이제 사건은
-- 관리자가 대시보드의 "해결" 버튼을 눌러야만 CLOSED 가 된다.
--
-- IDLE = 마지막 이벤트로부터 config.INCIDENT_MERGE_IDLE_MINUTES(기본 30분) 넘게
-- 조용했는데 같은 IP에서 새 이벤트가 와서, 새 사건을 열기 위해 옛 사건을 "활동
-- 없음"으로 옮긴 상태다(아직 관리자 미해결). idx_security_incidents_open_ip 는
-- status='OPEN' 에만 걸려 있으므로, 옛 사건이 IDLE 로 빠져야 새 OPEN 사건을 만들 수 있다.

-- status 체크 제약 교체: 제약 이름은 Postgres 자동 이름이라 실제 이름을 찾아서 지운다.
do $$
declare c text;
begin
  select conname into c
  from pg_constraint
  where conrelid = 'public.security_incidents'::regclass
    and contype = 'c'
    and pg_get_constraintdef(oid) ilike '%status%';
  if c is not null then
    execute format('alter table public.security_incidents drop constraint %I', c);
  end if;
end $$;

alter table security_incidents add constraint security_incidents_status_check
  check (status in ('OPEN', 'IDLE', 'CLOSED'));

-- 누가/언제 해결했는지 남긴다. 예전에 잠금 해제로 자동 종료된 행은 NULL 로 남는다.
alter table security_incidents add column if not exists resolved_at timestamptz;
alter table security_incidents add column if not exists resolved_by text;

-- 사건 해결 API 전용 권한 — 쓰기 API 하나당 권한 하나(1:1) 관례를 따른다.
alter table permissions drop constraint permissions_action_check;
alter table permissions add constraint permissions_action_check check (
  action in (
    'unlock_ip', 'resolve_security_event', 'toggle_signup',
    'delete_user', 'delete_post', 'delete_comment', 'manage_admin_users',
    'approve_pending_action', 'resolve_incident'
  )
);
insert into permissions (role, action) values
  ('security_admin', 'resolve_incident'),
  ('super_admin', 'resolve_incident')
on conflict do nothing;


-- ============================================================================
-- 영구 잠금 + 이메일 인증 기반 해제 (guide33 / guide34-a)
--
-- Supabase SQL Editor에서 이 파일 전체를 "한 번에" 실행하세요. 여러 번 실행해도 안전하도록
-- (if not exists / drop ... if exists) 작성되어 있습니다. 이미 만들어 둔 데이터는 바뀌지 않습니다:
--   - 기존 lockouts / account_lockouts 행은 전부 lock_type='TEMPORARY'로 유지됩니다.
--   - 기존 users 행은 email_status='UNKNOWN'으로 시작합니다.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1) lockouts: 임시/영구 구분 + 복구 정책
--    영구 잠금은 자동 만료가 없으므로 unlock_at이 NULL이어야 한다.
--    ('infinity' 시각을 쓰면 파이썬/JS가 해석하지 못해 대시보드가 깨진다 → NULL + lock_type 방식)
-- ---------------------------------------------------------------------------
alter table lockouts add column if not exists lock_type text not null default 'TEMPORARY'
  check (lock_type in ('TEMPORARY', 'PERMANENT'));
alter table lockouts alter column unlock_at drop not null;
alter table lockouts add column if not exists recoverable text not null default 'EXEMPTION'
  check (recoverable in ('SELF', 'EXEMPTION', 'ADMIN_ONLY'));
alter table lockouts add column if not exists permanent_reason text;
alter table lockouts add column if not exists promoted_at timestamptz;
alter table lockouts drop constraint if exists lockouts_permanent_unlock_chk;
alter table lockouts add constraint lockouts_permanent_unlock_chk
  check ((lock_type = 'PERMANENT' and unlock_at is null) or (lock_type = 'TEMPORARY' and unlock_at is not null));

-- ---------------------------------------------------------------------------
-- 2) account_lockouts: 같은 변경 + 이메일 복구 후 보호관찰 종료 시각
--    계정 잠금의 복구 방식에는 EXEMPTION(IP 전용 개념)이 없다.
-- ---------------------------------------------------------------------------
alter table account_lockouts add column if not exists lock_type text not null default 'TEMPORARY'
  check (lock_type in ('TEMPORARY', 'PERMANENT'));
alter table account_lockouts alter column unlock_at drop not null;
alter table account_lockouts add column if not exists recoverable text not null default 'SELF'
  check (recoverable in ('SELF', 'ADMIN_ONLY'));
alter table account_lockouts add column if not exists permanent_reason text;
alter table account_lockouts add column if not exists promoted_at timestamptz;
alter table account_lockouts add column if not exists probation_until timestamptz;
alter table account_lockouts drop constraint if exists account_lockouts_permanent_unlock_chk;
alter table account_lockouts add constraint account_lockouts_permanent_unlock_chk
  check ((lock_type = 'PERMANENT' and unlock_at is null) or (lock_type = 'TEMPORARY' and unlock_at is not null));

-- ---------------------------------------------------------------------------
-- 3) lock_history: 잠금 이력 (append-only)
--    lockouts는 같은 IP/계정이 다시 잠기면 같은 행에 덮어쓰므로(upsert) "최근 30일 안에
--    몇 번 잠겼는가"를 셀 수 없다. 이 표는 잠금이 걸릴 때마다 한 줄씩 추가만 한다.
-- ---------------------------------------------------------------------------
create table if not exists lock_history (
  id bigint generated always as identity primary key,
  target_kind text not null check (target_kind in ('ip', 'account')),
  target_value text not null,
  lock_type text not null check (lock_type in ('TEMPORARY', 'PERMANENT')),
  trigger_reason text not null check (trigger_reason in
    ('THRESHOLD', 'REPEAT_OFFENDER', 'SIEM_CRITICAL', 'SIEM_HIGH', 'NETWORK_IDS', 'ADMIN_MANUAL')),
  source_event_type text,                                   -- BRUTE_FORCE / ADMIN_BRUTE_FORCE 등
  incident_id bigint references security_incidents(id) on delete set null,
  trigger_note text,                                        -- 관리자 수동 승격 사유 등
  locked_at timestamptz not null default now(),
  released_at timestamptz,
  released_by text,                                         -- 'AUTO_EXPIRE' / 'EMAIL_RECOVERY' / 'admin:<아이디>' / 'script:<이름>'
  release_note text
);
create index if not exists idx_lock_history_target on lock_history (target_kind, target_value, locked_at desc);

-- ---------------------------------------------------------------------------
-- 4) users: 메일 서버가 수신자를 거부(존재하지 않는 이메일)했는지
--    가입 때 이메일 소유 확인은 하지 않는다. 복구 메일 발송이 5xx로 영구 거부되면
--    UNDELIVERABLE로 표시하고, 그 계정의 영구 잠금은 이메일로 풀 수 없게(ADMIN_ONLY) 올린다.
-- ---------------------------------------------------------------------------
alter table users add column if not exists email_status text not null default 'UNKNOWN'
  check (email_status in ('UNKNOWN', 'UNDELIVERABLE'));
alter table users add column if not exists email_status_checked_at timestamptz;

-- ---------------------------------------------------------------------------
-- 5) recovery_requests: 이메일로 보낸 1회용 복구 링크/코드
--    토큰과 6자리 코드는 원문이 아니라 SHA-256 해시만 저장한다.
-- ---------------------------------------------------------------------------
create table if not exists recovery_requests (
  id bigint generated always as identity primary key,
  user_id bigint not null references users(id) on delete cascade,
  target_kind text not null check (target_kind in ('ip', 'account')),
  target_value text not null,
  token_hash text not null unique,
  code_hash text not null,
  device_hash text,                                         -- 요청한 기기(lw_dev 쿠키)의 해시
  requested_ip text not null,
  status text not null default 'PENDING'
    check (status in ('PENDING', 'VERIFIED', 'EXPIRED', 'REVOKED')),
  code_attempts int not null default 0,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  verified_at timestamptz
);
create index if not exists idx_recovery_requests_user_created on recovery_requests (user_id, created_at desc);
create index if not exists idx_recovery_requests_ip_created on recovery_requests (requested_ip, created_at desc);
-- 같은 (사용자, 대상)에 진행 중(PENDING)인 요청은 1건만 — 새 요청이 오면 기존 PENDING을
-- REVOKED로 바꾼 뒤 삽입한다(동시 요청이 겹쳐도 DB가 두 번째를 막는다).
create unique index if not exists idx_recovery_requests_one_pending
  on recovery_requests (user_id, target_kind, target_value) where status = 'PENDING';

-- ---------------------------------------------------------------------------
-- 6) ip_lock_exemptions: IP 영구 잠금 예외 (본인 + 본인 기기만 통과)
-- ---------------------------------------------------------------------------
create table if not exists ip_lock_exemptions (
  id bigint generated always as identity primary key,
  ip_address text not null,
  user_id bigint not null references users(id) on delete cascade,
  device_hash text not null,
  granted_via text not null check (granted_via in ('EMAIL_RECOVERY', 'ADMIN')),
  status text not null default 'ACTIVE' check (status in ('ACTIVE', 'REVOKED', 'EXPIRED')),
  granted_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_reason text
);
create unique index if not exists idx_ip_lock_exemptions_active
  on ip_lock_exemptions (ip_address, user_id, device_hash) where status = 'ACTIVE';

-- ---------------------------------------------------------------------------
-- 7) 권한 4종 — 쓰기 API 하나당 권한 하나(1:1) 관례
--    release_permanent_lock(영구 잠금 완전 해제)은 super_admin만 가진다.
-- ---------------------------------------------------------------------------
alter table permissions drop constraint if exists permissions_action_check;
alter table permissions add constraint permissions_action_check check (
  action in (
    'unlock_ip', 'resolve_security_event', 'toggle_signup',
    'delete_user', 'delete_post', 'delete_comment', 'manage_admin_users',
    'approve_pending_action', 'resolve_incident',
    'promote_permanent_lock', 'release_permanent_lock',
    'revoke_ip_exemption', 'revoke_recovery_request'
  )
);
insert into permissions (role, action) values
  ('security_admin', 'promote_permanent_lock'),
  ('security_admin', 'revoke_ip_exemption'),
  ('security_admin', 'revoke_recovery_request'),
  ('super_admin',    'promote_permanent_lock'),
  ('super_admin',    'release_permanent_lock'),
  ('super_admin',    'revoke_ip_exemption'),
  ('super_admin',    'revoke_recovery_request')
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- 8) access_requests: SIEM HIGH 사건을 관리자 승인 대기로 올릴 때 쓰는 값
--    (PERMANENT_LOCK_AUTO_ON_HIGH=false일 때). 기존 값은 그대로 두고 새 값만 추가한다.
-- ---------------------------------------------------------------------------
alter table access_requests drop constraint if exists access_requests_event_type_check;
alter table access_requests add constraint access_requests_event_type_check check (
  event_type in (
    'BRUTE_FORCE', 'DISTRIBUTED_BRUTE_FORCE', 'SIGNUP_RATE_LIMIT',
    'WEB_SCANNING', 'UNAUTHORIZED_ACCESS', 'PAGE_ACCESS', 'API_MACRO_PATTERN',
    'SIEM_HIGH_INCIDENT'
  )
);
alter table access_requests drop constraint if exists access_requests_pending_action_check;
alter table access_requests add constraint access_requests_pending_action_check check (
  pending_action in ('LOCK_IP', 'LOCK_ACCOUNT', 'ALERT_ONLY', 'PERMANENT_LOCK_IP')
);


-- ============================================================================
-- 비밀번호 변경 + 세션 무효화 (guide35)
--
-- users.session_version: 이 계정의 "로그인 세션 세대 번호". 로그인할 때 세션에 함께 저장하고,
-- 회원 화면에 들어올 때마다 DB 값과 비교한다. 비밀번호를 바꾸면 1 올라가서, 바꾸기 전에
-- 만들어진 다른 기기의 세션(탈취된 세션 포함)은 자동으로 로그아웃된다.
-- 기존 회원은 0으로 시작하고, 이미 로그인된 세션도 0으로 취급되어 그대로 유지된다.
-- 여러 번 실행해도 안전하다.
-- ============================================================================
alter table users add column if not exists session_version int not null default 0;


-- ============================================================================
-- 관리자 계정 단위 잠금 (guide38)
--
-- /admin/login은 IP 단위 잠금만 있어서, IP를 나눠 쓰는 분산 브루트포스로 관리자 계정을
-- 공격하면 막히지 않았다. 회원 계정 잠금(account_lockouts)과 같은 방식의 잠금을 관리자용
-- 표로 따로 둔다 — account_lockouts는 username이 기본키라 같은 이름의 회원과 관리자가 한
-- 줄을 쓰게 되기 때문이다. 관리자 계정 잠금은 항상 임시(5분) 잠금이라 표 구조가 단순하다.
--
-- **새 코드를 배포하기 전에** 실행해야 한다(없으면 /admin/login과 대시보드가 오류).
-- 여러 번 실행해도 안전하다.
-- ============================================================================

-- 1) 관리자 계정 잠금 현재 상태
create table if not exists admin_account_lockouts (
  username text primary key,
  locked_at timestamptz not null default now(),
  unlock_at timestamptz not null,
  failure_count int not null,
  active boolean not null default true
);

-- 2) 관리자 아이디별 실패 횟수를 15분 창으로 세는 조회용 인덱스
create index if not exists idx_admin_login_log_username_time
  on admin_login_log (username, attempted_at desc);

-- 3) 잠금 이력에 관리자 계정 대상(admin_account)을 허용
alter table lock_history drop constraint if exists lock_history_target_kind_check;
alter table lock_history add constraint lock_history_target_kind_check check (
  target_kind in ('ip', 'account', 'admin_account')
);

-- 4) 관리자 계정 잠금 해제 권한 — super_admin만 가진다
alter table permissions drop constraint if exists permissions_action_check;
alter table permissions add constraint permissions_action_check check (
  action in (
    'unlock_ip', 'resolve_security_event', 'toggle_signup',
    'delete_user', 'delete_post', 'delete_comment', 'manage_admin_users',
    'approve_pending_action', 'resolve_incident',
    'promote_permanent_lock', 'release_permanent_lock',
    'revoke_ip_exemption', 'revoke_recovery_request',
    'unlock_admin_account'
  )
);
insert into permissions (role, action) values
  ('super_admin', 'unlock_admin_account')
on conflict do nothing;


-- ============================================================================
-- 이메일 인증 + 이메일 변경 보호 (guide40) — 비밀번호 찾기(guide41)의 토대
--
-- 1) users.email_status에 'VERIFIED'(메일함 주인임이 확인됨)를 추가한다.
--    UNKNOWN = 아직 확인 안 됨(기존 회원 전부 포함), UNDELIVERABLE = 메일 서버가 영구 거부.
-- 2) email_tokens: 이메일 인증 / 이메일 변경 확인 / 비밀번호 재설정(guide41)용 1회용 링크.
--    영구 잠금 복구(recovery_requests)와 표를 나눈다 — 복구의 하루 한도·대시보드 카드·
--    기기 쿠키·6자리 코드 흐름과 섞이지 않게 하기 위해서다. 토큰은 SHA-256 해시만 저장한다.
--
-- **새 코드를 배포하기 전에** 실행해야 한다(없으면 회원가입·프로필 화면이 오류).
-- 여러 번 실행해도 안전하다.
-- ============================================================================

alter table users drop constraint if exists users_email_status_check;
alter table users add constraint users_email_status_check
  check (email_status in ('UNKNOWN', 'VERIFIED', 'UNDELIVERABLE'));

create table if not exists email_tokens (
  id bigint generated always as identity primary key,
  user_id bigint not null references users(id) on delete cascade,
  purpose text not null check (purpose in ('EMAIL_VERIFY', 'EMAIL_CHANGE', 'PASSWORD_RESET')),
  email text not null,                                      -- 이 토큰이 확인하는 주소(변경이면 새 주소)
  token_hash text not null unique,
  requested_ip text not null,
  status text not null default 'PENDING'
    check (status in ('PENDING', 'USED', 'EXPIRED', 'REVOKED')),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  used_at timestamptz
);
-- 같은 (회원, 용도)에 진행 중(PENDING)인 토큰은 1개만 — 새 요청이 오면 기존 것을 REVOKED로
-- 바꾼 뒤 넣는다(동시 요청이 겹쳐도 DB가 두 번째를 막는다).
create unique index if not exists idx_email_tokens_one_pending
  on email_tokens (user_id, purpose) where status = 'PENDING';
create index if not exists idx_email_tokens_user_created
  on email_tokens (user_id, purpose, created_at desc);
