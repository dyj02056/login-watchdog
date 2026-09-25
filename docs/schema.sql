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
-- 딱 한 번만" 알림 원칙과 동일). 사건이 닫혔다가(CLOSED) 새로 열리면 새 행이므로
-- 자동으로 false에서 다시 시작한다.
alter table security_incidents add column escalated boolean not null default false;
