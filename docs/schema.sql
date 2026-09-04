-- login-watchdog Supabase 스키마
-- Supabase SQL 편집기에서 1회 실행. 이 저장소에서 직접 실행되는 마이그레이션 파일이 아니라 문서용 기록입니다.
-- 근거: plan.md 3-3절(로그/잠금/관리자 테이블) + 회원가입 기능 확장(users 테이블)

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
