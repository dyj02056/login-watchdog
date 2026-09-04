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
