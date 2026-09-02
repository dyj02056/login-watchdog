-- login-watchdog Supabase 스키마
-- Supabase SQL 편집기에서 1회 실행. 이 저장소에서 직접 실행되는 마이그레이션 파일이 아니라 문서용 기록입니다.
-- 근거: plan.md 3-3절(로그/잠금/관리자 테이블) + 회원가입 기능 확장(users 테이블)

-- 감시 대상 /login 화면에 실제로 가입해 로그인하는 사용자 계정
create table users (
  id bigint generated always as identity primary key,
  username text not null unique,
  email text not null unique,
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
