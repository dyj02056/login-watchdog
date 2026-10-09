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
