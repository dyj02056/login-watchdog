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
