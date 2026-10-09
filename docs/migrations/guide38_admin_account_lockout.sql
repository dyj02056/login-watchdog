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
