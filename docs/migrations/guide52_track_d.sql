-- ============================================================================
-- Track D 네트워크 탐지·차단 저장 구조 (guide52)
--
-- 목적: 센서 이벤트, L4 차단 상태, 에이전트 생존 신호, 알림 쿨다운과 플레이북 실행
-- 이력을 저장하고 기존 보안 이벤트·사건·승인 구조를 Track D와 연결한다.
-- 실행 순서: 통합 담당자가 애플리케이션 배포 전에 Supabase SQL Editor에서 이 파일 전체를 실행한다.
-- 모든 DDL과 데이터 보정은 두 번 실행해도 같은 결과가 되도록 작성했다.
--
-- 되돌리기(필요한 문장만 주석을 풀어 역순 실행하며, 해당 데이터는 삭제된다):
-- drop table if exists playbook_runs;
-- drop table if exists notification_cooldowns;
-- drop table if exists agent_heartbeats;
-- drop table if exists network_blocks;
-- drop table if exists network_events;
-- alter table security_incidents drop column if exists app_severity_max;
-- alter table security_incidents drop column if exists matched_rules;
-- alter table security_events drop column if exists layer;
-- alter table security_events drop column if exists source;
-- ============================================================================

-- 센서의 재전송은 event_id 유일성으로 같은 행에 모으고, 관측·수신 시각은 따로 보존한다.
create table if not exists network_events (
  id bigint generated always as identity primary key,
  event_id text not null unique,
  sensor text not null check (sensor in ('suricata', 'scapy')),
  layer text not null check (layer in ('L3', 'L4', 'L7')),
  src_ip text not null,
  dst_port int,
  proto text,
  category text not null check (
    category in ('SYN_FLOOD', 'PORT_SCAN', 'SCANNER_UA', 'WEB_ATTACK', 'LOGIN_BURST', 'OTHER')
  ),
  signature_id int,
  signature text,
  sensor_severity smallint,
  packet_count int not null default 1,
  window_start timestamptz not null,
  observed_at timestamptz not null,
  last_seen_at timestamptz not null,
  promoted boolean not null default false,
  received_at timestamptz not null default now()
);
create index if not exists idx_network_events_src_observed
  on network_events (src_ip, observed_at desc);
create index if not exists idx_network_events_observed
  on network_events (observed_at desc);

-- 앱은 원하는 차단 상태만 기록하고 실제 적용 결과는 fw-agent가 같은 행에 되돌려 쓴다.
create table if not exists network_blocks (
  ip_address text primary key,
  reason text not null,
  evidence text not null check (evidence in ('SPOOFABLE', 'CONNECTED')),
  status text not null check (
    status in ('PENDING_APPLY', 'APPLIED', 'PENDING_REMOVE', 'REMOVED', 'FAILED')
  ),
  expires_at timestamptz,
  requested_by text not null,
  requested_at timestamptz not null default now(),
  applied_at timestamptz,
  removed_at timestamptz,
  last_error text,
  constraint network_blocks_permanent_needs_connected
    check (expires_at is not null or evidence = 'CONNECTED')
);
create index if not exists idx_network_blocks_status on network_blocks (status);

-- 세 PC가 DB 하나를 공유하므로 에이전트 종류와 노드를 묶어 각 생존 신호를 분리한다.
create table if not exists agent_heartbeats (
  agent text not null check (agent in ('fw-agent', 'shipper')),
  node text not null,
  last_seen_at timestamptz not null,
  detail jsonb,
  primary key (agent, node)
);

-- 여러 프로세스와 PC가 같은 알림 쿨다운을 원자적으로 공유한다.
create table if not exists notification_cooldowns (
  key text primary key,
  last_sent_at timestamptz not null
);

-- 단계별 결과를 남겨 일부 조치 실패와 재실행 결과를 추적한다.
create table if not exists playbook_runs (
  id bigint generated always as identity primary key,
  playbook text not null,
  trigger_ref text not null,
  step text not null,
  status text not null check (status in ('OK', 'FAILED', 'SKIPPED')),
  error text,
  ran_at timestamptz not null default now()
);
create index if not exists idx_playbook_runs_ran_at on playbook_runs (ran_at desc);

-- 기존 호출은 기본 APP으로 유지하고 네트워크 이벤트만 출처와 계층을 명시한다.
alter table security_events add column if not exists source text not null default 'APP'
  check (source in ('APP', 'NET'));
alter table security_events add column if not exists layer text
  check (layer in ('L3', 'L4', 'L7'));

-- 앱 이벤트 최고 등급을 별도로 보존해야 네트워크 이벤트가 기존 영구 잠금 판단을 바꾸지 않는다.
alter table security_incidents add column if not exists matched_rules text[] not null default '{}';
alter table security_incidents add column if not exists app_severity_max text
  check (app_severity_max in ('MEDIUM', 'HIGH', 'CRITICAL'));
update security_incidents set app_severity_max = severity_max where app_severity_max is null;

-- 마지막 스키마 정의의 기존 값을 모두 유지하면서 Track D 승인 유형만 추가한다.
alter table access_requests drop constraint if exists access_requests_event_type_check;
alter table access_requests add constraint access_requests_event_type_check check (
  event_type in (
    'BRUTE_FORCE', 'DISTRIBUTED_BRUTE_FORCE', 'SIGNUP_RATE_LIMIT',
    'WEB_SCANNING', 'UNAUTHORIZED_ACCESS', 'PAGE_ACCESS', 'API_MACRO_PATTERN',
    'SIEM_HIGH_INCIDENT', 'NET_REPEAT_FLOOD', 'NET_SUBNET_ATTACK'
  )
);
alter table access_requests drop constraint if exists access_requests_pending_action_check;
alter table access_requests add constraint access_requests_pending_action_check check (
  pending_action in (
    'LOCK_IP', 'LOCK_ACCOUNT', 'ALERT_ONLY', 'PERMANENT_LOCK_IP',
    'BLOCK_L4_PERMANENT', 'BLOCK_SUBNET'
  )
);
alter table access_requests drop constraint if exists access_requests_target_kind_check;
alter table access_requests add constraint access_requests_target_kind_check check (
  target_kind in ('ip', 'account', 'subnet')
);

-- 기존 unlock_ip 역할에만 L4 차단 해제 권한을 복사해 권한 수준을 맞춘다.
alter table permissions drop constraint if exists permissions_action_check;
alter table permissions add constraint permissions_action_check check (
  action in (
    'unlock_ip', 'resolve_security_event', 'toggle_signup',
    'delete_user', 'delete_post', 'delete_comment', 'manage_admin_users',
    'approve_pending_action', 'resolve_incident',
    'promote_permanent_lock', 'release_permanent_lock',
    'revoke_ip_exemption', 'revoke_recovery_request',
    'unlock_admin_account', 'release_network_block'
  )
);
insert into permissions (role, action)
select role, 'release_network_block'
from permissions
where action = 'unlock_ip'
on conflict do nothing;
