-- ============================================================================
-- Track D 신뢰성·L3 보완 (guide57, 2026-10-29 점검)
-- 목적:
--   1. network_blocks.apply_attempts·failed_at — fw-agent가 차단 적용에 실패(FAILED)한 행을 앱이 횟수
--      상한(NET_BLOCK_APPLY_MAX_RETRIES) 안에서 다시 PENDING_APPLY로 돌린다. 예전에는 FAILED 행이 차단
--      목록에서 빠져 영구 차단(CR-01)이 한 번의 일시 오류로 조용히 걸리지 않을 수 있었다.
--   2. network_events.category — L3 경보 3종(ICMP_FLOOD·SPOOFED_SRC·GLOBAL_SYN_FLOOD)을 받는다(계약서 K4).
-- 실행: 통합 담당자가 Supabase SQL Editor에서 이 파일 전체를 실행한다. 여러 번 실행해도 결과가 같다.
-- 실행 전에도 앱은 동작한다: apply_attempts 칸이 없으면 재시도를 건너뛰고 예전처럼 알림만 보낸다.
--   단, category 제약을 넓히기 전에 새 경보가 오면 network_events 저장이 실패(shipper가 5xx 재시도)하므로
--   센서 이미지를 새로 빌드하기 전에 실행한다.
-- 설명: docs/beginner-guide/guide57_reliability_l3.md
--
-- 되돌리기(rollback):
-- alter table network_events drop constraint if exists network_events_category_check;
-- alter table network_events add constraint network_events_category_check check (
--   category in ('SYN_FLOOD', 'PORT_SCAN', 'SCANNER_UA', 'WEB_ATTACK', 'LOGIN_BURST', 'OTHER'));
-- alter table network_blocks drop column if exists failed_at;
-- alter table network_blocks drop column if exists apply_attempts;
-- ============================================================================

alter table network_blocks add column if not exists apply_attempts integer not null default 0;
alter table network_blocks add column if not exists failed_at timestamptz;

alter table network_events drop constraint if exists network_events_category_check;
alter table network_events add constraint network_events_category_check check (
  category in (
    'SYN_FLOOD', 'PORT_SCAN', 'SCANNER_UA', 'WEB_ATTACK', 'LOGIN_BURST', 'OTHER',
    'ICMP_FLOOD', 'SPOOFED_SRC', 'GLOBAL_SYN_FLOOD'
  )
);
