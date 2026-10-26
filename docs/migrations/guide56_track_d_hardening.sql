-- ============================================================================
-- Track D 예외 상황 보완 (guide56, 10/26 강사 피드백 4·추가 상황 "규칙 동시 기록")
-- 목적:
--   1. network_blocks.version — 차단·해제 요청이 바뀔 때마다 1 올리고, fw-agent의 ACK에 같은 값을
--      실어 "어느 요청에 대한 완료인지" 구분한다. 60초 차단의 늦은 ACK가 그 사이 바뀐 영구 차단의
--      완료로 받아들여지는 일을 막는다.
--   2. append_matched_rule() — 사건의 matched_rules에 규칙 하나를 "원자적으로" 덧붙인다. REST로는
--      읽은 목록을 통째로 다시 쓰므로, NET-01과 CR-02가 동시에 들어오면 한쪽 규칙이 지워졌다.
-- 실행: 통합 담당자가 Supabase SQL Editor에서 이 파일을 실행한다. 여러 번 실행해도 결과가 같다.
--       2026-10-26 공용 DB에 실행 완료(확인: version 칸·append_matched_rule 함수 각 1줄).
--       처음 파일 이름은 guide55였으나, guide55는 관제 화면·시연 가이드(I3-2) 번호라 guide56으로 바꿨다.
--       DB 안의 칸·함수 이름은 그대로라 다시 실행할 필요는 없다.
-- 실행 전에도 앱은 동작한다: 코드가 version 칸·함수가 없으면 예전 방식으로 돌아간다(fallback).
-- 설명: docs/beginner-guide/guide56_feedback_hardening.md
--
-- 되돌리기(rollback):
-- drop function if exists append_matched_rule(bigint, text, text[], text);
-- alter table network_blocks drop column if exists version;
-- ============================================================================

alter table network_blocks add column if not exists version integer not null default 0;

create or replace function append_matched_rule(
  p_incident_id bigint,
  p_rule text,
  p_event_types text[],
  p_severity_max text
)
returns boolean
language plpgsql
set search_path = public
as $$
begin
  -- 규칙이 아직 없을 때만 덧붙인다. 같은 규칙이 동시에 와도 한쪽만 true를 받아 플레이북이 한 번만 돈다.
  -- 유형·등급도 읽어 둔 값으로 덮지 않고 지금 행의 값과 합친다(동시에 올라간 등급을 낮추지 않게).
  update security_incidents
     set matched_rules = array_append(matched_rules, p_rule),
         event_types   = (select array_agg(distinct t order by t) from unnest(event_types || p_event_types) as t),
         severity_max  = case
                           when array_position(array['MEDIUM','HIGH','CRITICAL'], p_severity_max)
                              > array_position(array['MEDIUM','HIGH','CRITICAL'], severity_max)
                           then p_severity_max else severity_max
                         end,
         last_event_at = now()
   where id = p_incident_id
     and not (p_rule = any(matched_rules));
  return found;
end;
$$;
