-- ============================================================================
-- Track D 보존 (guide53)
-- 목적: 센서 이벤트 7일, 플레이북 실행 기록 90일, 종료된 L4 차단 기록 30일을
--       기존 일별 요약과 별개로 정리한다. guide47의 기존 정리와 예약 일정은 유지한다.
-- 실행: 11/2 통합일 머지 후 통합 담당자가 Supabase SQL Editor에서 이 파일을 실행한다.
-- 미리보기: select * from cleanup_old_logs(true);
-- 되돌리기: guide47_daily_log_summary.sql의 cleanup_old_logs 정의를 다시 실행한다.
-- 여러 번 실행해도 같은 함수 정의가 되며 표와 칸은 바꾸지 않는다.
-- ============================================================================

create or replace function cleanup_old_logs(dry_run boolean default false)
returns table (log_table text, deleted_rows bigint)
language plpgsql
set search_path = public
as $$
declare
  last_day date;
  safe_until timestamptz;
  raw_cutoff   timestamptz;
  login_cutoff timestamptz;
  done_cutoff  timestamptz;
  token_cutoff timestamptz;
  cache_cutoff timestamptz := now() - interval '30 days';  -- 위치 캐시는 요약하지 않으므로 그대로
  t text;
begin
  select last_summarized_day into last_day from log_summary_state where id = 1;
  safe_until := case when last_day is null then '-infinity'::timestamptz
                     else (last_day + 1)::timestamp at time zone 'Asia/Seoul' end;
  raw_cutoff   := least(now() - interval '30 days', safe_until);  -- 단순 접속·시도 기록
  login_cutoff := least(now() - interval '90 days', safe_until);  -- 로그인 기록
  done_cutoff  := least(now() - interval '90 days', safe_until);  -- 처리 완료된 보안 기록
  token_cutoff := least(now() - interval '30 days', safe_until);  -- 끝난 메일 링크

  foreach t in array array[
    'page_access_attempts', 'not_found_attempts', 'unauthorized_attempts',
    'signup_attempts', 'post_attempts', 'comment_attempts'
  ] loop
    log_table := t;
    deleted_rows := _delete_old_log_rows(t, 'attempted_at < $1', raw_cutoff, dry_run);
    return next;
  end loop;

  log_table := 'api_access_log';
  deleted_rows := _delete_old_log_rows('api_access_log', 'requested_at < $1', raw_cutoff, dry_run);
  return next;

  foreach t in array array['login_attempts', 'admin_login_log'] loop
    log_table := t;
    deleted_rows := _delete_old_log_rows(t, 'attempted_at < $1', login_cutoff, dry_run);
    return next;
  end loop;

  -- 처리 완료된 것만(처리 전인 것은 기간과 무관하게 남긴다). 처리 시각은 감지 시각 이후라서
  -- 처리 시각 기준으로 지워도 요약 안 된 날의 기록은 지워지지 않는다.
  log_table := 'security_events';
  deleted_rows := _delete_old_log_rows('security_events',
    'resolved_at is not null and resolved_at < $1', done_cutoff, dry_run);
  return next;

  -- lock_history.incident_id는 on delete set null이라 잠금 이력은 남는다.
  log_table := 'security_incidents';
  deleted_rows := _delete_old_log_rows('security_incidents',
    'status = ''CLOSED'' and coalesce(resolved_at, last_event_at) < $1', done_cutoff, dry_run);
  return next;

  log_table := 'access_requests';
  deleted_rows := _delete_old_log_rows('access_requests',
    'status <> ''PENDING'' and coalesce(decided_at, requested_at) < $1', done_cutoff, dry_run);
  return next;

  -- 끝난 메일 링크(사용·만료·취소). 대기 중이어도 유효 시간이 지난 것은 끝난 것으로 본다.
  log_table := 'email_tokens';
  deleted_rows := _delete_old_log_rows('email_tokens',
    'created_at < $1 and (status <> ''PENDING'' or expires_at < now())', token_cutoff, dry_run);
  return next;

  log_table := 'recovery_requests';
  deleted_rows := _delete_old_log_rows('recovery_requests',
    'created_at < $1 and (status <> ''PENDING'' or expires_at < now())', token_cutoff, dry_run);
  return next;

  log_table := 'ip_locations';
  deleted_rows := _delete_old_log_rows('ip_locations', 'looked_up_at < $1', cache_cutoff, dry_run);
  return next;

  -- 센서 원본과 플레이북 실행 기록은 각각 7일, 90일이 지나면 요약 없이 지운다.
  log_table := 'network_events';
  deleted_rows := _delete_old_log_rows('network_events',
    'observed_at < $1', now() - interval '7 days', dry_run);
  return next;

  log_table := 'playbook_runs';
  deleted_rows := _delete_old_log_rows('playbook_runs',
    'ran_at < $1', now() - interval '90 days', dry_run);
  return next;

  -- 실제 해제 시각을 우선 사용하고, 실패에는 별도 완료 시각이 없어 요청 시각을 쓴다.
  -- 진행 중인 세 상태는 삭제 조건에 들어가지 않아 보존 기간과 무관하게 남는다.
  log_table := 'network_blocks';
  deleted_rows := _delete_old_log_rows('network_blocks',
    '(status = ''REMOVED'' and coalesce(removed_at, requested_at) < $1) or (status = ''FAILED'' and requested_at < $1)',
    now() - interval '30 days', dry_run);
  return next;
end;
$$;

revoke all on function cleanup_old_logs(boolean) from public, anon, authenticated;
