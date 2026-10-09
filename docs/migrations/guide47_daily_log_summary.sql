-- ============================================================================
-- 매일 어제 하루치를 요약하고, 삭제는 따로 (guide47) — 44단계(guide44)의 요약 방식을 바꾼다
--
-- 44단계는 기록을 "지울 때" 요약했다. 그래서 요약표에는 보관 기간(30·90일)이 지난 오래된 날짜만
-- 있었고, 그래프를 그리려면 요약표와 원본 기록을 섞어 읽어야 했다. 이제는
--   ① 매일 새벽 3시(한국 시간)에 아직 요약하지 않은 날 ~ 어제까지 하루씩 요약하고
--   ② 그다음 보관 기간이 지난 원본 기록을 지운다(기준은 44단계와 같다).
-- 요약표에는 처음 기록된 날부터 어제까지 모든 날짜가 들어 있게 된다.
--
-- 요약표 두 개 (IP·아이디·이메일·정확한 시각은 어디에도 남지 않는다)
--   log_daily_summary   (day, hour, source, category, count) — 시간대(0~23시, 한국 시간)별 건수
--   log_daily_breakdown (day, source, dimension, value, count) — 하루 단위 상세
--       distinct_ips      그날 서로 다른 IP 수
--       failed_usernames  그날 로그인 실패에서 노린 서로 다른 아이디 수(로그인 기록만, 숫자만)
--       top_path          많이 노린 주소 상위 5개 + 나머지 합계 '(그 외)'
--       country           나라별 건수(로그인 기록만 — 위치는 로그인 기록의 IP만 조회해 두기 때문)
--
-- 같은 날을 다시 요약해도 안전하다 — 그날 값을 새로 계산해 덮어쓴다(더하지 않는다).
-- 요약하지 않은 날의 원본 기록은 지우지 않는다(cleanup_old_logs가 마지막 요약일까지만 지운다).
-- 이 파일을 실행하면 남아 있는 원본 기록(가장 오래된 날 ~ 어제)을 바로 요약한다.
-- 여러 번 실행해도 안전하다.
-- ============================================================================

-- 1) 요약표 ---------------------------------------------------------------------
create table if not exists log_daily_summary (
  day date not null,
  source text not null,
  category text not null,
  count bigint not null default 0,
  primary key (day, source, category)
);
-- 시간대 칸. 44단계 방식으로 이미 요약된 줄이 있다면 시간을 알 수 없으므로 -1(미상)로 남긴다.
alter table log_daily_summary add column if not exists hour smallint not null default -1;
alter table log_daily_summary drop constraint if exists log_daily_summary_hour_check;
alter table log_daily_summary add constraint log_daily_summary_hour_check check (hour between -1 and 23);
alter table log_daily_summary drop constraint if exists log_daily_summary_pkey;
alter table log_daily_summary add constraint log_daily_summary_pkey primary key (day, hour, source, category);

create table if not exists log_daily_breakdown (
  day date not null,
  source text not null,
  dimension text not null
    check (dimension in ('distinct_ips', 'failed_usernames', 'top_path', 'country')),
  value text not null default '',
  count bigint not null,
  primary key (day, source, dimension, value)
);

-- 어디까지 요약했는지(한 줄짜리 표). 밀린 날을 채우고, 요약 전 원본을 지우지 않는 데 쓴다.
create table if not exists log_summary_state (
  id int primary key default 1 check (id = 1),
  last_summarized_day date
);
insert into log_summary_state (id, last_summarized_day) values (1, null) on conflict (id) do nothing;

-- 2) 표 하나의 하루치를 요약한다 ----------------------------------------------------
--    p_category: 종류를 만드는 식. p_ip_col / p_path_col: 없으면 null.
--    p_login: 로그인 기록이면 true — 실패한 아이디 수와 나라별 건수를 더 남긴다.
create or replace function _summarize_log_source(
  p_day date,
  p_table text,
  p_time_col text,
  p_category text,
  p_ip_col text,
  p_path_col text,
  p_login boolean
) returns bigint
language plpgsql
set search_path = public
as $$
declare
  day_start timestamptz := p_day::timestamp at time zone 'Asia/Seoul';
  day_end   timestamptz := (p_day + 1)::timestamp at time zone 'Asia/Seoul';
  window_sql text := format('%I >= $1 and %I < $2', p_time_col, p_time_col);
  n bigint;
begin
  -- 덮어쓰기: 이 날·이 표의 기존 요약을 지우고 새로 계산한다(44단계 방식의 시간 미상(-1) 줄은 둔다).
  delete from log_daily_summary where day = p_day and source = p_table and hour >= 0;
  delete from log_daily_breakdown where day = p_day and source = p_table;

  execute format($f$
    insert into log_daily_summary (day, hour, source, category, count)
    select $3, extract(hour from %I at time zone 'Asia/Seoul')::smallint, %L, coalesce((%s)::text, 'unknown'), count(*)
    from %I where %s
    group by 2, 4
  $f$, p_time_col, p_table, p_category, p_table, window_sql)
  using day_start, day_end, p_day;
  get diagnostics n = row_count;

  if p_ip_col is not null then
    execute format($f$
      insert into log_daily_breakdown (day, source, dimension, value, count)
      select $3, %L, 'distinct_ips', '', count(distinct %I)
      from %I where %s
      having count(*) > 0
    $f$, p_table, p_ip_col, p_table, window_sql)
    using day_start, day_end, p_day;
  end if;

  if p_path_col is not null then
    execute format($f$
      with counted as (
        select coalesce(%I, '(없음)') as v, count(*) as n from %I where %s group by 1
      ),
      ranked as (
        select v, n, row_number() over (order by n desc, v) as rk from counted
      )
      insert into log_daily_breakdown (day, source, dimension, value, count)
      select $3, %L, 'top_path', case when rk <= 5 then v else '(그 외)' end, sum(n)
      from ranked
      group by 4
    $f$, p_path_col, p_table, window_sql, p_table)
    using day_start, day_end, p_day;
  end if;

  if p_login then
    execute format($f$
      insert into log_daily_breakdown (day, source, dimension, value, count)
      select $3, %L, 'failed_usernames', '', count(distinct username)
      from %I where %s and not success
      having count(*) > 0
    $f$, p_table, p_table, window_sql)
    using day_start, day_end, p_day;

    execute format($f$
      insert into log_daily_breakdown (day, source, dimension, value, count)
      select $3, %L, 'country', coalesce(nullif(l.country, ''), '알 수 없음'), count(*)
      from %I a left join ip_locations l on l.ip_address = a.ip_address
      where a.%s
      group by 4
    $f$, p_table, p_table, replace(window_sql, ' and ', ' and a.'))
    using day_start, day_end, p_day;
  end if;

  return n;
end;
$$;

-- 3) 하루치 전체 요약 -------------------------------------------------------------
create or replace function summarize_log_day(p_day date)
returns table (log_table text, summary_rows bigint)
language plpgsql
set search_path = public
as $$
declare
  t text;
begin
  foreach t in array array['login_attempts', 'admin_login_log'] loop
    log_table := t;
    summary_rows := _summarize_log_source(p_day, t, 'attempted_at',
      'case when success then ''success'' else ''failure'' end', 'ip_address', null, true);
    return next;
  end loop;

  foreach t in array array['page_access_attempts', 'not_found_attempts', 'unauthorized_attempts'] loop
    log_table := t;
    summary_rows := _summarize_log_source(p_day, t, 'attempted_at', '''all''', 'ip_address', 'path', false);
    return next;
  end loop;

  foreach t in array array['signup_attempts', 'post_attempts', 'comment_attempts'] loop
    log_table := t;
    summary_rows := _summarize_log_source(p_day, t, 'attempted_at', '''all''', 'ip_address', null, false);
    return next;
  end loop;

  log_table := 'api_access_log';
  summary_rows := _summarize_log_source(p_day, 'api_access_log', 'requested_at', 'method', 'ip_address', 'path', false);
  return next;

  log_table := 'security_events';
  summary_rows := _summarize_log_source(p_day, 'security_events', 'detected_at', 'event_type', 'ip_address', 'path', false);
  return next;

  log_table := 'security_incidents';
  summary_rows := _summarize_log_source(p_day, 'security_incidents', 'first_event_at', 'severity_max', 'ip_address', null, false);
  return next;

  log_table := 'access_requests';
  summary_rows := _summarize_log_source(p_day, 'access_requests', 'requested_at', 'event_type', null, null, false);
  return next;

  log_table := 'email_tokens';
  summary_rows := _summarize_log_source(p_day, 'email_tokens', 'created_at', 'purpose', null, null, false);
  return next;

  log_table := 'recovery_requests';
  summary_rows := _summarize_log_source(p_day, 'recovery_requests', 'created_at', 'target_kind', null, null, false);
  return next;
end;
$$;

-- 4) 아직 요약하지 않은 날 ~ 어제를 요약한다 ----------------------------------------
--    처음이면 원본 기록이 남아 있는 가장 오래된 날부터 시작한다. 요약한 날 수를 돌려준다.
create or replace function summarize_pending_log_days()
returns integer
language plpgsql
set search_path = public
as $$
declare
  yesterday date := (now() at time zone 'Asia/Seoul')::date - 1;
  last_day date;
  first_at timestamptz;
  d date;
  days integer := 0;
begin
  select last_summarized_day into last_day from log_summary_state where id = 1 for update;

  if last_day is null then
    select min(x) into first_at from (
      select min(attempted_at) as x from login_attempts
      union all select min(attempted_at) from admin_login_log
      union all select min(attempted_at) from page_access_attempts
      union all select min(attempted_at) from not_found_attempts
      union all select min(attempted_at) from unauthorized_attempts
      union all select min(attempted_at) from signup_attempts
      union all select min(attempted_at) from post_attempts
      union all select min(attempted_at) from comment_attempts
      union all select min(requested_at) from api_access_log
      union all select min(detected_at) from security_events
      union all select min(first_event_at) from security_incidents
      union all select min(requested_at) from access_requests
      union all select min(created_at) from email_tokens
      union all select min(created_at) from recovery_requests
    ) firsts;
    if first_at is null then
      return 0;  -- 기록이 하나도 없다
    end if;
    last_day := (first_at at time zone 'Asia/Seoul')::date - 1;
  end if;

  d := last_day + 1;
  while d <= yesterday loop
    perform summarize_log_day(d);
    days := days + 1;
    d := d + 1;
  end loop;

  if days > 0 then
    update log_summary_state set last_summarized_day = yesterday where id = 1;
  end if;
  return days;
end;
$$;

-- 5) 삭제만 하는 정리 (44단계 함수를 바꾼다) ------------------------------------------
--    요약은 더 이상 여기서 하지 않는다. 마지막으로 요약한 날 다음 날 0시(한국 시간) 이후의 원본은
--    보관 기간이 지났더라도 지우지 않는다 — 요약 전에 지워지는 일이 없게.
create or replace function _delete_old_log_rows(p_table text, p_condition text, p_cutoff timestamptz, p_dry_run boolean)
returns bigint
language plpgsql
set search_path = public
as $$
declare
  n bigint;
begin
  if p_dry_run then
    execute format('select count(*) from %I where %s', p_table, p_condition) into n using p_cutoff;
  else
    execute format('with gone as (delete from %I where %s returning 1) select count(*) from gone', p_table, p_condition)
      into n using p_cutoff;
  end if;
  return n;
end;
$$;

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
end;
$$;

-- 44단계의 "요약하면서 지우는" 함수는 더 쓰지 않는다.
drop function if exists _cleanup_log_table(text, text, text, text, timestamptz, boolean);

-- 6) 매일 할 일: 요약 → 삭제 ----------------------------------------------------------
create or replace function run_daily_log_maintenance()
returns void
language plpgsql
set search_path = public
as $$
begin
  perform summarize_pending_log_days();
  perform cleanup_old_logs(false);
end;
$$;

-- 7) 사이트·API 키로는 호출할 수 없게 막는다 -----------------------------------------
revoke all on function _summarize_log_source(date, text, text, text, text, text, boolean) from public, anon, authenticated;
revoke all on function summarize_log_day(date) from public, anon, authenticated;
revoke all on function summarize_pending_log_days() from public, anon, authenticated;
revoke all on function _delete_old_log_rows(text, text, timestamptz, boolean) from public, anon, authenticated;
revoke all on function cleanup_old_logs(boolean) from public, anon, authenticated;
revoke all on function run_daily_log_maintenance() from public, anon, authenticated;

-- 8) 예약 작업: 44단계의 'cleanup-old-logs'를 지우고 매일 새벽 3시(한국 시간 = UTC 18시)에 등록 ----
create extension if not exists pg_cron with schema pg_catalog;
select cron.unschedule(jobid) from cron.job where jobname = 'cleanup-old-logs';
select cron.schedule(
  'daily-log-maintenance',
  '0 18 * * *',
  $$select public.run_daily_log_maintenance()$$
);

-- 9) 남아 있는 원본 기록을 지금 바로 요약한다(가장 오래된 날 ~ 어제) ---------------------
select summarize_pending_log_days() as summarized_days;
