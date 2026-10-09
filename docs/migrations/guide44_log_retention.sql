-- ============================================================================
-- 로그 테이블 자동 정리 + 일별 요약 보관 (guide44)
--
-- 접속·시도 기록은 요청마다 한 줄씩 쌓이는데 지울 방법이 없었다. 지금은 양이 작지만
-- (2026-10 기준 전체 약 2,500건), 여러 IP에서 몰려오는 공격을 받으면 하루에 수십만 줄이
-- 쌓일 수 있다. 그래서 보관 기간이 지난 기록을 매일 지운다.
--
-- 지우기 전에 "날짜(한국 시간)·표·종류별 건수"를 log_daily_summary에 더해 둔다 — 개별
-- 기록은 사라져도 "9월 10일 404 접근 120건" 같은 통계는 영구히 남는다.
--
--   보관 기간(아래 cleanup_old_logs 맨 위에서 바꿀 수 있다)
--   - 30일: 페이지 접속·404·권한 없는 접근·가입/글/댓글 시도·API 기록, 끝난 메일 링크
--           (탐지는 길어야 최근 1시간~하루를 본다)
--   - 90일: 로그인 기록(회원·관리자), 처리 완료된 보안 이벤트·사건·승인 요청
--   - 30일: 위치 조회 캐시(ip_locations) — 요약 없이 지운다(다음에 새로 조회)
--   - 지우지 않음: 처리 전인 이벤트·사건·승인 요청, 대기 중인 메일 링크, 회원·관리자,
--     잠금·잠금 이력(lock_history)·IP 예외, 게시글·댓글, 설정·권한
--
-- 실행 방법
--   select * from cleanup_old_logs(true);    -- 미리보기: 지울 건수만 보여주고 지우지 않는다
--   select * from cleanup_old_logs();        -- 실제로 요약을 남기고 지운다
--
-- 이 파일은 여러 번 실행해도 안전하다(예약 작업도 같은 이름으로 덮어쓴다).
-- ============================================================================

-- 1) 일별 요약 -----------------------------------------------------------------
--    source  = 원래 표 이름, category = 종류(로그인 성공/실패, 이벤트 유형 등, 구분 없으면 'all')
--    count   = 그날 그 종류의 행 수. 하루가 두 번에 나뉘어 지워져도(보관 기간 경계) 더해진다.
create table if not exists log_daily_summary (
  day date not null,
  source text not null,
  category text not null,
  count bigint not null default 0,
  primary key (day, source, category)
);

-- 2) 표 하나를 정리한다 ------------------------------------------------------------
--    p_condition: 지울 행 조건(보관 기준 시각은 $1). p_time_col: 요약의 날짜로 쓸 칸.
--    p_category: 요약의 종류를 만드는 식. null이면 요약 없이 지운다(캐시용).
--    삭제와 요약 추가가 한 문장(같은 트랜잭션)이라, 요약만 되고 안 지워지거나 그 반대가 없다.
create or replace function _cleanup_log_table(
  p_table text,
  p_time_col text,
  p_condition text,
  p_category text,
  p_cutoff timestamptz,
  p_dry_run boolean
) returns bigint
language plpgsql
set search_path = public
as $$
declare
  n bigint;
begin
  if p_dry_run then
    execute format('select count(*) from %I where %s', p_table, p_condition)
      into n using p_cutoff;
  elsif p_category is null then
    execute format(
      'with gone as (delete from %I where %s returning 1) select count(*) from gone',
      p_table, p_condition
    ) into n using p_cutoff;
  else
    execute format($f$
      with gone as (
        delete from %I where %s
        returning %I as happened_at, (%s)::text as category
      ),
      summary as (
        insert into log_daily_summary as s (day, source, category, count)
        select (happened_at at time zone 'Asia/Seoul')::date, %L, coalesce(category, 'unknown'), count(*)
        from gone
        group by 1, 3
        on conflict (day, source, category) do update set count = s.count + excluded.count
      )
      select count(*) from gone
    $f$, p_table, p_condition, p_time_col, p_category, p_table)
    into n using p_cutoff;
  end if;
  return n;
end;
$$;

-- 3) 전체 정리 -------------------------------------------------------------------
create or replace function cleanup_old_logs(dry_run boolean default false)
returns table (log_table text, deleted_rows bigint)
language plpgsql
set search_path = public
as $$
declare
  raw_cutoff   timestamptz := now() - interval '30 days';  -- 단순 접속·시도 기록
  login_cutoff timestamptz := now() - interval '90 days';  -- 로그인 기록
  done_cutoff  timestamptz := now() - interval '90 days';  -- 처리 완료된 보안 기록
  token_cutoff timestamptz := now() - interval '30 days';  -- 끝난 메일 링크
  cache_cutoff timestamptz := now() - interval '30 days';  -- 위치 조회 캐시
  t text;
begin
  -- 단순 접속·시도 기록: 종류 구분 없이 날짜별 건수
  foreach t in array array[
    'page_access_attempts', 'not_found_attempts', 'unauthorized_attempts',
    'signup_attempts', 'post_attempts', 'comment_attempts'
  ] loop
    log_table := t;
    deleted_rows := _cleanup_log_table(t, 'attempted_at', 'attempted_at < $1', '''all''', raw_cutoff, dry_run);
    return next;
  end loop;

  log_table := 'api_access_log';
  deleted_rows := _cleanup_log_table('api_access_log', 'requested_at',
    'requested_at < $1', 'method', raw_cutoff, dry_run);
  return next;

  -- 로그인 기록: 성공/실패별
  foreach t in array array['login_attempts', 'admin_login_log'] loop
    log_table := t;
    deleted_rows := _cleanup_log_table(t, 'attempted_at', 'attempted_at < $1',
      'case when success then ''success'' else ''failure'' end', login_cutoff, dry_run);
    return next;
  end loop;

  -- 처리 완료된 보안 기록만(처리 전인 것은 기간과 무관하게 남긴다)
  log_table := 'security_events';
  deleted_rows := _cleanup_log_table('security_events', 'detected_at',
    'resolved_at is not null and resolved_at < $1', 'event_type', done_cutoff, dry_run);
  return next;

  -- lock_history.incident_id는 on delete set null이라 잠금 이력은 남는다.
  log_table := 'security_incidents';
  deleted_rows := _cleanup_log_table('security_incidents', 'first_event_at',
    'status = ''CLOSED'' and coalesce(resolved_at, last_event_at) < $1', 'severity_max', done_cutoff, dry_run);
  return next;

  log_table := 'access_requests';
  deleted_rows := _cleanup_log_table('access_requests', 'requested_at',
    'status <> ''PENDING'' and coalesce(decided_at, requested_at) < $1',
    'event_type || '':'' || status', done_cutoff, dry_run);
  return next;

  -- 끝난 메일 링크(사용·만료·취소). 대기 중이어도 유효 시간이 지난 것은 끝난 것으로 본다.
  log_table := 'email_tokens';
  deleted_rows := _cleanup_log_table('email_tokens', 'created_at',
    'created_at < $1 and (status <> ''PENDING'' or expires_at < now())',
    'purpose || '':'' || status', token_cutoff, dry_run);
  return next;

  log_table := 'recovery_requests';
  deleted_rows := _cleanup_log_table('recovery_requests', 'created_at',
    'created_at < $1 and (status <> ''PENDING'' or expires_at < now())',
    'target_kind || '':'' || status', token_cutoff, dry_run);
  return next;

  -- 위치 조회 캐시: 요약 없이 지운다
  log_table := 'ip_locations';
  deleted_rows := _cleanup_log_table('ip_locations', 'looked_up_at',
    'looked_up_at < $1', null, cache_cutoff, dry_run);
  return next;
end;
$$;

-- 4) 사이트·API 키로는 호출할 수 없게 막는다 ----------------------------------------
--    Supabase는 새 함수에 anon/authenticated 실행 권한을 기본으로 주므로 명시적으로 회수한다.
--    예약 작업(postgres)과 SQL Editor에서만 실행된다.
revoke all on function _cleanup_log_table(text, text, text, text, timestamptz, boolean)
  from public, anon, authenticated;
revoke all on function cleanup_old_logs(boolean) from public, anon, authenticated;

-- 5) 매일 새벽 3시(한국 시간 = UTC 18시)에 실행 ---------------------------------------
--    같은 이름으로 다시 등록하면 기존 예약을 덮어쓴다.
create extension if not exists pg_cron with schema pg_catalog;
select cron.schedule(
  'cleanup-old-logs',
  '0 18 * * *',
  $$select * from public.cleanup_old_logs()$$
);
