# 26단원 — 로그 자동 정리 + 일별 요약 흐름도 명세 (앱 코드 밖, DB 안의 SQL 함수들)

from scripts.docs.dsl import Scenario, call

SLUG = "26-log-retention"
TITLE = "26. 로그 자동 정리 + 일별 요약"
SUBTITLE = "매일 새벽 3시, DB 안에서 '요약 → 정리' 순서로 도는 SQL 함수들의 코드 흐름도 (앱 코드와 무관)"

SQL = "docs/schema.sql"
END = "re:^\\$\\$;"

FILE_ROLES = {
    SQL: "DB 전체 정의 파일(표·함수·예약 작업). 이 단원은 그중 로그 요약·정리 함수와 예약 작업(pg_cron)만 다룬다.",
}

s1 = Scenario("daily", "매일 새벽 3시: 요약 → 정리",
              "페이지 접속·404·로그인 시도 같은 기록은 요청마다 한 줄씩 쌓이는데 지울 방법이 없었습니다. 여러 IP에서 공격이 몰리면 하루 수십만 줄이 될 수 있습니다. 그래서 DB 안에서(Supabase pg_cron) 매일 '하루씩 요약'한 뒤, 보관 기간이 지난 원본을 지웁니다. 순서가 중요합니다 — 요약하기 전의 기록은 절대 지우지 않습니다.")
s1.screen("예약 작업 (pg_cron) — 매일 UTC 18시 = 한국 새벽 3시", "앱 서버가 아니라 DB 안에서 정해진 시각에 SQL 을 실행합니다. 앱 코드와 무관해 언제 켜도 됩니다.",
          snippet=(SQL, "select cron.unschedule(jobid) from cron.job where jobname = 'cleanup-old-logs';", "re:^\\);"), label="pg_cron 예약",
          hl=("select cron.schedule(", "re:^\\);"))
s1.step("① run_daily_log_maintenance() — 요약 먼저, 정리는 그다음", "이 순서를 지키기 때문에 '요약되지 않은 날의 기록'이 먼저 지워지는 일이 없습니다.",
        kind="db", col=1, snippet=(SQL, "create or replace function run_daily_log_maintenance()", END), label="run_daily_log_maintenance",
        hl=("perform summarize_pending_log_days();", "perform cleanup_old_logs(false);"))
s1.step("② 요약 안 한 날부터 어제까지, 하루씩 요약", "마지막으로 요약한 날(log_summary_state)의 다음 날부터 어제까지 한 날씩 처리하고, 끝나면 '어디까지 요약했는지'를 기록합니다. 밀린 날도 이 방식으로 채웁니다.",
        kind="db", col=1, snippet=(SQL, "create or replace function summarize_pending_log_days()", END), label="summarize_pending_log_days",
        hl=("d := last_day + 1;", "return days;"),
        calls=[call(snippet=(SQL, "create or replace function summarize_log_day(p_day date)", END), title="하루치 전체 요약", plain="로그인 기록·접속 기록·보안 이벤트 등 표 14개를 하나씩 요약 함수에 넘깁니다.", label="summarize_log_day", kind="db"),
               call(snippet=(SQL, "create table if not exists log_summary_state (", "on conflict (id) do nothing;"), title="어디까지 요약했나 (한 줄짜리 표)", plain="last_summarized_day 한 칸. 밀린 날을 채우고, 요약 전 원본을 지우지 않는 데 쓰입니다.", label="log_summary_state", kind="db")])
s1.step("③ 한 표의 하루치를 '덮어쓰기'로 요약", "그날·그 표의 기존 요약을 지우고 새로 계산해서, 여러 번 실행해도 결과가 같습니다. 한국 시간 기준 하루(00:00~24:00)를 UTC 로 바꿔 범위를 잡습니다.",
        kind="db", col=1, snippet=(SQL, "create or replace function _summarize_log_source(", END), label="_summarize_log_source",
        hl=("delete from log_daily_summary where day = p_day", "delete from log_daily_breakdown where day = p_day and source = p_table;"),
        calls=[call(snippet=(SQL, "create table if not exists log_daily_summary (", "primary key (day, hour, source, category)", 2), title="시간대별 건수 요약표", plain="(날짜, 시간, 표, 종류) → 건수. IP·아이디 자체는 남지 않고 건수만 남습니다.", label="log_daily_summary", kind="db"),
               call(snippet=(SQL, "create table if not exists log_daily_breakdown (", "primary key (day, source, dimension, value)"), title="하루 상세 요약표", plain="서로 다른 IP 수 · 로그인 실패에서 노린 아이디 수 · 많이 노린 주소 상위 5개 · 로그인 기록의 나라별 건수.", label="log_daily_breakdown", kind="db")])
s1.step("④ 시간대별 건수 + 상세(IP 수·상위 경로·나라별)", "요약표에는 건수만 들어갑니다. 상위 5개 경로 외의 나머지는 '(그 외)'로 묶습니다.",
        kind="db", col=1, snippet=(SQL, "create or replace function _summarize_log_source(", END), label="_summarize_log_source",
        hl=("execute format($f$", "using day_start, day_end, p_day;"))
s1.step("⑤ 삭제 기준 = min(보관 기간, 마지막 요약일 다음 날 0시)", "보관 기간이 지났더라도 '요약 전' 기록은 지우지 않습니다. 접속·시도 기록은 30일, 로그인 기록과 처리 완료된 보안 기록은 90일입니다.",
        kind="db", col=1, snippet=(SQL, "create or replace function cleanup_old_logs(", END, 2), label="cleanup_old_logs",
        hl=("select last_summarized_day into last_day from log_summary_state where id = 1;", "token_cutoff := least(now() - interval '30 days', safe_until);"))
s1.step("⑥ 처리 전·대기 중인 것은 지우지 않는다", "처리 완료된 보안 이벤트·종결된 사건·끝난 메일 링크만 지웁니다. 처리 전 이벤트, 대기 중인 링크, 잠금 이력, 회원 정보는 남깁니다.",
        kind="db", col=1, snippet=(SQL, "create or replace function cleanup_old_logs(", END, 2), label="cleanup_old_logs",
        hl=("log_table := 'security_events';", "log_table := 'ip_locations';"))
s1.step("⑦ 실제 삭제 (dry_run 이면 건수만 센다)", "cleanup_old_logs(true) 로 부르면 아무것도 지우지 않고 '지울 건수'만 미리 볼 수 있습니다.",
        kind="db", col=1, snippet=(SQL, "create or replace function _delete_old_log_rows(", END), label="_delete_old_log_rows",
        hl=("if p_dry_run then", "end if;"))
s1.step("⑧ 사이트·API 키로는 호출할 수 없게 막는다", "유지보수 함수는 DB 안의 예약 작업만 부를 수 있고, 웹 요청(익명·로그인 사용자)으로는 호출할 수 없습니다.",
        kind="db", col=1, snippet=(SQL, "revoke all on function _summarize_log_source(", "revoke all on function run_daily_log_maintenance() from public, anon, authenticated;"), label="revoke all")

SCENARIOS = [s1.build()]
