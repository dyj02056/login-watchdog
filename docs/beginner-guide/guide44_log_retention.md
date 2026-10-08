# 44단계 — 로그 자동 정리와 일별 요약

[◀ 43단계](guide43_recovery_request_limit.md) · [전체 목차](beginner-guide.md)

> 페이지 접속, 404, 로그인 시도 같은 기록은 요청마다 한 줄씩 쌓이는데, 지금까지는 지울 방법이 없었습니다(`scripts/delete_security_events.py`는 보안 이벤트만 수동으로 지움). 그래서 Supabase 안의 예약 작업(pg_cron)이 **매일 새벽 3시(한국 시간)** 보관 기간이 지난 기록을 지우게 했습니다. 지우기 전에는 **날짜·종류별 건수**를 요약표에 남겨, 개별 기록이 사라져도 오래된 통계는 계속 볼 수 있습니다. 앱 코드는 바뀌지 않았고, SQL 한 번 실행으로 켜집니다.

## 왜 필요한가

| 확인 (2026-10-08 운영 DB) | 결과 |
|---|---|
| 전체 기록 | 약 2,500건 — 무료 용량(500MB)의 0.1%도 안 됨 |
| 가장 많은 표 | `page_access_attempts` 1,422건(9/4부터 약 5주) |

지금은 급하지 않습니다. 진짜 위험은 공격을 받을 때입니다. 여러 IP에서 몰려오는 요청은 요청 한 번마다 한 줄씩 쌓이므로 하루에 수십만 줄이 될 수 있는데, 그걸 지울 방법이 없었습니다.

## 보관 기간

탐지 기능이 원본 기록을 얼마나 거슬러 보는지 먼저 확인했습니다. 가장 긴 판단인 영구 잠금("30일 안에 두 번째 잠금")은 원본 기록이 아니라 `lock_history`를 보고, 원본 기록을 보는 탐지는 길어야 1시간~하루입니다.

| 분류 | 표 | 보관 | 요약 종류(category) |
|---|---|---|---|
| 단순 접속·시도 기록 | `page_access_attempts`, `not_found_attempts`, `unauthorized_attempts`, `signup_attempts`, `post_attempts`, `comment_attempts` | 30일 | `all` |
| API 기록 | `api_access_log` | 30일 | 요청 방식(`GET`, `POST` …) |
| 로그인 기록 | `login_attempts`, `admin_login_log` | 90일 | `success` / `failure` |
| 처리 완료된 보안 이벤트 | `security_events`(`resolved_at`이 있는 것) | 처리 후 90일 | 이벤트 유형(`HTTP_FLOOD` …) |
| 끝난 사건 | `security_incidents`(`CLOSED`) | 해결 후 90일 | 최고 등급 |
| 결정된 승인 요청 | `access_requests`(`PENDING`이 아닌 것) | 결정 후 90일 | `이벤트유형:상태` |
| 끝난 메일 링크 | `email_tokens`, `recovery_requests`(사용·만료·취소, 또는 유효 시간이 지난 것) | 30일 | `용도:상태` |
| 위치 조회 캐시 | `ip_locations` | 30일 | 요약 없음 — 다음에 새로 조회 |

**지우지 않는 것:** 처리 전인 이벤트·진행 중인 사건·결정 전인 승인 요청·대기 중인 메일 링크, 회원·관리자, 현재 잠금·잠금 이력(`lock_history`)·IP 예외, 게시글·댓글, 설정·권한. 사건이 지워져도 `lock_history.incident_id`는 비워지기만 해서(`on delete set null`) 잠금 이력은 그대로 남습니다.

보관 기간은 `cleanup_old_logs` 함수 맨 위의 `interval '30 days'` 같은 값을 바꾸면 됩니다.

## 만든 것

| 이름 | 역할 |
|---|---|
| 표 `log_daily_summary` | `(날짜, 원래 표, 종류) → 건수`. 날짜는 한국 시간 기준 |
| 함수 `cleanup_old_logs(dry_run)` | 표마다 정리하고 지운 건수를 돌려준다. `dry_run = true`면 **세기만 하고 지우지 않는다** |
| 함수 `_cleanup_log_table(...)` | 표 하나를 정리한다. 삭제와 요약 추가가 **한 문장**이라, 요약만 되고 안 지워지거나 그 반대가 생기지 않는다 |
| 예약 작업 `cleanup-old-logs` | 매일 UTC 18시(= 한국 새벽 3시)에 `cleanup_old_logs()` 실행 |

보관 기간의 경계 때문에 하루치 기록이 이틀에 걸쳐 나뉘어 지워져도, 요약은 같은 칸에 **더해지므로** 건수가 맞습니다.

**보안:** Supabase는 새 함수에 사이트용 키(anon/authenticated)의 실행 권한을 기본으로 주므로, 두 함수 모두 권한을 회수했습니다. 예약 작업과 SQL Editor에서만 실행됩니다. 요약표는 다른 표들과 같은 방식(RLS 없음)입니다 — RLS는 보완점 3번에서 따로 다룰 범위입니다.

## 켜는 방법

Supabase **SQL Editor**에서 [docs/migrations/guide44_log_retention.sql](../migrations/guide44_log_retention.sql)을 실행합니다. 여러 번 실행해도 안전합니다(예약 작업도 같은 이름으로 덮어씀).

## 확인·운영 방법

```sql
-- 지금 정리하면 몇 건이 지워질지(아무것도 지우지 않음)
select * from cleanup_old_logs(true) where deleted_rows > 0;

-- 지금 바로 한 번 정리
select * from cleanup_old_logs() where deleted_rows > 0;

-- 예약 작업이 등록됐는지
select jobid, jobname, schedule, active from cron.job where jobname = 'cleanup-old-logs';

-- 최근 실행 기록(성공/실패)
select start_time, status, return_message
from cron.job_run_details
where jobid = (select jobid from cron.job where jobname = 'cleanup-old-logs')
order by start_time desc limit 5;

-- 남아 있는 요약 보기: 표별 일별 건수
select day, source, category, count from log_daily_summary order by day desc, source, category;

-- 월별 합계 예시: 달마다 404 접근이 몇 번이었나
select date_trunc('month', day)::date as month, sum(count)
from log_daily_summary where source = 'not_found_attempts'
group by 1 order by 1;
```

예약 작업을 멈추려면 `select cron.unschedule('cleanup-old-logs');`를 실행합니다.

## 감수하는 점

- **지운 기록은 되돌릴 수 없습니다.** 무료 요금제에는 사용자가 복원할 수 있는 백업이 없습니다. 요약에는 건수만 남고 IP·경로·아이디는 남지 않습니다.
- 지운 기간을 대상으로 하는 조회는 결과가 비어 나옵니다 — `daily_report.py --start/--end`로 30·90일보다 오래된 기간을 보는 경우, 대시보드 "보안 이벤트" 표의 오래된 처리 완료 항목 등.
- 요약의 보안 이벤트 건수는 **이벤트 행 수**입니다. 한 이벤트 안에서 반복된 횟수(`count` 칸)는 더하지 않습니다.

## 확인한 결과

**실제 Postgres에서의 검증** — 로컬에 Postgres 서버가 없어 임베디드 Postgres(PGlite)에 `schema.sql` 전체와 이 SQL(예약 작업 부분 제외)을 올려 확인했습니다.

| 확인 | 결과 |
|---|---|
| 마이그레이션 두 번 실행 | 오류 없음 |
| 미리보기(`dry_run`) | 지울 건수만 나오고 표는 그대로(접속 기록 4건 유지) |
| 실제 실행 | 40일·35일 전 접속 3건, 100일 전 로그인 2건, 처리 후 100일 지난 이벤트 1건, 오래된 캐시 1건 삭제. 5일 전 접속·40일 전 로그인·**처리 전 이벤트**·처리 후 10일 이벤트는 남음 |
| 요약 | 날짜(한국 시간)·종류별로 정확히 기록(로그인 성공 1·실패 1, `GET` 1, `HTTP_FLOOD` 1 …) |
| 다시 실행 | 지울 것이 없어 0건 |
| 같은 날 기록이 나중에 더 지워짐 | 요약 건수가 더해짐(3 → 4) |
| 권한 | anon·authenticated 모두 실행 불가 |

**자동 테스트** — 653개 → **660개**, 전부 통과 (`tests/test_log_retention.py` 7개 신규). 정리 함수는 DB 안에서만 돌아서, 앞으로 바뀔 수 있는 부분을 지킵니다.

| 테스트 | 확인한 것 |
|---|---|
| 모든 표의 분류 | `schema.sql`의 모든 표가 "정리" 또는 "지우지 않음" 중 하나 — 새 기록 표를 만들고 정리 대상에 넣는 것을 잊지 않게 |
| 표·칸 이름 | 정리 대상 표와 날짜 칸, 조건에 쓰인 칸이 `schema.sql`에 실제로 있음 — 이름이 틀리면 매일 밤 조용히 실패하므로 |
| 남겨야 할 것 | 처리 전 이벤트·진행 중 사건·대기 중 요청/링크는 조건에서 제외 |
| 권한·동기화 | 두 함수의 실행 권한 회수, 마이그레이션과 `schema.sql` 내용 일치 |

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [docs/migrations/guide44_log_retention.sql](../migrations/guide44_log_retention.sql), `tests/test_log_retention.py`
- 수정: [docs/schema.sql](../schema.sql)(맨 아래에 같은 내용), [README.md](../../README.md), 목차, 43단계 다음 링크
