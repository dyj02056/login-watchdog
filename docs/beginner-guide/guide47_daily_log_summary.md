# 47단계 — 매일 어제 하루치를 요약한다 (시각화용 요약표)

[◀ 46단계](guide46_dashboard_responsiveness.md) · [전체 목차](beginner-guide.md)

> [44단계](guide44_log_retention.md)는 기록을 **지울 때** 날짜·종류별 건수를 요약표에 옮겨 적었습니다. 그래서 요약표에는 보관 기간(30·90일)이 지난 **오래된 날짜만** 있었습니다. 나중에 관리자 대시보드에 그래프를 넣으려면 요약표와 원본 기록을 섞어 읽어야 했습니다. 이제는 **매일 새벽 3시에 어제 하루치를 먼저 요약**하고, 삭제는 따로 합니다. 요약표에는 처음 기록된 날부터 어제까지 모든 날짜가 들어 있습니다. 시간대, IP 수, 노린 주소, 나라, 로그인 실패에서 노린 아이디 수도 함께 남깁니다. **IP와 아이디 자체는 남기지 않습니다.**

## 바뀐 점

| | 44단계 | 47단계 |
|---|---|---|
| 요약 시점 | 기록을 지울 때(30·90일 뒤) | **매일 새벽 3시, 어제 하루치** |
| 요약표의 날짜 | 오래된 날짜만 | **처음 기록된 날 ~ 어제 전부** |
| 남는 정보 | 날짜·종류·건수 | 날짜·**시간대**·종류·건수 + **IP 수, 실패 아이디 수, 노린 주소, 나라** |
| 삭제 | 요약하면서 함께 | 요약 **뒤에** 따로(보관 기간은 그대로) |
| 예약 작업 | `cleanup-old-logs` | `daily-log-maintenance` |

## 요약표 두 개

### `log_daily_summary` — 시간대별 건수

| 칸 | 내용 |
|---|---|
| `day` | 날짜(한국 시간) |
| `hour` | 시간대 0~23(한국 시간). 44단계 방식으로 이미 요약된 줄은 `-1`(시간 미상) |
| `source` | 원본 기록 이름 |
| `category` | 종류(아래 표) |
| `count` | 건수 |

### `log_daily_breakdown` — 하루 상세

| `dimension` | `value` | `count` | 대상 |
|---|---|---|---|
| `distinct_ips` | (빈칸) | 그날 서로 다른 IP 수 | IP 칸이 있는 기록 |
| `failed_usernames` | (빈칸) | 로그인 **실패**에서 노린 서로 다른 아이디 수 | 로그인 기록(회원·관리자)만 |
| `top_path` | 주소 | 그 주소의 건수. 상위 5개 + 나머지 합계 `(그 외)` → 다 더하면 그날 총 건수 | 주소 칸이 있는 기록 |
| `country` | 나라 이름(위치를 모르면 `알 수 없음`) | 그 나라의 건수 | 로그인 기록(회원·관리자)만 |

나라는 **로그인 기록에서만** 셉니다. 위치는 대시보드가 로그인 기록 표에 보여 줄 IP만 외부에서 조회해 저장해 두기 때문에(`ip_locations`), 다른 기록의 IP는 대부분 위치를 모릅니다.

실패 아이디 수는 공격 유형을 구분하는 데 씁니다.

| IP 수 | 실패 아이디 수 | 공격 유형 |
|---|---|---|
| 1 | 1 | 한 계정 집중(브루트포스) |
| 1 | 많음 | 여러 계정을 돌아가며(패스워드 스프레이) |
| 많음 | 1 | 여러 IP로 한 계정(분산 공격) |

### 기록별로 남는 것

| 원본 기록 | 날짜·시간 기준 | 종류(`category`) | 하루 상세 |
|---|---|---|---|
| `login_attempts`, `admin_login_log` | 시도 시각 | `success` / `failure` | IP 수, 실패 아이디 수, 나라 |
| `page_access_attempts`, `not_found_attempts`, `unauthorized_attempts` | 시도 시각 | `all` | IP 수, 노린 주소 |
| `signup_attempts`, `post_attempts`, `comment_attempts` | 시도 시각 | `all` | IP 수 |
| `api_access_log` | 요청 시각 | 요청 방식(`GET`/`POST`) | IP 수, 호출한 API 주소 |
| `security_events` | 감지 시각 | 경고 종류(`HTTP_FLOOD` …) | IP 수, 노린 주소 |
| `security_incidents` | 첫 이벤트 시각 | 최고 등급 | IP 수 |
| `access_requests` | 요청 시각 | 경고 종류 | — |
| `email_tokens` | 발급 시각 | 용도(`EMAIL_VERIFY`, `PASSWORD_RESET` …) | — |
| `recovery_requests` | 발급 시각 | 대상(`ip` / `account`) | — |

보안 경고 건수는 **경고가 생긴 횟수**입니다(한 경고 안에서 반복된 요청 수는 더하지 않음). 승인 요청의 승인·거절 결과와 메일 링크의 사용 여부는 남기지 않습니다. 다음 날 새벽에도 아직 결정되지 않았을 수 있어서 값이 정확하지 않기 때문입니다.

## 매일 하는 일

```
새벽 3시(한국 시간) — run_daily_log_maintenance()
 ① summarize_pending_log_days(): 아직 요약하지 않은 날 ~ 어제를 하루씩 요약
 ② cleanup_old_logs(): 보관 기간이 지난 원본 삭제(44단계와 같은 기준)
```

| 원칙 | 구현 |
|---|---|
| 다시 요약해도 안전 | 그날·그 기록의 요약을 지우고 **새로 계산해 덮어쓴다**(더하지 않음). 두 번 돌려도 숫자가 그대로 |
| 빠진 날 채우기 | `log_summary_state`에 마지막으로 요약한 날을 적어 두고, 다음 실행 때 그다음 날부터 어제까지 채운다 |
| 요약 전에는 지우지 않음 | 삭제 기준 시각을 "보관 기간"과 "마지막 요약일 다음 날 0시" 중 **이른 쪽**으로 잡는다. 한 번도 요약하지 않았으면 아무것도 지우지 않는다 |
| 오늘은 요약하지 않음 | 하루가 끝나지 않았으므로 어제까지만. 그래프에서 오늘 값이 필요하면 원본에서 실시간으로 센다 |
| 처음 설치 | SQL을 실행하는 순간 원본이 남아 있는 가장 오래된 날(운영: 2026-09-04)부터 어제까지 한 번에 요약 |

요약표는 지우지 않습니다. 하루에 수십~수백 줄이라 몇 년이 지나도 용량 부담이 없습니다. 사이트용 키(anon/authenticated)로는 요약·정리 함수를 실행할 수 없습니다.

## 켜는 방법

Supabase **SQL Editor**에서 [docs/migrations/guide47_daily_log_summary.sql](../migrations/guide47_daily_log_summary.sql)을 실행합니다(44단계 SQL을 먼저 실행해 둔 상태에서). 여러 번 실행해도 안전합니다. 마지막 줄의 결과 `summarized_days`가 한 번에 요약한 날 수입니다.

## 확인·조회 방법

```sql
-- 예약 작업 등록 확인
select jobid, jobname, schedule, active from cron.job where jobname = 'daily-log-maintenance';

-- 최근 실행 기록
select start_time, status, return_message from cron.job_run_details
where jobid = (select jobid from cron.job where jobname = 'daily-log-maintenance')
order by start_time desc limit 5;

-- 어디까지 요약했나
select last_summarized_day from log_summary_state;

-- 날짜별 로그인 실패 추이(그래프용)
select day, sum(count) as failures from log_daily_summary
where source = 'login_attempts' and category = 'failure' group by day order by day;

-- 시간대별 히트맵용(최근 30일, 404 접근)
select day, hour, count from log_daily_summary
where source = 'not_found_attempts' and day >= current_date - 30 order by day, hour;

-- 공격 유형 판단용: 날짜별 IP 수와 실패 아이디 수
select day, dimension, count from log_daily_breakdown
where source = 'login_attempts' and dimension in ('distinct_ips', 'failed_usernames') order by day, dimension;

-- 특정 날짜를 다시 요약(덮어쓰기)
select * from summarize_log_day('2026-09-05');
```

## 확인한 결과

**실제 Postgres에서의 검증** — 임베디드 Postgres(PGlite)에 `schema.sql` 전체(44단계 포함, 예약 작업 제외)와 이 SQL을 올리고 시각을 정해 둔 데이터로 확인했습니다. 26개 항목 모두 통과했습니다.

| 확인 | 결과 |
|---|---|
| 마이그레이션 두 번 실행 | 오류 없음. 44단계 방식으로 이미 있던 요약 줄은 `hour = -1`로 보존 |
| 요약 전 정리 | 100일 지난 로그인·40일 지난 404도 **지우지 않음** |
| 밀린 날 채우기 | 가장 오래된 기록(100일 전)부터 어제까지 100일 요약, 상태표에 어제 기록 |
| 시간대 | 14시 실패 3·성공 1, 15시 실패 1. 전날 23:59:59(한국 시간)는 전날로, 오늘 0시 이후는 요약 안 함 |
| 하루 상세 | IP 2곳, 실패 아이디 3개, 나라 South Korea 4·알 수 없음 1 |
| 노린 주소 | 상위 5개(/a 6, /b 4, /c 3, /d 2, /e 2) + (그 외) 2 = 그날 404 19건 |
| 404 | 나라·실패 아이디 없음(로그인 기록만) |
| 보안 경고 | 처리 여부와 관계없이 감지 시각 기준으로 셈 |
| 다시 요약 | 결과 동일(덮어쓰기), 밀린 날 없음 |
| 요약 후 정리 | 오래된 원본만 지우고 어제 기록은 그대로, 지운 날의 요약은 남음 |
| 하루 건너뜀 | 상태를 이틀 전으로 돌리면 2일 채움 |
| 권한 | 함수 4개 모두 anon·authenticated 실행 불가, 44단계의 `_cleanup_log_table` 제거 |

**자동 테스트** — 684개 → **693개**, 전부 통과 (`tests/test_daily_log_summary.py` 9개 신규, `test_log_retention.py`의 표 분류에 새 표 2개 추가).

| 테스트 | 확인한 것 |
|---|---|
| 요약 대상 | 지우는 기록은 모두(위치 캐시 제외) 요약 대상 — 지우기 전에 반드시 요약 |
| 표·칸 이름 | 요약에 쓰는 날짜·종류·IP·주소·아이디 칸이 `schema.sql`에 실제로 있음 |
| 남는 정보 | 요약표 칸은 날짜·시간대·표·종류·항목·값·건수뿐, IP·아이디는 `count(distinct …)` 숫자로만 |
| 로그인 전용 | 나라·실패 아이디 수는 로그인 기록 2종에만 |
| 순서·보호 | 매일 작업은 요약 → 삭제, 삭제 기준은 마지막 요약일을 넘지 않음 |
| 권한·동기화 | 새 함수 전부 실행 권한 회수, 예약 작업 교체, 마이그레이션과 `schema.sql` 일치 |

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [docs/migrations/guide47_daily_log_summary.sql](../migrations/guide47_daily_log_summary.sql), `tests/test_daily_log_summary.py`
- 수정: [docs/schema.sql](../schema.sql)(맨 아래에 같은 내용), `tests/test_log_retention.py`, [guide44_log_retention.md](guide44_log_retention.md)(바뀐 점 안내), [README.md](../../README.md), 목차, 46단계 다음 링크
