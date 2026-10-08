# 43단계 — 복구 요청 한도와 처리 시간 기록

[◀ 42단계](guide42_ipv6_prefix.md) · [전체 목차](beginner-guide.md)

> 복구 요청(`/recovery/request`)과 비밀번호 찾기 요청(`/password/forgot`)은 가입 여부가 응답 시간으로 드러나지 않도록 **항상 8초 뒤에** 응답합니다([34단계](guide34a_email_recovery.md), [41단계](guide41_password_reset.md)). 이 8초 동안 서버리스 함수 하나가 묶여 있습니다. 그래서 요청이 몰리면 함수 자원이 고갈될 수 있습니다. 이번 단계에서는 **복구 요청에 전용 한도**를 걸고, **실제 처리 시간을 기록**하게 한 뒤, 운영 실측을 근거로 고정 시간을 **8초에서 5초로** 줄였습니다. DB 스키마 변경은 없습니다.

## 문제

| 항목 | 이전 상태 |
|---|---|
| 8초 대기가 걸리는 곳 | `/recovery/request`, `/password/forgot` (공용 함수 `run_with_fixed_response_time`) |
| 화면 단위 요청 한도 | `/password/forgot`은 IP당 분당 10회. **`/recovery/request`는 없음**(전역 분당 120회만 적용) |
| 8초의 근거 | "원격 DB 조회 여러 번과 메일 발송에 4~5초쯤 걸린다"는 추정. **실측 기록 없음** |

IP 하나가 분당 120번 복구를 요청하면 함수 120개가 8초씩 묶입니다.

대기 시간을 바로 줄이는 것도 위험합니다. 실제 처리(메일 발송)가 대기 시간보다 오래 걸리면 메일을 보낸 경우에만 응답이 늦어집니다. 그러면 "이 아이디는 존재하고 이메일도 인증됐다"는 사실이 다시 드러납니다. 그래서 **먼저 재고 나서 줄이는** 순서로 진행합니다.

## 바꾼 것

### 1. `/recovery/request` 전용 한도

- `RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE`(기본 **5**)를 추가했습니다. 다른 화면 단위 한도처럼 `app.py`에서 뷰 함수를 감쌉니다.
- 한도를 넘긴 요청은 뷰 함수가 실행되기 전에 걸러지므로 **8초를 기다리지 않고 바로 429**를 받습니다.
- 계정 존재 여부와는 관계가 없습니다. 한도는 IP 기준이라서 있는 아이디든 없는 아이디든 똑같이 6번째에 막힙니다.
- 한도에 걸리면 다른 한도와 마찬가지로 `HTTP_FLOOD` 보안 이벤트가 기록됩니다.

정상 사용자는 1분에 복구 메일을 5번 넘게 요청할 이유가 없습니다. 게다가 회원별 재요청 간격(`RECOVERY_COOLDOWN_SECONDS`, 60초) 때문에 두 번째 요청부터는 어차피 메일이 나가지 않습니다.

### 2. 실제 처리 시간 기록

`run_with_fixed_response_time`이 작업을 마친 시점에 로그를 한 줄 남깁니다.

```
[timing] /recovery/request work=0.52s target=8.0s
[timing] /password/forgot work=0.86s target=8.0s
[timing] /password/forgot work=8.41s target=8.0s overrun   ← 작업이 고정 시간을 넘김
```

- `work`: 요청을 받은 순간부터 작업(DB 조회, 메일 발송)을 마칠 때까지 걸린 시간입니다.
- `overrun`: 작업이 고정 시간을 넘겨서 **이 요청만 응답이 늦어졌다**는 표시입니다. 이 표시가 자주 보이면 고정 시간을 늘려야 합니다.
- **아이디와 IP는 남기지 않습니다.** 경로와 시간만 남깁니다.
- 고정 시간이 0일 때(테스트)는 기록하지 않습니다.

## 로컬에서 확인한 결과

`MAIL_BACKEND=console`로 띄운 로컬 서버와 운영 Supabase로 확인했습니다.

| 요청 | 응답 | 실제 처리(`work`) |
|---|---|---|
| `/recovery/request` 없는 아이디 1~5번째 | 200, 각 8.01초 | 0.51~0.54초 |
| `/recovery/request` 6번째 | **429, 0.54초** (대기 없음) | (실행 안 됨) |
| `/password/forgot` 인증된 테스트 회원(재설정 메일 생성) | 200, 8.00초 | 0.86초 |
| `/password/forgot` 없는 아이디 2번 | 200, 각 8.00초 | 0.70~0.94초 |

로컬은 메일을 터미널에 출력하므로 **SMTP 발송 시간이 빠져 있습니다**. 그래서 실제 Gmail SMTP를 거치는 운영에서 다시 측정했습니다.

## 운영(Vercel)에서 측정한 결과

배포 직후 테스트 회원과 없는 아이디로 요청했습니다(고정 시간 8초일 때, 서버 로그의 `[timing]` 값).

| 요청 | 응답 | 실제 처리(`work`) |
|---|---|---|
| `/password/forgot` 인증된 테스트 회원 — **실제 메일 발송**(배포 후 첫 요청) | 200, 8.24초 | **3.04초** |
| `/password/forgot` 메일 없음(없는 아이디, 하루 한도를 넘긴 회원) | 200, 8.2~8.5초 | 0.81~1.47초 |
| `/recovery/request` 없는 아이디 1~5번째 | 200, 8.2~8.4초 | 0.61~0.68초 |
| `/recovery/request` 6번째 | **429, 1.74초** (거절 기록을 DB에 남기는 시간 포함) | (실행 안 됨) |

`overrun`은 없었고, 응답 시간은 모든 경우에 8.2초 안팎으로 같았습니다.

## 고정 시간을 5초로

| 선택지 | 판단 |
|---|---|
| 4초 (메일 발송 3.04초 + 1초) | 메일 발송을 실측한 것이 1번뿐이고 Gmail 응답 속도가 들쭉날쭉해서 여유가 적다 |
| **5초 (채택)** | 실측보다 약 2초 여유. 함수가 묶이는 시간이 약 40% 줄어든다 |
| 8초 유지 | 안전하지만 줄일 근거가 생겼으므로 유지할 이유가 약하다 |

`config.RECOVERY_MIN_RESPONSE_SECONDS`의 기본값을 5.0으로 바꿨습니다. Vercel에는 이 환경변수를 따로 설정하지 않았으므로 코드의 기본값이 그대로 운영에 적용됩니다.

운영하면서 `[timing] ... overrun`이 보이면 처리가 5초를 넘긴 것입니다. 그 요청은 응답이 늦어져 시간 차이가 드러날 수 있습니다. 이때는 Vercel 환경변수 `RECOVERY_MIN_RESPONSE_SECONDS`를 6~8로 설정하면 코드를 고치지 않고 늘릴 수 있습니다.

## 확인한 결과 (자동 테스트)

650개 → **653개**, 전부 통과했습니다.

| 테스트 | 확인한 것 |
|---|---|
| `test_recovery_request_has_its_own_rate_limit_and_rejects_without_waiting` | 5번까지는 200, 6번째는 429. 고정 시간을 2초로 두어도 429는 1초 안에 응답 |
| `test_work_time_is_logged_without_identifiers` | `[timing] /recovery/request work=… target=…` 형식, `overrun` 없음 |
| `test_work_slower_than_the_target_is_flagged_as_overrun` | 작업이 고정 시간을 넘기면 `overrun` 표시 |

## 이 단계에서 만들어지거나 바뀐 파일

- 수정: [app.py](../../app.py)(한도 등록), [config.py](../../config.py)(`RECOVERY_REQUEST_RATE_LIMIT_PER_MINUTE`, `RECOVERY_MIN_RESPONSE_SECONDS` 8→5), [routes/recovery.py](../../routes/recovery.py)(`_log_timing`, `run_with_fixed_response_time`), `tests/test_recovery.py`, [.env.example](../../.env.example), [README.md](../../README.md), 8초를 언급하던 문서(34a·41단계, `scenario.md`, `feature-reference`, `architecture-map.html`)
