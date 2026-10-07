# 33단계 — 영구 잠금 (자동 만료 없는 잠금 + 관리자 해제)

[◀ 32단계](guide32_incident_resolution.md) · [전체 목차](beginner-guide.md) · [34단계 ▶](guide34a_email_recovery.md)

> 지금까지의 잠금은 5분이면 자동으로 풀렸습니다. 같은 사람이 5분마다 다시 시도하면 계속 반복할 수 있다는 뜻입니다. 이 단계에서는 **같은 IP·계정이 반복해서 잠기면 자동 만료 없는 "영구 잠금"으로 올리고**, 영구 잠금은 **이메일 인증([34단계](guide34a_email_recovery.md)) 또는 관리자 해제로만** 풀리게 했습니다.

## 용어부터 정리

| 용어 | 뜻 |
|---|---|
| **임시 잠금** (`TEMPORARY`) | 5분 뒤 자동으로 풀리는 기존 잠금 |
| **영구 잠금** (`PERMANENT`) | 자동 만료가 없는 잠금. `unlock_at`이 비어 있다 |
| **승격** | 이미 있는 임시 잠금을 같은 줄에서 영구 잠금으로 "올리는" 것 |
| **허용 목록** | 절대 영구 잠그지 않을 IP 목록(관리자 PC 등). 자기 자신을 잠그는 실수를 막는다 |

## 언제 영구 잠금이 걸리나

| # | 상황 | 대상 | 이메일 복구 |
|---|---|---|---|
| T1 | 같은 IP가 최근 30일 안에 **2번째** 잠금(`BRUTE_FORCE`/`PASSWORD_SPRAYING`) | IP | 본인+본인 기기 예외만 |
| T2 | 같은 계정이 최근 30일 안에 **2번째** 잠금(`DISTRIBUTED_BRUTE_FORCE`) | 계정 | 완전 해제 |
| T3 | 연관 사건(SIEM)의 최고 등급이 **CRITICAL** → 즉시 | 사건 IP | 본인+본인 기기 예외만 |
| T4 | 연관 사건의 최고 등급이 **HIGH** → 기본은 관리자 승인 대기(`PERMANENT_LOCK_AUTO_ON_HIGH=true`면 즉시) | 사건 IP | 본인+본인 기기 예외만 |
| T5 | 관리자 로그인 잠금(`ADMIN_BRUTE_FORCE`)이 **2번째** | IP | **불가 — 관리자만** |

- 횟수와 기간은 `config.py`의 `PERMANENT_LOCK_STRIKE_COUNT`(IP, 기본 2) / `PERMANENT_LOCK_ACCOUNT_STRIKE_COUNT`(계정, 기본 2) / `PERMANENT_LOCK_STRIKE_WINDOW_DAYS`(30)로 바꿀 수 있습니다. 기간이 없으면 1년 전 잠금 한 번이 평생 누적되어 정상 사용자가 다음 실수 한 번에 영구 잠금됩니다.
- **가입되지 않은 아이디는 영구 잠금하지 않습니다.** 공격자가 아무 아이디나 넣어서 영구 잠금 줄을 무한히 만드는 걸 막기 위해서입니다(임시 잠금까지만 걸립니다).
- 이메일 서버가 수신자를 영구 거부한 계정(`users.email_status = UNDELIVERABLE`)은 이메일로 풀 수 없게 관리자 전용으로 올라갑니다.

## 왜 `lock_history` 표가 따로 필요한가

`lockouts`는 같은 IP가 다시 잠기면 같은 줄을 덮어씁니다(upsert). 그래서 "최근 30일 안에 몇 번 잠겼나"를 셀 수 없습니다. 그래서 **잠길 때마다 한 줄씩 추가만 하는** `lock_history`를 만들었습니다. 영구 승격 이력과 "누가 언제 왜 풀었는지(`released_by`)"도 여기 남습니다.

## 처리 흐름

```
로그인 실패가 임계값을 넘음
 └─ soar.enforce_lockout()
      ├─ 5분 임시 잠금 + Slack 알림 + 보안 이벤트 기록       (기존)
      └─ lockdown.after_temporary_lock()                        (신규)
           ├─ lock_history에 임시 잠금 이력 추가
           ├─ 최근 30일 임시 잠금 횟수 집계
           └─ 기준 이상이면 lockdown.promote_ip() → 영구 잠금
                ├─ 조건부 UPDATE(WHERE lock_type='TEMPORARY') — 실제로 바뀐 경우만 이후 단계 실행
                ├─ PERMANENT_LOCK(CRITICAL) 이벤트 → 상관분석으로 전달
                └─ Slack "영구 잠금" 알림 (한 번만)
```

### 왜 `lockdown.py`를 따로 만들었나 (순환 import)

`soar.py`는 이미 `correlate.py`를 가져다 씁니다. 그런데 `correlate.py`(사건 위험등급 T3/T4)도 승격을 해야 합니다. 둘이 서로를 import하면 파이썬이 "아직 다 읽지 못한 파일"을 쓰려다 오류를 냅니다. 그래서 승격·해제 로직을 `lockdown.py` 한 곳에 모으고 `soar.py`와 `correlate.py`가 둘 다 이 파일만 import합니다. `lockdown.py`가 사건 상관분석을 호출해야 하는 한 군데(영구 잠금 이벤트 전달)만 함수 안에서 늦게 import합니다.

### 영구 잠금 이벤트와 사건

승격하면 `PERMANENT_LOCK`(CRITICAL) 이벤트가 기록되고 상관분석에도 전달돼서, 같은 IP의 사건 표에 "영구 잠금까지 갔다"는 표시가 남습니다. 이 이벤트가 다시 승격을 부르지는 않습니다(재귀 방지). 기본값은 사건을 **자동으로 닫지 않습니다** — [32단계](guide32_incident_resolution.md)의 원칙("접속 차단과 검토 완료는 별개")대로 관리자가 직접 "해결"을 눌러야 합니다. `PERMANENT_LOCK_AUTO_CLOSE_INCIDENT=true`로 바꾸면 시스템(`system:permanent_lock`)이 자동으로 닫습니다.

## 영구 잠금이 "안 잠김"으로 보이지 않게 — 함께 고친 기존 코드

| 파일 | 문제 | 수정 |
|---|---|---|
| `db/lockouts.py`, `db/account_lockouts.py`의 `get_active_*` | `unlock_at > 지금`만 보면 영구 잠금(`unlock_at` 비어 있음)이 "안 잠김" | `lock_type='PERMANENT'` **또는** `unlock_at > 지금` |
| `list_expired_active_*` | 영구 잠금을 "만료됨"으로 풀어버릴 수 있음 | `lock_type='TEMPORARY'`만 대상 |
| `create_lockout`/`create_account_lockout` | 5분 잠금 upsert가 영구 잠금을 덮어쓰거나, 풀린 영구 행에 `unlock_at`만 채워 DB 제약(CHECK) 위반 | 활성 영구 행은 건드리지 않고, 새 임시 잠금은 `lock_type='TEMPORARY'` 등을 명시해 덮어씀 |
| `soar.manual_release*` | 대시보드 "즉시 해제"가 영구 잠금을 사유 없이 풀 수 있음 | 영구 잠금이면 `False` — 영구 해제 경로로만 풀림 |

> `unlock_at`에 `'infinity'` 시각을 넣으면 위 쿼리를 하나도 안 고쳐도 되지만, 파이썬(`datetime.fromisoformat`)과 JS(`Date`)가 이 값을 해석하지 못해 대시보드가 깨집니다. 그래서 "비어 있음(NULL) + `lock_type`" 방식을 택했습니다.

## 관리자 해제와 권한(RBAC)

쓰기 API 하나당 권한 하나(1:1) 관례를 따랐습니다.

| 권한 | API | security_admin | super_admin |
|---|---|:---:|:---:|
| `promote_permanent_lock` | `POST /api/permanent-locks/promote` | ○ | ○ |
| `release_permanent_lock` | `POST /api/permanent-locks/release` | ✕ | ○ |
| `revoke_ip_exemption` | `POST /api/ip-exemptions/revoke` | ○ | ○ |
| `revoke_recovery_request` | `POST /api/recovery-requests/revoke` | ○ | ○ |

- **영구 잠금의 완전 해제는 `super_admin`만** 합니다. 사유(`note`)가 비어 있으면 400으로 거부되고, 푼 관리자는 요청 본문이 아니라 로그인 세션에서 가져와 `lock_history.released_by = 'admin:<아이디>'`로 기록됩니다.
- 수동 승격은 관리자만 풀 수 있게(`ADMIN_ONLY`) 걸립니다. 허용 목록 IP와 가입되지 않은 아이디는 거부합니다.
- 기존 "즉시 해제" API(`/api/unlock`, `/api/unlock-account`)를 영구 잠금에 쓰면 409와 "영구 해제로만 풀 수 있습니다" 안내가 돌아옵니다.

### 대시보드

- **"영구 잠금" 카드** — 대상·승격 사유·복구 방식·승격 시각을 보여주고, 시간 대신 "영구" 배지를 표시합니다(영구 행은 아래 "현재 잠긴 IP / 계정" 임시 잠금 카드에서 빠집니다). 이메일을 신뢰할 수 없는 계정에는 "이메일 확인 불가" 배지가 붙습니다.
- **"영구 해제" 버튼** — `super_admin`에게만 보입니다(다른 역할에는 "super_admin 전용" 문구). 누르면 사유 입력창이 뜨고 사유가 비어 있으면 닫히지 않습니다. 화면에서 버튼을 숨기는 건 편의일 뿐이고 서버가 `require_permission`으로 따로 403을 돌려줍니다.
- **수동 승격 폼**, **복구 요청**(진행 중이면 "취소"), **IP 예외**("회수") 카드도 각자의 권한이 있는 관리자에게만 버튼이 보입니다.
- 터미널에서는 `python scripts/unlock_ip.py --ip <IP> --permanent`, `python scripts/unlock_account.py --username <아이디> --permanent`로 풉니다(`--permanent` 없이는 영구 잠금을 건너뜁니다, `--note`로 사유 지정).

## 로그인/가입에서의 판정

- 영구 잠긴 **계정**: "영구 잠금" 안내 + 이메일 복구 링크 (비밀번호 확인은 하지 않음)
- 영구 잠긴 **IP**: "이 네트워크는 차단되어 있습니다" + 복구 링크. 단 **이메일 복구로 예외를 받은 회원+기기**는 정상적으로 비밀번호 확인까지 진행 — 예외 통과자가 연속 3번(`IP_EXEMPTION_MAX_FAILURES`) 실패하면 예외가 회수됩니다.
- 영구 잠긴 IP에서는 **회원가입이 거부**됩니다(공격자가 새 계정을 만들어 예외를 받아내는 경로 차단).
- `/admin/login`은 영구 잠긴 IP에 예외·이메일 복구가 없습니다(관리자 로그인은 위험도가 가장 높음).

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [lockdown.py](../../lockdown.py), [db/lock_history.py](../../db/lock_history.py), [docs/migrations/guide33_permanent_lock.sql](../migrations/guide33_permanent_lock.sql), [tests/test_permanent_lock.py](../../tests/test_permanent_lock.py), [tests/test_permanent_admin_api.py](../../tests/test_permanent_admin_api.py)
- 수정: [config.py](../../config.py), [soar.py](../../soar.py), [correlate.py](../../correlate.py), [detector.py](../../detector.py), [alert.py](../../alert.py), [db/lockouts.py](../../db/lockouts.py), [db/account_lockouts.py](../../db/account_lockouts.py), [db/incidents.py](../../db/incidents.py), [db/roles.py](../../db/roles.py), [routes/admin.py](../../routes/admin.py), [routes/auth.py](../../routes/auth.py), 대시보드(`templates/admin_dashboard.html`, `public/js/dashboard/*`, `public/css/dashboard.css`), `scripts/unlock_ip.py`, `scripts/unlock_account.py`, `scripts/tune_thresholds.py`(영구 잠금 이벤트는 "조기 해제" 집계에서 제외)
- 스키마: [docs/schema.sql](../schema.sql) 맨 아래 + 같은 내용의 마이그레이션 파일. 여러 번 실행해도 안전합니다.

## 알려진 제한

- 영구 IP 잠금은 `TRUST_FORWARDED_FOR=true`에서 헤더 위조로 악용될 수 있고, Vercel에서는 `remote_addr` 확인이 필요합니다(README "알려진 제한사항").
- 영구 잠금은 이미 로그인된 세션을 끊지 않습니다.
- 관리자 로그인 IP가 영구 잠금되면 그 IP에서는 관리자 로그인이 안 되므로 `scripts/unlock_ip.py --permanent`나 다른 관리자가 필요합니다.
