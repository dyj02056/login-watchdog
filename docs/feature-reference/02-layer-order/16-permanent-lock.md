# 16. 영구 잠금

<aside>
🎯 **한 줄 요약**
5분 잠금은 풀리면 **같은 공격자가 5분마다 다시** 시도할 수 있습니다. 그래서 **같은 IP·계정이 반복해서 잠기면 자동 만료가 없는 "영구 잠금"으로 올리고**, 사람이 풀 때까지(이메일 인증 또는 관리자 해제) 유지합니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 흐름도**: [16-permanent-lock.html](16-permanent-lock.html)
> 📚 **계층**: Layer 5-A. 확장 기능 — Layer 3(대응)이 "5분 잠금"에서 한 단계 더 나아간 것

---

## 🏢 비유로 먼저 이해하기

| 현실 | 이 프로젝트 |
|---|---|
| 소란을 피우면 **오늘 하루 출입 정지** | 5분 임시 잠금 |
| 한 달 안에 **두 번째**면 **출입 금지 명단 등재** | 30일 안 2번째 잠금 → 영구 잠금 |
| 명단 해제는 **심사(본인 인증 / 관리자 서명)** 후에만 | 이메일 복구(17단원) / 관리자 "영구 해제" |
| 출입 기록을 **지우지 않고 계속 적어 둠** | `lock_history` (추가만 하는 표) |

---

## 🚨 영구 잠금이 걸리는 경우

| 번호 | 조건 | 결과 |
|---|---|---|
| T1 | 같은 **IP**가 30일 안 **2번째** 임시 잠금 | IP 영구 잠금 (회원 로그인끼리 / 관리자 로그인끼리 따로 셈) |
| T2 | 같은 **계정**이 30일 안 2번째 임시 잠금 | 계정 영구 잠금 (**가입된 아이디만**) |
| T3 | SIEM 사건이 **CRITICAL** | **즉시** 영구 잠금 |
| T4 | SIEM 사건이 **HIGH** | **관리자 승인 대기** (11단원의 승인 표 재사용) |
| T5 | 관리자 로그인 잠금이 반복 | 관리자만 풀 수 있는 영구 잠금 |
| 수동 | 관리자가 직접 승격 | 관리자만 풀 수 있음 |

<aside>
🛡️ **절대 영구 잠그지 않는 것**
허용 목록 IP(`PERMANENT_LOCK_IP_ALLOWLIST`, 관리자 PC 등)는 **절대** 영구 잠금하지 않습니다. 관리자 본인을 가두는 자충수를 막기 위해서입니다. 또 **가입되지 않은 아이디**는 영구 잠금하지 않습니다. 공격자가 아무 아이디나 넣어 영구 잠금 행을 무한히 만드는 것을 막기 위해서입니다.
</aside>

---

## 🔄 승격되는 순서

| 순서 | 동작 | 쉬운 설명 |
|:-:|---|---|
| ① | 임시 잠금 직후 **이력 한 줄 추가** | `lock_history`에 기록 (고치거나 지우지 않음) |
| ② | **최근 30일 안에 몇 번째?** | 이력에서 셈 |
| ③ | 기준(2회) 이상이면 **승격** | 허용 목록 IP면 중단 |
| ④ | 같은 줄을 **조건부로 영구로 변경** | 동시에 두 요청이 와도 **한 번만** 바뀜 |
| ⑤ | PERMANENT 이력 + `PERMANENT_LOCK`(CRITICAL) 이벤트 + Slack 알림 | 알림은 **한 번만** |

<aside>
📒 **왜 횟수를 `lock_history`에서 셀까요?**
`lockouts` 표는 같은 IP를 **덮어쓰기(upsert)** 하기 때문에 "몇 번째 잠금인지" 알 수 없습니다. 그래서 **추가만 하는(append-only) 이력 표**에서 셉니다.
</aside>

<aside>
🔁 **재귀 방지**
`PERMANENT_LOCK` 이벤트는 사건에 기록은 되지만, **다시 승격을 부르지 않습니다.** (승격이 승격을 부르는 무한 루프 방지)
</aside>

### 이메일 복구 직후 "보호관찰"
이메일 복구로 계정 잠금을 푼 뒤 **24시간 안에 다시 잠기면**, 본인 인증 수단(메일함)이 공격자에게 넘어갔을 수 있다고 보고 **횟수와 무관하게 관리자 전용 영구 잠금**으로 올립니다.

---

## 🔒 영구 잠금이 걸린 뒤

| 동작 | 결과 |
|---|---|
| 로그인 | 영구 잠긴 IP·계정은 차단 + **복구 링크** 표시 (예외를 받은 "본인+본인 기기"만 통과) |
| **회원가입** | 영구 잠긴 IP는 **가입도 차단** (새 계정을 만들어 예외를 받아내는 우회로 차단) |
| 임시 해제 버튼 | **못 풂** — "영구 해제"로만 가능 (409) |
| **영구 해제** | **super_admin만**, **사유 필수**. 누가·언제·왜 풀었는지 `lock_history`에 기록 |

<aside>
🔎 **영구 잠금이 "안 잠김"으로 보이지 않게**
영구 잠금은 풀릴 시각(`unlock_at`)이 **비어 있습니다.** 예전처럼 "풀릴 시각이 미래인가"만 보면 안 잠긴 것으로 판정되므로, 조회 쿼리가 **영구 잠금을 따로 포함**시킵니다.
</aside>

---

## 🧩 왜 `security/lockdown.py`를 따로 뒀나요?

`security/soar/`(집행)가 이미 `security/correlate.py`(상관분석)를 가져다 씁니다. 그런데 상관분석도 승격을 해야 하는데 `soar`를 가져오면 **서로가 서로를 가져오는 순환**이 생깁니다. 그래서 승격·해제 로직을 `lockdown.py`에 모으고 **둘 다 이 파일만** 가져다 씁니다.

---

## 📍 코드는 어디에 있나요?

| 하는 일 | 파일 | 함수 |
|---|---|---|
| 임시 잠금 직후 이력·승격 판단 | `security/lockdown.py` | `after_temporary_lock()` |
| IP·계정 승격 | `security/lockdown.py` | `promote_ip()`, `promote_account()` |
| 사건 기반 승격 | `security/lockdown.py` | `consider_incident_promotion()` |
| 영구 해제 | `security/lockdown.py` | `release()` |
| 이력 추가·집계 | `db/lock_history.py` | `insert_lock_history()`, `count_lock_history()` |
| 조건부 승격 | `db/lockouts.py`, `db/account_lockouts.py` | `promote_lockout_permanent()` 등 |
| 관리자 승격·해제 API | `routes/admin/locks.py` | `api_permanent_locks_promote()`, `api_permanent_locks_release()` |
| 설정 | `config.py` | `PERMANENT_LOCK_STRIKE_COUNT`, `PERMANENT_LOCK_STRIKE_WINDOW_DAYS` 등 |

---

## 🧪 예시로 보기

같은 IP `112.150.15.124`가 60초 안에 6번 실패 → 임시 잠금 #1(`lock_history` 1줄) → 잠금이 풀린 뒤 또 6번 실패 → 임시 잠금 #2 → 최근 30일 2회
→ `lockouts`가 `lock_type=PERMANENT`, `unlock_at=NULL`, `recoverable=EXEMPTION`, `permanent_reason=REPEAT_OFFENDER`로 바뀌고 `security_events`에 `PERMANENT_LOCK`(CRITICAL)이 기록됩니다.

## 🖥️ 직접 해보기

- [ ] `.env`에 `TRUST_FORWARDED_FOR=true` 설정 후 `bruteforce_sim.py --ip 1.2.3.4`로 가짜 IP를 6회 실패시킨다
- [ ] `python scripts/management/unlock_ip.py --ip 1.2.3.4`로 임시 잠금만 해제한 뒤 다시 실패시킨다 → 영구 잠금으로 승격되는지 확인
- [ ] 관리자 대시보드 "영구 잠금" 카드에 **"영구"** 배지가 뜨고, **super_admin에게만** "영구 해제"가 보이는지 확인
- [ ] 해제는 사유를 적어야만 진행되는지 확인 (터미널: `python scripts/management/unlock_ip.py --ip 1.2.3.4 --permanent --note "사유"`)

---

## 📖 용어 사전

<details>
<summary><b>승격(promotion)</b></summary>

이미 있는 임시 잠금을 **같은 줄에서** 영구 잠금으로 올리는 것입니다.
</details>

<details>
<summary><b>append-only 표</b></summary>

줄을 고치거나 지우지 않고 **추가만** 하는 표입니다(`lock_history`). 과거 횟수를 셀 수 있습니다.
</details>

<details>
<summary><b>조건부 UPDATE</b></summary>

`WHERE lock_type='TEMPORARY'`처럼 조건을 걸어, 동시에 두 요청이 와도 **한 번만** 바뀌게 하는 방법입니다.
</details>

## ⚠️ 알아둘 한계

- 영구 잠금은 **새 로그인만** 막고, 이미 로그인된 세션은 끊지 않습니다.
- `TRUST_FORWARDED_FOR=true`에서는 헤더로 임의 IP를 잠글 수 있어 **로컬 시연 전용**입니다.

---

⬅️ 이전: 15. L7 공격 방어 보강 · ➡️ 다음: 17. 이메일 인증 복구
