# 5. 브루트포스 탐지 + 자동 IP 잠금

<aside>
🎯 **한 줄 요약**
"같은 곳에서 짧은 시간에 너무 많이 틀리면, **잠깐 문을 잠가버린다**." 비밀번호를 수백~수천 번 자동으로 넣어보는 무차별 대입(브루트포스) 공격을 이 원리로 막습니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 흐름도**: [05-bruteforce.html](05-bruteforce.html)
> 📚 **계층**: Layer 2. 탐지 — "판사" 역할 (`security/detector.py`)

---

## 🏢 비유로 먼저 이해하기

| 현실 | 이 프로젝트 |
|---|---|
| 도어락에 비밀번호를 연달아 틀리면 잠깐 먹통 | IP 5분 잠금 |
| 판사 (유죄인지 **판단만** 함) | `security/detector.py` |
| 집행관 (판결대로 **실제로 집행**) | `security/soar/` (Layer 3) |
| 경비실 상황판에 기록 | `login_attempts` 표 (시도 기록) |

<aside>
⚖️ **판단과 집행을 분리한 이유**
`detector.py`는 DB를 **읽기만** 하고 아무것도 바꾸지 않습니다. "기준을 바꾸고 싶다"는 수정이 훨씬 쉬워지고, 판정 로직을 테스트하기도 쉽습니다. 실제로 잠그고 알리는 일은 다음 계층이 합니다.
</aside>

---

## 📏 두 가지 기준

| 종류 | 기준 | 조치 | 막으려는 공격 |
|---|---|---|---|
| **IP 단위** | 같은 IP에서 **60초 안에 실패 5회 초과**(= 6번째 실패) | 그 IP를 **5분 잠금** | Brute Force(계정 하나 집중), Password Spraying(계정 여러 개 순회) |
| **계정 단위** | 같은 계정에 어느 IP에서든 **합쳐서 8회 초과** | **계정 자체를 잠금** | 분산 브루트포스(IP를 나눠 쓰는 공격) |

<aside>
🧩 **왜 계정 단위 기준이 따로 있나요?**
공격자가 IP를 8개로 나눠 한 계정만 노리면, IP마다 실패는 1번뿐이라 IP 기준(5회)에 **절대 안 걸립니다.** 그래서 "IP와 상관없이 이 계정이 총 몇 번 틀렸나"를 따로 세서 그 빈틈을 메웁니다. 일부러 IP 기준(5)보다 높게(8) 잡아, 정상 사용자가 여러 기기에서 몇 번 틀려도 계정이 잠기지 않게 했습니다.
</aside>

---

## 🔄 탐지가 일어나는 순서

### ① 잠금 확인 → 시도 기록
1. 이미 **잠긴 IP**인가? → 잠겨 있으면 비밀번호도 안 보고 거부
2. 이미 **잠긴 계정**인가? → 마찬가지로 거부
3. 비밀번호 확인 → **성공이든 실패든 한 줄 기록** (이 기록이 탐지의 재료)

### ② 실패했다면: IP 단위 판정 → 잠금
1. **최근 60초 안에 몇 번 틀렸나?** (판사: `is_suspicious`)
2. 5회 초과면, 이 IP가 시도한 **서로 다른 아이디 개수**를 셉니다 (1개면 Brute Force, 2개 이상이면 Password Spraying)
3. 집행관이 **5분 잠금**을 DB에 저장
4. **Slack 알림** (잠그는 순간 딱 한 번)
5. **CRITICAL 위험등급**으로 기록
6. 잠금 이력을 남기고 **영구 잠금 승격 여부** 판단 (16단원)

### ③ IP 기준으로는 아직 정상이면: 계정 단위 판정 → 계정 잠금
1. **이 계정이 합쳐서 몇 번 틀렸나?** (판사: `is_account_suspicious`)
2. 8회 초과면 **서로 다른 IP 개수**를 세고
3. 계정 잠금 저장 → Slack 알림 → CRITICAL 기록(`DISTRIBUTED_BRUTE_FORCE`)

<aside>
🔔 **알림은 "새로 잠그는 순간에만" 보냅니다.**
잠긴 상태에서 시도가 계속될 때마다 알림을 보내면 관리자가 알림 폭탄을 맞아 정작 중요한 알림을 놓칩니다(알림 피로). 그래서 "새로 잠기는 순간"에만 알립니다.
</aside>

---

## 📍 코드는 어디에 있나요?

| 하는 일 | 파일 | 함수 |
|---|---|---|
| 흐름 지휘 (확인→기록→판정→집행) | `routes/auth.py` | `login_submit()` |
| IP·계정 기준 판정 | `security/detector.py` | `is_suspicious()`, `is_account_suspicious()` |
| 잠금 여부 판단 | `security/detector.py` | `is_locked()`, `is_account_locked()` |
| 아이디·IP 종류 개수 | `security/detector.py` | `count_distinct_usernames()`, `count_distinct_ips_by_username()` |
| 잠금 집행 | `security/soar/lockouts.py` | `enforce_lockout()`, `enforce_account_lockout()` |
| 실패 횟수 세기·시도 기록 | `db/attempts.py` | `count_recent_failures()`, `log_attempt()` 등 |
| 잠금 저장·조회 | `db/lockouts.py`, `db/account_lockouts.py` | `create_lockout()`, `create_account_lockout()` 등 |
| Slack 알림 | `notify/alert.py` | `send_lockout_alert()`, `send_account_lockout_alert()` |
| 임계값 설정 | `config.py` | `FAILURE_THRESHOLD`, `DETECTION_WINDOW_SECONDS`, `LOCKOUT_DURATION_SECONDS`, `ACCOUNT_FAILURE_THRESHOLD` |

---

## 🧪 예시 (Before → After)

**IP 단위 (Brute Force)**

| 시도 순서 (같은 IP) | 결과 | 상태 |
|---|---|---|
| 1~5번째 | 비밀번호 틀림 | 아직 통과 — `5 > 5`는 거짓 |
| **6번째** | 틀림 (누적 6회) | **잠금 발동** — IP 5분 잠금 + Slack 알림 |

**계정 단위 (분산 브루트포스, IP 8개에서 나눠 시도)**

| 상황 | 결과 |
|---|---|
| IP 8개가 각 1회씩 시도 | 각 IP는 1회뿐이라 IP 잠금에 안 걸림 |
| 합계가 **8회를 초과**하는 시점 | **계정 자체가 잠김** — 어느 IP로 접속해도 이 아이디는 로그인 불가 |

Slack 알림 예시:
```
🚨 [CRITICAL] 로그인 워치독 알림
시도 IP: 127.0.0.1
실패 횟수: 6회
공격 유형: Brute Force (단일 계정 집중 시도)
조치: 5분간 IP 잠금 처리
```

## 🖥️ 직접 해보기

- [ ] `/login`에서 일부러 틀린 비밀번호로 **6번 연속** 시도 → 6번째부터 "잠긴 계정입니다"로 바뀌는지 확인
- [ ] `/admin/dashboard`에서 잠긴 IP와 CRITICAL 이벤트를 확인
- [ ] 또는 `python scripts/simulation/critical/bruteforce_sim.py` 실행 (내 컴퓨터 서버에만 동작하는 안전장치가 있고, 5회 실패 후 6번째에서 잠금 문구가 뜨는지 자동 검증)

> 참고 화면: `docs/screenshots/login.png`, `admin_dashboard.png`

---

## 📖 용어 사전

<details>
<summary><b>임계값(Threshold)</b></summary>

"여기부터는 위험하다"고 정해둔 기준 숫자입니다. 이 프로젝트에서는 `config.py`에서 한 곳에 모아 관리합니다.
</details>

<details>
<summary><b>Password Spraying</b></summary>

한 계정을 집중 공격하는 대신, 탐지를 피하려고 **여러 계정을 돌아가며** 시도하는 공격입니다. 이 프로젝트에서는 판정 코드는 브루트포스와 같고, "이 IP가 시도한 서로 다른 아이디 개수"로만 구분합니다.
</details>

<details>
<summary><b>초과 vs 이상</b></summary>

로그인 실패는 정상 사용자도 몇 번 겪을 수 있어 "초과"(6번째부터)를 기준으로 하지만, 회원가입·글쓰기 같은 요청은 반복할 이유가 거의 없어 "이상"(5번째부터)에서 바로 막습니다.
</details>

## ⚠️ 알아둘 한계

- 전용 시뮬레이션 스크립트는 현재 **IP 단위 브루트포스만** 검증합니다. Password Spraying·분산 브루트포스는 코드는 구현되어 있지만 전용 시뮬레이션은 아직 없습니다.

---

⬅️ 이전: 4. IP 위치 조회 (GeoIP) · ➡️ 다음: 6. 공격 유형별 탐지 매트릭스
