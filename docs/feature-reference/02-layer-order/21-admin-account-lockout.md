# 21. 관리자 계정 단위 잠금

<aside>
🎯 **한 줄 요약**
관리자 로그인은 IP 단위로만 잠겼습니다. **IP 100개로 나눠 IP당 4회씩** 시도하면 어느 IP도 기준을 넘지 않아 관리자 계정은 사실상 **무제한 시도**를 당할 수 있었습니다. 회원 로그인에 있던 **계정 단위 잠금**을 관리자에게도 적용했습니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 흐름도**: [21-admin-account-lockout.html](21-admin-account-lockout.html)
> 📚 **계층**: Layer 5-B. 확장 기능 — Layer 1(화면)·2(탐지)·3(대응)·4(관리)에 걸쳐 있음

---

## 🏢 비유로 먼저 이해하기

| 현실 | 이 프로젝트 |
|---|---|
| 금고에 **여러 사람이 번갈아** 번호를 대입 | IP를 나눠 쓴 분산 브루트포스 |
| 사람이 아니라 **금고 자체를 잠가버림** | 관리자 **계정** 단위 잠금 |
| 금고 주인(관리자)은 **사무실 PC에서는 항상 열 수 있게** | 허용 목록 IP는 계정 잠금을 건너뜀 |

---

## 📏 기준 — 회원과 다른 점

| 항목 | 회원 계정 (5단원) | 관리자 계정 (21단원) |
|---|---|---|
| 집계 창 | 60초 | **15분** (분당 몇 회씩 천천히 시도하는 공격도 잡으려고) |
| 임계값 | 8회 **초과** | 8회 **초과** |
| 잠금 표 | `account_lockouts` | **`admin_account_lockouts`** (분리) |
| 영구 잠금 | 승격 가능 | **승격 안 함** |
| 즉시 해제 권한 | `unlock_ip` | **`unlock_admin_account`** (super_admin만) |

<aside>
🧩 **표를 분리한 이유**
회원 `alice`와 관리자 `alice`가 **서로 영향을 주지 않게** 하기 위해서입니다.
</aside>

<aside>
🚫 **관리자는 왜 영구 잠금으로 올리지 않을까요?**
**관리자를 영구히 못 들어오게 만드는 것 자체가 공격자가 원하는 결과**(서비스 거부)이기 때문입니다. 감사 추적을 위해 잠금 이력만 한 줄 남깁니다.
</aside>

---

## 🔄 잠기는 순서

| 순서 | 동작 | 쉬운 설명 |
|:-:|---|---|
| ① | 이미 잠긴 관리자 아이디면 **비밀번호 확인 없이 거절** | **허용 목록 IP는 건너뜀** |
| ② | 비밀번호 확인 + **관리자 로그인 기록** | 성공이든 실패든 기록 |
| ③ | **IP 기준** 판정이 먼저 | 넘으면 IP 잠금 (`lockouts` 표 공유 → `/login`에서도 함께 잠김) |
| ④ | 아니면 **아이디 기준** 판정 (IP와 무관) | 15분 안에 8회 초과 |
| ⑤ | **5분 잠금 + CRITICAL 알림** | `ADMIN_DISTRIBUTED_BRUTE_FORCE` 이벤트 + 잠금 이력 1줄 |
| ⑥ | 같은 문구로 거절 | 아이디가 **실제로 없어도 똑같이** 잠그고 같은 문구로 거절 |

<aside>
🛡️ **허용 목록 IP는 왜 계정 잠금을 건너뛰나요?**
공격자가 **일부러 틀려서 관리자를 쫓아내는** 일을 막기 위해서입니다. 관리자 PC에서는 로그인해 대시보드에서 잠금을 풀 수 있어야 합니다. (IP 잠금은 그대로 적용됩니다.)
</aside>

---

## 📍 코드는 어디에 있나요?

| 하는 일 | 파일 | 함수 |
|---|---|---|
| 로그인 흐름 지휘 | `routes/admin/login.py` | `admin_login_submit()` |
| 아이디 기준 판정 | `security/detector.py` | `is_admin_account_suspicious()`, `is_admin_account_locked()` |
| 계정 잠금 집행 | `security/soar/lockouts.py` | `enforce_admin_account_lockout()` |
| 잠금 저장·조회 | `db/admin_lockouts.py` | `create_admin_account_lockout()`, `get_active_admin_account_lockout()` 등 |
| 실패 세기 | `db/admin_lockouts.py` | `count_recent_admin_failures_by_username()` |
| 즉시 해제 API | `routes/admin/locks.py` | `api_unlock_admin_account()` |
| 설정 | `config.py` | `ADMIN_ACCOUNT_FAILURE_THRESHOLD`, `ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS` |

---

## 🧪 예시로 보기

| 시도 | IP 잠금 | 관리자 계정 잠금 |
|---|---|---|
| IP 3개에서 IP당 4회(총 12회) | 걸리지 않음 (IP당 5회 이하) | **9번째 실패에서 잠김** |

## 🖥️ 직접 해보기

`.env`에 `TRUST_FORWARDED_FOR=true`를 켜고 IP를 바꿔가며 IP당 4회씩 보냅니다.
```bash
python scripts/simulation/critical/bruteforce_sim.py --admin --username demo_admin --attempts 4 --ip 203.0.113.21
python scripts/simulation/critical/bruteforce_sim.py --admin --username demo_admin --attempts 4 --ip 203.0.113.22
python scripts/simulation/critical/bruteforce_sim.py --admin --username demo_admin --attempts 4 --ip 203.0.113.23
```

- [ ] 대시보드 "현재 잠긴 IP / 계정" 카드에 **관리자 계정 잠금**이 생기는지 확인
- [ ] "즉시 해제"는 **super_admin에게만** 보이는지 확인
- [ ] 터미널에서는 `python scripts/management/unlock_account.py --admin --username <아이디>`로 풀 수 있음

---

## ⚠️ 알아둘 한계

- **허용 목록 IP가 뚫리면** 그 IP에서는 IP 잠금만 남습니다. 허용 목록에는 **실제 관리자 PC만** 넣습니다.
- **5분 임시 잠금뿐**이라, 천천히 계속 시도하는 공격은 5분마다 다시 잠기며 그때마다 Slack 알림이 갑니다.
- LLM 조기 경보(11단원)는 **관리자 계정에는 아직 연결하지 않았습니다.**

---

⬅️ 이전: 20. 복구 코드 시도 제한 + 관리자 세션 검증 · ➡️ 다음: 22. 계정 존재 여부 노출 방지
