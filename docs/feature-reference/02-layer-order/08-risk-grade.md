# 8. 통합 보안 위험등급

<aside>
🎯 **한 줄 요약**
브루트포스, 웹 스캐닝, 도배 같은 **서로 다른 이상 행위를 하나의 표**에 **위험등급(CRITICAL / HIGH / MEDIUM)** 과 함께 모아, 관리자가 "오늘 뭐가 제일 심각했나"를 한눈에 보게 합니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 흐름도**: [08-risk-grade.html](08-risk-grade.html)
> 📚 **계층**: Layer 3. 대응 — "집행관" 역할 (`security/soar/`)

---

## 🏢 비유로 먼저 이해하기

| 현실 | 이 프로젝트 |
|---|---|
| 병원 응급실 **분류(트리아지)** — 빨강/주황/노랑 | 위험등급 CRITICAL / HIGH / MEDIUM |
| 각 과마다 따로 적던 접수 기록을 하나의 **통합 상황판**으로 | `security_events` 표 |
| 접수 창구가 하나 | `_record_event()` (공통 기록 지점) |

<aside>
💡 **왜 필요한가요?**
이상 행위를 각자 다른 표에 따로 기록하면, 관리자는 우선순위를 알 수 없습니다. 등급과 함께 **공통 표 하나**에 모으면 "빨간 것부터" 볼 수 있습니다.
</aside>

---

## 🚦 등급은 "얼마나 강하게 대응했나"로 정해집니다

| 등급 | 의미 | 대표 이벤트 | 처리 방법 |
|---|---|---|---|
| 🔴 **CRITICAL** | **실제로 잠갔다** | `BRUTE_FORCE`, `PASSWORD_SPRAYING`, `ADMIN_BRUTE_FORCE`, `DISTRIBUTED_BRUTE_FORCE` | **잠금이 풀리면 자동 처리** (관리자 버튼으로는 못 지움) |
| 🟠 **HIGH** | **요청을 거부했다** | `SIGNUP_RATE_LIMIT`, `POST_RATE_LIMIT`, `COMMENT_RATE_LIMIT`, `HTTP_FLOOD` | 관리자가 **"처리 완료"** 클릭 |
| 🟡 **MEDIUM** | **관찰만 했다 (알림 + 기록)** | `WEB_SCANNING`, `UNAUTHORIZED_ACCESS`, `PAGE_ACCESS`, `API_MACRO_PATTERN`, `BOT_DETECTED` | 관리자가 **"처리 완료"** 클릭 |

> LOW 등급은 이 표에 저장하지 않고 개별 시도 기록(예: `post_attempts`)만 남깁니다. 추세는 볼 수 있지만 대시보드 등급 배지로는 뜨지 않습니다.

---

## 🔄 기록되는 순서

1. **조치 함수**가 자기 등급으로 기록을 요청합니다.
   - 잠금(`enforce_*`) → CRITICAL
   - 요청 거부(`record_rejection`) → HIGH
   - 관찰 알림(`notify_*`) → MEDIUM
2. 모든 요청이 **`_record_event()` 한 곳**을 지납니다.
3. `security_events` 표에 저장하고,
4. 곧바로 **상관분석**(9단원)을 호출합니다.

<aside>
🧰 **한 곳으로 모은 이유**
새 조치 함수를 만들 때 "상관분석 호출"을 빠뜨리기 쉽습니다. 모든 조치가 같은 입구를 지나게 하면 저장과 상관분석 호출이 **항상 짝**으로 일어납니다.
</aside>

### HIGH 는 "중복 방지"가 핵심
같은 IP·같은 유형의 **미해결 이벤트가 이미 있으면 새 줄을 만들지 않고 횟수만 1 올립니다.** 그렇지 않으면 봇 한 대가 거부당할 때마다 행이 쌓여 HIGH 이벤트가 CRITICAL/MEDIUM을 화면에서 밀어내 버립니다.

---

## 🧹 "처리 완료"는 어떻게 동작하나요?

| 상황 | 동작 |
|---|---|
| HIGH · MEDIUM | 관리자가 **"처리 완료"** → 해결됨으로 표시 |
| CRITICAL | 버튼이 **아예 안 보임**. 잠금이 풀리는 순간(자동 만료·수동 해제) 함께 해결 처리 |
| CRITICAL 을 API 로 직접 지우려 하면 | **서버가 막음** (쿼리에서 CRITICAL 제외) |

<aside>
🛡️ **화면에서 버튼을 숨기는 것만으로는 부족합니다.** 개발자 도구로 API를 직접 호출하면 우회할 수 있으므로, **서버의 DB 쿼리에서도** CRITICAL을 제외해 둡니다. (IP는 아직 잠겨 있는데 사건만 "처리 완료"로 보이는 상태를 막기 위해서입니다.)
</aside>

---

## 📍 코드는 어디에 있나요?

| 하는 일 | 파일 | 함수 |
|---|---|---|
| 공통 기록 지점 | `security/soar/_events.py` | `_record_event()` |
| CRITICAL 기록 | `security/soar/lockouts.py` | `enforce_lockout()`, `enforce_account_lockout()` |
| HIGH 기록(중복 방지) | `security/soar/observe.py` | `record_rejection()` |
| MEDIUM 기록 | `security/soar/observe.py` | `notify_web_scanning()` 등 |
| 이벤트 저장·해결 | `db/security_events.py` | `insert_security_event()`, `resolve_security_event()`, `resolve_security_events_for_ip()` |
| "처리 완료" API | `routes/admin/incidents.py` | `api_security_events_resolve()` |

---

## 🧪 시현 방법

- [ ] 브루트포스를 발생시켜 CRITICAL 이벤트 생성 → 대시보드 "보안 이벤트" 표에서 **빨간 배지**, **"처리 완료" 버튼 없음** 확인
- [ ] `/signup`을 5회 초과 시도해 HIGH(`SIGNUP_RATE_LIMIT`) 생성 → "처리 완료" 클릭 시 사라지는지 확인
- [ ] 존재하지 않는 경로를 10회 초과 방문해 MEDIUM(`WEB_SCANNING`) 생성 (6단원)

---

## 📖 용어 사전

<details>
<summary><b>위험등급(Severity)</b></summary>

이벤트가 얼마나 심각한지를 나타내는 꼬리표입니다. 관리자가 한 번에 우선순위를 보기 위한 것입니다.
</details>

<details>
<summary><b>이벤트(event)와 사건(incident)</b></summary>

이벤트는 개별 이상 행위 한 건, 사건은 같은 IP의 이벤트 여러 건을 묶은 "하나의 공격 흐름"입니다. 사건은 9단원에서 다룹니다.
</details>

---

⬅️ 이전: 7. API 엔드포인트 매크로/봇 탐지 · ➡️ 다음: 9. SIEM 상관분석
