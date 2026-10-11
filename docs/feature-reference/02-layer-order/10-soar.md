# 10. SOAR 플레이북

<aside>
🎯 **한 줄 요약**
사건이 여러 개 쌓이는 것과 **"정말 심각한 복합 공격"** 은 다릅니다. 모든 사건에 긴급 알림을 보내면 알림 피로가 생기므로, **정말 심각할 때만 사건당 딱 한 번** 강조 알림을 보냅니다. 이 단원은 더불어 `security/soar/`(집행관) 전체 지도도 보여줍니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 흐름도**: [10-soar.html](10-soar.html)
> 📚 **계층**: Layer 3. 대응

---

## 🏢 비유로 먼저 이해하기

| 현실 | 이 프로젝트 |
|---|---|
| **비상 대응 매뉴얼** ("이런 상황이면 이렇게 한다") | `PLAYBOOKS` |
| 일반 민원은 접수만, 큰 사건은 **서장 보고** | 에스컬레이션 알림 |
| 같은 사건을 서장에게 **두 번 보고하지 않음** | `escalated` 표시 |

<aside>
💡 **SOAR란?** Security Orchestration, Automation and Response. 보안 이상 징후를 **자동으로 판단하고 대응 조치까지 실행**한다는 뜻의 업계 용어입니다. 이 프로젝트에서는 `security/soar/` 패키지가 그 역할을 합니다.
</aside>

---

## 🚨 에스컬레이션이 일어나는 순서

사건이 갱신된 직후, 아래 **세 가지 조건을 모두 통과**해야 알림이 나갑니다.

| 순서 | 조건 | 통과 못 하면 |
|:-:|---|---|
| ① | 이 사건에 **이미 알린 적이 없나?** | 건너뜀 (중복 알림 방지) |
| ② | 최고 위험등급이 **CRITICAL** 인가? (잠금까지 일어났나) | 건너뜀 |
| ③ | 서로 다른 공격 유형이 **3개 이상**인가? | 건너뜀 |
| ④ | → **플레이북 실행**: Slack 에스컬레이션 알림 | |
| ⑤ | → **"이미 알림" 표시**: 4번째·5번째 유형이 붙어도 재발송 없음 | |

<aside>
📖 **플레이북을 "목록"으로 둔 이유**
```python
PLAYBOOKS = {
    "CRITICAL_MULTI_STAGE": ["send_incident_escalation_alert"],
}
```
대응이 늘어나면 **이 목록에 이름만 추가**하면 됩니다. 함수 자체가 아니라 **이름(문자열)** 을 담아 두고 실행 순간에 찾는 이유는, 테스트에서 일부러 바꿔치기한 함수가 그대로 반영되게 하기 위해서입니다.
</aside>

### 예시
IP `1.2.3.4`가 5분 안에 `WEB_SCANNING` → `BRUTE_FORCE`(CRITICAL) → 회원가입 도배 `SIGNUP_RATE_LIMIT`까지 → 서로 다른 유형 **3개**, 그중 CRITICAL 포함 → **"복합 공격 발생" 알림 1회.**
같은 사건에 **4번째 유형**이 붙어도 재발송은 없습니다.

---

## 🗺️ 집행관(`security/soar/`) 함수 지도

호출하는 쪽은 파일 위치를 몰라도 `soar.함수()` 하나로 부릅니다. 실제 코드는 아래처럼 나뉩니다.

| 파일 | 하는 일 | 대표 함수 |
|---|---|---|
| `lockouts.py` | **잠그고·풀기** (IP · 회원 계정 · 관리자 계정) | `enforce_lockout()`, `enforce_account_lockout()`, `try_release_expired_lockouts()`, `manual_release()` |
| `observe.py` | **잠그지 않고 알림 + 기록만** | `notify_web_scanning()`, `notify_unauthorized_access()`, `notify_page_access()`, `notify_macro_pattern()`, `notify_bot_detected()`, `record_rejection()` |
| `early_warning.py` | **AI 조기 경보**와 관리자 승인·반려 (11단원) | `consider_early_warning()`, `execute_approved_request()` |
| `_events.py` | 이벤트 **공통 기록 지점** (8단원) | `_record_event()` |

<aside>
⏱️ **자동 해제는 "타이머"가 아니라 "요청이 올 때마다 확인"합니다.**
별도의 타이머 프로그램 없이, 로그인 요청이 들어올 때마다 `try_release_expired_lockouts()`가 "5분이 지난 잠금"을 찾아 풀어줍니다. 요청이 올 때마다 확인하는 방식으로 "자동 해제"를 흉내 낸 것입니다.
</aside>

---

## 📍 코드는 어디에 있나요?

| 하는 일 | 파일 | 함수 |
|---|---|---|
| 에스컬레이션 판단·실행 | `security/correlate.py` | `_maybe_escalate()`, `PLAYBOOKS` |
| 에스컬레이션 Slack 알림 | `notify/alert.py` | `send_incident_escalation_alert()` |
| "이미 알림" 표시 | `db/incidents.py` | `mark_incident_escalated()` |
| 필요한 유형 수 설정 | `config.py` | `INCIDENT_ESCALATION_MIN_EVENT_TYPES` (기본 3) |
| 집행관 모음 | `security/soar/` | (위 표 참고) |

## 🖥️ 직접 해보기

- [ ] 9단원 시현에 이어, 서로 다른 유형 3개(웹 스캐닝 + 브루트포스 + 가입 도배)를 5분 안에 재현한다
- [ ] 3번째 유형에서 에스컬레이션 알림이 별도로 뜨는지 확인한다
- [ ] 4번째 유형을 추가해도 알림이 **다시** 뜨지 않는지 확인한다

> 참고: Slack(또는 콘솔)의 에스컬레이션 메시지

---

## 📖 용어 사전

<details>
<summary><b>플레이북(Playbook)</b></summary>

"이런 상황이면 이런 대응을 한다"를 미리 정해 둔 매뉴얼입니다. 코드 안의 `PLAYBOOKS` 딕셔너리가 그 역할을 합니다.
</details>

<details>
<summary><b>에스컬레이션(Escalation)</b></summary>

문제의 심각도가 올라갔을 때 더 높은 단계(관리자의 긴급 알림)로 올려 보내는 것입니다.
</details>

## ⚠️ 알아둘 한계

- 현재 플레이북은 **"에스컬레이션 알림 전송" 하나뿐**입니다. "자동으로 더 긴 잠금을 건다" 같은 더 강한 자동 조치까지는 실행하지 않습니다.

---

⬅️ 이전: 9. SIEM 상관분석 · ➡️ 다음: 11. LLM 판단 에이전트
