# 6. 공격 유형별 탐지 매트릭스

<aside>
🎯 **한 줄 요약**
브루트포스처럼 "잠글 대상"이 있는 공격이 있는가 하면, **잠글 대상이 없거나 잠그면 오히려 위험한** 이상 행위도 있습니다. 이런 것들은 **"기록 + 알림"까지만** 자동화합니다. 이 단원은 그 "관찰형 탐지"를 한곳에 모은 지도입니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 흐름도**: [06-detection-matrix.html](06-detection-matrix.html)
> 📚 **계층**: Layer 2. 탐지

---

## 🏢 비유로 먼저 이해하기

| 현실 | 이 프로젝트 |
|---|---|
| 건물 주변을 계속 서성이는 사람 (아직 범죄는 아님) | 404 반복 (Web Scanning) |
| 출입증 없이 직원 전용문을 계속 두드림 | 미인증 관리자 API 접근 |
| 같은 문만 수십 번 여닫음 | 반복 페이지 접근 |
| 게시판에 같은 글을 도배 | 가입·글·댓글 도배 |

<aside>
👀 **관찰형 탐지란?** 실제로 막지는 않고 "누가 이상하다"를 **기록하고 관리자에게 알리는** 데까지만 자동화하는 방식입니다. 잠글 명확한 대상이 없거나, 잠그면 정상 사용자가 피해를 볼 위험이 있을 때 씁니다.
</aside>

---

## 🗺️ 한눈에 보는 매트릭스

| 위험등급 | 공격 유형 | 판정 함수 | 호출되는 곳 | 조치 |
|---|---|---|---|---|
| 🟡 MEDIUM | **Web Scanning** (404 반복) | `is_web_scanning` | 404 처리기 (`helpers/hooks.py`) | 잠금 없음, 알림 + 기록 |
| 🟡 MEDIUM | **Unauthorized Access** (세션 없이 관리자 API 반복) | `is_unauthorized_access_suspicious` | 관리자 문지기 (`helpers/auth.py`) | 잠금 없음, 알림 + 기록 |
| 🟢 LOW | **반복 페이지 접근** (같은 경로 20회 초과) | `is_page_access_suspicious` | 요청 훅 `track_page_access` | 잠금 없음, 알림 + 기록 |
| 🟢 LOW | **글쓰기 도배** (60초 5회) | `is_post_rate_limited` | `routes/board.py` | **요청 거부** (HIGH 기록) |
| 🟢 LOW | **댓글 도배** (60초 10회) | `is_comment_rate_limited` | `routes/board.py` | **요청 거부** (HIGH 기록) |
| 🟢 LOW | **가입 도배** (60초 5회) | `is_signup_rate_limited` | `routes/auth.py` | **요청 거부** (HIGH 기록) |

<aside>
📝 **등급 표기 주의**
README에서는 "관리자 API 반복 접근"을 위험도가 높은 것으로 표현하는 경우가 있지만, **실제 코드가 기록하는 등급은 MEDIUM**입니다. 문서와 코드를 대조할 때 코드가 기준입니다.
</aside>

> 🔗 Password Spraying은 5단원에서 이미 다뤘습니다(같은 코드, 아이디 개수로만 구분). 게시글 번호를 순차 조회하는 스크래핑은 탐지 코드가 없는 **의도된 사각지대**입니다(32단원).

---

## 🔍 유형별 동작

### 1) Web Scanning — 없는 주소를 계속 두드림

1. 404가 나면 **먼저 기록**합니다 (화면과 상관없이 항상).
2. 최근 60초 404가 **10회 초과**이고 **정확히 11번째**일 때만 알립니다.
3. Slack 알림 + MEDIUM 이벤트 기록 (**잠그지 않음**).
4. 기준치 코앞(8~10회)이면 AI 조기 경보를 검토합니다 (11단원).

<aside>
🔕 **"지금 막 넘긴 순간"에만 알리는 이유**
만약 이 구분이 없으면, 임계값을 넘은 뒤 계속되는 요청마다 Slack 알림이 반복 발송됩니다. 그래서 판정 함수는 `(수상한가, 횟수, 지금 막 넘겼나)` 세 값을 돌려주고, **세 번째가 True인 순간에만** 알립니다.
</aside>

### 2) Unauthorized Access — 로그인 없이 관리자 API 반복

- **세션이 있는데 무효**(만료·삭제)한 관리자 → 공격이 아니라 "다시 로그인할 사람"이므로 **기록하지 않습니다.** (기록하면 그 관리자의 대시보드 자동 폴링이 공격으로 오탐됩니다.)
- **세션이 아예 없음** → 기록하고, 10회 초과 + 막 넘긴 순간에 알림.
- 일부러 **잠그지 않습니다.** 대시보드가 세션 만료 직후에도 자동 폴링을 보내므로, 잠가버리면 관리자 본인이 재로그인도 못 하는 자충수가 됩니다.

### 3) 반복 페이지 접근 — 같은 페이지만 계속 요청

- GET 요청만, 존재하는 경로만, 정적 파일·자동 폴링 API는 **제외**하고 관찰합니다. (안 빼면 정상 사용자가 항상 "수상"으로 잡힙니다.)
- 이 IP가 **이 경로**를 20회 초과 요청한 순간 알림.

### 4) 도배 — 가입 · 글 · 댓글

- 기준치에 **도달하면** 곧바로 요청을 거부하고 **HIGH**로 기록합니다(Slack 알림은 없음).
- 이미 열린 이벤트가 있으면 새 행을 만들지 않고 **횟수만 1 올립니다.** 봇 한 대가 이벤트 표를 도배하지 못하게 하기 위해서입니다.

---

## 📍 코드는 어디에 있나요?

| 하는 일 | 파일 | 함수 |
|---|---|---|
| 판정 6종 | `security/detector.py` | `is_web_scanning()`, `is_unauthorized_access_suspicious()`, `is_page_access_suspicious()`, `is_post_rate_limited()`, `is_comment_rate_limited()`, `is_signup_rate_limited()` |
| 404 처리 | `helpers/hooks.py` | `handle_not_found()` |
| 반복 접근 관찰 | `helpers/hooks.py` | `track_page_access()` |
| 미인증 접근 | `helpers/auth.py` | `_reject_admin_request()` |
| 알림 + 기록 | `security/soar/observe.py` | `notify_web_scanning()`, `notify_unauthorized_access()`, `notify_page_access()` |
| 도배 거부 기록 | `security/soar/observe.py` | `record_rejection()` |
| 기록·집계 | `db/access_logs.py` | `log_not_found_attempt()`, `count_recent_not_found_attempts()` 등 |

---

## 🧪 예시로 보기

같은 IP가 60초 안에 `/no-such-page-1` ~ `/no-such-page-11`을 요청하면
→ **11번째 요청 순간** MEDIUM(`WEB_SCANNING`) 이벤트 1건 + Slack 알림 1회.
→ 12번째 이후 요청은 계속 404를 받지만 **추가 알림은 없습니다.**

## 🖥️ 직접 해보기

```bash
for i in $(seq 1 11); do curl -s -o /dev/null http://127.0.0.1:5000/no-such-page-$i; done
```

- [ ] 11번째 요청 직후 콘솔(또는 Slack)에 MEDIUM 알림이 뜨는지 확인
- [ ] `/admin/dashboard`의 보안 이벤트 표에서도 확인

---

## 📖 용어 사전

<details>
<summary><b>Web Scanning</b></summary>

숨어 있는 관리자 페이지·설정 파일을 찾으려고 수많은 주소를 차례로 요청해 보는 행위입니다. 대부분 "없음(404)"이 돌아오기 때문에 404 횟수로 탐지합니다.
</details>

<details>
<summary><b>훅(hook)</b></summary>

"이 시점이 되면 이 함수를 자동으로 실행해 줘"라고 걸어 두는 장치입니다. 이 프로젝트는 404가 났을 때, 그리고 모든 요청의 화면 함수 실행 직전에 관찰 함수를 걸어 둡니다.
</details>

## ⚠️ 알아둘 한계

- 게시글 번호를 순서대로 조회하는 **Automated Scraping**은 게시판이 "회원 전체 공개" 설계라서 의도적으로 막지 않습니다(README "알려진 제한사항").

---

⬅️ 이전: 5. 브루트포스 탐지 + 자동 IP 잠금 · ➡️ 다음: 7. API 엔드포인트 매크로/봇 탐지
