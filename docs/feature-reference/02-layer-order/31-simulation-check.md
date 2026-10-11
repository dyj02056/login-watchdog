# 31. 시뮬레이션 일괄 점검

<aside>
🎯 **한 줄 요약**
탐지 기능을 고칠 때마다 "다른 공격은 아직 잡히는가?"를 공격 시뮬레이터 20여 개로 **손수 확인하기는 어렵습니다.** 그래서 **한 번에 전부 돌려서** "기대한 이벤트가 기록됐는지" 자동으로 **PASS/FAIL**을 알려주는 점검기를 만들었습니다. 추가로 **7일치 샘플 로그**를 만드는 도구도 있습니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 흐름도**: [31-simulation-check.html](31-simulation-check.html)
> 📚 **계층**: Layer 5-C. 확장 기능 — **앱 밖 터미널 도구**(`scripts/`). 서버 코드는 바뀌지 않습니다

---

## 🏢 비유로 먼저 이해하기

| 현실 | 이 프로젝트 |
|---|---|
| 소방 훈련: **가짜 불**을 내서 **경보가 울리는지** 확인 | 공격 시뮬레이터로 가짜 공격 → 탐지 이벤트 확인 |
| 훈련은 **실제 건물이 아닌 모형**에서 | **메모리 DB**(진짜 Supabase·Slack·메일 접속 없음) |
| 훈련 결과표 **합격/불합격** | `PASS` / `FAIL` |

---

## 🧪 1) 시뮬레이션 일괄 점검 — `check_simulations.py`

```bash
python scripts/demo/check_simulations.py              # 전부
python scripts/demo/check_simulations.py honeypot     # 이름에 honeypot이 들어간 것만
```
> `python app.py`로 띄운 개발 서버가 5000번을 쓰고 있으면 **먼저 끕니다.**

| 순서 | 동작 | 쉬운 설명 |
|:-:|---|---|
| ① | **환경을 고정** | `.env` 값을 무시하고 진짜 DB·Slack·메일·Groq에 접속하지 않게 덮어씀. 임시 잠금 3초, 복구 대기 0초 |
| ② | **진짜 DB 대신 메모리 DB**를 끼움 | 앱 코드는 하나도 안 바꾸고 점검 |
| ③ | 시뮬레이션을 **하나씩 실행** | 사례마다 기록·잠금·요청 한도를 초기화한 뒤 별도 프로세스로 실행 |
| ④ | **기대한 이벤트가 기록됐는지** 대조 | ① 종료 코드 0 **그리고** ② 기대한 `(event_type, severity)` 가 기록됨 → 둘 다 맞아야 PASS |
| ⑤ | **PASS / FAIL** 출력 | 실패하면 누락된 이벤트와 시뮬레이션 출력 끝 15줄도 보여줌 |

### 결과 예시
```
[PASS] critical  critical/bruteforce_sim.py  종료코드=0  1.2s
...
합계: N PASS / M FAIL / 총 K건
```

### 대조하는 기대 이벤트 (일부)

| 시뮬레이터 | 기대 이벤트 |
|---|---|
| `critical/bruteforce_sim.py` | `BRUTE_FORCE` (CRITICAL) |
| `critical/incident_correlation_sim.py` | `WEB_SCANNING`·`UNAUTHORIZED_ACCESS`(MEDIUM) → `BRUTE_FORCE`·`PERMANENT_LOCK`(CRITICAL) |
| `high/http_flood_sim.py` | `HTTP_FLOOD` (HIGH) |
| `medium/honeypot_bot_sim.py` | `BOT_DETECTED` (MEDIUM) |

<aside>
🧠 **메모리 DB(`memory_supabase.py`)란?**
`db` 패키지가 쓰는 쿼리 체인(`.table().select().eq()...`)을 **흉내 내는 가짜 DB**입니다. insert한 행을 **실제로 기억하고** 조건으로 걸러 세기 때문에 "5번 틀리면 잠금" 같은 탐지가 **진짜처럼** 동작합니다.
</aside>

---

## 📅 2) 7일치 샘플 로그 — `generate_demo_logs.py`

시연·스크린샷용 기록을 **서버가 직접 만들게** 하는 도구입니다.

| 순서 | 동작 |
|:-:|---|
| ① | **실행 계획**을 세운다 — 가짜 회원 가입·정상 접속·공격 시뮬레이션을 지난 7일 안의 시각에 배정. 마지막에 "방금 일어난 공격"(진행 중 사건·활성 잠금·승인 대기)을 둠 |
| ② | 가짜 회원 12명을 **실제 `/signup`** 으로 가입 — 실제 방어 코드를 그대로 통과 |
| ③ | 공격 시뮬레이션 21종을 실행 (`X-Forwarded-For`로 가짜 공격자 IP 흉내) |
| ④ | 묶음이 끝날 때마다 **기록 시각을 배정한 시각으로 옮기고**, IP를 **17개국의 실제 할당 대역 IP**로 바꿈 |
| ⑤ | **일별 요약표·관리자 처리 이력·복구 기록**을 채움 |
| ⑥ | `scripts/demo/output/demo_logs.json`에 **저장** |

그리고 **`demo_server.py`** 가 그 JSON을 메모리 DB에 올려 대시보드를 띄웁니다(열 때마다 시각을 "지금" 기준으로 옮겨 항상 최근 7일처럼 보임).

- **AI 조기경보**: 기본은 로컬 판정기, `--use-groq`를 주면 진짜 Groq API로 판정합니다(`GROQ_API_KEY` 필요, 샘플 데이터가 Groq로 전송됨).
- **실제 DB에 넣기(선택)**: `load_demo_to_supabase.py` — 기본은 미리보기, `--apply`로 적재, `--purge`로 **넣은 행만** 삭제. 회원 비밀번호는 **로그인 불가 값**으로 넣고, 관리자 계정·메일 토큰은 넣지 않습니다.

---

## 📍 코드는 어디에 있나요?

| 하는 일 | 파일 |
|---|---|
| 일괄 점검 | `scripts/demo/check_simulations.py` |
| 메모리 가짜 DB | `scripts/demo/memory_supabase.py` |
| 시뮬레이터 (위험등급별) | `scripts/simulation/critical/`, `high/`, `medium/` + `_sim_common.py` |
| 샘플 로그 생성 | `scripts/demo/generate_demo_logs.py` |
| 데모 서버 | `scripts/demo/demo_server.py` |
| 나라별 IP 대역·시각 이동 | `scripts/demo/demo_data.py` |
| (선택) 실제 DB 적재 | `scripts/demo/load_demo_to_supabase.py` |

> 운영 도구는 `scripts/management/`, 데모·점검은 `scripts/demo/`로 나뉘어 있습니다.

---

## 📖 용어 사전

<details>
<summary><b>시뮬레이션(Simulation)</b></summary>

실제 공격자가 아니라 **우리가 만든 가짜 공격 프로그램**으로 공격 상황을 흉내 내는 것입니다.
</details>

<details>
<summary><b>PASS / FAIL</b></summary>

기대한 결과가 나오면 PASS, 아니면 FAIL입니다. 이 점검기는 "종료 코드 0 + 기대 이벤트 기록"을 모두 만족해야 PASS입니다.
</details>

## ⚠️ 알아둘 한계

- **메모리 DB는 `db` 패키지가 실제로 쓰는 연산만** 흉내 냅니다. 운영 DB 고유의 동작(`pg_cron`, 제약 조건 등)은 검증하지 못합니다.
- 가짜 공격자 IP는 서버가 `TRUST_FORWARDED_FOR=true`일 때만 반영됩니다(점검기는 이 값을 켠 채로 서버를 띄웁니다).
- 샘플 로그의 IP 대역은 **직접 고른 값**이라 외부 위치 조회와 도시가 다를 수 있고, 이메일 복구 요청·IP 예외는 **직접 만든 행**입니다.

---

⬅️ 이전: 30. Next.js 관제 화면과 집계 API · ➡️ 다음: 32. 부록 (Layer 6)
