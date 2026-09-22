# 25단계 — 팀원 브랜치 병합 정리 및 `daily_report.py` AI 보안 총평(Gemini) 연동

[◀ 24단계](guide24_l7_attack_hardening.md) · [전체 목차](beginner-guide.md)

> 팀원별로 나뉘어 있던 로컬 브랜치(`main`, `seunghoon`, `yoojieun`)를 순서대로 검토하고 병합했습니다. 병합 과정에서 각 브랜치의 신규 스크립트에 비전공자용 설명 주석을 보강했고, `yoojieun` 브랜치에서 시도했던 "AI 보안 총평" 기능이 실제로는 크래시가 나거나 미완성 상태였던 것을 발견해 직접 고친 뒤 Google Gemini API와 실제로 연동했습니다.

---

## 1. `scripts/jh` 폴더 정리 (main)

`scripts/jh/` 하위에 있던 공격 시뮬레이션 스크립트 3개를 `scripts/` 바로 아래로 옮기고, 빈 폴더가 된 `jh`는 삭제했습니다.

- [scripts/web_scanning_sim.py](../../scripts/web_scanning_sim.py) — 로그인 없이 존재하지 않는 경로(`/admin.php`, `/.env` 등)로 GET 11회를 보내 Web Scanning 탐지를 재현
- [scripts/unauthorized_access_sim.py](../../scripts/unauthorized_access_sim.py) — 로그인 세션 없는 새 `requests.Session()`으로 `/api/status`에 GET 11회를 보내 Unauthorized Access 탐지를 재현
- [scripts/password_spraying_sim.py](../../scripts/password_spraying_sim.py) — `/login`에 매번 다른 아이디로 틀린 비밀번호를 6회 제출(IP·세션은 고정)해 Password Spraying 탐지를 재현

세 파일 모두 "이 공격이 왜 이렇게 동작하는지", "왜 이 안전장치(로컬 서버만 허용, 민감정보 가림 등)가 필요한지"를 비전공자도 이해할 수 있도록 상단 설명 블록과 함수별 주석을 대폭 보강했습니다.

## 2. `seunghoon` 브랜치 병합 — 반복 접근 / 회원가입 남용 / 게시글 스팸 시뮬레이터

`seunghoon` 브랜치에는 main에 없던 시뮬레이터 3개가 있었고, 충돌 없이 그대로 병합했습니다.

- [scripts/repeated_access_sim.py](../../scripts/repeated_access_sim.py) — 같은 IP가 같은 페이지를 21회 반복 GET(서버의 `PAGE_ACCESS_ALERT_THRESHOLD=20`을 "초과"하는 지점)
- [scripts/signup_abuse_sim.py](../../scripts/signup_abuse_sim.py) — `/signup`에 서로 다른 계정으로 POST 반복(서버의 `SIGNUP_RATE_LIMIT=5`와 연동)
- [scripts/spam_sim.py](../../scripts/spam_sim.py) — 로그인 후 `/board/new`에 게시글 작성 POST를 6회 반복(서버의 `POST_RATE_LIMIT=5`를 "초과"하는 지점)

병합 후, 각 스크립트의 기본 요청 횟수가 서버(`config.py`)의 실제 임계값과 어떻게 연결되는지("왜 하필 이 숫자인지"), CSRF 토큰이 뭔지, 성공/실패 판정 기준이 뭔지를 설명하는 주석을 추가했습니다.

## 3. `yoojieun` 브랜치 검토 — 발견한 문제와 수정

`yoojieun` 브랜치는 `daily_report.py`에 "특정 기간 조회(`--start`/`--end`)"와 "AI 보안 총평(`llm_summary`)" 기능을 추가하려던 시도였지만, 실제로 실행해보니 여러 문제가 있었습니다.

### 3-1. 크래시 버그 — `db` 패키지에 새 함수가 등록되지 않음

`db/attempts.py`에 `list_attempts_between(start_time, end_time)` 함수는 잘 구현되어 있었지만, `db/__init__.py`(각 모듈의 함수를 다시 내보내는 "전화번호부" 역할)에 이 함수 이름이 등록되지 않아, `--start`/`--end` 옵션을 쓰면 `AttributeError: module 'db' has no attribute 'list_attempts_between'`로 즉시 크래시했습니다. → [db/__init__.py](../../db/__init__.py)에 등록해서 해결.

### 3-2. 조용한 오류 — 잠금 건수가 항상 "최근 24시간" 기준으로만 나옴

특정 기간을 지정해서 조회해도 로그인 시도는 정확히 그 기간만 가져오지만, 잠금(IP 차단) 건수는 `list_lockouts_between` 함수 자체가 없어서 항상 `list_lockouts_since(24)`(최근 24시간)로 대체되고 있었습니다. 크래시가 나지 않아서 눈치채기 어려운, "그럴듯하게 보이는 틀린 결과"였습니다. → [db/lockouts.py](../../db/lockouts.py)에 `list_lockouts_between()`을 새로 구현해서 해결.

### 3-3. 입력 검증 부재

- `--start`만 넣고 `--end`를 빼먹으면 조용히 `--hours`(기본 24시간) 조회로 넘어가던 문제 → 하나만 입력되면 즉시 에러 메시지로 안내하도록 수정
- 날짜 형식이 잘못됐거나(`2026-13-99`), 시작이 종료보다 늦은 경우, `--hours`에 0 이하 값을 넣은 경우를 걸러내지 않던 문제 → 실행 전에 검증해서 이해하기 쉬운 한국어 메시지로 즉시 안내하도록 수정

### 3-4. `llm_summary`가 "받을 자리"만 있고 실제로 채워주는 코드가 없던 문제

`build_report()`는 `llm_summary` 값을 받으면 리포트에 "[AI 보안 총평 & 분석]" 섹션을 추가하도록 만들어져 있었지만, 실제로 AI를 호출해서 그 값을 채워주는 코드가 어디에도 없어 이 기능은 절대 동작할 수 없는 상태였습니다.

**Google Gemini API와 실제로 연동**했습니다. 별도 구글 SDK를 새로 설치하지 않고, 이 프로젝트가 이미 쓰는 `requests`로 Gemini의 REST API를 직접 호출하는 방식을 택했습니다.

```python
# scripts/daily_report.py
def generate_ai_summary(report_text: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    ...
    response = requests.post(GEMINI_API_URL, params={"key": api_key},
                              json={"contents": [{"parts": [{"text": prompt}]}]},
                              timeout=GEMINI_REQUEST_TIMEOUT)
```

- `--ai` 옵션을 주면 방금 만든 리포트 텍스트를 Gemini에게 보여주고, 3~5문장 분량의 한국어 보안 총평을 받아와 리포트에 덧붙입니다.
- API 키는 `.env`의 `GEMINI_API_KEY`에서만 읽고, 키가 없거나 Gemini 서버 호출이 실패해도(타임아웃, 일시적 과부하 등) 전체를 중단하지 않고 `[WARN]` 메시지만 남긴 뒤 숫자 집계 리포트는 정상적으로 보여줍니다.
- 처음 테스트 때는 모델 이름(`gemini-2.0-flash`)이 이미 단종되어 404 에러가 났고, 구글이 응답으로 알려준 대체 모델(`gemini-3.6-flash`)로 교체한 뒤 정상 동작을 확인했습니다.

### 실제로 확인한 것 (로컬 테스트)

```
$ python scripts/daily_report.py --ai
===== 로그인 워치독 보안 리포트 (최근 24시간 기준) =====
...
--------------------------------------------------
[AI 보안 총평 & 분석]
최근 24시간 동안 발생한 모든 로그인 시도는 실패했으나, 보안 시스템이 이상 징후를
즉시 감지하고 차단하여 현재 서비스는 안전하게 보호되고 있습니다. ...
--------------------------------------------------
```

`pytest tests/` 전체 232개 테스트 통과(이 세션에서 병합·수정한 내용을 모두 포함한 `main` 브랜치 기준). AI가 실제로 리포트 데이터를 근거로("반복 실패했지만 자동 차단됨", "출처가 내부 IP라 테스트일 가능성도 있음") 맥락 있는 요약을 만들어주는 것을 확인했습니다.

## 4. 세 브랜치를 `main`에 순서대로 병합

로컬 `main` → `seunghoon` → `yoojieun` 순서로 병합했습니다. `git merge-tree`로 사전에 충돌 가능성을 시뮬레이션해본 결과 세 병합 모두 겹치는 수정이 없어 충돌 없이 자동 병합됐고, 병합 후에도 전체 테스트가 통과하는 것을 확인했습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- [scripts/web_scanning_sim.py](../../scripts/web_scanning_sim.py), [scripts/unauthorized_access_sim.py](../../scripts/unauthorized_access_sim.py), [scripts/password_spraying_sim.py](../../scripts/password_spraying_sim.py) (jh 폴더에서 이동 + 주석 보강)
- [scripts/repeated_access_sim.py](../../scripts/repeated_access_sim.py), [scripts/signup_abuse_sim.py](../../scripts/signup_abuse_sim.py), [scripts/spam_sim.py](../../scripts/spam_sim.py) (seunghoon 병합 + 주석 보강)
- [db/__init__.py](../../db/__init__.py) (`list_attempts_between`/`list_lockouts_between` 등록 누락 수정)
- [db/lockouts.py](../../db/lockouts.py) (`list_lockouts_between` 신규 구현)
- [scripts/daily_report.py](../../scripts/daily_report.py) (입력 검증 추가, Gemini AI 연동, 주석 보강)
- [.env.example](../../.env.example) (`GEMINI_API_KEY` 항목 추가)

---

## 다음 단계 후보

- `--ai` 옵션을 CI/정기 실행에 자동으로 포함시킬지, 수동 실행 전용으로 남길지 결정 필요
- `daily_report.py`의 `--output` 저장 결과를 발표 자료/보고서에 실제로 활용하는 흐름 정리
