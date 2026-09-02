# 10단계 — Vercel 배포 준비 및 배포

[◀ 9단계](guide09_quota.md) · [전체 목차](beginner-guide.md) · [11단계 ▶](guide11_merge.md)


### 우리가 한 일
1. `static/` 폴더 이름을 `public/`으로 바꿈 (Vercel이 정적 파일을 찾는 규칙에 맞춤)
2. [app.py](../../app.py)의 Flask 앱 생성 코드를 한 줄 수정해서, 템플릿 코드는 전혀 안 고치고도 로컬 개발 환경과 Vercel 배포 환경이 똑같은 주소 구조를 쓰게 만듦
3. 로컬 서버(자동 테스트 + 실제 브라우저)로 화면이 안 깨지는지 확인
4. 실제 배포는 Vercel 계정 로그인이 필요해 사용자가 직접 진행 (아래 "배포 단계" 참고)

### 왜 했는가 (쉬운 설명)

**"정적 파일"과 "실행되는 코드"는 왜 다르게 취급되나?**
`app.py`는 요청이 올 때마다 파이썬이 그 내용을 실제로 **실행**해서 결과를 만들어내는 코드입니다(예: "이 아이디/비밀번호가 맞는지 데이터베이스에 물어봐라"). 반면 `auth.css`, `dashboard.js` 같은 파일은 실행되는 게 아니라 **내용 그대로 브라우저에 전달**되고, 브라우저가 스스로 해석해서 화면을 꾸미거나 동작시킵니다.

Vercel은 이 둘을 완전히 다른 방식으로 서빙합니다. `app.py`처럼 실행되는 코드는 "함수(Function)"로 등록해서 요청이 올 때마다 파이썬을 돌리고, `public/` 폴더 안의 정적 파일은 아예 파이썬을 거치지 않고 **CDN**(전 세계 여러 곳에 파일을 미리 복사해두고, 사용자와 가장 가까운 곳에서 즉시 내려주는 시스템)에서 바로 전달합니다. 정적 파일을 매번 파이썬으로 처리하면 느리고 낭비이기 때문에, "이 폴더 안의 건 그냥 파일 그대로 빨리 내려줘라"고 미리 분리해두는 것입니다. 그 "이 폴더"의 이름이 Vercel에서는 관례상 `public/`으로 정해져 있어서, 우리도 여기에 맞췄습니다.

**템플릿을 하나도 안 고치고 해결한 방법**
`static_folder="public", static_url_path=""`이라는 옵션 하나를 Flask 앱 생성 코드에 추가했습니다. 원래 Flask는 기본값으로 "static이라는 이름의 폴더를 /static/파일명이라는 주소로 서빙해라"는 규칙을 갖고 있는데, 이 옵션으로 "public이라는 이름의 폴더를 /파일명(맨 앞에 static 안 붙임)이라는 주소로 서빙해라"로 바꿔치기한 것입니다. 템플릿 안의 `url_for('static', filename='css/auth.css')` 코드는 그대로 두었는데도, 이 설정 덕분에 자동으로 `/css/auth.css`라는 Vercel 방식 주소를 만들어냅니다 — 템플릿 파일을 4개나 일일이 찾아 고치는 대신, 설정 한 줄로 전체가 한 번에 맞춰진 것입니다.

**로컬 개발과 배포 환경이 "일치"해야 하는 이유**
만약 로컬에서는 `/static/css/auth.css`로 접속하고 Vercel에서는 `/css/auth.css`로 접속해야 한다면, 로컬에서는 멀쩡하던 화면이 배포하고 나서야 CSS가 깨진 채로 발견될 수 있습니다. 이런 사고를 막으려고, 로컬 Flask 서버도 처음부터 Vercel과 똑같은 주소 구조(`/css/auth.css`)로 파일을 내려주도록 맞춰뒀습니다. 그래서 "로컬에서 잘 되면 배포해서도 잘 된다"는 확신을 가질 수 있습니다.

### 실제 코드 함께 보기

**`app.py` — Flask 앱 생성 부분**
```python
# static_folder="public", static_url_path="": 기본값이면 Flask가 "static/" 폴더를
# "/static/파일명" 주소로 서빙하는데, Vercel은 CSS/JS 같은 정적 파일을 "public/" 폴더에서
# 찾아 "/파일명" 형태의 루트 경로로 서빙하는 게 규칙이다.
# 로컬 개발 서버와 Vercel 배포본이 똑같은 주소 구조를 쓰도록, Flask도 처음부터
# "public/" 폴더를 "/파일명" 경로로 서빙하게 맞춰뒀다 — 이러면 템플릿 코드는
# 하나도 안 고쳐도 된다(url_for('static', ...)가 알아서 "/css/auth.css" 형태로 바뀜).
app = Flask(__name__, static_folder="public", static_url_path="")
```

**변경 후 실제로 확인한 것 (자동 테스트)**
```python
r = c.get('/css/auth.css')
print(r.status_code, r.content_type)   # 200 text/css; charset=utf-8

r = c.get('/static/css/auth.css')      # 예전 주소
print(r.status_code)                    # 404 (의도대로 더 이상 존재하지 않음)
```
Flask 테스트 클라이언트(진짜 브라우저 없이 요청/응답을 흉내내는 도구)로 새 주소(`/css/auth.css`)는 정상 응답하고, 예전 주소(`/static/css/auth.css`)는 사라졌는지 확인했습니다. 이어서 실제 브라우저로 `/login` 화면을 열어 스타일이 깨지지 않고 그대로인 것도 눈으로 확인했습니다. `pytest tests/`도 16개 전부 그대로 통과해서, 이번 변경이 판정 로직 쪽에는 전혀 영향을 주지 않았다는 것도 재확인했습니다.

### 배포 단계 (Vercel 계정 로그인이 필요해 직접 진행)

Vercel 배포는 사용자님의 Vercel 계정으로 GitHub 저장소를 연결해야 해서, 이 부분은 직접 진행해주셔야 합니다.

1. [vercel.com](https://vercel.com)에 GitHub 계정으로 로그인
2. **Add New... → Project** 클릭
3. **Import Git Repository**에서 `dyj02056/login-watchdog` 선택
4. Vercel이 `requirements.txt`를 보고 자동으로 "Flask 프로젝트"로 인식합니다(별도 설정 파일 없이도 인식되는 걸 "제로 설정(zero-configuration)"이라고 부릅니다)
5. **Environment Variables** 섹션에서 로컬 `.env`에 있는 값들을 그대로 하나씩 입력:
   `SUPABASE_URL`, `SUPABASE_KEY`, `SLACK_WEBHOOK_URL`, `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `TRUST_FORWARDED_FOR`
   (이 화면은 Vercel이 안전하게 암호화해서 보관하는 곳으로, `.env` 파일이 깃에 안 올라가는 것과 같은 이유로 여기서만 따로 입력합니다)
6. **Deploy** 클릭 → 몇 분 뒤 `https://프로젝트이름.vercel.app` 같은 실제 주소가 발급됩니다

### 배포 후 확인해야 할 것

- 배포된 주소로 접속해 `/login`, `/signup`, `/admin/login`이 화면 깨짐 없이 뜨는지 확인
- 관리자 로그인 → 대시보드 접근 → 최근 로그인 시도/잠금 목록이 정상 표시되는지 확인
- `TRUST_FORWARDED_FOR`는 여전히 `false`로 유지 — Vercel 뒤에서도 IP 스푸핑 위험은 그대로이므로, 이 값을 함부로 켜면 안 됨(5단계 `get_request_ip()` 설명 참고). 다만 Vercel처럼 리버스 프록시 뒤에 배포하면 `request.remote_addr`가 실제 방문자 IP가 아니라 Vercel 내부망 주소로 찍힐 수 있는데, 이 문제의 정확한 해결 방법(신뢰할 수 있는 프록시 헤더만 선택적으로 신뢰하는 방식)은 이번 단계 범위 밖이라 실제 배포 후 IP 잠금이 의도대로 동작하는지 별도로 확인이 필요합니다
- 첫 접속 시 "콜드 스타트"로 응답이 살짝 느릴 수 있음(서버리스 함수가 방금 깨어난 경우) — 이후 요청은 빨라짐

### 실제 배포 사이트로 최종 검증한 결과

`https://login-watchdog.vercel.app` 실제 주소로 4단계 스모크 테스트를 처음부터 끝까지 다시 돌려봤습니다.

1. 회원가입 → 정상
2. 60초 안에 6번 연속 틀리게 로그인 → Supabase `lockouts` 표에 실제 방문자 IP(`112.150.15.124`) 기준으로 잠금 생성 확인
3. 관리자로 로그인 후 `/api/status`를 직접 호출 → 방금 생긴 잠금이 정확히 조회됨
4. `/api/unlock`으로 즉시 해제 → 재조회 시 잠금 목록이 비어있는 것까지 확인
5. **Slack 채널에도 실제로 알림이 도착** — 시각·IP·실패 횟수·조치 내용이 테스트 데이터와 정확히 일치하는 메시지를 사용자가 직접 캡처해서 확인해줌

**걱정했던 부분이 실제로는 문제없었던 점**: 배포 전엔 "Vercel처럼 프록시 뒤에 서면 방문자의 진짜 IP 대신 Vercel 내부 주소가 찍힐 수 있다"고 우려했는데, 실제로는 `request.remote_addr`에 진짜 방문자 IP가 정상적으로 들어왔습니다. 즉 `TRUST_FORWARDED_FOR`를 계속 `false`로 둔 채로도(안전한 기본값을 유지한 채로도) IP 기반 잠금이 정확하게 동작한다는 걸 확인했습니다.

### 배포 후 발견: "/" 접속 시 404 대신 /login으로 안내

배포 후 사용자가 직접 사이트에 접속해보니, 도메인 주소만 입력했을 때(`https://login-watchdog.vercel.app/`, 경로 없이) 404 오류 화면이 떴습니다. 원래 이 프로젝트는 "/"에 아무 화면도 만들어두지 않았기 때문에(첫 화면은 `/login`), 라우트가 없는 주소로 들어오면 Flask가 자동으로 404를 보여주는 게 기본 동작입니다 — 로컬에서도 똑같이 재현되는 걸 배포 전에 미리 확인했었지만, "실제 방문자가 도메인만 치고 들어올 수 있다"는 점까지는 미리 감안하지 못했습니다.

**고친 방법**: `/` 주소에 대한 라우트를 하나 추가해서, 들어오자마자 `/login`으로 돌려보내게 했습니다.
```python
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))
```
`redirect(url_for("login"))`은 "화면을 직접 그리지 말고, 브라우저에게 '/login으로 다시 가봐'라고 알려줘라"는 뜻입니다. 브라우저는 이 안내를 받으면 자동으로 `/login`에 새 요청을 보내고, 사용자 눈에는 그냥 로그인 화면이 바로 뜨는 것처럼 보입니다. 코드 한 줄로 해결되는 문제였고, 실제로 재배포 후 도메인 주소만 입력해도 정상적으로 로그인 화면이 뜨는 것까지 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- `static/` → [public/](../../public/) 폴더 이름 변경 (내용은 그대로, 파일 3개)
- [app.py](../../app.py) (`Flask()` 생성 옵션에 `static_folder`/`static_url_path` 추가, `/` 라우트 1개 추가)
- 템플릿 파일들은 **변경 없음** (설정만으로 해결됨)
- Vercel에 실제 배포 완료: `https://login-watchdog.vercel.app`
