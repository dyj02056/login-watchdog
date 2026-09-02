# 15단계 — 화면 리디자인 (색상 토큰 + 자연스러운 페이지 전환)

[◀ 14단계](guide14_geoip.md) · [전체 목차](beginner-guide.md)

### 우리가 한 일
1. Claude Artifact로 새 디자인(색상·글꼴·화면 전환)을 먼저 미리보기로 만들어서 확인받음
2. [public/css/tokens.css](../../public/css/tokens.css)라는 새 파일을 만들어 색상·글꼴·전환 효과를 한 곳에 모음
3. `auth.css`/`dashboard.css`/`member.css`가 하드코딩된 색 대신 `tokens.css`의 값을 가져다 쓰도록 전부 수정
4. 템플릿 6개에 `tokens.css`를 새로 링크
5. 실제 페이지 이동이 자연스럽게 넘어가도록 `@view-transition` 규칙 추가 (새 라이브러리 없음)

### 왜 했는가 (쉬운 설명)

**코드를 짜기 전에 "미리보기"부터 만든 이유**
디자인은 "말로 설명 듣고 상상하기"보다 "직접 보고 결정하기"가 훨씬 정확합니다. 그래서 실제 프로젝트 파일을 건드리기 전에, Claude의 Artifact 기능으로 새 색상·글꼴이 적용된 화면과 전환 효과를 미리 만들어서 먼저 확인받았습니다. "마음에 든다"는 답을 받은 뒤에야 실제 코드에 반영했습니다 — 큰 폭의 디자인 변경을 코드로 먼저 만들었다가 "역시 별로다"라며 되돌리는 것보다 훨씬 안전한 순서입니다.

**왜 `tokens.css`라는 파일을 새로 만들었나**
3단계에서 "임계값·윈도우·잠금시간 같은 숫자를 `config.py` 한 곳에 모아두면, 나중에 하나만 고쳐도 전체에 반영된다"고 설명했던 것과 똑같은 원리를 색상에 적용했습니다. 예전에는 `#2563eb`(파랑) 같은 색이 `auth.css`, `dashboard.css`, `member.css` 세 파일에 흩어져 있었는데, 이러면 "포인트 색을 바꾸고 싶다"는 요청 하나에도 세 파일을 전부 찾아다니며 고쳐야 하고 하나라도 빠뜨리면 화면마다 색이 미묘하게 달라지는 사고가 납니다. 지금은 `tokens.css`의 `--accent: #0f9b8b;` 한 줄만 바꾸면 로그인·회원·관리자 화면 전체의 포인트 색이 한꺼번에 바뀝니다.

**CSS 변수(`var(--이름)`)가 정확히 뭘 하는 건가**
`tokens.css`에 `--accent: #0f9b8b;`라고 적어두면, 다른 CSS 파일에서 `background: var(--accent);`라고 쓸 때마다 그 자리에 `#0f9b8b`가 그대로 대입됩니다. 마치 코드에서 상수 하나를 여러 곳에서 재사용하는 것과 같은 개념을, CSS 안에서도 쓸 수 있게 해주는 문법입니다. 이 방식이 통하려면 `tokens.css`를 각 페이지의 실제 스타일 파일(`auth.css` 등)보다 **먼저** `<link>`로 걸어둬야 합니다 — 그래야 변수가 정의된 다음에 그 변수를 쓰는 코드가 실행되는 순서가 맞습니다. 그래서 템플릿마다 `tokens.css` 링크를 `auth.css`/`dashboard.css`/`member.css` 링크보다 한 줄 위에 추가했습니다.

**IP·시각에 왜 다른 글꼴(고정폭 글꼴)을 따로 지정했나**
`203.0.113.14`처럼 숫자가 나열되는 값은 일반 글꼴로 쓰면 숫자마다 폭이 달라서 여러 줄을 세로로 비교하기 불편합니다. "고정폭(monospace) 글꼴"은 모든 글자가 같은 너비를 차지해서, 표에서 자릿수를 눈으로 맞춰보기 쉬워집니다. 처음에는 "표의 몇 번째 칸"으로 지정하려고 했는데, 표마다(최근 로그인 시도/회원 목록/관리자 로그인 기록) 칸 순서가 달라서 잘못된 칸에 적용될 뻔했습니다 — 그래서 "몇 번째 칸인가"가 아니라 `.mono`라는 이름의 클래스를 실제 IP·시각 값을 그리는 자바스크립트·템플릿 쪽에서 직접 붙이는 방식으로 바꿨습니다. "위치에 의존하지 말고 의미에 의존하라"는, 흔히 저지르는 실수를 피하는 방법입니다.

**"화면 전환"에 자바스크립트 라이브러리를 안 쓴 이유**
페이지가 바뀔 때 자연스럽게 넘어가는 효과를 만드는 방법은 여러 가지가 있는데, 그중 일부(예: barba.js 같은 도구)는 실제 페이지 이동을 가로채서 자바스크립트로 흉내 내는 방식이라, 로그인 폼 제출(POST 요청)처럼 "진짜 페이지 이동이 필요한 동작"과 부딪힐 위험이 있습니다. 대신 이번에 쓴 **View Transitions API**는 브라우저에 이미 내장된 기능이라 CSS 세 줄만 추가하면 되고, `/login` → `/dashboard`처럼 진짜로 새 페이지를 요청하는 이동에도 그대로 적용됩니다.
```css
@view-transition {
    navigation: auto;
}
```
이 기능을 아직 모르는 구형 브라우저는 이 규칙을 그냥 못 알아듣고 넘어갈 뿐이라서, "지원 안 하면 어떡하지?"를 걱정하지 않고 켜둘 수 있습니다(점진적 향상 — progressive enhancement).

### 실제로 확인한 것
1. 로그인·회원가입·회원 대시보드·로그인 기록·프로필·관리자 대시보드 6개 화면 전부 새 팔레트가 적용되는지 브라우저로 확인
2. 콘솔에 폰트 로딩 실패 등 오류가 없는지 확인
3. `getComputedStyle()`로 실제 적용된 글꼴이 의도한 대로(`Sora`, `Public Sans`)인지 코드로 재확인
4. `document.startViewTransition`이 실제로 함수로 존재하는지(브라우저가 View Transitions API를 지원하는지) 확인
5. `pytest tests/` 36개 재실행 — 색·글꼴만 바꿨을 뿐 파이썬 로직은 손대지 않았으므로 전부 그대로 통과

**테스트 중 우연히 발견해서 고친 문제**: 이번 작업과 무관하게, 이전 단계에서 검증용으로 껐던 "회원가입" 설정이 켜지지 않은 채로 남아있던 걸 발견했습니다. 로컬과 라이브 사이트가 같은 Supabase를 쓰기 때문에, 이 상태로는 실제 배포 사이트에서도 회원가입이 막혀 있었던 것입니다. 바로 다시 켜뒀습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [public/css/tokens.css](../../public/css/tokens.css) (신규 — 색상·글꼴·전환 효과 토큰)
- [public/css/auth.css](../../public/css/auth.css), [public/css/dashboard.css](../../public/css/dashboard.css), [public/css/member.css](../../public/css/member.css) (하드코딩된 색 → `var(--이름)`으로 전환)
- [public/js/dashboard.js](../../public/js/dashboard.js) (IP·시각 칸에 `.mono` 클래스 추가)
- [templates/login_form.html](../../templates/login_form.html), [templates/signup.html](../../templates/signup.html), [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [templates/member_dashboard.html](../../templates/member_dashboard.html), [templates/member_history.html](../../templates/member_history.html), [templates/member_profile.html](../../templates/member_profile.html) (`tokens.css` 링크 추가, `member_history.html`은 `.mono` 클래스도 추가)
- Supabase `app_settings.signup_enabled`를 다시 `true`로 되돌림 (이번 작업과 무관한 발견)
