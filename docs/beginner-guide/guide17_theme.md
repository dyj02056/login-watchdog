# 17단계 — 제목 가운데 정렬, 입력창 테두리 강화, 수동 라이트/다크 전환 버튼

[◀ 16단계](guide16_darkmode.md) · [전체 목차](beginner-guide.md)

### 우리가 한 일
1. 카드 안의 큰 제목(`.auth-card h1`, `.member-card h2`)을 가운데 정렬
2. 입력창 테두리 색을 `--line`(구분선용, 너무 흐림)에서 `--input-border`라는 새 전용 토큰으로 분리해 눈에 잘 띄게 함
3. `tokens.css`의 다크모드 구조를 "OS 자동 감지"만 하던 방식에서, "방문자가 직접 고른 값이 있으면 그걸 최우선으로 따르는" 3단 구조로 보강
4. `public/js/theme.js`를 새로 만들어 우측 상단 라이트/다크 전환 버튼의 동작을 구현
5. 화면 6개 전부에 전환 버튼을 추가 — topbar가 있는 화면(관리자·회원 대시보드, 로그인 기록, 프로필)은 로그아웃 버튼 옆에, topbar가 없는 화면(로그인·회원가입)은 화면 우측 상단에 고정

### 왜 했는가 (쉬운 설명)

**왜 `--line`을 그대로 안 쓰고 `--input-border`를 새로 만들었나**
`--line`은 표의 가로줄처럼 "있는 듯 없는 듯" 은은해야 예쁜 곳에 쓰려고 만든 토큰입니다. 그런데 입력창 테두리는 반대로 "여기가 클릭할 수 있는 칸이다"를 눈에 띄게 알려줘야 합니다. 두 역할에 같은 흐린 색을 쓰다 보니 입력창이 잘 안 보인다는 문제가 생겼습니다. 16단계에서 "색 하나를 두 가지 역할로 겸용하면 안 된다"는 교훈을 얻었던 것과 정확히 같은 상황이라, 이번에도 역할별로 토큰을 분리하는 방식으로 해결했습니다.

**"3단 구조"가 정확히 뭘 하는 건가**
16단계까지는 다크모드가 오직 OS/브라우저 설정만 따랐습니다. 이번에 수동 버튼을 추가하려면 "방문자가 직접 고른 값이 OS 설정보다 우선해야" 합니다. 그래서 우선순위를 3단계로 나눴습니다.

1. **방문자가 직접 고른 값** — 우측 상단 버튼을 눌러서 정한 값. `<html data-theme="dark">`처럼 태그에 표시가 붙고, `localStorage`에 저장되어 다른 페이지로 이동해도 계속 기억됩니다.
2. **OS/브라우저 설정** — 방문자가 버튼을 아직 한 번도 안 눌렀다면, 컴퓨터의 "어두운 화면" 설정을 그대로 따릅니다(16단계에서 만든 기능).
3. **기본값(라이트)** — 위 둘 다 해당 없으면 그냥 밝은 화면.

이걸 CSS로 표현하면 이렇습니다.
```css
/* 2번: OS가 다크모드이면 적용. 단, 방문자가 "라이트"를 직접 골랐다면(:not) 적용 안 함 */
@media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
        --canvas: #10201c;
        /* ... 나머지 다크 팔레트 ... */
    }
}

/* 1번: 방문자가 "다크"를 직접 골랐다면, OS 설정과 상관없이 항상 적용 */
:root[data-theme="dark"] {
    --canvas: #10201c;
    /* ... 나머지 다크 팔레트 (위와 같은 값) ... */
}
```
`:not([data-theme="light"])`은 "data-theme 값이 light가 아니라면"이라는 뜻입니다. 방문자가 라이트를 직접 골랐을 때는 `data-theme="light"`가 붙어있으므로 이 조건이 거짓이 되어, OS가 다크여도 다크 팔레트가 적용되지 않습니다. 반대로 `:root[data-theme="dark"]`는 "다크를 직접 골랐을 때"만 적용되는 규칙이라, OS가 라이트여도 다크 팔레트를 강제로 적용시킵니다.

**`theme.js`를 왜 `<head>` 안에서, 그것도 가장 먼저 불러오나**
페이지가 다 그려진 뒤에 테마를 정하면, 아주 짧은 순간이지만 "원래 있어야 할 색"이 아닌 다른 색으로 화면이 한 번 번쩍였다가 바뀌는 현상(테마 깜빡임)이 생깁니다. 이걸 막으려면 브라우저가 화면을 그리기도 전에 `localStorage`를 확인해서 `data-theme`을 미리 붙여둬야 합니다. 그래서 `theme.js`의 앞부분은 `DOMContentLoaded`(화면 요소가 다 만들어진 뒤에 울리는 신호)를 기다리지 않고 스크립트가 로드되는 즉시 실행되도록 만들었고, 템플릿에서도 이 스크립트를 다른 CSS/스크립트보다 위쪽인 `<head>`의 앞부분에 배치했습니다.
```js
(function () {
    try {
        var saved = localStorage.getItem("theme");
        if (saved === "light" || saved === "dark") {
            document.documentElement.setAttribute("data-theme", saved);
        }
    } catch (e) {
        // localStorage를 못 쓰는 환경(프라이빗 브라우징 등)이면 자동 다크모드만 동작
    }
})();
```
버튼을 실제로 누른 뒤의 동작은 `DOMContentLoaded` 이후에 등록합니다 — 이건 버튼이라는 화면 요소가 실제로 존재해야 클릭 이벤트를 걸 수 있기 때문에, 화면이 다 그려진 뒤에 해도 늦지 않습니다.
```js
document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    updateButtonLabel(btn);
    btn.addEventListener("click", function () {
        var isDark = currentlyDark();
        var next = isDark ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", next);
        try { localStorage.setItem("theme", next); } catch (e) {}
        updateButtonLabel(btn);
    });
});
```

**버튼 위치를 화면마다 다르게 만든 이유**
관리자·회원 대시보드처럼 상단바(topbar)가 있는 화면은 이미 로그아웃 버튼이 우측에 있어서, 그 옆에 나란히 두는 게 자연스럽습니다. 그래서 `.topbar-actions`라는 그릇(`<div>`)을 새로 만들어 전환 버튼과 로그아웃 버튼(폼)을 같이 묶었습니다. 반면 로그인·회원가입 화면은 애초에 상단바 자체가 없어서, `position: fixed`로 화면 우측 상단에 독립적으로 띄워뒀습니다(`.theme-toggle--floating` 클래스).

**"큰 제목 가운데 정렬"을 어디까지 적용했나**
로그인·회원가입 카드의 `<h1>`과 회원 대시보드·기록·프로필 카드의 `<h2>`만 가운데로 맞췄습니다. 관리자 대시보드의 `section h2`(예: "최근 로그인 시도", "등록된 회원")는 일부러 그대로 왼쪽 정렬로 뒀습니다 — 이 제목들은 "감상하는 큰 제목"이 아니라 표를 훑어볼 때 "여기부터 어떤 표인지" 빠르게 스캔하는 라벨에 더 가까운 역할이라, 카드 중앙의 인사말·폼 제목과는 성격이 다르다고 판단했습니다.

### 실제로 확인한 것
1. 로그인 화면에서 우측 상단 버튼을 눌러 라이트 → 다크 → 라이트로 전환되는지, 버튼 문구(`다크 모드`/`라이트 모드`)가 매번 정확히 바뀌는지 확인
2. `localStorage`에 저장된 값이 `/signup`, `/dashboard` 등 다른 화면으로 이동해도 그대로 유지되는지 확인 (`localStorage.getItem("theme")`로 직접 조회)
3. `getComputedStyle()`로 `--canvas`, 카드 배경, 글자색이 라이트/다크 각각 의도한 값과 정확히 일치하는지 코드로 재확인 — 특히 관리자 대시보드는 미리보기 도구의 화면 캡처가 실제 색과 다르게 보이는 표시 오류가 있어서, 눈으로 보는 스크린샷 대신 이 방법으로 검증
4. 임시 테스트 계정(`themetest01`)으로 회원가입 → 로그인 → 내 대시보드 → 로그인 기록 → 프로필까지 전 화면을 돌며 제목 가운데 정렬, 입력창 테두리, 전환 버튼이 모두 의도대로 보이는지 스크린샷으로 확인 후 계정 삭제(관리자 API로 정리)
5. `pytest tests/` 36개 재실행 — 이번에도 화면(CSS/JS)만 바꿨을 뿐 파이썬 로직은 그대로라 전부 통과

**검증 중 발견한, 코드와 무관한 도구 이슈**: 미리보기 브라우저 창이 화면 뒤에 숨겨진 상태(hidden)이거나 특정 화면(관리자 대시보드)에서 스크린샷 기능이 실제 색상과 다른 이미지를 보여주는 경우가 있었습니다. `getComputedStyle()`로 실제 CSS 값을 직접 조회해보면 항상 의도한 라이트/다크 값이 정확히 적용되어 있어서, 이건 우리 코드의 문제가 아니라 스크린샷 촬영 도구 자체의 표시 오류로 판단했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [public/css/tokens.css](../../public/css/tokens.css) (`--input-border` 신규, 다크모드를 3단 구조로 재구성, `.theme-toggle` 버튼 스타일 추가)
- [public/css/auth.css](../../public/css/auth.css) (`.auth-card h1` 가운데 정렬, 입력창 테두리를 `var(--input-border)`로 변경)
- [public/css/member.css](../../public/css/member.css) (`.member-card h2` 가운데 정렬, 입력창 테두리 변경, `.topbar-actions` 추가)
- [public/css/dashboard.css](../../public/css/dashboard.css) (`.topbar-actions` 추가)
- [public/js/theme.js](../../public/js/theme.js) (신규 — 전환 버튼 동작)
- [templates/login_form.html](../../templates/login_form.html), [templates/signup.html](../../templates/signup.html) (`theme.js` 링크, 우측 상단 고정 버튼 추가)
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [templates/member_dashboard.html](../../templates/member_dashboard.html), [templates/member_history.html](../../templates/member_history.html), [templates/member_profile.html](../../templates/member_profile.html) (`theme.js` 링크, topbar 안에 전환 버튼 추가)
