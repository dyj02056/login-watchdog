# web/ — Next.js 화면 소스

Flask(`app.py`)가 서빙하는 정적 화면의 소스입니다. 구조와 규칙은 [docs/beginner-guide/guide48_nextjs_dashboard.md](../docs/beginner-guide/guide48_nextjs_dashboard.md)를 보세요.

```bash
npm ci
npm run typecheck
npm run build   # → ../spa/ , ../public/_next/ (이 결과도 함께 커밋)
```

- 화면 이동은 `<a>`와 `go()`(`src/lib/api.ts`)만 씁니다. `next/link`는 쓰지 않습니다.
- 인라인 `style`·`onclick`은 CSP가 막습니다. 색은 `src/styles/tokens.css` 변수로만 바꿉니다.

> 시각 표시 형식(`formatDateTime`·`formatShortDateTime`)과 표·차트 레이아웃 규칙은 [guide48의 "시각 표시와 표·차트 레이아웃 규칙"](../docs/beginner-guide/guide48_nextjs_dashboard.md)에 있습니다.
> 404 화면은 `src/app/not-found.tsx`이고, 빌드하면 `spa/404.html`이 된다. 동작 방식은 [guide48의 "404 화면"](../docs/beginner-guide/guide48_nextjs_dashboard.md) 참고.
