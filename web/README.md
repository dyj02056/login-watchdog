# web/ — Next.js 화면 소스

Flask(`app.py`)가 서빙하는 정적 화면의 소스입니다. 구조와 규칙은 [docs/beginner-guide/guide48_nextjs_dashboard.md](../docs/beginner-guide/guide48_nextjs_dashboard.md)를 보세요.

```bash
npm ci
npm run typecheck
npm run build   # → ../spa/ , ../public/_next/ (이 결과도 함께 커밋)
```

- 화면 이동은 `<a>`와 `go()`(`src/lib/api.ts`)만 씁니다. `next/link`는 쓰지 않습니다.
- 인라인 `style`·`onclick`은 CSP가 막습니다. 색은 `src/styles/tokens.css` 변수로만 바꿉니다.
