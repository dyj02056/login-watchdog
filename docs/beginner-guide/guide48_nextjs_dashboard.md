# 48단계 — Next.js 관제 화면으로 바꾸기

[◀ 47단계](guide47_daily_log_summary.md) · [전체 목차](beginner-guide.md)

> 화면을 Jinja 템플릿 + 바닐라 JS에서 **Next.js(React)** 로 옮겼습니다. 서버(Flask)의 로그인·잠금·요청 한도·CSRF·권한 검사는 **한 줄도 다시 쓰지 않았고**, 서버 실행 방법(`python app.py`)과 Vercel 배포 방식도 그대로입니다.

## 한눈에 보기

```
web/ (Next.js 소스)  ──npm run build──▶  spa/*.html          화면 껍데기(Flask가 서빙)
                                         public/_next/…      JS·CSS·폰트(해시 이름, 길게 캐시)

브라우저가 /admin/dashboard 를 열면
  1) Flask가 spa/admin/dashboard.html 을 그대로 내려준다      ← DB·잠금 판정 없음
  2) 화면이 같은 주소를 헤더(X-Requested-With)와 함께 다시 요청한다
  3) Flask가 기존 라우트를 평소대로 실행하고, 결과를 JSON 봉투로 돌려준다
```

### 왜 이런 구조인가

| 선택 | 이유 |
|---|---|
| Next.js를 **정적 내보내기**(`output: "export"`)로 | Next 서버를 따로 띄우면 CORS·쿠키 도메인 문제가 생기고 서버가 두 개가 된다. 정적 파일이면 Flask가 같은 주소에서 서빙해서 세션 쿠키·CSRF·`Secure` 설정을 그대로 쓴다 |
| 기존 라우트를 JSON으로 **바꿔 주는 어댑터**(`helpers/spa.py`) | `routes/*`에는 허니팟·타이밍 방어·계정 존재 여부 숨기기 같은 보안 로직이 들어 있다. 이걸 API로 다시 쓰다 보면 빠뜨릴 위험이 크다 |
| 빌드 결과를 **저장소에 커밋** | Vercel의 파이썬 빌드는 `npm`을 돌리지 않는다. 결과물이 저장소에 있으면 배포가 그대로 동작한다 |
| `next/link`·라우터를 쓰지 않고 `<a>` 사용 | 정적 내보내기의 클라이언트 이동은 `/login.txt` 같은 조각을 요청하는데, Flask에는 없는 주소라 404로 기록되어 **웹 스캐닝 탐지가 오탐**한다. 항상 일반 주소 이동을 한다 |

## 어댑터가 하는 일 (`helpers/spa.py`)

| 요청 | 응답 |
|---|---|
| 화면 주소 + 일반 브라우저 이동 | 정적 HTML(껍데기). 인라인 스크립트의 해시를 CSP `script-src`에 더한다(`'unsafe-inline'`은 쓰지 않음) |
| 어댑터 헤더가 붙은 요청 | 기존 라우트 실행 → `render_template` 값은 `{"page", "data"}`, `flash`는 `{"messages"}`, `redirect`는 `{"redirect"}` 로 변환. 모든 응답에 `csrf` 토큰이 들어 있다 |
| 어댑터 헤더가 붙은 `/api/*` JSON 응답 | 그대로 통과 |

- 템플릿에 넘기던 값에서 `password`, `hash`, `token`, `secret`, `session_version`이 들어간 칸은 JSON으로 내보내기 전에 지운다(예전에는 서버에서만 쓰여서 문제가 없었다).
- 리다이렉트로 가는 화면이 flash 문장을 보여줄 수 있게, 리다이렉트 응답에서는 flash를 꺼내지 않고 세션에 남겨 둔다.
- `spa/`가 없거나 `SPA_ENABLED=false`면 어댑터는 아무것도 하지 않아 **예전 Jinja 화면이 그대로** 나온다(문제가 생겼을 때 되돌리는 스위치).

## 화면 구성

| 주소 | 내용 | 데이터 |
|---|---|---|
| `/admin/dashboard` | 위협 현황: KPI, 시간대별 추이, 7일 로그량, 공격자 IP 히트맵, 공격 흐름도, 신규 공격자·잠금 현황·미처리 이벤트·연관 사건(미처리·방치) 표 | `/api/stats` (30초) |
| `/admin/attack` | 공격 상세: 시간대별 탐지, 국가 흐름, 출발지·유형 Top 5, 경로 비중, 최근 이벤트, **L3/L4 "수집 전" 빈 상태** | `/api/stats` (15초) |
| `/admin/ops` | 처리 작업대: 대응 / 기록 / 관리 세 묶음. 기존 대시보드의 처리 기능 전부 | `/api/status` (5초, 기존과 동일) |
| `/login` `/signup` `/admin/login` | 인증 | 기존 라우트 |
| `/dashboard` `/dashboard/history` `/dashboard/profile` | 회원 | 기존 라우트 |
| `/board` `/board/new` `/board/<id>` `/board/<id>/edit` | 게시판 | 기존 라우트 |
| `/recovery` `/recovery/verify` `/password/forgot` `/password/reset` `/email/confirm` | 복구 흐름 | 기존 라우트 |

차트에 쓰는 집계는 `db/stats.py`가 만든다. 새 표나 마이그레이션 없이 기존 표(`security_events`, `login_attempts`, `log_daily_summary` 등)에서 계산한다. 계산 부분(`build_threat_stats`)은 DB 없이 테스트할 수 있다(`tests/test_stats.py`).

> 이미지의 "탐지/차단 7,509,990건" 같은 숫자는 이 프로젝트에 없는 데이터라 따라 만들지 않았다. L3/L4(SYN 플러드·포트 스캔)도 아직 수집하지 않으므로 빈 상태로 둔다.

## 개발 방법

```bash
cd web
npm ci
npm run typecheck   # 타입 검사
npm run build       # 정적 빌드 + spa/, public/_next/ 갱신
```

- `next dev`(핫리로드)는 `/api`를 로컬 Flask(`FLASK_ORIGIN`, 기본 5000번)로 넘긴다. 다만 `/board/<번호>` 같은 주소는 개발 서버에 없으므로, 최종 확인은 항상 빌드 후 Flask로 한다.
- 이후 `scripts/`를 용도별 폴더로 나누고 시뮬레이션 일괄 점검 도구를 추가했다([49단계](guide49_scripts_reorganization.md)). 아래 `demo_server.py` 경로도 그에 따른 새 위치다.
- Supabase 없이 화면만 볼 때는 `python scripts/demo/demo_server.py` → `http://127.0.0.1:5077/__demo_login`(관리자) / `__demo_member`(회원). DB·Slack·메일에는 아무것도 보내지 않는다.
- CSP(`script-src 'self'`, `style-src 'self'`)가 그대로라서 **인라인 `style` 속성과 `onclick=` 을 쓰면 안 된다**. `npm run build`의 후처리(`web/scripts/postbuild.mjs`)가 이를 검사해서 있으면 빌드를 실패시킨다. 색은 CSS 변수·클래스로만 바꾼다.

## 디자인 규칙 (`web/src/styles/tokens.css`)

- 색·간격·글자 크기는 토큰에서만 정하고 다른 곳은 `var()`로만 쓴다. 의미가 있는 색(위험 등급, 정상)만 채도를 주고, 장식에는 쓰지 않는다.
- 숫자·IP·시각은 `JetBrains Mono`(자릿수 고정), 본문은 `Noto Sans KR`.
- 위험 등급은 색과 함께 글자(치명·높음·보통)를 쓴다 — 색만으로 구분하지 않는다.
- 탭이 숨겨지면 폴링을 멈춘다(`web/src/lib/usePolling.ts`, 45단계의 규칙 그대로).

## 배포 (Vercel)

- `vercel.json`: 함수에 `spa/**`를 포함시키고, `/_next/static/*`을 오래 캐시한다.
- `.vercelignore`: `web/`(소스·`node_modules`)는 올리지 않는다. 런타임에는 빌드 결과만 필요하다.
- 빌드 ID를 고정(`generateBuildId`)해서 같은 소스는 항상 같은 결과가 나온다. 그래서 커밋된 결과와 비교할 수 있다.
- 소스를 고쳤다면 **빌드 결과도 함께 커밋**해야 한다. CI(`.github/workflows/tests.yml`의 `web` 작업)가 타입 검사·빌드를 하고, 커밋된 결과와 다르면 경고를 남긴다.

## 테스트

- `tests/test_spa.py` — 껍데기 서빙과 CSP 해시, 템플릿 값·flash·리다이렉트 변환, 비밀 칸 제거, 빌드가 없을 때의 폴백, 이중 flash 방지.
- `tests/test_stats.py` — 집계(시간대별, 7일 로그량, 히트맵, 신규·반복 공격자, 미처리 정렬, 복합 공격, 흐름 링크).
- `tests/conftest.py`는 기존 테스트가 Jinja 화면을 기준으로 쓰여 있어 `SPA_ENABLED=false`를 기본으로 깐다.
