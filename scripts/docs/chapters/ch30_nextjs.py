# 30단원 — Next.js 관제 화면과 집계 API 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "30-nextjs-dashboard"
TITLE = "30. Next.js 관제 화면과 집계 API"
SUBTITLE = "화면은 Next.js 정적 빌드로, 보안 로직은 기존 Flask 라우트 그대로 — 둘을 이어주는 어댑터와 집계 API 의 코드 흐름도"

SPA = "helpers/spa.py"
API_TS = "web/src/lib/api.ts"

FILE_ROLES = {
    SPA: "Next.js 정적 화면과 기존 Flask 라우트를 이어주는 얇은 어댑터. 화면 껍데기를 내려주고, 라우트 결과를 JSON 봉투로 바꾼다.",
    API_TS: "화면(브라우저) 쪽에서 Flask 와 대화하는 얇은 클라이언트. 어댑터 헤더를 붙여 기존 라우트를 JSON 으로 부른다.",
    "routes/admin/status.py": "관리자 화면 라우트와 /api/stats(집계) 입구 파일.",
    "db/stats.py": "대시보드 차트·히트맵 숫자를 기존 표에서 계산한다(새 표 없음). 계산부는 DB 없이 테스트할 수 있다.",
}

s1 = Scenario("adapter", "화면 껍데기 → 데이터 요청 (어댑터)",
              "서버의 로그인·잠금·요청 한도·CSRF·권한 검사는 이미 검증된 코드라 다시 쓰고 싶지 않았습니다. 그래서 화면(React)만 Next.js 로 바꾸고, 기존 라우트를 그대로 실행한 뒤 결과를 JSON 으로 바꿔 주는 어댑터를 얇게 끼웠습니다.")
s1.screen("브라우저가 /admin/dashboard 를 연다", "주소를 직접 열면(GET, 어댑터 헤더 없음) 먼저 '껍데기'가 옵니다.",
          fn=f"{SPA}:serve_shell", hl="def serve_shell():")
s1.step("① 정적 HTML 껍데기를 그대로 내려준다", "껍데기는 DB 조회·잠금 판정을 하지 않고, 반복 접근 관찰 훅에도 잡히지 않습니다. 화면이 뜬 뒤에 진짜 요청이 일어납니다.",
        fn=f"{SPA}:serve_shell", hl=('if request.method != "GET" or is_spa_request() or not is_enabled():', 'response.headers["X-Spa-Shell"] = filename'),
        calls=[call(f"{SPA}:is_enabled", "화면 빌드가 있나?", "spa/ 가 없거나 SPA_ENABLED=false 면 예전 Jinja 화면이 그대로 나옵니다.")])
s1.step("② 인라인 스크립트만 CSP 해시로 허용", "Next 정적 빌드는 화면 데이터를 인라인 스크립트로 심는데, 이 사이트의 CSP 는 script-src 'self' 라 그대로는 막힙니다. 'unsafe-inline' 으로 풀면 XSS 방어가 사라지므로, 우리가 빌드한 그 스크립트의 내용만 해시로 허용합니다(내용이 바뀌면 해시도 달라져 막힘).",
        fn=f"{SPA}:apply_script_hashes", hl=('hashes = response.headers.pop("X-Spa-Script-Hashes", None)', 'response.headers["Content-Security-Policy"] = csp'),
        calls=[call(f"{SPA}:inline_script_hashes", "스크립트 내용 → sha256 해시", "다시 빌드하면 해시도 새로 계산합니다.")])
s1.step("③ 화면이 같은 주소를 '어댑터 헤더'와 함께 다시 요청", "X-Requested-With: login-watchdog-spa 헤더는 다른 사이트가 보낼 수 없습니다(브라우저가 사전 검사 없이는 교차 출처 요청에 임의 헤더를 못 붙임). CSRF 토큰 검사와 별개의 보조 방어선입니다.",
        kind="screen", col=0, snippet=(API_TS, "export async function getPage", "re:^}"), label="getPage()",
        calls=[call(snippet=(API_TS, "export function go(", "re:^}"), title="화면 이동은 일반 주소 이동만", plain="next/link·라우터를 쓰지 않습니다. 정적 내보내기의 조각 요청(/login.txt)이 404 로 기록되어 웹 스캐닝(6단원) 탐지가 오탐하기 때문입니다.", label="go()", kind="screen")])
s1.step("④ 기존 라우트가 평소대로 실행된다", "로그인 확인·권한 확인·요청 기록이 모두 평소처럼 일어납니다. render_template 이 호출되면 어떤 템플릿에 어떤 값이 넘어갔는지 어댑터가 가로채서 기억해 둡니다.",
        fn=f"{SPA}:_capture_context", hl=("if not is_spa_request():", "g._spa_page = (template.name, data)"))
s1.step("⑤ 비밀 칸은 JSON 으로 나가기 전에 지운다", "템플릿은 서버에서만 그려져서 user 딕셔너리를 통째로 넘겨도 괜찮았지만, JSON 은 그대로 브라우저로 나갑니다. password·hash·token·secret·session_version 이 들어간 칸은 지웁니다.",
        fn=f"{SPA}:_scrub", hl=("if isinstance(value, dict):", "if not any(part in str(k).lower() for part in _SECRET_KEY_PARTS)"),
        calls=[call(snippet=(SPA, "_SECRET_KEY_PARTS =", "_SECRET_KEY_PARTS ="), title="지우는 칸 이름 목록", plain="이름에 이 글자가 들어가면 응답에서 뺍니다.", label="_SECRET_KEY_PARTS")])
s1.step("⑥ 응답을 {page, data, messages, csrf} JSON 봉투로 변환", "render_template → page+data, redirect → 이동할 주소(HTTP 리다이렉트 대신 본문으로 알려 fetch 가 따라가 버리지 않게), flash → messages. 모든 응답에 다음 POST 에 쓸 CSRF 토큰이 들어 있습니다.",
        fn=f"{SPA}:convert_response", hl=("payload: dict = {", 'response.headers["Content-Type"] = "application/json; charset=utf-8"'),
        calls=[call(f"{SPA}:_path_with_query", "리다이렉트 주소 정리", "경로와 쿼리만 남깁니다.")])

s2 = Scenario("post", "폼 제출 (POST)",
              "화면의 폼 제출도 기존 라우트(request.form 을 읽는 코드)를 그대로 부릅니다. 허니팟 칸은 일부러 비워서 보냅니다.")
s2.screen("가입·로그인 등 폼 제출", "화면이 postForm() 으로 같은 주소에 POST 합니다.",
          snippet=(API_TS, "export async function postForm", "re:^}"), label="postForm()", hl=("body: new URLSearchParams({ website: \"\", ...fields }),", "body: new URLSearchParams({ website: \"\", ...fields }),"))
s2.step("① CSRF 토큰을 헤더에 실어 보낸다", "토큰은 이전 응답 봉투에서 기억해 둔 값이고, 없으면 세션 조회(/api/spa/session)로 받아옵니다.",
        kind="screen", col=0, snippet=(API_TS, "export async function postForm", "re:^}"), label="postForm()",
        hl=("const token = await sessionCsrf();", '"Content-Type": "application/x-www-form-urlencoded" },'),
        calls=[call(f"{SPA}:register", "세션 조회 라우트 등록", "/api/spa/session 은 CSRF 토큰과 로그인 상태만 알려주고 DB 에는 접근하지 않습니다.")])
s2.step("② 응답이 리다이렉트면 그 주소로 이동", "성공하면 서버가 redirect 를 돌려주고, 어댑터가 이를 본문의 redirect 칸으로 바꿔 보내므로 화면이 직접 이동합니다.",
        kind="screen", col=0, snippet=(API_TS, "export async function postForm", "re:^}"), label="postForm()",
        hl=("if (body.redirect && body.status !== 400) {", "return null;"))

s3 = Scenario("stats", "관제 화면 숫자 (/api/stats)",
              "관제 보드(위협 현황·공격 상세)의 차트·히트맵·표 숫자는 목록 전체가 아니라 '집계'만 내려받습니다. 새 표 없이 기존 표에서 계산합니다.")
s3.screen("차트가 숫자를 요청 (GET /api/stats)", "로그인만 확인합니다(조회 전용).",
          fn="routes/admin/status.py:api_stats", hl=('@admin_bp.route("/api/stats", methods=["GET"])', "@login_required"))
s3.step("① 잠금 목록 4개를 동시에 조회", "IP·회원 계정·관리자 계정 잠금과 AI 대기 건수를 같은 배치로 보내 활성 잠금 수를 구합니다.",
        fn="routes/admin/status.py:api_stats", hl=("with ThreadPoolExecutor(max_workers=4) as executor:", "pending_count = pending.result()[1]"),
        calls=[call(refs=["db.list_active_lockouts", "db.list_active_account_lockouts", "db.list_active_admin_account_lockouts", "db.list_pending_requests"], title="잠금·대기 건수", plain="현재 잠긴 대상 수와 AI 승인 대기 수.")])
s3.step("② 집계를 계산한다 (짧게 보관)", "같은 집계를 여러 관리자 탭이 동시에 요청해도 DB 조회는 한 번만 합니다(단일 비행 + 짧은 보관). 잠금 목록은 건수가 같아도 내용이 바뀔 수 있어 보관된 집계에 매번 새로 얹습니다.",
        fn="db/stats.py:get_threat_stats", hl=("ttl = config.ADMIN_STATS_CACHE_SECONDS", "return _cache[\"value\"]"),
        calls=[call("db/stats.py:build_locks", "잠금 목록 정리", "화면용 형태로 바꿉니다.")])
s3.step("③ 원본 줄을 동시에 가져온다", "보안 이벤트·실패 로그인·404·미인증·사건·일별 요약·오늘 건수를 한꺼번에 조회합니다.",
        fn="db/stats.py:fetch_raw", hl=("with ThreadPoolExecutor(max_workers=len(jobs)) as executor:", 'raw["now"] = now'),
        calls=[call("db/stats.py:_fetch_rows", "표에서 기준 시각 이후 줄 조회", "필요한 칸만 가져옵니다.")])
s3.step("④ 순수 계산 — DB 없이 테스트할 수 있다", "시간대별 건수·7일 로그량·공격자 히트맵·신규/반복 공격자·국가별 흐름·미처리 이벤트 정렬 등을 계산합니다. 계산부가 DB 와 분리되어 있어 테스트가 쉽습니다.",
        fn="db/stats.py:build_threat_stats", hl="def build_threat_stats(",
        calls=[call("db.get_cached_ip_locations", "상위 IP 의 국가 정보", "4단원의 위치 캐시를 재사용합니다.", later="4단원")])

SCENARIOS = [s1.build(), s2.build(), s3.build()]
