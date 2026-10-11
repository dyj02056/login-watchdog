# 28단원 — 대시보드 즉시 반응 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "28-dashboard-responsiveness"
TITLE = "28. 대시보드 즉시 반응"
SUBTITLE = "버튼을 누르는 순간 화면이 먼저 반응하고, 표 하나만 다시 받는 대시보드 속도 개선의 코드 흐름도"

API = "public/js/dashboard/api.js"
ACT = "public/js/dashboard/actions.js"
UTL = "public/js/dashboard/utils.js"

FILE_ROLES = {
    API: "서버에서 상태를 받아 화면을 그리는 조회 함수들. 표 하나만 다시 받는 fetchSection/goToPage 가 있다.",
    ACT: "서버 상태를 바꾸는 요청 모음(잠금 해제·삭제·처리 완료 등). 요청 직전에 버튼을 '처리 중…'으로 바꾼다.",
    UTL: "화면 도구 모음. 버튼을 '처리 중…'으로 바꾸고 더블 클릭을 막는 markBusy/runAction 이 있다.",
    "routes/admin/status.py": "대시보드 갱신 API. ?only=<표 이름> 으로 표 하나만 돌려주는 기능이 있다.",
}

s1 = Scenario("page", "'다음 페이지' — 화면 먼저, 표 하나만 요청",
              "대시보드에서 버튼을 누르면 2초 넘게 아무 반응이 없었습니다(운영 측정 평균 2.22초). '다음 페이지' 하나를 눌러도 대시보드 전체(표 8개 + 카드 6개, DB 조회 약 21번)를 다시 받았고, 응답 전에는 화면 변화가 없어 같은 버튼을 다시 누르게 됐습니다.")
s1.screen("'다음' 클릭", "페이지가 있는 표(로그인 시도·회원·게시글·댓글·관리자 로그인 기록·보안 이벤트·연관 사건·AI 조기 경보) 8개가 같은 방식입니다.",
          snippet=(API, "export const SECTIONS = {", "re:^};"), label="SECTIONS 표 목록")
s1.step("① 응답을 기다리지 않고 번호부터 바꾼다", "페이지 번호를 1~마지막 사이로 맞춰 바로 그리고, 표를 흐리게 만들어 '불러오는 중'임을 알립니다. 누른 지 3ms 만에 '2 / 8' 로 바뀝니다.",
        kind="screen", col=0, snippet=(API, "export function goToPage(", "re:^}"), label="goToPage()")
s1.step("② 그 표 하나만 서버에 요청", "/api/status?only=attempts&attempts_page=2 처럼 표 이름과 쪽 번호만 보냅니다. DB 조회가 약 21번에서 1~2번으로 줄어듭니다.",
        kind="screen", col=0, snippet=(API, "export async function fetchSection(", "re:^}"), label="fetchSection()",
        hl=("const requestId = ++latestSectionRequest[name];", "const response = await fetch(`/api/status?${params}`);"))
s1.step("③ 서버: 표 하나의 이번 쪽 + 전체 쪽 수만", "페이지가 있는 표 8개만 받을 수 있고, 모르는 이름은 400 입니다. 세션 확인 + 조회 1번(로그인 시도 표는 위치 캐시 1번 더)으로 끝납니다.",
        fn="routes/admin/status.py:_api_status_section", hl=("if name not in _PAGED_SECTIONS:", "return jsonify({rows_key: rows, total_key"),
        reject="알 수 없는 표입니다. (400)",
        calls=[call(snippet=("routes/admin/status.py", "_PAGED_SECTIONS = {", "re:^}"), title="표 이름 → 조회 함수 매핑", plain="이름·쪽 번호 파라미터·응답 키를 한곳에 모아 둡니다.", label="_PAGED_SECTIONS")])
s1.step("④ 늦게 도착한 옛 응답은 버린다", "'이전'을 6번 연타해도 요청은 1번뿐이고, 늦게 도착한 옛 응답이 사용자가 방금 넘긴 페이지를 되돌려 놓지 않습니다. 표마다 '가장 최근 요청 번호'를 기억해 마지막 요청의 응답만 그립니다.",
        kind="screen", col=0, snippet=(API, "export async function fetchSection(", "re:^}"), label="fetchSection()",
        hl=("if (requestId !== latestSectionRequest[name]) {", "return; // 이 응답을 기다리는 동안 같은 표의 더 새로운 요청이 나갔다"))
s1.step("⑤ 응답이 오면 그 표만 다시 그린다", "표와 페이지 번호를 그리고 '불러오는 중' 흐림을 걷습니다. 그사이 항목이 줄어 지금 페이지가 없어졌다면 마지막 페이지로 다시 받습니다.",
        kind="screen", col=0, snippet=(API, "function drawSection(", "re:^}"), label="drawSection()")

s2 = Scenario("action", "처리 버튼 — 누르는 즉시 '처리 중…'",
              "처리 버튼(해제·삭제·처리 완료·승인 등 17종)은 누르는 즉시 '처리 중…'으로 바뀌고 두 번 눌리지 않습니다. 확인 팝업을 취소하면 버튼은 바뀌지 않습니다.")
s2.screen("'즉시 해제' 클릭", "버튼을 눌러 처리가 시작됩니다. 이미 처리 중인 버튼이면 아무 일도 하지 않습니다(더블 클릭 방지).",
          snippet=(UTL, "export async function runAction(", "re:^}"), label="runAction()")
s2.step("① 요청을 보내는 순간 '처리 중…'", "확인 팝업·사유 입력을 취소하면 여기까지 오지 않으므로 버튼이 바뀌지 않습니다.",
        kind="screen", col=0, snippet=(ACT, "function sendAction(", "re:^}"), label="sendAction()",
        calls=[call(snippet=(UTL, "export function markBusy(", "re:^}"), title="버튼을 '처리 중…'으로", plain="원래 글자를 기억해 두고 버튼을 비활성화합니다.", label="markBusy()", kind="screen")])
s2.step("② 서버에 처리 요청 (CSRF 토큰과 함께)", "세션 쿠키는 자동으로 가지만 '이 화면에서 온 요청'임은 보장하지 못하므로, 화면이 서버에게 받은 CSRF 토큰을 헤더로 함께 보냅니다.",
        kind="screen", col=0, snippet=(ACT, "export async function unlockIp(", "re:^}"), label="unlockIp()",
        hl=('await sendAction(button, "/api/unlock", {', "await fetchStatus();"),
        calls=[call("routes/admin/locks.py:api_unlock", "즉시 해제 API", "권한 확인 후 잠금을 풉니다(12단원).", later="12단원")])
s2.step("③ 끝나면 전체 갱신 + 버튼 복구", "다음 폴링을 기다리지 않고 한 번 더 갱신해서 카드가 바로 사라지는 걸 보여줍니다. 성공·실패·취소 모두 끝나면 버튼을 원래대로 돌립니다.",
        kind="screen", col=0, snippet=(API, "export async function fetchStatus()", "re:^}"), label="fetchStatus()")
s2.step("④ 서버: 만료된 잠금 정리는 15초에 한 번만", "대시보드 갱신마다 정리하지 않고 정해진 간격(기본 15초)마다 한 번만 합니다. 동시에 들어온 갱신 둘이 함께 정리하지 않게 잠금으로 보호합니다.",
        fn="routes/admin/status.py:_release_expired_locks_if_due", hl=("interval = config.ADMIN_STATUS_RELEASE_INTERVAL_SECONDS", "_expiry_release_state[\"at\"] = now"),
        calls=[call(snippet=("config.py", "ADMIN_STATUS_RELEASE_INTERVAL_SECONDS =", "ADMIN_STATUS_RELEASE_INTERVAL_SECONDS ="), title="정리 간격 (15초)", plain="만료된 잠금이 화면에 '잠김'으로 최대 15초 더 보일 수 있습니다. 실제 차단 해제는 로그인 요청마다 따로 처리되므로 늦어지지 않습니다.", label="ADMIN_STATUS_RELEASE_INTERVAL_SECONDS")])

SCENARIOS = [s1.build(), s2.build()]
