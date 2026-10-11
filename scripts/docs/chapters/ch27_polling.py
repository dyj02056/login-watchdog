# 27단원 — 보이지 않는 탭은 폴링하지 않음 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "27-visible-tab-polling"
TITLE = "27. 보이지 않는 탭은 폴링하지 않음"
SUBTITLE = "탭이 안 보이면 멈추고, 돌아오면 즉시 갱신하는 공용 폴링 부품(polling.js)의 코드 흐름도"

POLL = "public/js/polling.js"

FILE_ROLES = {
    POLL: "화면을 주기적으로 갱신하는 공용 부품. 탭이 숨겨지면 멈추고, 응답을 받은 뒤에 다음 요청을 예약한다.",
    "public/js/dashboard/main.js": "관리자 대시보드 화면의 시작 파일. 폴링 부품에 '5초마다 상태 갱신'을 맡긴다.",
    "public/js/board.js": "게시글 화면의 '새 댓글 알림' 파일. 같은 폴링 부품을 쓴다.",
    "routes/admin/status.py": "대시보드 갱신 API. 만료된 잠금 정리 3종을 동시에 돌린다.",
}

s1 = Scenario("poll", "공용 폴링 부품이 하는 일",
              "관리자 대시보드는 5초마다 /api/status 를 부르고, 요청 한 번에 DB 조회가 약 21번 일어납니다. 그런데 탭이 안 보여도 계속 불러서, 관리자 탭을 켜 둔 채 다른 일을 하면 분당 약 250번씩 DB 를 왕복했습니다. 또 setInterval 은 이전 요청이 끝났는지 보지 않아 서버가 느리면 요청이 겹쳐 쌓였습니다.")
s1.screen("대시보드 시작 — 폴링 부품에 맡긴다", "'5초마다 이 갱신 작업을 해 줘'라고 부탁하는 한 줄입니다. 게시글 화면의 새 댓글 확인도 같은 부품을 씁니다.",
          snippet=("public/js/dashboard/main.js", "startPolling(fetchStatus, pollIntervalMs);", "startPolling(fetchStatus, pollIntervalMs);"), label="main.js 폴링 시작",
          calls=[call(snippet=("public/js/board.js", "startPolling(checkForNewComments", "startPolling(checkForNewComments"), title="게시글 화면도 같은 부품", plain="새 댓글 알림 배너(3단원)가 이 부품으로 5초마다 확인합니다.", label="board.js 폴링 시작", kind="screen")])
s1.step("① 시작: 바로 한 번 하고, 이후는 '예약'", "immediate=true 면 시작하자마자 한 번 실행하고, 아니면(게시글 화면) 한 주기 뒤에 첫 실행을 예약합니다. 화면이 방금 서버에서 최신으로 그려졌기 때문입니다.",
        kind="screen", col=0, snippet=(POLL, "if (immediate) {", "re:^    }"), label="시작 방식")
s1.step("② 응답을 받은 '뒤에' 다음 요청을 예약 (setTimeout 연쇄)", "setInterval 은 이전 요청이 안 끝나도 시간이 되면 또 보내서, 서버가 느릴수록 요청이 쌓입니다. 이 부품은 응답이 온 뒤 주기만큼 기다렸다가 다음 요청을 보내서, 한 화면에서 진행 중인 요청은 항상 하나입니다.",
        kind="screen", col=0, snippet=(POLL, "async function run()", "re:^    }"), label="run()",
        hl=("await task();", "schedule();"))
s1.step("③ 탭이 숨겨져 있으면 예약하지 않는다", "다른 탭으로 이동하거나 창을 최소화하면 document.hidden 이 참이 되어 다음 요청을 예약하지 않습니다. 끝난 시점에 탭이 숨겨져 있어도 마찬가지입니다.",
        kind="screen", col=0, snippet=(POLL, "function schedule()", "re:^    }"), label="schedule()",
        hl=("if (timer === null && !running && !document.hidden) {", "timer = setTimeout(run, intervalMs);"))
s1.step("④ 탭이 숨겨지면 멈추고, 다시 보이면 '즉시' 한 번 갱신", "돌아오면 다음 주기를 기다리지 않고 바로 갱신합니다. 자리를 비운 사이 달린 댓글·잠금을 바로 알려주기 위해서입니다. 요청이 진행 중이면 그게 끝난 뒤 이어서 예약합니다.",
        kind="screen", col=0, snippet=(POLL, 'document.addEventListener("visibilitychange"', "re:^    }\\);"), label="visibilitychange")
s1.step("⑤ 실패해도 폴링은 멈추지 않는다", "일시적인 네트워크 오류 한 번으로 화면이 영영 멈추면 안 됩니다. 예외는 콘솔에만 남기고 다음 주기를 이어갑니다.",
        kind="screen", col=0, snippet=(POLL, "async function run()", "re:^    }"), label="run()",
        hl=("try {", 'console.error("[polling] 갱신 실패:", error);'))
s1.step("⑥ 서버: 만료된 잠금 정리 3종을 동시에", "대시보드 갱신 때 IP·회원 계정·관리자 계정의 만료된 잠금을 서로 무관하므로 동시에 정리합니다(12단원). 정해진 간격마다만 하도록 28단원에서 한 번 더 줄입니다.",
        fn="routes/admin/status.py:_release_expired_locks_if_due", hl=("with ThreadPoolExecutor(max_workers=3) as executor:", "future.result()"),
        calls=[call("soar.try_release_expired_lockouts", "IP 잠금 만료 해제", "풀릴 시각이 지난 잠금을 풉니다.", later="10단원")])

SCENARIOS = [s1.build()]
