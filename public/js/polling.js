// ============================================================================
// polling.js — 화면을 주기적으로 갱신하는 공용 부품 (guide45)
//
// 관리자 대시보드(dashboard/main.js)와 게시글 화면(board.js)이 같이 쓴다. 예전에는 두
// 화면 모두 setInterval로 "주기마다 무조건" 요청을 보냈는데, 두 가지 문제가 있었다.
//
// 1) 탭이 안 보여도 계속 보냈다. 대시보드 요청 한 번은 DB 조회 약 21번이라, 관리자 탭을
//    켜 둔 채 다른 일을 하면 분당 약 250번씩 DB를 왕복했다.
//    → 탭이 숨겨지면(다른 탭으로 이동, 창 최소화) 멈추고, 다시 보이면 즉시 한 번 갱신한 뒤
//      주기를 다시 시작한다(document.hidden / visibilitychange).
// 2) 이전 요청이 끝났는지 보지 않아서, 서버가 주기보다 느리면 요청이 겹쳐 쌓였다.
//    → "응답을 받은 뒤 주기만큼 기다렸다가 다음 요청"(setTimeout 연쇄). 한 화면에서
//      진행 중인 요청은 항상 하나다.
//
// task가 실패(예외)해도 폴링은 멈추지 않는다 — 일시적인 네트워크 오류 한 번으로 화면이
// 영영 멈추면 안 된다.
// ============================================================================

/**
 * task를 intervalMs 간격으로 반복 실행한다.
 *
 * @param {() => Promise<void>} task  한 번의 갱신 작업(끝날 때까지 다음 실행을 미룬다)
 * @param {number} intervalMs          이전 실행이 끝난 뒤 다음 실행까지 기다릴 시간
 * @param {{immediate?: boolean}} options  immediate=true면 시작하자마자 한 번 실행한다
 */
export function startPolling(task, intervalMs, { immediate = true } = {}) {
    let timer = null;
    let running = false;

    function schedule() {
        if (timer === null && !running && !document.hidden) {
            timer = setTimeout(run, intervalMs);
        }
    }

    function cancel() {
        if (timer !== null) {
            clearTimeout(timer);
            timer = null;
        }
    }

    async function run() {
        timer = null;
        if (running || document.hidden) {
            return;
        }
        running = true;
        try {
            await task();
        } catch (error) {
            console.error("[polling] 갱신 실패:", error);
        } finally {
            running = false;
        }
        schedule(); // 끝난 시점에 탭이 숨겨져 있으면 예약하지 않는다(돌아올 때 다시 시작)
    }

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            cancel();
        } else {
            // 돌아오면 다음 주기를 기다리지 않고 바로 갱신한다. 요청이 진행 중이면 그게
            // 끝난 뒤 schedule()이 이어서 예약한다.
            cancel();
            run();
        }
    });

    if (immediate) {
        run();
    } else {
        schedule();
    }
}
