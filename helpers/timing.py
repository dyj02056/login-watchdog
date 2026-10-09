# ============================================================================
# helpers/timing.py — 응답 시간 고정(타이밍 사이드채널 방지) — 원래 routes/recovery.py에 있던 함수
#
# 예전 helpers.py(314줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from helpers import ...`로 가져다 쓴다(helpers/__init__.py가
# 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import threading
import time

import httpx
from flask import has_request_context, request

import config
from notify import mailer


def report_internal_error(error: Exception) -> None:
    """복구 요청 처리 중 예외를 로그에 남기고 관리자에게 알린다. 사용자 화면에는 영향이 없다
    (예외가 500으로 새면 계정 존재 여부가 드러나므로 응답은 항상 같다) — 그래서 이 알림이 없으면
    복구 메일이 안 나가고 있어도 아무도 모른다."""
    print(f"[recovery] 복구·재설정 요청 처리 중 오류: {type(error).__name__}: {error}", flush=True)
    mailer.report_failure(mailer.FAIL_INTERNAL, f"복구·재설정 요청 처리 중 오류: {type(error).__name__}")


def _log_timing(path: str, work_seconds: float, target: float) -> None:
    """실제 처리 시간을 한 줄로 남긴다(guide43) — 고정 시간을 실측으로 조정하기 위한 기록.
    처리가 고정 시간을 넘기면 그 요청만 응답이 늦어져 계정 존재 여부가 드러날 수 있으므로
    `overrun`을 붙인다. 아이디·IP는 남기지 않는다."""
    overrun = " overrun" if work_seconds > target else ""
    print(f"[timing] {path} work={work_seconds:.2f}s target={target:.1f}s{overrun}", flush=True)


def run_with_fixed_response_time(work, started: float) -> None:
    """`work()`를 실행하고, 처리가 빨리 끝났든 오래 걸렸든 응답 시점이 항상
    RECOVERY_MIN_RESPONSE_SECONDS로 같아지게 맞춘다(타이밍 사이드채널 방지).
    복구 요청(routes/recovery.py, guide34-a)과 비밀번호 찾기 요청(routes/password.py, guide41)이
    같은 이유로 이 함수를 쓴다 — 그래서 한 라우트 파일이 다른 라우트 파일을 import하지 않도록
    공용 helpers로 옮겼다.

    "아이디 없음"은 DB 조회 한두 번으로 끝나고 "실제 복구 메일"은 조회 여러 번 + SMTP까지
    거치므로, 그냥 두면 응답 시간 차이로 아이디 존재 여부가 드러난다.

    - 기본(RECOVERY_BACKGROUND_WORK=false): 요청 안에서 처리(메일 발송 포함)를 끝낸 뒤
      남은 시간만큼 기다리고 응답한다. Vercel 같은 서버리스는 응답을 보내는 순간 함수를
      멈추므로, 메일 발송을 응답 뒤로 미루면 끝나기 전에 끊길 수 있다.
    - RECOVERY_BACKGROUND_WORK=true(상시 실행 서버): 처리를 스레드로 돌리고 고정 시간까지만
      기다린 뒤 응답한다(처리가 더 걸리면 응답 뒤에도 스레드가 마무리한다).
    - 고정 시간이 0이면(테스트) 기다림 없이 그 자리에서 처리한다.

    어느 쪽이든 처리 중 예외는 로그만 남기고 삼킨다 — 예외가 500으로 새면 "이 아이디는
    처리 중 오류가 났다"는 신호가 되어 계정 존재 여부가 드러난다.

    고정 시간이 0보다 크면 처리가 끝난 시점까지 걸린 시간을 `[timing]` 로그로 남긴다(guide43).
    """
    target = config.RECOVERY_MIN_RESPONSE_SECONDS
    path = request.path if has_request_context() else "-"

    def safe_work():
        # 서버리스에서 한동안 쉬던 DB 연결을 재사용하면 첫 요청이 "Server disconnected" 같은
        # 일시적 전송 오류로 실패한다(실제 배포 테스트에서 복구 요청이 이 오류로 조용히 사라졌다).
        # 이런 오류만 한 번 더 시도한다 — work()는 메일을 보내기 전까지의 DB 작업이 다시 해도
        # 안전하게 짜여 있고(기존 PENDING 요청을 취소하고 새로 만든다), 메일 발송 실패는
        # mailer가 예외 없이 처리하므로 재시도해도 메일이 두 번 나가지 않는다.
        for attempt in (1, 2):
            try:
                work()
                return
            except httpx.TransportError as e:
                if attempt == 1:
                    continue
                report_internal_error(e)
            except Exception as e:  # noqa: BLE001
                report_internal_error(e)
            return

    if target <= 0:
        safe_work()
        return

    def timed_work():
        safe_work()
        _log_timing(path, time.monotonic() - started, target)

    if config.RECOVERY_BACKGROUND_WORK:
        thread = threading.Thread(target=timed_work, daemon=True)
        thread.start()
        thread.join(timeout=max(0.0, target - (time.monotonic() - started)))
    else:
        timed_work()

    remaining = target - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)
