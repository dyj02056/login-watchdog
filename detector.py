# ============================================================================
# detector.py — "판사" 역할: 지금 이 IP가 수상한지, 지금 잠겨있는지만 판단한다
#
# 이 파일은 데이터베이스의 상태를 절대 바꾸지 않는다(아무것도 저장/수정/삭제하지 않음).
# 오직 db.py에게 "지금 상태가 어때?"라고 물어보고, 그 답을 바탕으로
# True/False 같은 "판정 결과"만 돌려준다.
#
# 실제로 잠그거나 알림을 보내는 "실행"은 이 파일이 아니라 soar.py가 담당한다
# (판단과 실행을 분리해두면, "판단 기준만 바꾸고 싶다" 같은 수정이 훨씬 쉬워진다).
# 여기에 쓸줄은 몰랐겠지. 내이름은 코난 해적이죠
# ============================================================================

import db
from config import FAILURE_THRESHOLD


def is_suspicious(ip: str) -> tuple[bool, int]:
    """이 IP가 "수상한 상태"인지 판단한다.

    판단 기준: 최근 60초(config.DETECTION_WINDOW_SECONDS) 안에 실패한 횟수가
    기준치(FAILURE_THRESHOLD, 기본 5회)를 "초과"했는가?

    반환값은 (수상한가?, 실제 실패 횟수) 형태의 튜플(값 2개를 한 번에 묶어서 돌려주는 것).
    예: (True, 6)  → "수상함, 지금까지 6번 실패했음"
        (False, 3) → "아직 수상하지 않음, 3번 실패했음"
    """
    failure_count = db.count_recent_failures(ip)
    return failure_count > FAILURE_THRESHOLD, failure_count


def is_locked(ip: str) -> bool:
    """이 IP가 지금 이 순간 잠긴 상태인지 True/False로 알려준다.

    실제 "잠겨있는지" 판단은 db.get_active_lockout()이 이미 하고 있으므로
    (active=True 이면서 아직 풀릴 시각이 안 지난 것만 찾아줌),
    여기서는 그 결과가 있는지(None이 아닌지)만 확인한다.
    """
    return db.get_active_lockout(ip) is not None
