# ============================================================================
# security/soar/early_warning.py — LLM 조기 경보와 관리자 승인/반려 (Track A, guide31)
#
# 예전 soar.py(497줄)를 기능 묶음별로 나눈 조각 중 하나다. 다른 파일은 이 파일을 직접
# 가리키지 않고 예전처럼 `from security import soar` 후 `soar.enforce_lockout(...)`으로
# 쓴다(security/soar/__init__.py가 재내보내기). 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================

import db
from notify import alert
from security import lockdown, soar
from services import llm_client


# ============================================================================
# LLM 조기 경보 (Track A, guide31)
#
# lockouts.py의 enforce_*()와 observe.py의 notify_*() 함수들은 전부 "규칙이 임계값을 넘었다고
# 이미 확정 판단을 내린 뒤"에만 호출된다. 이 구간의 함수들은 그 반대 —
# "아직 임계값을 못 넘었지만 코앞(config.EARLY_WARNING_BAND)인" 원래 아무
# 조치도 없던 사각지대에서, LLM에게 "지켜볼 필요가 있는지" 한 번 더 물어보고
# 위험하면 access_requests에 관리자 승인 대기 요청을 남긴다.
#
# 임계값을 이미 넘은 경우는 이 구간을 거치지 않는다 — 규칙이 이미 검증을
# 끝낸 확정 판단이므로 LLM이 다시 판단할 이유도, 응답을 기다리며 대응을
# 늦출 이유도 없다(login_watchdog_expansion_plan.md 논의 참고).
# ============================================================================

_EARLY_WARNING_LABELS = {
    "BRUTE_FORCE": "로그인 브루트포스(IP)",
    "DISTRIBUTED_BRUTE_FORCE": "계정 단위 분산 브루트포스",
    "SIGNUP_RATE_LIMIT": "회원가입 남용",
    "WEB_SCANNING": "Web Scanning",
    "UNAUTHORIZED_ACCESS": "Unauthorized Access",
    "PAGE_ACCESS": "반복 페이지 접근",
    "API_MACRO_PATTERN": "매크로/봇 패턴",
    "SIEM_HIGH_INCIDENT": "SIEM HIGH 사건 → 영구 잠금",
}


def consider_early_warning(
    event_type: str,
    pending_action: str,
    target_kind: str,
    target_value: str,
    count: int,
    threshold: int,
    path: str | None = None,
    context_count: int | None = None,
    context_ip: str | None = None,
) -> None:
    """임계값 코앞 구간에 진입한 대상 하나를 LLM에게 보여주고, 위험하다고
    판단되면 access_requests에 PENDING 요청을 등록한다.

    호출부(routes/auth.py, helpers/auth.py, helpers/hooks.py)는 전부 "아직 suspicious가
    False인" 분기에서만 이 함수를 부른다 — 이미 규칙이 조치를 실행하는
    경우와 절대 겹치지 않는다.

    LLM 쪽이 실패해도 예외를 밖으로 던지지 않는다: LLM 호출이 실패하거나
    GROQ_API_KEY가 없으면(llm_client.judge_early_warning이 None을 돌려줌)
    그냥 조용히 넘어간다. 이 구간은 원래 Track A 이전에는 아무 조치도 없던
    사각지대였으므로, "덤으로 추가한 조기 경보 기능"이 실패한다고 해서
    로그인 흐름 자체가 막히거나 원래 있던 임계값 기반 방어가 약해지면
    안 되기 때문이다.

    같은 (event_type, target_kind, target_value)에 이미 PENDING 요청이 있으면
    새로 LLM을 호출하지 않는다 — 관리자가 하나를 처리하기 전까지 매 요청마다
    Groq를 부르고 Slack을 또 보내는 건 낭비이자 알림 피로다.

    path/context_count/context_ip는 유형마다 의미가 다르다 — LOCK_IP(로그인
    브루트포스)는 context_count에 distinct_usernames를, LOCK_ACCOUNT(분산
    브루트포스)는 context_count에 distinct_ips·context_ip에 이번 시도의 IP를,
    ALERT_ONLY 유형들은 path에 관련 경로를 담아 나중에 execute_approved_request()가
    승인 시 실행할 조치에 그대로 넘겨준다. path/context_count는 access_requests에
    저장하는 용도와 별개로, llm_client.judge_early_warning()에게 판단 근거로도
    그대로 전달한다 — 처음 버전은 이 값들을 계산해두고도 LLM에게는 안 보여주고
    있었다(login_watchdog_expansion_plan.md 논의).
    """
    if db.get_pending_request(event_type, target_kind, target_value) is not None:
        return

    label = _EARLY_WARNING_LABELS.get(event_type, event_type)
    prior_occurrences = db.count_recent_requests_for_target(event_type, target_kind, target_value)
    judgment = llm_client.judge_early_warning(
        label, target_kind, target_value, count, threshold,
        path=path, context_count=context_count, prior_occurrences=prior_occurrences,
    )
    if judgment is None or not judgment.get("risky"):
        return

    reason = judgment.get("reason", "")
    db.insert_pending_request(
        event_type,
        pending_action,
        target_kind,
        target_value,
        count,
        threshold,
        reason,
        path=path,
        context_count=context_count,
        context_ip=context_ip,
    )
    alert.send_pending_approval_alert(label, target_kind, target_value, count, threshold, reason)


# ALERT_ONLY 요청이 승인됐을 때 실행할 조치 — 이 유형들이 실제로 임계값을
# 넘었을 때 이미 호출하는 notify_*()/record_rejection()을 그대로 재사용한다
# (위 조기 경보 설계 원칙: "그 유형이 원래 하던 조치를 조금 더 일찍 실행"할
# 뿐, 새로운 조치를 만들지 않는다). security/correlate.py의 PLAYBOOKS와 같은 이유로
# 함수를 람다로 감싸고 soar 패키지 속성(soar.notify_web_scanning)으로 호출 시점에
# 찾게 해서, 테스트에서 monkeypatch.setattr(soar, "notify_web_scanning", ...)로
# 바꿔치기한 게 그대로 반영되게 한다(다른 파일인 observe.py의 함수를 이름만으로
# 가져오면 바꿔치기 전의 원래 함수를 계속 부르게 된다).
_ALERT_ONLY_DISPATCH = {
    "SIGNUP_RATE_LIMIT": lambda r: soar.record_rejection(
        "SIGNUP_RATE_LIMIT", r["target_value"], r["path"] or "/signup", r["count"]
    ),
    "WEB_SCANNING": lambda r: soar.notify_web_scanning(r["target_value"], r["count"], r["path"] or "-"),
    "UNAUTHORIZED_ACCESS": lambda r: soar.notify_unauthorized_access(
        r["target_value"], r["count"], r["path"] or "-"
    ),
    "PAGE_ACCESS": lambda r: soar.notify_page_access(r["target_value"], r["count"], r["path"] or "-"),
    "API_MACRO_PATTERN": lambda r: soar.notify_macro_pattern(r["target_value"], r["count"]),
}


def _run_pending_action(request: dict) -> None:
    """승인이 확정되기 직전에, 이 요청의 pending_action에 맞는 실제 조치를 실행한다."""
    pending_action = request["pending_action"]
    if pending_action == "LOCK_IP":
        soar.enforce_lockout(request["target_value"], request["count"], request["context_count"] or 1)
    elif pending_action == "LOCK_ACCOUNT":
        soar.enforce_account_lockout(
            request["target_value"],
            request["count"],
            request["context_count"] or 1,
            request["context_ip"] or "-",
        )
    elif pending_action == "ALERT_ONLY":
        _ALERT_ONLY_DISPATCH[request["event_type"]](request)
    elif pending_action == "PERMANENT_LOCK_IP":
        # SIEM HIGH 사건을 관리자가 승인했다(PERMANENT_LOCK_AUTO_ON_HIGH=false 경로, guide33 T4).
        lockdown.promote_ip(request["target_value"], "SIEM_HIGH", "EXEMPTION")


def execute_approved_request(request_id: int, admin_id: int) -> bool:
    """관리자가 대시보드 "AI 조기 경보" 표에서 "승인" 버튼을 눌렀을 때 실행된다.

    순서: 1) 요청이 아직 PENDING인지 확인 2) 그 유형이 원래 하던 조치를
    지금 실행 3) db.decide_request()로 APPROVED 확정.

    조치 실행과 상태 확정 사이가 완전한 원자적 트랜잭션은 아니다(db/_client.py
    설명 참고 — 이 프로젝트는 Supabase REST API를 통하므로 파이썬에서 진짜
    트랜잭션을 걸 수 없다). 다만 두 관리자가 "거의 동시에" 같은 요청을 두 번
    승인하는 극히 드문 경쟁 조건이 이 함수의 마지막 db.decide_request() 단계
    에서는 걸러지므로(두 번째 호출은 status가 이미 바뀌어 있어 False를 받음),
    실제 조치가 중복 실행될 위험은 "완전히 동시에 눌렀을 때"로 한정된다.
    """
    request = db.get_request(request_id)
    if request is None or request["status"] != "PENDING":
        return False

    _run_pending_action(request)
    return db.decide_request(request_id, "APPROVED", admin_id)


def reject_pending_request(request_id: int, admin_id: int) -> bool:
    """관리자가 "반려" 버튼을 눌렀을 때 실행된다.

    아무 조치도 실행하지 않고 상태만 REJECTED로 바꾼다 — 이 구간은 원래
    규칙이 아무 것도 하지 않던 사각지대였으므로, 반려는 "AI의 조기 경보를
    기각하고 원래 상태(관찰만 계속)로 되돌린다"는 뜻이다.
    """
    return db.decide_request(request_id, "REJECTED", admin_id)
