# ============================================================================
# test_early_warning.py — LLM 조기 경보(Track A, guide31) 단위 테스트
#
# test_soar.py와 동일한 원칙 — 진짜 Groq/Supabase를 부르지 않고, "호출된 사실을
# 기록만 해두는 가짜 함수"로 바꿔치기해서 soar.py/llm_client.py의 판단·분기
# 로직만 확인한다.
# ============================================================================

import json

import alert
import db
import llm_client
import soar


# ============================================================================
# llm_client.judge_early_warning() — Groq 응답 파싱
# ============================================================================

def test_judge_early_warning_parses_risky_json_response(monkeypatch):
    monkeypatch.setattr(
        llm_client,
        "ask_groq",
        lambda prompt, json_mode=False, temperature=None, system=None: json.dumps(
            {"risky": True, "reason": "의심됨"}
        ),
    )

    result = llm_client.judge_early_warning("로그인 브루트포스(IP)", "ip", "1.2.3.4", 4, 5)

    assert result == {"risky": True, "reason": "의심됨"}


def test_judge_early_warning_passes_temperature_and_system_prompt(monkeypatch):
    # 같은 입력에 항상 같은 결론이 나오도록 temperature를 낮게 고정하고,
    # 프롬프트 인젝션 방어용 system 메시지를 함께 보내는지 확인한다
    # (로컬 시뮬레이션에서 temperature 미지정 시 risky 값이 뒤집히는 걸 확인한 뒤 추가).
    calls = []

    def fake_ask_groq(prompt, json_mode=False, temperature=None, system=None):
        calls.append((json_mode, temperature, system))
        return json.dumps({"risky": False, "reason": "정상"})

    monkeypatch.setattr(llm_client, "ask_groq", fake_ask_groq)

    llm_client.judge_early_warning("로그인 브루트포스(IP)", "ip", "1.2.3.4", 4, 5)

    assert calls[0][0] is True
    assert calls[0][1] == llm_client._JUDGE_TEMPERATURE
    assert calls[0][1] < 0.5
    assert calls[0][2] == llm_client._JUDGE_SYSTEM_PROMPT


def test_judge_early_warning_includes_context_and_history_in_prompt(monkeypatch):
    # context_count/path/prior_occurrences가 실제로 프롬프트 본문에 반영되는지
    # 확인한다 — 처음 버전은 이 값들을 계산해두고도 프롬프트에는 넣지 않고 있었다.
    captured_prompts = []

    def fake_ask_groq(prompt, json_mode=False, temperature=None, system=None):
        captured_prompts.append(prompt)
        return json.dumps({"risky": False, "reason": "정상"})

    monkeypatch.setattr(llm_client, "ask_groq", fake_ask_groq)

    llm_client.judge_early_warning(
        "Web Scanning", "ip", "9.9.9.9", 8, 10, path="/admin/.env", context_count=3, prior_occurrences=2,
    )

    prompt = captured_prompts[0]
    assert "/admin/.env" in prompt
    assert "3" in prompt
    assert "2번" in prompt


def test_judge_early_warning_truncates_and_labels_untrusted_input(monkeypatch):
    # 공격자가 로그인 아이디 칸에 넣은 값이 그대로 프롬프트에 삽입되는 지점이라,
    # 길이가 제한되고 "신뢰할 수 없는 데이터" 구간 안에 들어가는지 확인한다.
    captured_prompts = []

    def fake_ask_groq(prompt, json_mode=False, temperature=None, system=None):
        captured_prompts.append(prompt)
        return json.dumps({"risky": False, "reason": "정상"})

    monkeypatch.setattr(llm_client, "ask_groq", fake_ask_groq)

    huge_username = "a" * 500
    llm_client.judge_early_warning("계정 단위 분산 브루트포스", "account", huge_username, 6, 8)

    prompt = captured_prompts[0]
    assert huge_username not in prompt  # 잘려나가서 원본 그대로는 들어가지 않아야 함
    assert "...(생략)" in prompt
    assert "신뢰할 수 없는 사용자 입력" in prompt


def test_judge_early_warning_returns_none_when_groq_call_fails(monkeypatch):
    def _raise(*args, **kwargs):
        raise RuntimeError("GROQ_API_KEY가 설정되어 있지 않습니다.")

    monkeypatch.setattr(llm_client, "ask_groq", _raise)

    assert llm_client.judge_early_warning("로그인 브루트포스(IP)", "ip", "1.2.3.4", 4, 5) is None


def test_judge_early_warning_returns_none_on_malformed_json(monkeypatch):
    monkeypatch.setattr(
        llm_client, "ask_groq", lambda prompt, json_mode=False, temperature=None, system=None: "이건 JSON이 아니다"
    )

    assert llm_client.judge_early_warning("로그인 브루트포스(IP)", "ip", "1.2.3.4", 4, 5) is None


# ============================================================================
# soar.consider_early_warning() — 판단 결과에 따른 분기
# ============================================================================

def test_consider_early_warning_skips_when_already_pending(monkeypatch):
    monkeypatch.setattr(db, "get_pending_request", lambda event_type, kind, value: {"request_id": 1})

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("이미 PENDING 요청이 있는데 LLM을 또 호출했다")

    monkeypatch.setattr(llm_client, "judge_early_warning", _fail_if_called)

    soar.consider_early_warning("BRUTE_FORCE", "LOCK_IP", "ip", "1.2.3.4", 4, 5)


def test_consider_early_warning_does_nothing_when_llm_says_not_risky(monkeypatch):
    monkeypatch.setattr(db, "get_pending_request", lambda event_type, kind, value: None)
    monkeypatch.setattr(db, "count_recent_requests_for_target", lambda *a, **k: 0)
    monkeypatch.setattr(llm_client, "judge_early_warning", lambda *a, **k: {"risky": False, "reason": "정상"})

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("위험하지 않다고 판단했는데 PENDING 요청이 등록되었다")

    monkeypatch.setattr(db, "insert_pending_request", _fail_if_called)

    soar.consider_early_warning("BRUTE_FORCE", "LOCK_IP", "ip", "1.2.3.4", 4, 5)


def test_consider_early_warning_does_nothing_when_llm_call_fails(monkeypatch):
    # llm_client.judge_early_warning()이 실패 시 예외 대신 None을 돌려주므로,
    # 이 구간은 원래 아무 조치도 없던 사각지대로 조용히 남는다.
    monkeypatch.setattr(db, "get_pending_request", lambda event_type, kind, value: None)
    monkeypatch.setattr(db, "count_recent_requests_for_target", lambda *a, **k: 0)
    monkeypatch.setattr(llm_client, "judge_early_warning", lambda *a, **k: None)

    def _fail_if_called(*args, **kwargs):
        raise AssertionError("LLM 호출이 실패했는데 PENDING 요청이 등록되었다")

    monkeypatch.setattr(db, "insert_pending_request", _fail_if_called)

    soar.consider_early_warning("BRUTE_FORCE", "LOCK_IP", "ip", "1.2.3.4", 4, 5)


def test_consider_early_warning_registers_request_and_alerts_when_risky(monkeypatch):
    monkeypatch.setattr(db, "get_pending_request", lambda event_type, kind, value: None)
    monkeypatch.setattr(db, "count_recent_requests_for_target", lambda *a, **k: 0)
    judge_calls = []
    monkeypatch.setattr(
        llm_client,
        "judge_early_warning",
        lambda *a, **k: judge_calls.append((a, k)) or {"risky": True, "reason": "임계값을 피해가려는 패턴"},
    )
    insert_calls = []
    monkeypatch.setattr(
        db,
        "insert_pending_request",
        lambda *args, **kwargs: insert_calls.append((args, kwargs)),
    )
    alert_calls = []
    monkeypatch.setattr(
        alert,
        "send_pending_approval_alert",
        lambda *args: alert_calls.append(args),
    )

    soar.consider_early_warning(
        "BRUTE_FORCE", "LOCK_IP", "ip", "1.2.3.4", 4, 5, context_count=2,
    )

    assert insert_calls[0][0] == (
        "BRUTE_FORCE", "LOCK_IP", "ip", "1.2.3.4", 4, 5, "임계값을 피해가려는 패턴",
    )
    assert insert_calls[0][1] == {"path": None, "context_count": 2, "context_ip": None}
    assert alert_calls == [("로그인 브루트포스(IP)", "ip", "1.2.3.4", 4, 5, "임계값을 피해가려는 패턴")]
    # soar.py가 이미 계산해둔 context_count와, db에서 조회한 이력(prior_occurrences)이
    # 실제로 judge_early_warning() 호출에 전달되는지 확인한다 — 처음 버전은 이
    # 값들을 계산해두고도 LLM에게는 넘기지 않고 있었다.
    assert judge_calls[0][1] == {"path": None, "context_count": 2, "prior_occurrences": 0}


# ============================================================================
# soar.execute_approved_request() / reject_pending_request()
# ============================================================================

def _base_request(**overrides):
    request = {
        "request_id": 1,
        "status": "PENDING",
        "event_type": "BRUTE_FORCE",
        "pending_action": "LOCK_IP",
        "target_kind": "ip",
        "target_value": "1.2.3.4",
        "path": None,
        "count": 4,
        "threshold": 5,
        "context_count": 2,
        "context_ip": None,
        "llm_reason": "의심됨",
    }
    request.update(overrides)
    return request


def test_execute_approved_request_returns_false_when_not_pending(monkeypatch):
    monkeypatch.setattr(db, "get_request", lambda request_id: None)

    assert soar.execute_approved_request(1, 99) is False


def test_execute_approved_request_runs_lock_ip_action(monkeypatch):
    monkeypatch.setattr(db, "get_request", lambda request_id: _base_request())
    lock_calls = []
    monkeypatch.setattr(soar, "enforce_lockout", lambda ip, count, distinct: lock_calls.append((ip, count, distinct)))
    monkeypatch.setattr(db, "decide_request", lambda request_id, decision, admin_id: True)

    assert soar.execute_approved_request(1, 99) is True
    assert lock_calls == [("1.2.3.4", 4, 2)]


def test_execute_approved_request_runs_lock_account_action(monkeypatch):
    request = _base_request(
        event_type="DISTRIBUTED_BRUTE_FORCE", pending_action="LOCK_ACCOUNT",
        target_kind="account", target_value="victim", context_ip="9.9.9.9",
    )
    monkeypatch.setattr(db, "get_request", lambda request_id: request)
    lock_calls = []
    monkeypatch.setattr(
        soar,
        "enforce_account_lockout",
        lambda username, count, distinct, triggering_ip: lock_calls.append(
            (username, count, distinct, triggering_ip)
        ),
    )
    monkeypatch.setattr(db, "decide_request", lambda request_id, decision, admin_id: True)

    assert soar.execute_approved_request(1, 99) is True
    assert lock_calls == [("victim", 4, 2, "9.9.9.9")]


def test_execute_approved_request_runs_alert_only_action(monkeypatch):
    request = _base_request(
        event_type="WEB_SCANNING", pending_action="ALERT_ONLY", path="/no-such-page",
    )
    monkeypatch.setattr(db, "get_request", lambda request_id: request)
    notify_calls = []
    monkeypatch.setattr(
        soar, "notify_web_scanning", lambda ip, count, path: notify_calls.append((ip, count, path))
    )
    monkeypatch.setattr(db, "decide_request", lambda request_id, decision, admin_id: True)

    assert soar.execute_approved_request(1, 99) is True
    assert notify_calls == [("1.2.3.4", 4, "/no-such-page")]


def test_reject_pending_request_does_not_run_any_action(monkeypatch):
    decide_calls = []
    monkeypatch.setattr(
        db, "decide_request", lambda request_id, decision, admin_id: decide_calls.append((request_id, decision, admin_id)) or True
    )

    assert soar.reject_pending_request(1, 99) is True
    assert decide_calls == [(1, "REJECTED", 99)]
