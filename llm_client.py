# ============================================================================
# llm_client.py — Groq(LLM) 호출을 담당하는 유일한 창구 (Track A, guide31)
#
# 원래 scripts/daily_report.py 안에만 있던 Groq 호출 로직(재시도, 타임아웃,
# 에러 처리)을 이 파일로 옮겨 일반화했다. daily_report.py의 "하루치 리포트
# 요약"과 soar.py의 "임계값 코앞 조기 경보 판단"이 똑같은 Groq 호출 부품을
# 재사용하게 된다 — db.py가 "데이터베이스와 대화하는 유일한 창구"인 것과
# 같은 원칙으로, 이 파일이 "Groq와 대화하는 유일한 창구"가 된다.
# ============================================================================

import json
import os
import time

import requests

# 2026년 9월 기준 Groq 무료 등급에서 쓸 수 있는 모델. daily_report.py가 원래
# Gemini에서 Groq로 교체한 이유(무료 등급 응답 지연/실패)는 그대로 유지된다.
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "openai/gpt-oss-120b"
GROQ_REQUEST_TIMEOUT = 20
GROQ_MAX_RETRIES = 3
GROQ_RETRY_DELAY_SECONDS = 3


def ask_groq(prompt: str, *, json_mode: bool = False) -> str:
    """Groq에게 프롬프트 하나를 보내고, 답변 텍스트를 그대로 돌려준다.

    daily_report.py의 generate_ai_summary()에 있던 재시도(429/5xx/타임아웃)·
    에러 처리 로직을 그대로 옮겨왔다 — 동작은 바뀌지 않았다.

    json_mode=True면 Groq에게 "반드시 JSON 객체 하나로만 답하라"고 강제한다
    (OpenAI 호환 API의 response_format 옵션). soar.consider_early_warning()처럼
    "risky/reason" 같은 정해진 필드를 코드로 그대로 읽어야 하는 호출에 쓰인다 —
    daily_report.py의 자유 서술형 요약은 이 옵션 없이 그대로 문장을 받는다.

    API 키가 없거나 호출이 끝내 실패하면 RuntimeError/requests.RequestException을
    던진다 — 호출하는 쪽이 "AI가 지금 못 쓰는 상태"를 어떻게 다룰지(전체 기능을
    멈출지, 조용히 건너뛸지)는 이 함수의 책임이 아니라 호출부의 책임이다.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY가 설정되어 있지 않습니다. "
            ".env 파일에 GROQ_API_KEY=발급받은키 형식으로 추가하세요."
        )

    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    for attempt in range(1, GROQ_MAX_RETRIES + 1):
        try:
            response = requests.post(
                GROQ_API_URL, headers=headers, json=payload, timeout=GROQ_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            break
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as error:
            is_retryable_http_error = (
                isinstance(error, requests.exceptions.HTTPError)
                and error.response is not None
                and error.response.status_code in (429, 500, 502, 503, 504)
            )
            is_last_attempt = attempt == GROQ_MAX_RETRIES
            if is_last_attempt or not (
                isinstance(error, requests.exceptions.Timeout) or is_retryable_http_error
            ):
                raise
            time.sleep(GROQ_RETRY_DELAY_SECONDS)

    data = response.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as error:
        raise RuntimeError(f"Groq 응답 형식을 해석하지 못했습니다: {error}") from error


def judge_early_warning(
    label: str, target_kind: str, target_value: str, count: int, threshold: int
) -> dict | None:
    """"임계값을 아직 안 넘었지만 코앞인" 상황을 Groq에게 보여주고, 지금 미리
    지켜볼 필요가 있는지 판단을 받아온다 (Track A, guide31).

    soar.consider_early_warning()이 이 함수의 유일한 호출부다 — 이 함수 자체는
    "판단 결과를 어떻게 쓸지"(access_requests에 등록할지 등)는 전혀 모르고,
    그저 "위험해 보이는가/왜 그런가"만 answering해서 돌려준다(detector.py가
    판단만 하고 조치는 soar.py에 맡기는 것과 같은 분리 원칙).

    반환값은 {"risky": bool, "reason": str} 또는, API 키가 없거나 호출/응답
    해석에 실패하면 None이다. None을 받은 쪽(soar.py)은 "아직 규칙이 발동하지
    않은 원래 사각지대로 그냥 남겨두고 조용히 넘어간다" — 이 조기 경보 기능은
    "원래 없던 걸 덤으로 추가하는" 성격이라, 실패해도 예외를 전파해 로그인
    흐름 자체를 막으면 안 된다.
    """
    prompt = (
        "너는 웹 서비스 로그인 보안 모니터링 시스템의 보조 판단 에이전트다.\n"
        f"지금 '{target_kind}' 대상 '{target_value}'에서 '{label}' 패턴이 "
        f"관찰되고 있다. 정해진 자동 대응 기준치는 {threshold}회인데, 아직 "
        f"기준치를 넘지 않은 {count}회 상태다(규칙 기반 시스템은 아직 아무 "
        "조치도 하지 않는다).\n"
        "이 정도 수치만으로 미리 관리자에게 확인을 요청할 만큼 위험해 보이는지 "
        "판단해줘. 지금 즉시 위험하다고 보기보다는, 기준치를 살짝 피해 가려는 "
        "의도적인 패턴일 가능성이 있는지를 중심으로 판단해줘.\n"
        '반드시 다음 JSON 형식으로만 답해: {"risky": true 또는 false, '
        '"reason": "한국어로 1~2문장의 판단 근거"}'
    )

    try:
        raw_reply = ask_groq(prompt, json_mode=True)
        judgment = json.loads(raw_reply)
        return {"risky": bool(judgment["risky"]), "reason": str(judgment["reason"])}
    except (RuntimeError, requests.RequestException, json.JSONDecodeError, KeyError, TypeError):
        return None
