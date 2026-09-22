# ============================================================================
# daily_report.py — 지정한 시간 범위(최근 N시간, 또는 특정 시작~종료 시각) 동안의
# 로그인 시도/잠금 현황을 사람이 읽을 수 있는 텍스트 리포트로 만들어서,
# 화면에 출력하거나 파일로 저장하는 스크립트.
#
# 원래 기획서(research.md 질문 8)는 "LLM(AI)이 로그를 읽고 자연어로 요약해주는
# 리포트"를 그리고 있었지만, 처음엔 프롬프트 설계·모델 선택 등 세부 사양이
# 정해지지 않아 "AI 요약 없이도 바로 쓸 수 있는 숫자 집계 리포트"만 먼저
# 만들어뒀었다. 이 버전에서는 그 AI 요약 기능을 실제로 이어붙였다:
#   - --ai 옵션을 주면 Groq API를 호출해서 리포트 내용을 바탕으로 한국어
#     보안 총평을 만들고, 그 총평을 리포트 맨 아래에 추가로 붙여준다.
#   - --start/--end 옵션으로 "이 시간대에 무슨 일이 있었는지"처럼 특정
#     기간만 정밀하게 뽑아서 AI에게 넘길 수 있다(전체 기록을 통째로 주는
#     것보다 정확하고 효율적이다).
#   - --output 옵션으로 리포트를 파일로 저장할 수 있다(발표 자료나 증빙
#     자료로 보관하거나, 나중에 다른 곳에 첨부할 때 쓴다).
#
# 담당 범위: 이 스크립트는 "이미 쌓여있는 로그 데이터를 모아서 보여주는"
# 역할만 한다 — 탐지 자체(누가 공격인지 판단하는 로직)는 detector.py가,
# 실시간 알림은 alert.py/soar.py가 담당한다.
# ============================================================================

import argparse
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

# 이 스크립트는 scripts/ 폴더 안에 있어서, "python scripts/daily_report.py"로
# 실행하면 파이썬이 기본적으로 scripts/ 폴더 안에서만 다른 파일(모듈)을 찾는다.
# db 패키지는 프로젝트 루트(scripts/의 부모 폴더)에 있으므로, 그 루트 폴더를
# sys.path(파이썬이 모듈을 찾아보는 폴더 목록)에 직접 추가해줘야 "import db"가
# 이 스크립트를 어느 위치에서 실행하든 항상 성공한다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# .env 파일에 적어둔 값들(SUPABASE_URL, GROQ_API_KEY 등)을 환경변수로 읽어온다.
# 아래에서 db를 import하기 전에 반드시 먼저 실행해야 한다 — db 모듈이 켜지자마자
# SUPABASE_URL 같은 값을 곧바로 읽어가기 때문이다.
load_dotenv()

import db  # noqa: E402  (load_dotenv()가 SUPABASE_URL 등을 먼저 읽어들인 뒤에 import 해야 함)


# Groq(전용 LPU 하드웨어로 추론 속도가 매우 빠른 AI 추론 서비스)에게 요약을
# 요청할 때 쓰는 주소. Groq는 OpenAI와 같은 형식의 REST API(Chat Completions)를
# 그대로 제공해서, 별도 SDK 없이 이 프로젝트가 이미 쓰는 requests로 바로
# 호출할 수 있다.
#
# 원래는 Google Gemini(gemini-3.6-flash → gemini-flash-lite-latest)를 썼지만,
# 무료 등급 응답이 24~45초씩 걸리거나 "고수요(503)"로 자주 실패해서(구글 쪽
# 서버 사정, 우리 코드 문제가 아니었다) Groq로 교체했다. Groq는 전용 하드웨어
# 덕분에 보통 1~2초 안에 응답이 오고, 카드 등록 없이 영구적으로 무료다.
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
# 2026년 9월 기준 Groq 무료 등급에서 쓸 수 있는 모델 중 하나. Llama 계열은
# 2026년 8월부로 무료 등급에서 빠졌고, 지금은 openai/gpt-oss-* 나 qwen 계열이
# 무료로 제공된다. Groq 콘솔(console.groq.com/docs/models)에서 최신 무료
# 모델 목록을 확인할 수 있다.
GROQ_MODEL = "openai/gpt-oss-120b"
# Groq는 원래도 빠르지만(보통 1~2초), 드물게 느려질 수 있으니 여유 있게 잡았다.
GROQ_REQUEST_TIMEOUT = 20
# 일시적인 오류(429 요청 과다, 5xx 서버 오류)를 만났을 때 몇 번까지 다시
# 시도할지, 재시도 사이에 몇 초 쉴지.
GROQ_MAX_RETRIES = 3
GROQ_RETRY_DELAY_SECONDS = 3


def generate_ai_summary(report_text: str) -> str:
    """이미 만들어진 리포트 텍스트를 Groq에게 보내서, 한국어로 된
    짧은 "보안 총평"을 받아온다.

    API 키는 코드에 직접 적지 않고 .env 파일의 GROQ_API_KEY 환경변수에서만
    읽는다(비밀번호처럼 다뤄야 하는 값이라 소스코드에 남기면 안 된다 — 실수로
    깃허브에 올라가면 누구나 그 키로 내 계정의 API 사용량을 써버릴 수 있다).
    키가 없거나 API 호출이 실패하면 예외를 던진다 — 이 함수를 부르는 쪽(main())
    에서 그 예외를 잡아서, 실패해도 "AI 요약만 빠진 리포트"를 대신 보여줄 수
    있게 설계했다(AI가 잠깐 안 된다고 리포트 전체를 못 보면 안 되니까).
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY가 설정되어 있지 않습니다. "
            ".env 파일에 GROQ_API_KEY=발급받은키 형식으로 추가하세요."
        )

    # Groq(및 대부분의 OpenAI 호환 API)에게 "무엇을, 어떤 톤으로 써달라"고
    # 요청하는 지시문(프롬프트). 방금 만든 리포트 텍스트를 통째로 붙여서,
    # 그 내용을 바탕으로 요약하게 한다.
    prompt = (
        "다음은 웹 서비스의 로그인 보안 모니터링 시스템이 집계한 리포트다.\n"
        "보안 지식이 없는 사람도 이해할 수 있는 쉬운 한국어로, 3~5문장 분량의 "
        "간결한 보안 총평을 작성해줘. 숫자를 단순히 반복하기보다는 지금 상황이 "
        "정상적인지, 주의가 필요한 부분이 있다면 무엇인지를 중심으로 설명해줘.\n\n"
        f"{report_text}"
    )

    # Groq API는 OpenAI Chat Completions와 같은 형식을 쓴다: messages 배열에
    # role(누가 말하는지)과 content(내용)를 담아 보낸다. 인증은 구글과 달리
    # URL이 아니라 Authorization 헤더에 "Bearer <키>" 형태로 넣는다.
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
    }

    # 429(요청 과다)나 5xx(서버 오류), 타임아웃을 만나면 곧바로 포기하지 않고
    # 짧게 쉬었다가 최대 GROQ_MAX_RETRIES번까지 다시 시도한다. Groq는 대체로
    # 안정적이지만, 만약을 대비해 Gemini 때와 같은 재시도 구조를 유지했다.
    for attempt in range(1, GROQ_MAX_RETRIES + 1):
        try:
            response = requests.post(
                GROQ_API_URL, headers=headers, json=payload, timeout=GROQ_REQUEST_TIMEOUT
            )
            # 상태 코드가 400번대/500번대(에러)면 여기서 바로 예외를 던지게 한다.
            # 이걸 안 하면 에러 응답의 이상한 내용을 정상 응답인 것처럼 잘못 읽어버릴 수 있다.
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
        # OpenAI 호환 API 응답은 choices(후보 답변들) 중 첫 번째의 message
        # 안의 content(글자) 값에 실제 답변 텍스트가 들어있다.
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as error:
        # 응답은 정상(200)으로 왔지만 구조가 예상과 다르면 여기서 걸러낸다.
        raise RuntimeError(f"Groq 응답 형식을 해석하지 못했습니다: {error}") from error


def build_report(
    hours: int = None,
    start: str = None,
    end: str = None,
    llm_summary: str = None,
) -> str:
    """로그인 시도/잠금 기록을 모아 사람이 읽을 수 있는 텍스트 리포트를 만든다.

    조회 방식은 두 가지 중 하나를 고른다:
    - start와 end를 둘 다 주면: "그 시작~종료 시각 사이"만 정밀하게 조회한다.
    - 그게 아니면: hours(기본 24시간) 동안, 즉 "지금부터 몇 시간 전까지"를
      상대적으로 조회한다.

    Args:
        hours (int, optional): 최근 몇 시간의 기록을 집계할지 설정 (기본값: 24시간).
        start (str, optional): 정적 조회 시작 시각 (예: '2026-09-01T00:00:00').
        end (str, optional): 정적 조회 종료 시각 (예: '2026-09-01T12:00:00').
        llm_summary (str, optional): Groq가 생성한 보안 요약/총평 문장.
            이 값이 있으면 리포트 맨 아래에 별도 섹션으로 추가된다.
    """
    # 1. 정적 기간 조회 (--start 및 --end 지정 시)
    if start and end:
        attempts = db.list_attempts_between(start, end)
        lockouts = db.list_lockouts_between(start, end)
        period_info = f"조회 기간: {start} ~ {end}"

    # 2. 상대적 시간 조회 (--hours 지정 시 또는 기본 동작)
    else:
        target_hours = hours if hours is not None else 24
        attempts = db.list_attempts_since(target_hours)
        lockouts = db.list_lockouts_since(target_hours)
        period_info = f"최근 {target_hours}시간 기준"

    # 전체 로그인 시도 중, 실패한 것만 따로 뽑아낸다. "성공 횟수"는 별도로
    # 세지 않고 "전체 - 실패"로 계산한다(같은 숫자를 두 번 다른 방식으로
    # 세다가 어긋나는 실수를 막기 위해서다).
    total = len(attempts)
    failures = [a for a in attempts if not a["success"]]
    successes = total - len(failures)

    # Counter: 리스트 안에서 어떤 값이 몇 번씩 나왔는지 세어주는 표준 라이브러리
    # 도구. 실패한 시도들의 IP 주소만 뽑아 넣으면, "이 IP가 몇 번 실패했는지"를
    # 자동으로 세어준다. "실패가 가장 많았던 IP 상위 5개"를 뽑을 때 쓴다.
    failure_ip_counts = Counter(a["ip_address"] for a in failures)
    top_ips = failure_ip_counts.most_common(5)

    # 리포트를 한 줄씩 리스트에 쌓아뒀다가, 맨 마지막에 한꺼번에 줄바꿈으로
    # 이어 붙인다(문자열을 계속 += 로 이어 붙이는 것보다 더 깔끔하고 빠르다).
    lines = [
        f"===== 로그인 워치독 보안 리포트 ({period_info}) =====",
        f"생성 시각: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        f"전체 로그인 시도: {total}건 (성공 {successes}건 / 실패 {len(failures)}건)",
        f"신규 IP 잠금 발생: {len(lockouts)}건",
        "",
    ]

    if top_ips:
        lines.append("실패가 가장 많았던 IP (상위 5개):")
        for ip, count in top_ips:
            lines.append(f"  - {ip}: 실패 {count}건")
    else:
        lines.append("실패한 로그인 시도가 없었습니다.")

    if lockouts:
        lines.append("")
        lines.append("이 기간에 잠긴 IP 목록:")
        for lockout in lockouts:
            lines.append(
                f"  - {lockout['ip_address']} "
                f"(실패 {lockout['failure_count']}회, {lockout['locked_at']} 잠금)"
            )

    # LLM 보안 총평 섹션 (llm_summary 값이 전달되었을 때만 추가).
    # build_report() 자신은 Groq를 직접 호출하지 않는다 — main()이 먼저
    # generate_ai_summary()로 요약문을 만들어서 여기로 전달해주는 구조다.
    # 이렇게 나눠둔 이유: build_report()는 "데이터를 모아 글로 만드는 역할"만,
    # generate_ai_summary()는 "AI에게 물어보는 역할"만 맡게 해서, AI 연동이
    # 없어도(즉 llm_summary=None이어도) 이 함수 혼자서 완전한 리포트를 만들 수 있다.
    if llm_summary:
        lines.append("")
        lines.append("--------------------------------------------------")
        lines.append("[AI 보안 총평 & 분석]")
        lines.append(llm_summary)
        lines.append("--------------------------------------------------")

    return "\n".join(lines)


def main() -> None:
    """명령행 옵션(--hours, --start/--end, --output, --ai)을 읽어서 리포트를
    생성하고, 화면에 출력하거나(항상) 파일로 저장한다(--output 지정 시).
    """
    parser = argparse.ArgumentParser(
        description="로그인 워치독 일일/기간별 요약 리포트를 출력 및 저장합니다."
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="몇 시간 전부터 현재까지 집계할지 설정 (기본값: 24시간)",
    )
    parser.add_argument(
        "--start",
        type=str,
        default=None,
        help="조회 시작 시각 (ISO format, 예: 2026-09-01T00:00:00)",
    )
    parser.add_argument(
        "--end",
        type=str,
        default=None,
        help="조회 종료 시각 (ISO format, 예: 2026-09-01T12:00:00)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="리포트 결과를 저장할 파일 경로 (예: report.txt)",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help=(
            "Groq API로 AI 보안 총평을 리포트에 추가한다. "
            ".env 파일에 GROQ_API_KEY가 설정되어 있어야 한다."
        ),
    )
    args = parser.parse_args()

    # --start와 --end는 반드시 둘 다 있어야 "특정 기간 조회"가 성립한다.
    # 하나만 입력하면 조용히 --hours(기본 24시간)로 넘어가지 않고, 사용자가
    # 실수를 바로 알아챌 수 있도록 명확한 에러 메시지를 보여주고 종료한다.
    if bool(args.start) != bool(args.end):
        missing = "--end" if args.start else "--start"
        parser.error(f"--start와 --end는 함께 입력해야 합니다. {missing}이(가) 빠졌습니다.")

    # --start/--end가 정말 날짜·시각 형식인지, 순서가 맞는지(시작이 종료보다
    # 빠른지) 여기서 미리 확인한다. 이걸 건너뛰면 잘못된 값이 그대로 데이터베이스
    # 요청까지 넘어가서, 사용자가 이해하기 어려운 기술적 에러로 나타나거나
    # (형식 오류) 아무 이유 없이 결과가 텅 비어버릴 수 있다(순서가 뒤바뀐 경우).
    if args.start and args.end:
        try:
            start_dt = datetime.fromisoformat(args.start)
            end_dt = datetime.fromisoformat(args.end)
        except ValueError:
            parser.error(
                "--start/--end는 ISO 형식(예: 2026-09-01T00:00:00)이어야 합니다."
            )
        if start_dt >= end_dt:
            parser.error("--start는 --end보다 빠른 시각이어야 합니다.")

    # --hours는 0 이하이면 "0시간 전부터"나 "역방향 조회"처럼 의미 없는 조회가
    # 되므로, 양수만 허용한다.
    if args.hours <= 0:
        parser.error("--hours는 1 이상의 정수여야 합니다.")

    # 두 곳(최초 생성, --ai로 요약을 덧붙인 재생성)에서 같은 조회 조건을
    # 반복해서 쓰므로, 매번 --start/--end인지 --hours인지 분기하지 않도록
    # 조회 조건만 딕셔너리로 한 번 묶어둔다. build_report(**period_kwargs)처럼
    # 풀어서 넘기면 build_report(start=..., end=...) 또는
    # build_report(hours=...)를 호출한 것과 똑같이 동작한다.
    period_kwargs = (
        {"start": args.start, "end": args.end} if args.start and args.end
        else {"hours": args.hours}
    )

    report_text = build_report(**period_kwargs)

    # --ai가 켜져 있으면 방금 만든 리포트를 Groq에게 보여주고 총평을 받아와서,
    # 그 총평을 포함한 리포트를 다시 만든다(조회 조건은 동일하게 유지).
    # 데이터베이스 조회를 한 번 더 하게 되지만, 이 스크립트는 사람이 가끔
    # 수동으로 실행하는 리포트 도구라 성능보다는 코드를 단순하게 유지하는
    # 쪽을 택했다.
    if args.ai:
        try:
            summary = generate_ai_summary(report_text)
            report_text = build_report(**period_kwargs, llm_summary=summary)
        except (RuntimeError, requests.RequestException) as error:
            # AI 요약이 실패해도 숫자 집계 리포트 자체는 이미 있으므로,
            # 전체를 중단하지 않고 경고만 남긴 뒤 AI 요약 없이 계속 진행한다.
            # (API 키가 없거나, Groq 서버가 일시적으로 응답이 없거나 등)
            print(f"[WARN] AI 요약 생성에 실패했습니다: {error}", file=sys.stderr)

    # 콘솔 출력 — --output 여부와 상관없이 항상 화면에도 보여준다.
    print(report_text)

    # 파일 저장 옵션 지정 시 저장 실행. UTF-8로 저장해야 한글이 깨지지 않는다.
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n[+] 리포트가 성공적으로 저장되었습니다: {args.output}")


if __name__ == "__main__":
    # 터미널에서 "python daily_report.py"로 직접 실행했을 때만 동작하고,
    # 다른 파일에서 import만 했을 때는 자동으로 실행되지 않게 하는 관용적인 표현이다.
    main()
