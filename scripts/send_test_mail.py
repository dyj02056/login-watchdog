# ============================================================================
# send_test_mail.py — 메일 발송 설정(SMTP)이 맞는지 테스트 메일 한 통으로 미리 확인한다 (guide34-a)
#
# 영구 잠금 이메일 복구는 "사용자가 실제로 잠겨서 복구를 요청했을 때"에만 메일을 보내므로,
# 배포 후 설정이 틀렸다는 걸 알려면 일부러 잠금을 만들어 봐야 했다. 이 스크립트는 .env(또는
# 현재 환경변수)의 MAIL_BACKEND/SMTP_*/MAIL_FROM 설정으로 지정한 주소에 테스트 메일을
# 한 통 보내서, 접속·인증·발송이 되는지와 실패한다면 무엇을 고쳐야 하는지를 바로 알려준다.
#
# 배포 환경의 값으로 확인하려면 Vercel 환경변수를 로컬로 가져오거나(.env에 같은 값을 넣고)
# 실행한다. 비밀번호는 출력하지 않는다.
#
#   python scripts/send_test_mail.py --to 내이메일@gmail.com
# ============================================================================

import argparse
import os
import sys

from dotenv import load_dotenv

# unlock_ip.py 등과 같은 이유: scripts/ 폴더 밖(프로젝트 루트)의 모듈을 항상 찾을 수 있게 경로를 추가한다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

import config  # noqa: E402  (load_dotenv()가 환경변수를 먼저 읽어들인 뒤에 import 해야 함)
import mailer  # noqa: E402

_HINTS = {
    mailer.FAIL_CONFIG: "MAIL_BACKEND=smtp 와 SMTP_HOST 를 설정하세요(운영에서는 console 백엔드를 쓸 수 없습니다).",
    mailer.FAIL_AUTH: "SMTP_USER/SMTP_PASSWORD를 확인하세요. Gmail은 일반 비밀번호가 아니라 '앱 비밀번호'(2단계 인증 필요)여야 합니다.",
    mailer.FAIL_CONNECT: "SMTP_HOST/SMTP_PORT 를 확인하세요. 587이면 SMTP_STARTTLS=true, 465면 SMTP_USE_SSL=true 입니다.",
    mailer.FAIL_OTHER: "MAIL_FROM이 SMTP_USER와 같은 주소인지(Gmail), 서버 일시 장애는 아닌지 확인하세요.",
}


def describe_settings() -> list[str]:
    """지금 적용된 메일 설정을 사람이 읽을 수 있게 정리한다(비밀번호는 있는지 없는지만 표시)."""
    transport = "SSL(암시적 TLS)" if config.SMTP_USE_SSL else ("STARTTLS" if config.SMTP_STARTTLS else "암호화 없음")
    return [
        f"MAIL_BACKEND      : {config.MAIL_BACKEND}",
        f"SMTP_HOST:PORT    : {config.SMTP_HOST or '(없음)'}:{config.SMTP_PORT} / {transport}",
        f"SMTP_USER         : {config.SMTP_USER or '(없음)'}",
        f"SMTP_PASSWORD     : {'설정됨' if config.SMTP_PASSWORD else '(없음)'}",
        f"MAIL_FROM         : {config.MAIL_FROM}",
        f"PUBLIC_BASE_URL   : {config.PUBLIC_BASE_URL or '(없음 — 운영에서는 복구 메일이 발송되지 않음)'}",
        f"IS_PRODUCTION     : {config.IS_PRODUCTION}",
    ]


def run(to_address: str) -> int:
    """테스트 메일을 보내고 결과를 출력한다. 성공이면 0, 실패면 1을 돌려준다(종료 코드)."""
    print("[*] 적용된 메일 설정:")
    for line in describe_settings():
        print(f"    {line}")
    for warning in mailer.configuration_warnings():
        print(f"[!] 경고: {warning}")

    print(f"\n[*] {to_address} 로 테스트 메일을 보냅니다...")
    result, category, detail = mailer.send_test_mail(to_address)

    if result == mailer.SENT:
        print("[OK] 메일 서버가 메일을 받아줬습니다. 수신함(스팸함 포함)을 확인하세요.")
        return 0
    if result == mailer.REFUSED:
        print("[X] 메일 서버가 이 수신자를 거부했습니다. 존재하는 주소인지 확인하세요.")
        return 1
    print(f"[X] 발송 실패 ({category}): {detail}")
    print(f"    해결 방법: {_HINTS.get(category, _HINTS[mailer.FAIL_OTHER])}")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="메일 발송 설정(SMTP)을 테스트 메일 한 통으로 확인한다.")
    parser.add_argument("--to", required=True, help="테스트 메일을 받을 주소 (예: me@gmail.com)")
    args = parser.parse_args()
    sys.exit(run(args.to))


if __name__ == "__main__":
    main()
