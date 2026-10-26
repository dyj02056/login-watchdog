"""S6 자동 점검 — 네트워크 증거가 있는 출발지에서의 "로그인 성공"이 의심 로그인으로 처리되는지 확인한다.

실행 방법(저장소 루트에서, docker compose로 단지를 켜고 환경 변수 LW_VICTIM_PASSWORD를 넣은 뒤):
    $env:LW_VICTIM_PASSWORD = Read-Host "victim 비밀번호"   # PowerShell
    python -m scripts.net.check_s6

재현(모두 "같은" 새 출발지 IP의 일회용 공격 컨테이너로):
    1) scanner-ua 를 보낸다(L7 증거 NET_SCANNER_UA를 만든다).
    2) security_events에 그 IP의 NET_SCANNER_UA(source=NET)가 생길 때까지 기다린다.
       (센서→shipper→DB를 거쳐 몇 초 늦으므로, 기다리지 않으면 CR-03 근거가 아직 없어 로그인이 그냥 성공해 버린다.)
    3) victim_c 계정으로 올바른 비밀번호 로그인 1회(비밀번호는 환경 변수로만 넘긴다).
    4) 같은 로그인을 한 번 더 보낸다(경고 메일이 더 안 나가는지 확인).
       같은 사건에서는 CR-03 플레이북이 한 번만 돌고("사건당 규칙당 1회"), 메일에는 받는 주소 쿨다운도 있어
       두 번째 시도로는 메일이 늘지 않아야 한다.
내 브라우저(.1)에는 네트워크 기록이 없어 CR-03이 걸리지 않으므로, 로그인은 반드시 공격 컨테이너(새 IP)에서 보낸다.

기대 결과(모두 맞아야 PASS):
    - login 명령 출력이 success:false (README 출력 형식 기준 — 세션이 바로 끊겨 대시보드로 못 감)
    - playbook_runs에 SUSPICIOUS_SUCCESS_LOGIN의 notify_owner_email 단계 기록
    - 경고 메일은 그 단계 결과에 따라 판정한다:
        OK      → Mailpit에 그 IP가 담긴 경고 메일 1통
        SKIPPED → 메일 0통이 정상(받는 주소 쿨다운으로 생략)
        FAILED  → FAIL
      메일 쿨다운은 IP가 아니라 "받는 주소" 기준(mail:suspicious:<이메일>, 기본 1시간)이라,
      --repeat의 2회차 이후나 1시간 안에 다시 돌리면 새 IP여도 메일이 가지 않는다. 그래서 메일 수를 1통으로
      고정하지 않고 플레이북이 남긴 단계 결과를 기준으로 삼는다. (SKIPPED는 REFUSED(수신 거부)일 때도 나오지만
      Docker 단지의 메일은 모두 Mailpit이 받으므로 여기서는 쿨다운뿐이다.)
    - 같은 시도를 한 번 더 해도 메일 수가 늘지 않음
victim_c 비밀번호는 코드·문서·로그 어디에도 적지 않는다. 환경 변수가 없으면 S6는 SKIP.
DB는 읽기만 한다.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from scripts.net import check_common as cc

SCENARIO = "S6"
PLAYBOOK = "SUSPICIOUS_SUCCESS_LOGIN"


def run(ctx) -> cc.CheckResult:
    client, prefix = ctx.client, ctx.prefix
    if not os.environ.get("LW_VICTIM_PASSWORD"):
        return cc.CheckResult(SCENARIO, "SKIP", "LW_VICTIM_PASSWORD 환경 변수 없음 — victim 로그인을 재현할 수 없음", None)

    ip = cc.choose_fresh_ip(client, prefix)
    if ip is None:
        return cc.CheckResult(SCENARIO, "SKIP", "점검용 IP(.111~.139)를 모두 썼음 — 오래된 차단·사건 정리 후 재시도", None)

    print(f"  [{SCENARIO}] 출발지 {ip} — 스캐너 UA → (근거 대기) → victim 로그인")
    cc.run_oneshot(cc.SCANNER_UA, ip, prefix)

    # 로그인을 보내기 전에 CR-03 근거(NET_SCANNER_UA)가 DB에 들어오기를 기다린다.
    if cc.wait_until(lambda: cc.has_net_scanner_ua(client, ip)) is None:
        return cc.CheckResult(SCENARIO, "FAIL", "NET_SCANNER_UA(근거)가 제때 기록되지 않음 — 로그인을 보내지 않음", ip)

    first = cc.parse_json_line(cc.run_oneshot(cc.LOGIN, ip, prefix, capture=True))
    if first is None:
        return cc.CheckResult(SCENARIO, "FAIL", "login 명령 출력(JSON)을 읽지 못함", ip)
    if first.get("error") == "no_password":
        return cc.CheckResult(SCENARIO, "SKIP", "컨테이너에 비밀번호가 전달되지 않음(no_password)", ip)

    # 플레이북 단계는 순서대로(invalidate_sessions → notify_owner_email → notify_slack) 기록되므로,
    # 아무 행이나 보이자마자 판정하면 메일 단계가 아직 없을 수 있다. 메일 단계 행이 생길 때까지 기다린다.
    mail_step = cc.wait_until(lambda: _mail_step(cc.playbook_runs_for_ip(client, ip, PLAYBOOK)))
    mail_status = mail_step.get("status") if mail_step else None

    if mail_status == "OK":
        # 메일이 실제로 나갔으니 Mailpit에 도착할 때까지 기다린다(본문에 이 IP가 들어간다).
        first_count = cc.wait_until(lambda: cc.mailpit_match_count(ip) or None, timeout=15)
    else:
        first_count = None
    if first_count is None:
        # wait_until은 "0통"과 "접속 불가"를 둘 다 None으로 돌려주므로 한 번 더 읽어 둘을 가른다.
        first_count = cc.mailpit_match_count(ip)

    # 같은 로그인을 한 번 더 — 같은 사건의 플레이북은 다시 돌지 않고 받는 주소 쿨다운도 있어 메일이 늘면 안 된다.
    cc.run_oneshot(cc.LOGIN, ip, prefix, capture=True)
    second_count = cc.mailpit_match_count(ip)

    fails = []
    if first.get("success") is not False:
        fails.append(f"login 출력이 success:false 아님(현재 success={first.get('success')})")
    if mail_step is None:
        fails.append(f"playbook_runs에 {PLAYBOOK}의 notify_owner_email 단계 기록 없음")
    elif mail_status == "OK":
        if first_count is None:
            fails.append("Mailpit 접속 불가 — 경고 메일 수를 확인 못 함")
        elif first_count == 0:
            fails.append("메일 단계는 OK인데 Mailpit에 그 IP의 경고 메일이 없음")
        elif first_count != 1:
            fails.append(f"경고 메일이 1통이 아님(현재 {first_count}통)")
    elif mail_status == "SKIPPED":
        # 쿨다운으로 생략된 것이 정상. Mailpit에 접속되지 않으면 메일 수는 판정에 쓰지 않는다.
        if first_count:
            fails.append(f"메일 단계는 SKIPPED인데 Mailpit에 그 IP의 메일이 {first_count}통 있음")
    else:
        fails.append(f"notify_owner_email 단계가 {mail_status}({mail_step.get('error') or '이유 없음'})")
    if first_count is not None and second_count is not None and second_count > first_count:
        fails.append(f"재시도 때 메일이 늘어남({first_count}→{second_count}) — 한 번만 보내져야 함")

    if fails:
        return cc.CheckResult(SCENARIO, "FAIL", "; ".join(fails), ip)
    if mail_status == "SKIPPED":
        return cc.CheckResult(SCENARIO, "PASS",
                              "로그인 실패 처리·플레이북 실행 확인, 경고 메일은 받는 주소 쿨다운으로 생략(SKIPPED, 정상)", ip)
    return cc.CheckResult(SCENARIO, "PASS", "로그인 실패 처리·플레이북 실행·경고 메일 1통 확인", ip)


def _mail_step(runs: list[dict]) -> dict | None:
    """플레이북 기록 중 notify_owner_email 단계(가장 최근 것). 아직 없으면 None.

    실행마다 사건 이력이 없는 새 IP를 쓰므로 보통 한 건뿐이지만, 혹시 여러 건이면 마지막 실행을 본다.
    """
    steps = [run for run in runs if run.get("step") == "notify_owner_email"]
    if not steps:
        return None
    return max(steps, key=lambda run: run.get("ran_at") or "")


def main() -> int:
    cc.preflight()
    prefix = cc.edge_prefix()
    if not prefix:
        print("  (!) LW_EDGE_PREFIX가 없어 대상 IP를 만들 수 없습니다.")
        return 2
    from types import SimpleNamespace

    ctx = SimpleNamespace(client=cc.get_reader(), prefix=prefix)
    result = run(ctx)
    cc.append_rows([cc.format_row(datetime.now(timezone.utc), result)])
    print(f"  → {result.scenario} {result.status} {result.reason}")
    return 0 if result.status in ("PASS", "SKIP") else 1


if __name__ == "__main__":
    sys.exit(main())
