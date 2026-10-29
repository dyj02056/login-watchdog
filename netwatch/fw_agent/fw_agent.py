# ============================================================================
# netwatch/fw_agent/fw_agent.py — L4 차단 실행 및 동기화 에이전트 (계약서 K3, K9)
#
# 담당: 역할 C (C1-3).
#
# 앱은 network_blocks 표에 "막아야 할 목록"(원하는 상태)만 적고, 이 프로그램이 그 목록을
# 앱 내부 API로 받아 가(pull) gateway 네임스페이스의 ipset(lw_block)에 실제로 넣고 뺀다.
#
# 왜 DB를 직접 읽지 않고 앱 내부 API를 거치나: 이 컨테이너는 방화벽을 바꾸는 NET_ADMIN 권한을
# 갖는다. 여기에 Supabase 키까지 주면 이 컨테이너 하나가 털렸을 때 DB 전체가 털린다(상위 계획서
# P6·V7). 그래서 NET_AGENT_SECRET 서명(K3)만 들고 앱에 "목록 주세요 / 반영했어요"만 말한다.
#
# 왜 앱 코드(db, config 등)를 import하지 않나: 이 파일은 app과 다른 컨테이너(fw-agent)에서 돈다.
# 이미지에는 이 파일과 requests만 들어 있으므로, 서명 규칙(K3)도 여기에 직접 구현하고 테스트로
# B의 sign()과 같은 값이 나오는지 확인한다.
#
# 시험하기 쉽게 나눈 구성:
#   sign_headers      — K3 서명 헤더
#   CommandRunner     — 실제 명령 실행(SubprocessRunner) / 기록만 하는 가짜(FakeRunner)
#   FirewallBackend   — ipset·iptables 조작(IptablesBackend). 나중에 AWS 등으로 바꿀 때 파일 1개만 추가
#   AgentClient       — 앱 내부 API 호출(K9 ①②③)
#   process_blocks    — 받은 목록 한 번 처리(2초마다)
#   reconcile         — 실제 ipset과 원하는 상태 전체 비교(60초마다, drift 보정)
# ============================================================================

import hashlib
import hmac
import ipaddress
import json
import math
import os
import subprocess
import sys
import time
from typing import Any, Protocol, Sequence

import requests


# 앱이 돌려주는 상태 중 이 프로그램이 처리하는 값(계약서 K9 ①). 그 밖의 값은 무시한다.
_STATUS_PENDING_APPLY = "PENDING_APPLY"
_STATUS_APPLIED = "APPLIED"
_STATUS_PENDING_REMOVE = "PENDING_REMOVE"

# ack로 보고하는 오류 문자열 길이 상한. 앱도 500자로 자르지만(K9 ②), 보내기 전에 줄여 두면
# iptables 오류 출력이 길게 붙어도 요청 본문이 수집 창구 크기 한도에 걸리지 않는다.
_MAX_ERROR_LEN = 500


def sign_headers(secret: str, body: bytes = b"", timestamp: str | None = None) -> dict[str, str]:
    """계약서 K3 규격에 맞춰 HMAC-SHA256 서명 헤더를 생성한다.

    서명 대상은 timestamp.encode("ascii") + b"." + body — 즉 '보낸 바이트 그대로'다.
    그래서 호출하는 쪽은 JSON을 직접 바이트로 만든 뒤 그 바이트로 서명하고, 같은 바이트를
    data=로 보낸다(requests의 json=를 쓰면 직렬화 결과가 달라져 서명이 틀어질 수 있다).
    timestamp 인자는 테스트에서 계약서 기준 예시값(1760930000)을 재현하려고 받는다.
    """
    if timestamp is None:
        timestamp = str(int(time.time()))
    msg = timestamp.encode("ascii") + b"." + body
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return {
        "X-LW-Sender": "fw-agent",
        "X-LW-Timestamp": timestamp,
        "X-LW-Signature": sig,
    }


# ---------------------------------------------------------------------------
# 명령 실행기 — 실제 방화벽 명령과 테스트용 가짜를 바꿔 끼우기 위한 층
# ---------------------------------------------------------------------------

class CommandRunner(Protocol):
    """명령 한 줄을 실행하고 (종료 코드, 출력)을 돌려주는 것.

    IptablesBackend가 subprocess를 직접 부르지 않고 이 인터페이스를 거치는 이유: 개발 PC
    (Windows)에는 ipset·iptables가 없고 root 권한도 없으므로, 테스트에서는 FakeRunner로
    "어떤 명령을 어떤 순서로 불렀는지"만 확인한다.
    """

    def run(self, args: Sequence[str]) -> tuple[int, str]:
        ...


class SubprocessRunner:
    """실제 컨테이너 안에서 명령을 실행한다.

    shell=False로 인자 목록을 그대로 넘긴다 — IP 문자열이 셸을 거치지 않으므로, 앱이 이상한
    값을 보내더라도 셸 명령 주입이 일어나지 않는다. stdout과 stderr를 합쳐 돌려주는 이유는
    ipset이 오류 이유를 stderr에 쓰기 때문이다(ack FAILED의 error 칸에 그대로 실어 보낸다).
    """

    def run(self, args: Sequence[str]) -> tuple[int, str]:
        res = subprocess.run(args, capture_output=True, text=True, shell=False)
        output = (res.stdout or "") + (res.stderr or "")
        return res.returncode, output.strip()


class FakeRunner:
    """테스트용 실행기. 부른 명령을 calls에 기록하고, 미리 정한 결과(responses)를 돌려준다.

    responses에 없는 명령은 성공(0, "")으로 본다. 실패 상황을 시험하려면 그 명령의 튜플을
    키로 (1, "오류 메시지")를 넣는다.
    """

    def __init__(self, responses: dict[tuple[str, ...], tuple[int, str]] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.responses = responses or {}

    def run(self, args: Sequence[str]) -> tuple[int, str]:
        args_list = list(args)
        self.calls.append(args_list)
        key = tuple(args_list)
        if key in self.responses:
            return self.responses[key]
        return 0, ""


# ---------------------------------------------------------------------------
# 방화벽 백엔드
# ---------------------------------------------------------------------------

class FirewallBackend(Protocol):
    """차단 목록을 실제로 반영하는 곳의 공통 모양.

    process_blocks·reconcile은 이 네 함수만 쓴다. 상위 계획서 확장 메모(P6)처럼 AWS Security
    Group 등으로 바꾸고 싶으면 같은 모양의 클래스 하나만 추가하면 된다.
    """

    def ensure_ready(self) -> None:
        ...

    def add(self, ip: str, timeout: int | None) -> None:
        ...

    def remove(self, ip: str) -> None:
        ...

    def list_ips(self) -> set[str]:
        ...


class IptablesBackend:
    """ipset 집합 하나(lw_block) + iptables DROP 규칙 하나로 L4 차단을 건다.

    IP마다 iptables 규칙을 추가하지 않고 집합에 넣고 빼기만 하는 이유: 규칙 수와 상관없이
    조회 속도가 일정하고, TTL을 ipset의 timeout으로 커널이 직접 처리해 준다. 그래서 이
    프로그램이나 앱이 멈춰도 TTL 차단은 제시간에 풀린다(상위 계획서 2.6 "앱이 응답하지 않을 때").
    이 컨테이너는 network_mode: service:gateway로 gateway와 네트워크를 함께 쓰므로, 여기서 건
    규칙은 gateway(nginx)로 들어오는 패킷에 적용되고 호스트 방화벽은 바뀌지 않는다.
    """

    def __init__(self, runner: CommandRunner, set_name: str = "lw_block") -> None:
        self.runner = runner
        self.set_name = set_name

    def ensure_ready(self) -> None:
        """시작할 때 한 번: 집합과 DROP 규칙이 없으면 만든다. 이미 있으면 아무것도 바꾸지 않는다.

        - "timeout 0"으로 만드는 이유: 집합이 항목별 timeout을 지원하게 하면서, 기본값은
          '만료 없음'으로 둔다. 영구 차단(CONNECTED)은 add에서 timeout 0을 넘긴다.
        - "-exist": 컨테이너가 재시작돼도 기존 집합(이미 막힌 IP)을 지우지 않고 그대로 쓴다.
        - iptables는 -C(확인)로 규칙이 이미 있는지 본 뒤 없을 때만 -I로 맨 앞에 넣는다.
          재시작할 때마다 같은 규칙이 겹겹이 쌓이지 않게 하려는 것이다.
        - raw PREROUTING에도 같은 DROP을 둔다. raw는 연결 추적(conntrack)보다 앞이라, 차단된 IP의
          패킷마다 연결 추적 항목을 만들고 조회하는 일을 건너뛴다. INPUT에서 버린 패킷도 표에 확정되지는
          않아 표가 차오르지는 않는다(10/29 Docker 실측: INPUT만으로 SYN 3000개를 버려도 nf_conntrack_count
          증가 0) — 그래서 효과는 SYN Flood 때 패킷당 처리량을 줄이는 정도다.
          INPUT 규칙은 raw 규칙이 실패하거나 지워졌을 때의 예비로 그대로 둔다. 그래서 raw 실패는
          시작을 막지 않고 경고만 남긴다 — INPUT만으로도 차단 자체는 된다.
        """
        # 1. ipset 생성
        code, err = self.runner.run(
            ["ipset", "create", self.set_name, "hash:ip", "timeout", "0", "-exist"]
        )
        if code != 0:
            raise RuntimeError(f"ipset create failed: {err}")

        # 2. raw PREROUTING 규칙(연결 추적 전 차단). INPUT 규칙보다 먼저 확인한다.
        raw_rule = ["PREROUTING", "-m", "set", "--match-set", self.set_name, "src", "-j", "DROP"]
        raw_chk, _ = self.runner.run(["iptables", "-t", "raw", "-C", *raw_rule])
        if raw_chk != 0:
            raw_ins, raw_err = self.runner.run(["iptables", "-t", "raw", "-I", raw_rule[0], "1", *raw_rule[1:]])
            if raw_ins != 0:
                print(f"[fw-agent] 경고: raw PREROUTING 규칙을 넣지 못해 INPUT 규칙만 씁니다: {raw_err}")

        # 3. filter INPUT 규칙 확인 및 없으면 삽입
        chk_code, _ = self.runner.run(
            ["iptables", "-C", "INPUT", "-m", "set", "--match-set", self.set_name, "src", "-j", "DROP"]
        )
        if chk_code != 0:
            ins_code, ins_err = self.runner.run(
                ["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", self.set_name, "src", "-j", "DROP"]
            )
            if ins_code != 0:
                raise RuntimeError(f"iptables insert failed: {ins_err}")

    def add(self, ip: str, timeout: int | None) -> None:
        """IP를 집합에 넣는다. timeout=None이면 0(만료 없음 = 영구).

        "-exist"를 붙이는 이유: 이미 있는 IP를 다시 넣어도 오류가 나지 않고 timeout만 새 값으로
        바뀐다. 2초마다 같은 PENDING_APPLY를 받아도(ack가 늦게 반영된 경우) 안전하다.
        """
        to_val = str(timeout or 0)
        code, err = self.runner.run(
            ["ipset", "add", self.set_name, ip, "timeout", to_val, "-exist"]
        )
        if code != 0:
            raise RuntimeError(f"ipset add failed for {ip}: {err}")

    def remove(self, ip: str) -> None:
        """IP를 집합에서 뺀다. 이미 없어도(-exist) 성공으로 본다 — 해제 요청은 멱등이어야 한다."""
        code, err = self.runner.run(["ipset", "del", self.set_name, ip, "-exist"])
        if code != 0:
            raise RuntimeError(f"ipset del failed for {ip}: {err}")

    def list_ips(self) -> set[str]:
        """지금 집합에 실제로 들어 있는 IP 목록.

        "-output save" 형식은 "add lw_block 1.2.3.4 timeout 3599"처럼 한 줄에 한 항목이라
        사람용 출력보다 읽기 쉽다. 조회가 실패하면 빈 집합을 돌려준다 — 이 값은 heartbeat의
        ipset_size와 reconcile 비교에만 쓰이며, reconcile은 빈 집합이면 '빠진 IP를 다시 넣기'만
        하게 되어 차단을 잘못 지우지 않는다.
        """
        code, out = self.runner.run(["ipset", "list", self.set_name, "-output", "save"])
        if code != 0:
            return set()
        result = set()
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] == "add" and parts[1] == self.set_name:
                result.add(parts[2])
        return result


# ---------------------------------------------------------------------------
# 앱 내부 API 클라이언트 (계약서 K9)
# ---------------------------------------------------------------------------

class AgentClient:
    """앱의 /api/internal/* 세 창구를 부른다. 모든 요청에 K3 서명 헤더를 붙인다.

    시간 제한을 3초로 두는 이유: 폴링 주기가 2초라서, 앱이 멈췄을 때 요청 하나가 오래 붙잡고
    있으면 heartbeat까지 밀린다. 실패는 예외로 올려 main 루프가 poll_failures를 세게 한다.
    session을 인자로 받는 것은 테스트에서 가짜 세션으로 바꿔 끼우기 위해서다.
    """

    def __init__(self, base_url: str, secret: str, session: requests.Session | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self.session = session or requests.Session()

    def _post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """JSON 본문을 바이트로 만들고, 그 바이트로 서명해서 그대로 보낸다(K3 '보낸 바이트 그대로')."""
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = sign_headers(self.secret, body)
        headers["Content-Type"] = "application/json"
        resp = self.session.post(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            timeout=3,
        )
        resp.raise_for_status()
        return resp.json()

    def get_blocks(self) -> list[dict[str, Any]]:
        """K9 ① GET /api/internal/blocks — 원하는 상태 목록을 받는다.

        응답 모양: {"generated_at": "...", "blocks": [{"ip", "status", "ttl_seconds"}, ...]}.
        GET은 본문이 없으므로 빈 바이트 b""로 서명한다(K3).
        """
        headers = sign_headers(self.secret, b"")
        resp = self.session.get(f"{self.base_url}/api/internal/blocks", headers=headers, timeout=3)
        resp.raise_for_status()
        data = resp.json()
        # 응답이 이상한 모양이면 루프가 죽지 않도록 빈 목록 대신 예외로 올린다 — 빈 목록을
        # 돌려주면 다음 reconcile이 '막을 게 없다'고 판단해 기존 차단을 모두 지워 버린다.
        # "blocks" 칸이 아예 없는 응답도 같다: 기본값 []로 받으면 정상적인 '막을 것 없음'과 구분되지
        # 않으므로(10/26 강사 피드백), 칸이 있고 목록일 때만 받아들인다. 진짜 빈 목록은 "blocks": [] 로 온다.
        if not isinstance(data, dict) or "blocks" not in data:
            raise ValueError("blocks 응답에 blocks 칸이 없음")
        blocks = data["blocks"]
        if not isinstance(blocks, list):
            raise ValueError("blocks 응답이 목록이 아님")
        return blocks

    def ack(self, ip: str, status: str, error: str | None = None, version: int | None = None) -> dict[str, Any]:
        """K9 ② POST /api/internal/blocks/ack — 반영 결과를 보고한다.

        본문은 {"ip", "status", "error"} 세 칸을 항상 보낸다(error는 성공이면 null).
        앱은 '이전 상태가 맞을 때만' 바꾸므로(조건부 UPDATE) 같은 ack를 두 번 보내도 안전하다.
        """
        if error is not None:
            error = error[:_MAX_ERROR_LEN]
        payload: dict[str, Any] = {"ip": ip, "status": status, "error": error}
        # 목록에서 받은 요청 번호를 그대로 돌려준다(guide56). 앱은 같은 번호의 요청일 때만 상태를 바꾼다.
        if version is not None:
            payload["version"] = version
        return self._post_json("/api/internal/blocks/ack", payload)

    def heartbeat(self, detail: dict[str, Any]) -> dict[str, Any]:
        """K9 ③ POST /api/internal/heartbeat — 생존 신호. 10초마다 보낸다.

        본문의 agent 칸은 X-LW-Sender(fw-agent)와 같아야 한다(다르면 앱이 400). 10초인 이유는
        앱의 정지 판단 기준(FW_AGENT_STALE_SECONDS=30초)보다 충분히 짧아야 배지가 깜빡이지 않기 때문이다.
        """
        return self._post_json(
            "/api/internal/heartbeat",
            {"agent": "fw-agent", "detail": detail},
        )


# ---------------------------------------------------------------------------
# 목록 처리
# ---------------------------------------------------------------------------

def _parse_ttl(value: Any) -> tuple[bool, int | None]:
    """ttl_seconds 칸을 (올바른가, 값)으로 바꾼다.

    - None → (True, None): 영구 차단(또는 PENDING_REMOVE).
    - 1 이상의 정수 → (True, 그 값).
    - 그 밖(0 이하, 문자열, bool 등) → (False, None).
    0 이하를 따로 거르는 이유: ipset에서 timeout 0은 '만료 없음'이라, 잘못 넘어온 0이 그대로
    들어가면 위조 가능한 증거(SPOOFABLE)의 TTL 차단이 영구 차단으로 바뀐다(상위 계획서 P2 위반).
    앱은 남은 초가 0 이하인 행을 빼고 보내지만(K9 ①), 여기서 한 번 더 막는다.
    """
    if value is None:
        return True, None
    if isinstance(value, bool) or not isinstance(value, int):
        return False, None
    if value <= 0:
        return False, None
    return True, value


def _parse_ipv4(value: Any) -> str | None:
    """IPv4 문자열이면 표준 표기로 돌려주고, 아니면 None.

    앱(netblock.request_block)이 이미 IPv6·대역을 거절하지만, 이 값은 그대로 ipset 명령 인자가
    되므로 받는 쪽에서도 확인한다. lw_block은 hash:ip(IPv4) 집합이라 IPv6는 넣을 수 없다.
    """
    if not isinstance(value, str):
        return None
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip_obj.version != 4:
        return None
    return str(ip_obj)


def _is_ip_allowlisted(ip: str, allowlist: list[str]) -> bool:
    """ip가 PERMANENT_LOCK_IP_ALLOWLIST(관리자 PC·Docker 게이트웨이 등)에 있는지.

    앱의 request_block도 같은 목록으로 거절하지만, 앱 쪽 버그나 DB에 손으로 넣은 행 때문에
    관리자 PC가 정문에서 막히면 시연 중 화면 자체에 들어갈 수 없다. 그래서 실제로 막는 이
    프로그램이 한 번 더 확인한다(상위 계획서 2.6 "로컬 허용 목록도 다시 확인").
    문자열 대신 ipaddress 객체로 비교해 표기 차이(앞자리 0 등)에 흔들리지 않게 하고, 목록에
    "/"가 있는 대역이 적혀 있으면 그 대역 전체를 허용으로 본다. 잘못된 항목은 무시한다.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in allowlist:
        try:
            if "/" in item:
                if ip_obj in ipaddress.ip_network(item, strict=False):
                    return True
            elif ip_obj == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


def _safe_ack(client: Any, ip: str, status: str, error: str | None = None, version: int | None = None) -> bool:
    """ack를 보내고 성공 여부만 돌려준다. 실패해도 예외를 올리지 않는다.

    ack 실패(앱이 잠깐 멈춤 등)는 다음 폴링에서 같은 상태를 다시 받아 재시도하면 되므로,
    한 IP의 보고 실패 때문에 같은 목록의 다른 IP 처리가 멈추면 안 된다.
    """
    try:
        # version이 없을 때는 예전 모양 그대로 부른다(옛 앱·테스트용 가짜 클라이언트와 호환).
        extra = {} if version is None else {"version": version}
        if error is None:
            client.ack(ip, status, **extra)
        else:
            client.ack(ip, status, error, **extra)
        return True
    except Exception as e:
        print(f"[fw-agent] ack {status} 전송 실패 ({ip}): {e}")
        return False


def process_blocks(
    blocks: list[dict[str, Any]],
    backend: FirewallBackend,
    client: Any,
    allowlist: list[str],
) -> dict[str, int | None]:
    """받은 목록 한 번을 처리하고, "지금 ipset에 있어야 할 IP와 남은 TTL"을 돌려준다.

    계약서 K9 ①의 agent 동작:
      - PENDING_APPLY  → ipset add 후 ack APPLIED (실패하면 ack FAILED + 오류 문자열)
      - PENDING_REMOVE → ipset del 후 ack REMOVED (실패하면 ack FAILED)
      - APPLIED        → 여기서는 건드리지 않는다. 실제로 빠져 있으면 reconcile(60초)이 다시 넣는다.
        2초마다 ipset list를 부르지 않으려는 것이다(요청서 C1-3 5번).
    방화벽 반영 실패와 ack 전송 실패를 따로 다루는 이유: ipset add는 성공했는데 ack만 실패했을 때
    FAILED를 보고하면 앱은 '못 막았다'고 기록하고, 이 IP를 desired에서 빼면 reconcile이 실제
    차단까지 지워 버린다. 그래서 ack 실패는 로그만 남기고 desired에 그대로 두어 다음 폴링에서
    다시 보고하게 한다.
    """
    desired: dict[str, int | None] = {}

    for block in blocks:
        if not isinstance(block, dict):
            print(f"[fw-agent] 무시: 목록 항목이 객체가 아님 ({block!r})")
            continue

        ip = _parse_ipv4(block.get("ip"))
        status = block.get("status")
        if ip is None:
            # ack로 알릴 수도 없다(앱이 ip 칸 오류로 400을 돌려준다). 로그만 남기고 건너뛴다.
            print(f"[fw-agent] 무시: 잘못된 ip ({block.get('ip')!r})")
            continue

        ttl_ok, ttl = _parse_ttl(block.get("ttl_seconds"))
        # 요청 번호(guide56). 정수가 아니면 없는 것으로 보고 예전처럼 ack한다.
        version = block.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            version = None

        if _is_ip_allowlisted(ip, allowlist):
            # 허용 목록 IP는 어떤 상태로 와도 막지 않는다. PENDING_APPLY만 FAILED로 알려
            # 앱의 장부가 '대기 중'으로 계속 남지 않게 한다. reconcile이 집합에서도 지운다.
            if status == _STATUS_PENDING_APPLY:
                _safe_ack(client, ip, "FAILED", "allowlisted", version=version)
            continue

        if status == _STATUS_PENDING_APPLY:
            if not ttl_ok:
                _safe_ack(client, ip, "FAILED", f"invalid ttl_seconds: {block.get('ttl_seconds')!r}", version=version)
                continue
            try:
                backend.add(ip, ttl)
            except Exception as e:
                err_msg = str(e)
                print(f"[fw-agent] add 차단 실패 ({ip}): {err_msg}")
                _safe_ack(client, ip, "FAILED", err_msg, version=version)
                continue
            desired[ip] = ttl
            _safe_ack(client, ip, "APPLIED", version=version)

        elif status == _STATUS_PENDING_REMOVE:
            try:
                backend.remove(ip)
            except Exception as e:
                err_msg = str(e)
                print(f"[fw-agent] remove 해제 실패 ({ip}): {err_msg}")
                _safe_ack(client, ip, "FAILED", err_msg, version=version)
                continue
            _safe_ack(client, ip, "REMOVED", version=version)

        elif status == _STATUS_APPLIED:
            if not ttl_ok:
                # 남은 시간이 이상한 APPLIED는 desired에서 빼서 reconcile이 집합에서 지우게 한다.
                # 영구로 잘못 다시 넣는 것보다 잠시 풀리는 쪽이 안전하다(P2).
                print(f"[fw-agent] 무시: APPLIED의 ttl_seconds가 잘못됨 ({ip}, {block.get('ttl_seconds')!r})")
                continue
            desired[ip] = ttl

        else:
            print(f"[fw-agent] 무시: 알 수 없는 status ({ip}, {status!r})")

    return desired


def reconcile(
    desired: dict[str, int | None] | None,
    backend: FirewallBackend,
    allowlist: list[str] | None = None,
    received_at: float | None = None,
    now: float | None = None,
) -> None:
    """실제 ipset과 원하는 상태(desired)를 전부 비교해 어긋난 것(drift)을 바로잡는다.

    누가 손으로 ipset del을 했거나, 컨테이너가 재시작됐거나, ack가 유실된 경우를 60초 안에
    맞추려는 것이다(상위 계획서 2.6). 집합에 있는데 desired에 없거나 허용 목록인 IP는 지우고,
    desired에 있는데 집합에 없는 IP는 남은 TTL로 다시 넣는다.

    desired가 None이면(아직 한 번도 목록을 받지 못함) 아무것도 하지 않는다. 시작 직후 앱이
    응답하지 않을 때 빈 desired로 비교하면 재시작 전부터 있던 차단을 전부 지워 버리기 때문이다
    ("앱이 응답하지 않으면 마지막 상태 유지" — 요청서 C1-3 7번).

    received_at(목록을 받은 time.monotonic() 시각)을 주면 TTL을 "남은 초"가 아니라 "언제까지"로 본다.
    앱이 멈춰 목록이 오래 갱신되지 않는 동안 커널이 TTL 항목을 정상적으로 지웠는데, 옛 목록의 남은 초로
    다시 넣으면 10초 차단이 60초마다 끝없이 되살아난다(10/26 강사 피드백 2). 그래서 다시 넣을 때는
    "받은 시각 + 남은 초 - 지금"을 쓰고, 이미 지난 차단은 넣지 않고 desired에서도 뺀다.
    monotonic 시계를 쓰는 이유: PC 시계가 바뀌어도 경과 시간이 흔들리지 않는다.
    received_at 없이 부르면 예전처럼 받은 남은 초를 그대로 쓴다.
    """
    if desired is None:
        print("[fw-agent] reconcile 건너뜀: 아직 앱에서 목록을 받지 못함")
        return

    allowlist = allowlist or []
    current_ips = backend.list_ips()

    for ip in current_ips:
        if _is_ip_allowlisted(ip, allowlist) or ip not in desired:
            try:
                backend.remove(ip)
            except Exception as e:
                print(f"[fw-agent] reconcile remove 실패 ({ip}): {e}")

    if received_at is not None:
        elapsed = (time.monotonic() if now is None else now) - received_at
    else:
        elapsed = 0.0

    for ip, ttl in list(desired.items()):
        if _is_ip_allowlisted(ip, allowlist) or ip in current_ips:
            continue
        if ttl is not None and received_at is not None:
            remaining = math.ceil(ttl - elapsed)
            if remaining <= 0:
                # 정해진 시각이 지난 TTL 차단 — 커널이 지운 것이 맞으므로 다시 넣지 않는다.
                del desired[ip]
                continue
            ttl = remaining
        try:
            backend.add(ip, ttl)
        except Exception as e:
            print(f"[fw-agent] reconcile add 실패 ({ip}): {e}")


def _int_env(name: str, default: int) -> int:
    """정수 환경 변수를 읽는다. 비었거나 1 미만·숫자가 아니면 기본값.

    주기 값이 0이 되면 루프가 쉬지 않고 앱을 두드리게 되므로 1초 미만은 허용하지 않는다.
    """
    raw = os.environ.get(name, "")
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 1 else default


def main() -> None:
    """서비스 루프. 2초마다 목록 처리, 60초마다 reconcile, 10초마다 heartbeat.

    루프 한 바퀴 안의 어떤 예외도 잡아서 로그만 남긴다 — 이 프로그램이 죽으면 새 차단이
    걸리지 않고, 앱은 heartbeat가 끊긴 것으로 '정지'만 알 수 있기 때문이다.
    NET_AGENT_SECRET이 없으면 시작하지 않는다. 서명 없이 돌면 앱이 모든 요청을 401로 거절해
    아무 일도 못 하면서 로그만 쌓이므로, 처음부터 실패를 드러내는 편이 낫다.
    """
    secret = os.environ.get("NET_AGENT_SECRET")
    if not secret:
        print("[fw-agent] 필수 환경 변수 NET_AGENT_SECRET이 없어 종료합니다.")
        sys.exit(1)

    base_url = os.environ.get("APP_INTERNAL_URL", "http://app:5000")
    allowlist_str = os.environ.get("PERMANENT_LOCK_IP_ALLOWLIST", "")
    allowlist = [x.strip() for x in allowlist_str.split(",") if x.strip()]
    set_name = os.environ.get("IPSET_NAME", "lw_block")

    poll_interval = _int_env("POLL_INTERVAL", 2)
    reconcile_interval = _int_env("RECONCILE_INTERVAL", 60)
    heartbeat_interval = _int_env("HEARTBEAT_INTERVAL", 10)

    runner = SubprocessRunner()
    backend = IptablesBackend(runner, set_name=set_name)
    try:
        backend.ensure_ready()
    except Exception as e:
        # 집합·규칙을 만들 수 없으면(NET_ADMIN 권한 없음 등) 차단이 아예 안 되므로 종료해
        # docker compose 로그에 원인이 바로 보이게 한다.
        print(f"[fw-agent] 백엔드 초기화 실패: {e}")
        sys.exit(1)

    client = AgentClient(base_url, secret)

    poll_failures = 0
    # None = 아직 목록을 한 번도 받지 못함(reconcile 금지). 받은 뒤에는 마지막으로 받은 상태를 유지한다.
    desired_ips: dict[str, int | None] | None = None
    # desired_ips를 받은 시각(monotonic). reconcile이 남은 초를 "언제까지"로 바꿔 계산하는 기준이다.
    desired_received_at: float | None = None
    last_reconcile = 0.0
    last_heartbeat = 0.0

    print("[fw-agent] 서비스 루프를 시작합니다.")
    while True:
        now = time.time()

        try:
            # 1. Poll & Process
            try:
                blocks = client.get_blocks()
                desired_received_at = time.monotonic()
                desired_ips = process_blocks(blocks, backend, client, allowlist)
                poll_failures = 0
            except Exception as e:
                # 앱이 응답하지 않으면 desired_ips를 그대로 둔다(마지막 상태 유지).
                # 이미 ipset에 들어간 TTL 차단은 커널이 timeout으로 풀어 준다.
                poll_failures += 1
                print(f"[fw-agent] 폴링 실패 ({poll_failures}회 연속): {e}")

            # 2. Reconcile
            if now - last_reconcile >= reconcile_interval:
                try:
                    reconcile(desired_ips, backend, allowlist, received_at=desired_received_at)
                except Exception as e:
                    print(f"[fw-agent] reconcile 실패: {e}")
                last_reconcile = now

            # 3. Heartbeat — 폴링이 실패하는 중에도 보낸다. 앱은 poll_failures로
            #    'agent는 살아 있지만 목록을 못 받는 중'을 구분할 수 있다.
            if now - last_heartbeat >= heartbeat_interval:
                try:
                    ipset_size = len(backend.list_ips())
                    client.heartbeat({"poll_failures": poll_failures, "ipset_size": ipset_size})
                except Exception as e:
                    print(f"[fw-agent] heartbeat 실패: {e}")
                last_heartbeat = now
        except Exception as e:  # noqa: BLE001  (루프가 죽지 않게 하는 마지막 그물)
            print(f"[fw-agent] 루프 예외: {e}")

        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
