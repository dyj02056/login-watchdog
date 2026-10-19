# ============================================================================
# netwatch/fw_agent/fw_agent.py — L4 차단 실행 및 동기화 에이전트 (계약서 K3, K9)
# ============================================================================

from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import os
import subprocess
import sys
import time
from typing import Any, Protocol, Sequence

import requests


def sign_headers(secret: str, body: bytes = b"", timestamp: str | None = None) -> dict[str, str]:
    """계약서 K3 규격에 맞춰 HMAC-SHA256 서명 헤더를 생성한다."""
    if timestamp is None:
        timestamp = str(int(time.time()))
    msg = timestamp.encode("ascii") + b"." + body
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return {
        "X-LW-Sender": "fw-agent",
        "X-LW-Timestamp": timestamp,
        "X-LW-Signature": sig,
    }


class CommandRunner(Protocol):
    def run(self, args: Sequence[str]) -> tuple[int, str]:
        ...


class SubprocessRunner:
    def run(self, args: Sequence[str]) -> tuple[int, str]:
        res = subprocess.run(args, capture_output=True, text=True, shell=False)
        output = (res.stdout or "") + (res.stderr or "")
        return res.returncode, output.strip()


class FakeRunner:
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


class FirewallBackend(Protocol):
    def ensure_ready(self) -> None:
        ...

    def add(self, ip: str, timeout: int | None) -> None:
        ...

    def remove(self, ip: str) -> None:
        ...

    def list_ips(self) -> set[str]:
        ...


class IptablesBackend:
    def __init__(self, runner: CommandRunner, set_name: str = "lw_block") -> None:
        self.runner = runner
        self.set_name = set_name

    def ensure_ready(self) -> None:
        # 1. ipset 생성
        code, err = self.runner.run(
            ["ipset", "create", self.set_name, "hash:ip", "timeout", "0", "-exist"]
        )
        if code != 0:
            raise RuntimeError(f"ipset create failed: {err}")

        # 2. iptables 규칙 확인 및 없으면 삽입
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
        to_val = str(timeout or 0)
        code, err = self.runner.run(
            ["ipset", "add", self.set_name, ip, "timeout", to_val, "-exist"]
        )
        if code != 0:
            raise RuntimeError(f"ipset add failed for {ip}: {err}")

    def remove(self, ip: str) -> None:
        code, err = self.runner.run(["ipset", "del", self.set_name, ip, "-exist"])
        if code != 0:
            raise RuntimeError(f"ipset del failed for {ip}: {err}")

    def list_ips(self) -> set[str]:
        code, out = self.runner.run(["ipset", "list", self.set_name, "-output", "save"])
        if code != 0:
            return set()
        result = set()
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] == "add" and parts[1] == self.set_name:
                result.add(parts[2])
        return result


class AgentClient:
    def __init__(self, base_url: str, secret: str, session: requests.Session | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self.session = session or requests.Session()

    def get_blocks(self) -> list[dict[str, Any]]:
        headers = sign_headers(self.secret, b"")
        resp = self.session.get(f"{self.base_url}/api/internal/blocks", headers=headers, timeout=3)
        resp.raise_for_status()
        return resp.json().get("blocks", [])

    def ack(self, ip: str, status: str, error: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": status}
        if error is not None:
            payload["error"] = error
        import json
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = sign_headers(self.secret, body)
        headers["Content-Type"] = "application/json"
        resp = self.session.post(
            f"{self.base_url}/api/internal/blocks/{ip}/ack",
            data=body,
            headers=headers,
            timeout=3,
        )
        resp.raise_for_status()
        return resp.json()

    def heartbeat(self, detail: dict[str, Any]) -> dict[str, Any]:
        import json
        body = json.dumps(detail, separators=(",", ":")).encode("utf-8")
        headers = sign_headers(self.secret, body)
        headers["Content-Type"] = "application/json"
        resp = self.session.post(
            f"{self.base_url}/api/internal/heartbeat",
            data=body,
            headers=headers,
            timeout=3,
        )
        resp.raise_for_status()
        return resp.json()


def _parse_expires_ttl(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    try:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        ttl = int((dt - now).total_seconds())
        return max(1, ttl)
    except Exception:
        return None


def _is_ip_allowlisted(ip: str, allowlist: list[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in allowlist:
        try:
            if ip_obj == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    return False


def process_blocks(
    blocks: list[dict[str, Any]],
    backend: FirewallBackend,
    client: Any,
    allowlist: list[str],
) -> dict[str, int | None]:
    desired: dict[str, int | None] = {}

    for block in blocks:
        ip = block["ip_address"]
        status = block.get("status")
        expires_at = block.get("expires_at")
        ttl = _parse_expires_ttl(expires_at)

        if _is_ip_allowlisted(ip, allowlist):
            if status == "PENDING_APPLY":
                try:
                    client.ack(ip, "FAILED", "allowlisted")
                except Exception as e:
                    print(f"[fw-agent] ACK FAILED (allowlisted) 실패 ({ip}): {e}")
            continue

        if status == "PENDING_APPLY":
            try:
                backend.add(ip, ttl)
                client.ack(ip, "APPLIED")
                desired[ip] = ttl
            except Exception as e:
                err_msg = str(e)
                print(f"[fw-agent] add 차단 실패 ({ip}): {err_msg}")
                try:
                    client.ack(ip, "FAILED", err_msg)
                except Exception as ack_e:
                    print(f"[fw-agent] ACK FAILED 전송 실패 ({ip}): {ack_e}")

        elif status == "PENDING_REMOVE":
            try:
                backend.remove(ip)
                client.ack(ip, "REMOVED")
            except Exception as e:
                err_msg = str(e)
                print(f"[fw-agent] remove 해제 실패 ({ip}): {err_msg}")
                try:
                    client.ack(ip, "FAILED", err_msg)
                except Exception as ack_e:
                    print(f"[fw-agent] ACK FAILED 전송 실패 ({ip}): {ack_e}")

        elif status == "APPLIED":
            desired[ip] = ttl

    return desired


def reconcile(desired: dict[str, int | None], backend: FirewallBackend, allowlist: list[str] | None = None) -> None:
    allowlist = allowlist or []
    current_ips = backend.list_ips()

    for ip in current_ips:
        if _is_ip_allowlisted(ip, allowlist) or ip not in desired:
            try:
                backend.remove(ip)
            except Exception as e:
                print(f"[fw-agent] reconcile remove 실패 ({ip}): {e}")

    for ip, ttl in desired.items():
        if not _is_ip_allowlisted(ip, allowlist) and ip not in current_ips:
            try:
                backend.add(ip, ttl)
            except Exception as e:
                print(f"[fw-agent] reconcile add 실패 ({ip}): {e}")


def main() -> None:
    secret = os.environ.get("NET_AGENT_SECRET")
    if not secret:
        print("[fw-agent] 필수 환경 변수 NET_AGENT_SECRET이 없어 종료합니다.")
        sys.exit(1)

    base_url = os.environ.get("APP_INTERNAL_URL", "http://app:5000")
    allowlist_str = os.environ.get("PERMANENT_LOCK_IP_ALLOWLIST", "")
    allowlist = [x.strip() for x in allowlist_str.split(",") if x.strip()]
    set_name = os.environ.get("IPSET_NAME", "lw_block")

    poll_interval = int(os.environ.get("POLL_INTERVAL", "2"))
    reconcile_interval = int(os.environ.get("RECONCILE_INTERVAL", "60"))
    heartbeat_interval = int(os.environ.get("HEARTBEAT_INTERVAL", "10"))

    runner = SubprocessRunner()
    backend = IptablesBackend(runner, set_name=set_name)
    try:
        backend.ensure_ready()
    except Exception as e:
        print(f"[fw-agent] 백엔드 초기화 실패: {e}")
        sys.exit(1)

    client = AgentClient(base_url, secret)

    poll_failures = 0
    desired_ips: dict[str, int | None] = {}
    last_reconcile = 0.0
    last_heartbeat = 0.0

    print("[fw-agent] 서비스 루프를 시작합니다.")
    while True:
        now = time.time()

        # 1. Poll & Process
        try:
            blocks = client.get_blocks()
            desired_ips = process_blocks(blocks, backend, client, allowlist)
            poll_failures = 0
        except Exception as e:
            poll_failures += 1
            print(f"[fw-agent] 폴링 실패 ({poll_failures}회 연속): {e}")

        # 2. Reconcile
        if now - last_reconcile >= reconcile_interval:
            try:
                reconcile(desired_ips, backend, allowlist)
            except Exception as e:
                print(f"[fw-agent] reconcile 실패: {e}")
            last_reconcile = now

        # 3. Heartbeat
        if now - last_heartbeat >= heartbeat_interval:
            try:
                ipset_size = len(backend.list_ips())
                client.heartbeat({"poll_failures": poll_failures, "ipset_size": ipset_size})
            except Exception as e:
                print(f"[fw-agent] heartbeat 실패: {e}")
            last_heartbeat = now

        time.sleep(poll_interval)


if __name__ == "__main__":
    main()