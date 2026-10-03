#!/usr/bin/env python
"""D1 live proof: a real MCP server behind the gate, checked from both sides.

Starts two *separate processes*:

1. ``scripts/mcp_fixture_server.py`` - a real MCP server (official ``mcp`` SDK,
   streamable HTTP) on its own port, appending every call it receives to its own access
   log;
2. the warrnt node with ``WARRNT_UPSTREAM`` pointed at it.

Then it drives the demo vector and asserts each outcome twice: once from the node
(receipts, decisions) and once from the upstream's own log. "The denied export never
reached upstream" is therefore a fact about the other process, not a claim by the node.

    python scripts/upstream_check.py            # exits non-zero on any failure
    python scripts/upstream_check.py --keep     # leave the node up for manual poking
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from warrnt.seed import SEED_SPECS  # noqa: E402

os.environ.setdefault("WARRNT_ADMIN_TOKEN", "operator-token")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from warrnt import demo  # noqa: E402

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""), flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(host: str, port: int, timeout: float = 25.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing listening on {host}:{port} after {timeout}s")


def wait_health(url: str, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=2) as r:
                return json.loads(r.read().decode())
        except Exception as exc:                      # noqa: BLE001 - report the last error
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"node never became healthy: {last}")


def _norm(tool: str) -> str:
    """The node may register a tool under ``crm.read``; the MCP server also spells it
    ``crm.read``. Normalise so a fixture that uses underscores still matches."""
    return tool.replace("_", ".")


def upstream_calls(log_path: Path) -> list[str]:
    if not log_path.exists():
        return []
    out = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(_norm(json.loads(line)["tool"]))
    return out


def advertised_tools(url: str) -> list[str]:
    """Ask the fixture, as an MCP client, what it serves. Proves a real MCP handshake."""
    import asyncio

    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async def go() -> list[str]:
        async with streamable_http_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                return sorted(t.name for t in listed.tools)

    return asyncio.run(go())


def main() -> int:
    parser = argparse.ArgumentParser(description="Live check: real MCP upstream behind the gate.")
    parser.add_argument("--keep", action="store_true", help="leave the node running")
    args = parser.parse_args()

    work = ROOT / "state" / "upstream"
    work.mkdir(parents=True, exist_ok=True)
    upstream_log = work / "upstream_calls.jsonl"
    for stale in (upstream_log,):
        if stale.exists():
            stale.unlink()

    upstream_port = free_port()
    upstream_url = f"http://127.0.0.1:{upstream_port}/mcp"
    node_port = free_port()
    node_url = f"http://127.0.0.1:{node_port}"

    log_up = open(work / "upstream-server.log", "w")
    upstream = subprocess.Popen(
        [sys.executable, "scripts/mcp_fixture_server.py", "--port", str(upstream_port),
         "--log", str(upstream_log)],
        cwd=str(ROOT), stdout=log_up, stderr=subprocess.STDOUT,
    )

    env = {
        **os.environ,
        "WARRNT_DEV": "1",
        "WARRNT_HOME": str(work / "node-state"),
        "WARRNT_PORT": str(node_port),
        "WARRNT_UPSTREAM": upstream_url,
    }
    (work / "node-state").mkdir(parents=True, exist_ok=True)
    log_node = open(work / "node.log", "w")
    node = None
    try:
        wait_port("127.0.0.1", upstream_port)
        tools = advertised_tools(upstream_url)
        check("the upstream is a real MCP server (handshake + tools/list)",
              len(tools) >= 6, ",".join(tools))

        node = subprocess.Popen([sys.executable, "-m", "warrnt", "serve", "--port", str(node_port)],
                                cwd=str(ROOT), env=env, stdout=log_node, stderr=subprocess.STDOUT)
        health = wait_health(node_url)
        check("the node is up in front of it", health["ok"] and health["chain"]["ok"],
              f"upstream={upstream_url}")

        tokens = demo.fetch_tokens(node_url)
        # Against the seed table, not a remembered number: the seed set grew from three to four
        # when the analytics agent arrived, and a hard-coded 3 kept this gate red.
        check(f"the {len(SEED_SPECS)} seed warrants are issued in front of the real upstream",
              len(tokens) == len(SEED_SPECS))

        # --- 1. the allowed read really crosses the wire -------------------------------
        allowed = demo.rpc(node_url, "support-copilot", tokens["support-copilot"],
                           "crm.read", {"table": "tickets", "rows": 20})
        result = allowed.get("result", {})
        seen = upstream_calls(upstream_log)
        check("an allowed call is answered by the real upstream, not by a stub",
              result.get("executed") is True
              and result.get("upstream") is True
              and int(result.get("rows", 0)) == 20,
              f"result={json.dumps(result, sort_keys=True)[:160]}")
        check("the upstream's own log shows that call", seen.count("crm.read") == 1,
              f"upstream saw {seen}")

        # --- 2. the denied PII export never reaches the other process ------------------
        denied = demo.rpc(node_url, "support-copilot", tokens["support-copilot"], "crm.bulk_export",
                          {"table": "customers", "fields": ["email", "pesel"], "rows": 12000})
        check("a PII export is denied at the gate",
              denied.get("error", {}).get("data", {}).get("decision") == "deny")
        check("the denied export never reached the upstream's log",
              "crm.bulk_export" not in upstream_calls(upstream_log),
              f"upstream saw {upstream_calls(upstream_log)}")

        # --- 3. an over-limit transfer never reaches the other process -----------------
        over = demo.rpc(node_url, "fin-reconcile", tokens["fin-reconcile"], "payments.transfer",
                        {"amount_pln": 60000, "rows": 1})
        check("a transfer over the warrant limit is denied",
              over.get("error", {}).get("code") == -32001)
        check("the over-limit transfer never reached the upstream",
              "payments.transfer" not in upstream_calls(upstream_log),
              f"upstream saw {upstream_calls(upstream_log)}")

        # --- 4. money inside its own signed limit still does not move -------------------
        # The action-class taxonomy: an irreversible act is REQUIRE-HUMAN, whatever the order
        # says. What this check proves is that a *valid, untampered* warrant is still not
        # enough to move money, and that the other process never even hears about the call.
        in_limit = demo.rpc(node_url, "fin-reconcile", tokens["fin-reconcile"],
                            "payments.transfer", {"amount_pln": 42000, "rows": 1})
        check("an in-limit transfer stops at require-human, not at the upstream",
              in_limit.get("error", {}).get("code") == -32002
              and in_limit.get("error", {}).get("data", {}).get("class") == "irreversible",
              f"error={json.dumps(in_limit.get('error', {}), sort_keys=True)[:200]}")
        check("the upstream's log shows no transfer at all",
              upstream_calls(upstream_log).count("payments.transfer") == 0,
              f"upstream saw {upstream_calls(upstream_log)}")
        receipt = demo.get(node_url, "/receipts")[-1]
        check("and the refusal is on the record as 'human', naming the class",
              receipt["decision"] == "human" and "class irreversible" in receipt["reason"],
              f"{receipt['decision']} · {receipt['reason'][:140]}")

        # --- 5. require-human never reaches the other process --------------------------
        deploy = demo.rpc(node_url, "deploy-agent", tokens["deploy-agent"], "infra.deploy",
                          {"env": "prod", "rows": 1})
        check("deploy stops at require-human", deploy.get("error", {}).get("code") == -32002)
        check("a queued deploy never reached the upstream",
              "infra.deploy" not in upstream_calls(upstream_log))

        # --- 6. forged + revoked tokens never reach the other process ------------------
        demo.rpc(node_url, "support-copilot", "forged", "crm.read", {"table": "tickets", "rows": 5})
        demo.post(node_url, "/revoke", {"agent": "support-copilot"})
        revoked = demo.rpc(node_url, "support-copilot", tokens["support-copilot"], "crm.read",
                           {"table": "tickets", "rows": 5})
        check("a revoked agent cannot call again", revoked.get("error", {}).get("code") == -32003)
        check("neither the forged nor the revoked call reached the upstream",
              upstream_calls(upstream_log).count("crm.read") == 1,
              f"upstream saw {upstream_calls(upstream_log)}")

        # --- 7. the books still balance ------------------------------------------------
        chain = demo.get(node_url, "/verify")
        check("the receipt chain recomputes from genesis", chain["ok"] and chain["length"] > 0,
              f"{chain['length']} receipts, head {chain['head']}")
        check("the node's executor counter matches the upstream's log",
              demo.get(node_url, "/state")["executor_calls"] == {"crm.read": 1}
              and upstream_calls(upstream_log).count("payments.transfer") == 0,
              f"node={demo.get(node_url, '/state')['executor_calls']} "
              f"upstream={sorted(upstream_calls(upstream_log))}")

        print(f"\nupstream access log: {upstream_log}")
        print("upstream log contents:", json.dumps(upstream_calls(upstream_log)))
    finally:
        if not args.keep:
            if node is not None:
                node.terminate()
                try:
                    node.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    node.kill()
            upstream.terminate()
            try:
                upstream.wait(timeout=5)
            except subprocess.TimeoutExpired:
                upstream.kill()
        else:
            print(f"keeping node pid={node.pid if node else '-'} upstream pid={upstream.pid}")
        log_node.close()
        log_up.close()

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
