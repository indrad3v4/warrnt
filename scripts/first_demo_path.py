#!/usr/bin/env python3
"""WARRNT — the first demo path, one command, start to finish.

Boots the node on a free port with a *clean* state directory, waits for /health,
drives the whole 3:47 vector over real HTTP, asserts it with the P2.3 checkpoint
(7/7), then prints the live contract the jury will see: agents, warrants, the
executor counter that proves the PII export never ran, and the receipt chain
recomputed from genesis plus the signed anchor verdict.

    python3 scripts/first_demo_path.py                # prints the whole run
    python3 scripts/first_demo_path.py --json out.json

Exit code 0 only if the checkpoint passes and the chain verifies. Nothing here is
a mock: the transcript is measured on a live uvicorn process.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# The control plane is not anonymous (finding V1): the node this script boots must be told the
# operator token, or the demo vector dies at the revoke step with a 401. The other four gate
# scripts set it the same way.
os.environ.setdefault("WARRNT_ADMIN_TOKEN", "operator-token")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from warrnt import demo  # noqa: E402
import checkpoint_p23  # noqa: E402

STATE = ROOT / "state" / "first-demo"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_health(url: str, timeout: float = 25.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=2) as r:
                return json.loads(r.read().decode())
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"node never became healthy: {last}")


def rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="", help="also write the transcript here")
    args = ap.parse_args()

    if STATE.exists():
        shutil.rmtree(STATE)
    STATE.mkdir(parents=True, exist_ok=True)

    port = free_port()
    url = f"http://127.0.0.1:{port}"
    env = {**os.environ, "WARRNT_DEV": "1", "WARRNT_HOME": str(STATE),
           "WARRNT_PORT": str(port)}
    env.pop("WARRNT_UPSTREAM", None)          # countable sandbox upstream

    log_path = STATE / "server.log"
    log = open(log_path, "w")
    proc = subprocess.Popen([sys.executable, "-m", "warrnt", "serve", "--port", str(port)],
                            cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT)
    status = 1
    try:
        health = wait_health(url)
        rule("0. NODE UP")
        print(f"url            : {url}")
        print(f"state dir      : {STATE}")
        print(f"chain          : {health['chain']}")

        rule("1. ORDER — signed identity (scope + TTL + HMAC-SHA256)")
        for w in demo.get(url, "/warrants"):
            print(f"  {w['id']}  {w['agent']:<16} scope={w['scope']:<40} sig_ok={w['sig_ok']}")

        rule("2. DEMO VECTOR — reads allowed, PII export denied, agent revoked")
        transcript = demo.run(url)
        for s in transcript:
            if "tool" in s:
                print(f"  {s['decision']:<8} {s['agent']:<16} {s['tool']:<16} {s['note']}")
            elif "proof" in s:
                print(f"  PROOF   {s['proof']}: before={s['before']} after={s['after']} "
                      f"rows_left_perimeter={s['rows_left_perimeter']}")
            elif s.get("decision") == "revoked":
                print(f"  REVOKED {s['agent']:<16} observed_on_next_call="
                      f"{s['observed_on_next_call']} stop_latency_s={s['stop_latency_s']}")

        rule("3. CHECKPOINT — assert the vector happened (P2.3, 7 checks)")
        tpath = STATE / "transcript.json"
        tpath.write_text(json.dumps(transcript, indent=2, ensure_ascii=False))
        cp = checkpoint_p23.main(str(tpath))

        rule("4. PROOF — the live contract (what the jury sees)")
        st = demo.get(url, "/state")
        for a in st["agents"]:
            print(f"  agent   {a['id']:<16} state={a['state']:<8} warrant={a['warrant']}")
        print(f"  executor_calls : {st['executor_calls']}")
        print(f"  receipts       : {st['receipts']}")
        print(f"  chain          : {st['chain']}")

        rule("5. ANCHOR — the head is signed with the issuer key")
        print("  " + json.dumps(demo.get(url, "/anchor"), ensure_ascii=False))

        if args.json:
            Path(args.json).write_text(json.dumps(transcript, indent=2, ensure_ascii=False))

        rule("VERDICT")
        ok = cp == 0 and health["chain"]["ok"] and st["chain"]["ok"]
        print("FIRST DEMO PATH: " + ("PASS — the chain ran end to end" if ok else "FAIL"))
        status = 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
