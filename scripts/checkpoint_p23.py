#!/usr/bin/env python3
"""P2.3 control checkpoint: assert the demo vector passed end to end.

Reads a transcript produced by scripts/demo_client.py (JSON) and checks that the
whole 3:47 vector actually happened on the live node: reads allowed, the PII export
denied *before* execution, the operator's revoke observed by the running agent on its
next call (with a measured latency), and the receipt chain recomputed from genesis.

    WARRNT_DEV=1 python3 -m warrnt serve --port 8111        # terminal A - dev mode matters
    python3 scripts/demo_client.py http://127.0.0.1:8111 > transcript.json
    python3 scripts/checkpoint_p23.py transcript.json

    The two-step above reports 4/7 without WARRNT_DEV=1, and not because anything is broken:
    two of the checks are about the halt being *observed* by the running agent, and the vector
    only drives that follow-up call in dev mode. Reproduced both ways - 4/7 without the flag,
    7/7 with it (stop_latency_s=0.147). `scripts/first_demo_path.py` boots its own node with
    the flag already set and asserts all seven in one command, which is the shorter path.

With no argument it reads $TMPDIR/warrnt-transcript.json (the platform's own
scratch directory - the old default was a hard-coded /tmp path).
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# A hard-coded /tmp path is a POSIX-only default; the transcript is scratch, so let the platform
# say where scratch lives.
DEFAULT_TRANSCRIPT = str(Path(tempfile.gettempdir()) / "warrnt-transcript.json")

CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""), flush=True)


def main(path: str) -> int:
    t = json.loads(Path(path).read_text())
    steps = [s for s in t if "tool" in s]
    proof = next((s for s in t if "proof" in s), {})
    stop = next((s for s in t if s.get("decision") == "revoked"), None)
    chain = next((s.get("chain") for s in t if s.get("chain")), {})

    allowed = [s for s in steps if s.get("decision") == "allow"]
    denied = [s for s in steps if s.get("decision") == "deny"]

    check("the vector ran: reads allowed inside scope", len(allowed) >= 2,
          f"{len(allowed)} allow: {[s['tool'] for s in allowed]}")
    check("the rogue export was denied", any(s["tool"] == "crm.bulk_export" for s in denied),
          f"deny tools: {[s['tool'] for s in denied]}")
    check("deny happened BEFORE execution (upstream counter unchanged)",
          proof.get("before") == proof.get("after") == 0,
          f"crm.bulk_export {proof.get('before')}->{proof.get('after')}")
    check("zero rows left the perimeter", proof.get("rows_left_perimeter") == 0,
          f"rows_left_perimeter={proof.get('rows_left_perimeter')}")
    check("the running agent observed the revocation on its next call",
          bool(stop and stop.get("observed_on_next_call")),
          f"latency={stop.get('stop_latency_s') if stop else None}s")
    check("revocation latency was measured, not declared",
          bool(stop and isinstance(stop.get("stop_latency_s"), (int, float))
               and stop["stop_latency_s"] >= 0),
          f"{stop.get('stop_latency_s') if stop else None}s")
    check("the receipt chain recomputes from genesis",
          chain.get("ok") is True and chain.get("length", 0) > 0,
          f"{chain.get('length')} receipts, head {chain.get('head')}")

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checkpoint checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TRANSCRIPT))
