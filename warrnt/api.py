"""FastAPI surface of the node.

    POST /mcp       JSON-RPC 2.0 ``tools/call`` - the interception point
    POST /revoke    pull a warrant and halt the agent
    GET  /state     live contract (agents, warrants, receipts, chain)
    GET  /warrants  signed artifacts + signature validity
    GET  /receipts  the full append-only registry
    GET  /verify    recompute the hash chain from genesis
    GET  /health    liveness + chain head
    POST /reset     rotate the receipt chain and re-issue the seed warrants (operator token)
    POST /api/breakglass            a named person opens a policy pause for ≤15 min
    GET  /api/breakglass            every grant, its state, its window and its debt
    POST /api/breakglass/revoke     close a grant early
    POST /api/breakglass/postmortem record the review a used grant owes
    GET  /api/actions            the canonical Action log (one object per intercepted call)
    GET  /api/actions/pending    the human holds, newest first (declared before /{id})
    GET  /api/actions/{id}       one Action: decision, upstream_contacted, receipt
    POST /api/actions/{id}/approve  a named person releases a held action (runs upstream)
    POST /api/actions/{id}/deny     a named person refuses it (upstream NOT contacted)
    GET  /api/overview           counters + authority summary + mode, one payload
    GET  /api/activity           ordered recent events, newest first (?limit=, default 50)
    GET  /api/warrants           alias of /warrants under the /api/ prefix
    GET  /api/agents             alias of /agents under the /api/ prefix
    POST /api/agents/{id}/revoke revoke an agent/authority (thin wrapper over /revoke)
    POST /api/ask                an answer assembled from the record - never guessed

The proxy is built once in ``create_app`` and stored on ``app.state.proxy``; routes are
thin translators. A denied call returns a JSON-RPC ``error`` and the upstream is not
touched.

Mutating routes (``/reset``, ``/revoke``, ``/api/breakglass*``, ``/_dev/*``) require the
operator token in ``x-warrnt-admin``: an anonymous control plane is a control plane anyone
can drive (finding V1). Set ``WARRNT_ADMIN_TOKEN``; when it is unset the node generates one
and prints it once at startup.
"""
from __future__ import annotations

import csv
import hmac
import io
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from .actions import classify
from .actors import ActorRegistry
from .anchor import HeadAnchor
from .breakglass import MAX_TTL_S, BreakGlassRefused
from .controlplane import HoldRefused, answer
from .config import Settings
from .models import Decision
from .policy import PolicyEngine
from .proxy import MCPProxy, _receipt_row
from .registry import AppendOnlyRegistry
from .upstream import build_upstream, ExecutionCounter
from .warrants import WarrantIssuer, refresh_state

# Only refusals are errors. ``redact`` runs, so it is a result with a note - a receipt
# that says *executed, minus these fields* - never a JSON-RPC error.
RPC_CODES = {
    Decision.deny: -32001,
    Decision.human: -32002,
    Decision.revoked: -32003,
}


class RevokeRequest(BaseModel):
    agent: Optional[str] = None
    warrant: Optional[str] = None


class TamperRequest(BaseModel):
    warrant: str


class BreakGlassRequest(BaseModel):
    human: str
    agent: str
    tool: str
    reason: str
    ttl_s: float = MAX_TTL_S


class BreakGlassId(BaseModel):
    id: str


class BreakGlassPostmortem(BaseModel):
    id: str
    note: str


class DecideRequest(BaseModel):
    by: str
    note: str = ""


class AskRequest(BaseModel):
    q: str


class ResetRequest(BaseModel):
    reason: str = ""
    actor: str = ""


def build_proxy(settings: Settings) -> MCPProxy:
    issuer = WarrantIssuer.from_env_or_file(str(settings.key_path))
    registry = AppendOnlyRegistry(str(settings.registry_path))
    counter = ExecutionCounter()
    upstream = build_upstream(counter)
    engine = PolicyEngine(verify=issuer.signature_ok)
    # The persistence layer writes its store next to the registry, under the same directory
    # the process was pointed at (TENET_STATE_DIR, else WARRNT_HOME, else ./state).
    proxy = MCPProxy(issuer=issuer, registry=registry, engine=engine, upstream=upstream,
                     store_dir=str(settings.home))
    proxy.counter = counter
    # Every append, and every reset, re-signs the registry head with the issuer key and
    # records it in a separate anchor log. A rewritten registry no longer matches the last
    # signed anchor, and the anchor cannot be forged without the key (finding M1).
    anchor = HeadAnchor(str(settings.anchor_path), issuer.sign)
    proxy.anchor = anchor

    def _seal_append(rec: dict) -> None:
        anchor.seal(rec["hash"], len(registry.entries))

    def _seal_reset(rotation: Optional[dict[str, Any]] = None) -> None:
        # Seal the closed segment first, so the anchor log itself carries the rotation point
        # (head + row count), then seal the fresh empty chain.
        if rotation:
            anchor.seal(rotation["closed_head"], rotation["closed_length"])
        anchor.seal(registry.GENESIS, 0)

    registry.on_append = _seal_append
    registry.on_reset = _seal_reset
    return proxy


def _as_iso(value: str) -> str:
    """Accept an epoch second, a date or an ISO instant for `since` - a reviewer should not have
    to know which of the three this node happens to write."""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(text)))
    except ValueError:
        return text


def create_app(settings: Optional[Settings] = None, seed: bool = True) -> FastAPI:
    settings = settings or Settings.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if seed:
            app.state.proxy.issue_all(reset_registry=False)
            # A restart may bring back an order that was halted while a person still owed a
            # decision: that hold comes back expired, never pending (R2).
            app.state.proxy._expire_holds_of_halted_agents()
        yield

    app = FastAPI(title="WARRNT node", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.proxy = build_proxy(settings)

    admin_token = settings.admin_token or secrets.token_urlsafe(24)
    app.state.admin_token = admin_token
    if not settings.admin_token:
        print("[warrnt] WARRNT_ADMIN_TOKEN is unset - generated for this process only:\n"
              f"[warrnt]   {admin_token}\n"
              "[warrnt] mutating routes need the header x-warrnt-admin: <token>", flush=True)

    def require_admin(supplied: str) -> Optional[JSONResponse]:
        """401 unless the caller holds the operator token."""
        if not admin_token or not supplied or not hmac.compare_digest(supplied, admin_token):
            return JSONResponse({"error": "operator token required",
                                 "hint": "send the x-warrnt-admin header"}, status_code=401)
        return None

    def proxy() -> MCPProxy:
        return app.state.proxy

    def chain_view() -> dict[str, Any]:
        p = proxy()
        return {**p.registry.verify(),
                "anchor": p.anchor.verify(p.registry.head, len(p.registry.entries))}

    def warrants_payload() -> list[dict[str, Any]]:
        """Signed orders, one shape for both /warrants and /api/warrants (no drift)."""
        p = proxy()
        return [{
            "id": w.id, "agent": w.agent, "role": w.role, "scope": w.scope,
            "ttl": w.ttl, "issued": w.issued, "issuer": w.issuer,
            "state": w.state, "sig": w.sig, "sig_ok": p.issuer.signature_ok(w),
            "payload": w.payload(),
        } for w in p.warrants.values()]

    def agents_payload() -> list[dict[str, Any]]:
        """Agent identities, one shape for both /agents and /api/agents (no drift).

        Tokens are exposed only when WARRNT_DEV=1 - a demo convenience, not an API.
        """
        p = proxy()
        out = []
        for a in p.agents.values():
            row = {"id": a.id, "role": a.role, "warrant": a.warrant, "state": a.state,
                   "last": a.last}
            if settings.dev:
                row["token"] = a.token
            out.append(row)
        return out

    # ------------------------------------------------------------------- reads
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def console() -> HTMLResponse:
        """The console screen (IN-6): a live view of THIS node's /api/state.

        Served from inside the package so the demo is one artifact - clone, run, open
        the node - and the screen can never drift from the API it renders. Read per
        request: editing the file does not need a restart during the demo.
        """
        path = Path(__file__).with_name("console.html")
        if not path.exists():
            return HTMLResponse("<h1>WARRNT</h1><p>console.html missing from the package</p>",
                                status_code=500)
        return HTMLResponse(path.read_text(encoding="utf-8"))

    @app.get("/api/catalog")
    def catalog_view() -> JSONResponse:
        """The controls a reviewer turns, and how strictly each one acts (D3).

        Reads are open on purpose: the operator's own screen has to be able to see the knobs.
        Changing them is a file edit - see /api/catalog/reload to make one take effect now.
        """
        return JSONResponse(proxy().catalog.summary())

    @app.get("/api/budget")
    def budget_view() -> JSONResponse:
        """What each agent has spent inside its window (D7) - resource consumption, not a guess."""
        return JSONResponse({"spend": proxy().budget.snapshot()})

    @app.post("/api/catalog/reload")
    def catalog_reload(x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """Force a re-read of the catalog (operator token).

        The file is already re-read whenever its mtime moves, so this is the explicit form of
        the same thing: it is what a reviewer presses after editing a threshold, and it answers
        with the settings now in force rather than a bare ok.
        """
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        changed = proxy().catalog.reload(force=True)
        return JSONResponse({"reloaded": changed, **proxy().catalog.summary()})

    @app.get("/api/signatures")
    def signatures_view() -> JSONResponse:
        """The attack feed the node is enforcing right now (D8, brief 4.4).

        Operations owns the file; this is the view a person needs to answer "is the node
        actually checking against the current revision, and what is in it".
        """
        feed = proxy().signatures
        return JSONResponse({**feed.summary(),
                             "signatures": [s.as_detail() for s in feed.signatures]})

    @app.post("/api/signatures/reload")
    def signatures_reload(x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """Force a re-read of the feed (operator token) and answer with what is now in force."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        changed = proxy().signatures.reload(force=True)
        return JSONResponse({"reloaded": changed, **proxy().signatures.summary()})

    @app.get("/api/semantic")
    def semantic_view() -> JSONResponse:
        """The judging box: which model, and whether it is answering (brief 4.2).

        Reads only. It does not call the model - asking here must not load a box during a demo.
        """
        judge = proxy().semantic
        control = proxy().catalog.control("semantic_judge")
        return JSONResponse({**judge.summary(), "enabled": control.enabled,
                             "consulted": proxy().catalog.consulted("semantic_judge"),
                             "strictness": proxy().catalog.strictness("semantic_judge"),
                             "threshold": proxy().catalog.threshold("semantic_judge", 0.6)})

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "node": "warrnt", "chain": chain_view()}

    @app.get("/state")
    def state(limit: int = 60) -> dict[str, Any]:
        return proxy().state(limit=limit)

    @app.get("/api/state", include_in_schema=False)
    def api_state_alias(limit: int = 60) -> dict[str, Any]:
        """Alias kept for the console screen (P3), which polls /api/state."""
        return proxy().state(limit=limit)

    @app.get("/verify")
    def verify() -> dict[str, Any]:
        return chain_view()

    @app.get("/anchor")
    def anchor() -> dict[str, Any]:
        """The last head the issuer signed, and whether the live registry still matches it."""
        p = proxy()
        last = p.anchor.last
        hist = p.registry.history()
        verdict = p.anchor.verify(p.registry.head, len(p.registry.entries))
        # The anchor speaks for the live head. If a rotated segment is gone or edited, the
        # anchor must not be the one place that still says "fine" (finding V2).
        verdict = {**verdict, "history_ok": hist["archives_ok"],
                   "ok": bool(verdict.get("ok")) and hist["archives_ok"]}
        return {
            "anchors": len(p.anchor.records),
            "last": ({"head": last["head"], "length": last["length"], "ts": last["ts"],
                      "sig": last["sig"][:16] + "…"} if last else None),
            "verdict": verdict,
            "history": hist,
        }

    # ------------------------------------------------------------------ 4.5 the export
    # The security team asked for evidence they can take away and check without this node, so the
    # export is self-contained: the rows, the chain verdict, the anchor, and the revisions of the
    # controls that were in force. An export that needs its exporter to explain it is not
    # evidence, it is a screenshot.
    @app.get("/export")
    def export(format: str = "json", agent: str = "", decision: str = "",  # noqa: A002
               since: str = "", limit: int = 0) -> Response:
        """Export the receipt chain as evidence: `?format=csv`, `json` or `jsonl`.

        The filters are the ones a reviewer reaches for - one agent, one kind of decision,
        everything after a time - and they filter the ROWS only. The chain verdict and the anchor
        always describe the whole chain, because a filtered view of a chain is not a chain.
        """
        fmt = (format or "json").strip().lower()
        if fmt not in ("csv", "json", "jsonl"):
            return JSONResponse({"error": f"format must be csv, json or jsonl, not {format!r}"},
                                status_code=400)

        p = proxy()
        rows = list(p.registry.entries)
        if agent:
            rows = [r for r in rows if r.get("agent") == agent]
        if decision:
            rows = [r for r in rows if r.get("decision") == decision]
        if since:
            rows = [r for r in rows if max(str(r.get("t") or ""), str(r.get("ts") or "")) >=
                    max(since, _as_iso(since))]
        if limit and limit > 0:
            rows = rows[-limit:]

        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        filename = f"warrnt-export-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.{fmt}"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\n")
            writer.writerow(("seq", "t", "ts", "decision", "agent", "tool", "warrant", "reason",
                             "rows_after", "outcome", "receipt_hash", "prev_hash"))
            for i, row in enumerate(rows):
                writer.writerow([i + 1] + [row.get(col, "") for col in
                                           ("t", "ts", "decision", "agent", "tool", "warrant",
                                            "reason", "rows_after", "outcome", "hash", "prev")])
            return Response(content=buf.getvalue(), media_type="text/csv", headers=headers)

        if fmt == "jsonl":
            body = "\n".join(json.dumps(r, sort_keys=True) for r in rows)
            return Response(content=body, media_type="application/x-ndjson", headers=headers)

        return JSONResponse({
            "exported_at": stamp,
            "node": "warrnt",
            "exporter": "GET /export",
            "rows_total": len(rows),
            "filter": {"agent": agent, "decision": decision, "since": since, "limit": limit},
            "chain": chain_view(),
            "anchor": anchor(),
            "controls_in_force": {
                "catalog_version": p.catalog.version,
                "controls": p.catalog.summary().get("controls", {}),
                "signature_feed": {"version": p.signatures.version,
                                   "source": p.signatures.source,
                                   "count": len(p.signatures.signatures),
                                   "ok": p.signatures.ok},
            },
            "note": ("The chain verdict covers the whole chain; the rows may be filtered. Verify "
                     "a row by recomputing the chain from genesis - receipt_hash and prev_hash "
                     "are the inputs."),
            "receipts": rows,
        }, headers=headers)

    @app.get("/receipts")
    def receipts() -> list[dict[str, Any]]:
        return proxy().registry.entries

    @app.get("/actors")
    def actors() -> dict[str, Any]:
        """Who stands at the gate, by class, and what each may never call.

        The register is the answer to "this agent cannot": it is not a permission view of the
        user, it is a limit on the actor, and it is checked before the warrant is read.
        """
        p = proxy()
        return {"kinds": ActorRegistry.kinds(), "actors": p.actors.listing()}

    @app.get("/warrants")
    def warrants() -> list[dict[str, Any]]:
        return warrants_payload()

    @app.get("/agents")
    def agents() -> list[dict[str, Any]]:
        return agents_payload()


    # -------------------------------------------------------------- interception
    @app.post("/mcp")
    async def mcp(request: Request,
                  x_warrnt_agent: str = Header(default=""),
                  x_warrnt_token: str = Header(default=""),
                  x_warrnt_run: str = Header(default="")) -> JSONResponse:
        body = await request.json()
        rpc_id = body.get("id")
        if body.get("method") != "tools/call":
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id,
                                 "error": {"code": -32601,
                                           "message": "only tools/call is intercepted"}})
        params = body.get("params", {})
        tool = params.get("name")
        args = params.get("arguments") or {}
        if not tool:
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id,
                                 "error": {"code": -32602, "message": "params.name required"}})

        decision, reason, detail, receipt, executed = proxy().intercept(
            x_warrnt_agent, x_warrnt_token, tool, args, run_id=x_warrnt_run)

        if decision in (Decision.allow, Decision.redact):
            return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "decision": decision.value, "reason": reason, "executed": executed,
                "action_id": detail.get("action_id"),
                "receipt": detail.get("receipt"),
                "redacted": detail.get("redacted"),
                "upstream_params": detail.get("upstream_params"),
                **detail.get("result", {}),
            }})
        return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": {
            "code": RPC_CODES.get(decision, -32000), "message": reason,
            "data": {"decision": decision.value, "executed": executed, **detail},
        }})

    # ---------------------------------------------------------- control plane (PR-14)
    @app.get("/api/actions")
    def actions(state: str = "", limit: int = 60) -> dict[str, Any]:
        """The canonical Action log: the same object the console renders and an answer quotes."""
        p = proxy()
        return {"counts": p.actions.counts(),
                "pending": p.actions.pending(),
                "actions": p.actions.listing(state=state or None, limit=limit)}

    # Declared before /api/actions/{action_id}: otherwise \"pending\" is read as an id and the
    # hold list 404s. A projection of the ledger, not a second store.
    @app.get("/api/actions/pending")
    def actions_pending(limit: int = 50) -> dict[str, Any]:
        """Actions whose state is pending - the human holds, newest first."""
        p = proxy()
        rows = p.actions.listing(state="pending", limit=limit)
        return {"count": len(rows), "pending": rows}

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        """Counters + authority summary + mode, one payload - all projections of state.

        Nothing here is invented: every number is a field the enforcement path already
        recorded. With no data the lists are empty, not seeded.
        """
        p = proxy()
        st = p.state(limit=1)
        agents = agents_payload()
        return {
            "node": "TENET",
            "mode": "dev" if settings.dev else "ops",
            "counts": {
                "agents": len(agents),
                "agents_halted": sum(1 for a in agents if a["state"] == "halted"),
                "warrants": len(p.warrants),
                "receipts": len(p.registry.entries),
                "actions": p.actions.counts()["total"],
                "pending": p.actions.counts()["pending"],
            },
            "authority": {
                "issuer": "risk-office",
                "warrant_states": {
                    s: sum(1 for w in p.warrants.values()
                           if refresh_state(w, p._now()) == s)
                    for s in ("active", "revoked", "expired")
                },
                "actors": p.actors.listing(),
                "action_classes": st["actions"],
            },
            "chain": p.registry.verify(),
        }

    @app.get("/api/activity")
    def activity(limit: int = 50) -> dict[str, Any]:
        """Ordered recent events, newest first. Each event is a receipt or an action the
        node already holds - no synthesized events, no placeholder timestamps."""
        p = proxy()
        events: list[dict[str, Any]] = []
        for e in p.registry.recent(limit):
            events.append({**_receipt_row(e), "kind": "receipt", "ts": e.get("ts")})
        for a in p.actions.listing(limit=limit):
            events.append({"kind": "action", "t": None, "ts": a.get("ts"),
                           "action_id": a["action_id"], "agent": a["agent"],
                           "tool": a["tool"], "state": a["state"],
                           "decision": a.get("decision")})
        # Newest first by the timestamp the record itself carries; a stable tiebreak on the
        # action id keeps the order deterministic when two events share a second.
        events.sort(key=lambda ev: (ev.get("ts") or 0.0, ev.get("action_id") or ""),
                    reverse=True)
        return {"count": min(len(events), limit), "events": events[:limit]}

    @app.get("/api/warrants")
    def api_warrants() -> list[dict[str, Any]]:
        """Alias of /warrants under the /api/ prefix - the same payload, no second shape."""
        return warrants_payload()

    @app.get("/api/agents")
    def api_agents() -> list[dict[str, Any]]:
        """Alias of /agents under the /api/ prefix - the same payload, no second shape."""
        return agents_payload()

    @app.post("/api/agents/{agent_id}/revoke")
    def api_agent_revoke(agent_id: str,
                         x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """Revoke an agent/authority. A thin wrapper over the one revoke path: same
        receipts, same state change - there is no second code path to drift."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        p = proxy()
        if agent_id not in p.agents:
            return JSONResponse({"error": "unknown agent or already halted",
                                 "agent": agent_id}, status_code=409)
        t0 = p.revoke(agent_id)
        if t0 is None:
            return JSONResponse({"error": "unknown agent or already halted",
                                 "agent": agent_id}, status_code=409)
        return JSONResponse({"agent": agent_id, "state": "halted",
                             "warrant": p.agents[agent_id].warrant, "revoked_at": t0})

    @app.get("/api/actions/{action_id}")
    def action_one(action_id: str) -> JSONResponse:
        action = proxy().actions.get(action_id)
        if action is None:
            return JSONResponse({"error": f"unknown action {action_id}",
                                 "hint": "GET /api/actions lists the ledger"},
                                status_code=404)
        return JSONResponse(action.public())

    @app.post("/api/actions/{action_id}/approve")
    def action_approve(action_id: str, body: DecideRequest,
                       x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """A named person releases the hold: the upstream runs here, once, and the chain
        records the human decision *before* the execution it authorises."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        try:
            out = proxy().resolve_hold(action_id, approve=True, by=body.by)
        except HoldRefused as exc:
            return JSONResponse({"error": str(exc), "action_id": action_id}, status_code=409)
        return JSONResponse({"action_id": action_id, "state": out["action"]["state"],
                             "executed": out["executed"], "upstream_contacted": True,
                             "rows": out.get("rows", 0), "receipt": out["receipt"]})

    @app.post("/api/actions/{action_id}/deny")
    def action_deny(action_id: str, body: DecideRequest,
                    x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """A named person refuses the hold. The upstream is NOT contacted, and the receipt
        is the proof: ``upstream_contacted`` stays false for this action_id."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        try:
            out = proxy().resolve_hold(action_id, approve=False, by=body.by)
        except HoldRefused as exc:
            return JSONResponse({"error": str(exc), "action_id": action_id}, status_code=409)
        return JSONResponse({"action_id": action_id, "state": out["action"]["state"],
                             "executed": False, "upstream_contacted": False,
                             "receipt": out["receipt"]})

    @app.post("/api/ask")
    def ask(body: AskRequest) -> dict[str, Any]:
        """An answer built from the record. There is no model in this path on purpose: what
        the console says about a call must be a field of that call, or an admission that the
        field is missing."""
        p = proxy()
        st = p.state(limit=20)
        return answer(body.q, p.actions.listing(limit=60), st)

    # --------------------------------------------------------------------- brake
    @app.post("/revoke")
    def revoke(body: RevokeRequest, x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        p = proxy()
        agent_id = body.agent
        if agent_id is None and body.warrant:
            warrant = p.warrants.get(body.warrant)
            agent_id = warrant.agent if warrant else None
        if agent_id is None or agent_id not in p.agents:
            return JSONResponse({"error": "unknown agent or already halted",
                                 "agent": agent_id}, status_code=409)
        t0 = p.revoke(agent_id)
        if t0 is None:
            return JSONResponse({"error": "unknown agent or already halted",
                                 "agent": agent_id}, status_code=409)
        return JSONResponse({"agent": agent_id, "state": "halted",
                             "warrant": p.agents[agent_id].warrant, "revoked_at": t0})

    # ------------------------------------------------------------ break-glass
    @app.post("/api/breakglass")
    def breakglass_grant(body: BreakGlassRequest,
                         x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """A named person opens one policy pause, for one agent and one tool, briefly.

        The node checks the class first: what the taxonomy calls a person's act
        (``irreversible``, ``authorize``) is refused here with that sentence, and never
        reaches the grant. What is left is the ``human`` a *rule* asked for.
        """
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        p = proxy()
        if body.agent not in p.agents:
            return JSONResponse({"error": f"unknown agent {body.agent!r}"}, status_code=404)
        cls = classify(body.tool, None)
        if cls is None:
            return JSONResponse({"error": f"tool {body.tool!r} has no action class · "
                                          f"the layer refuses what it cannot classify"},
                                status_code=409)
        try:
            grant = p.breakglass.grant(human=body.human, agent=body.agent, tool=body.tool,
                                       reason=body.reason, cls=cls.value, ttl_s=body.ttl_s)
        except BreakGlassRefused as exc:
            return JSONResponse({"error": str(exc), "agent": body.agent, "tool": body.tool,
                                 "class": cls.value}, status_code=409)
        return JSONResponse({"id": grant.id, "human": grant.human, "agent": grant.agent,
                             "tool": grant.tool, "class": grant.cls, "reason": grant.reason,
                             "expires_in_s": int(round(p.breakglass.remaining_s(grant))),
                             "single_use": True, "postmortem_owed_after_use": True,
                             "sig": grant.sig[:16]})

    @app.get("/api/breakglass")
    def breakglass_list() -> dict[str, Any]:
        return proxy().breakglass.snapshot()

    @app.post("/api/breakglass/revoke")
    def breakglass_revoke(body: BreakGlassId,
                          x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        grant = proxy().breakglass.revoke(body.id)
        if grant is None:
            return JSONResponse({"error": f"grant {body.id} is not open"}, status_code=409)
        return JSONResponse({"id": grant.id, "state": grant.state})

    @app.post("/api/breakglass/postmortem")
    def breakglass_postmortem(body: BreakGlassPostmortem,
                              x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        try:
            grant = proxy().breakglass.postmortem(body.id, body.note)
        except BreakGlassRefused as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        return JSONResponse({"id": grant.id, "state": grant.state, "note": grant.postmortem,
                             "postmortem_at": grant.postmortem_at})

    # ------------------------------------------------------------------- reset
    @app.post("/reset")
    def reset(body: Optional[ResetRequest] = None,
              x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """Rotate the chain (archive it, record the rotation) and re-issue the orders.

        A reset is a maintainer action with a name on it, not an anonymous eraser: it needs
        the operator token, and the closed chain survives in the archive (finding V2).
        """
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        body = body or ResetRequest()
        p = proxy()
        rotation = p.issue_all(reset_registry=True,
                               reason=body.reason or "manual reset",
                               actor=body.actor or "operator")
        # A reset re-issues the orders; the recorded halts go with them, or a later restart
        # would re-halt an agent the operator just reinstated.
        p._revoked.clear()
        p._save_node_state()
        return JSONResponse({"ok": True, "rotated": rotation, "state": proxy().state()})

    # --------------------------------------------------------- dev probe (signature)
    @app.post("/_dev/tamper")
    def dev_tamper(body: TamperRequest,
                   x_warrnt_admin: str = Header(default="")) -> JSONResponse:
        """Dev-only: widen a signed order *after* issuance, to prove the gate trusts the
        signature and not the object in memory. Disabled unless WARRNT_DEV=1."""
        denied = require_admin(x_warrnt_admin)
        if denied is not None:
            return denied
        if not settings.dev:
            return JSONResponse({"error": "tamper probe is dev-only (set WARRNT_DEV=1)"},
                                status_code=403)
        p = proxy()
        warrant = p.warrants.get(body.warrant)
        if warrant is None:
            return JSONResponse({"error": "unknown warrant", "warrant": body.warrant},
                                status_code=404)
        widened = None
        for rule in warrant.rules:
            for guard in rule.guards:
                if isinstance(guard.value, (int, float)):
                    guard.value = guard.value * 1000          # e.g. 50,000 -> 50,000,000 PLN
                    widened = {"param": guard.param, "value": guard.value}
                    break
            if widened:
                break
        if widened is None:
            warrant.scope = warrant.scope + " · everything forever"
            widened = {"scope": warrant.scope}
        return JSONResponse({"ok": True, "warrant": warrant.id, "mutated": widened,
                             "sig_ok": p.issuer.signature_ok(warrant)})

    return app


app = None
if os.environ.get("WARRNT_EAGER_APP", "").strip():
    app = create_app()
