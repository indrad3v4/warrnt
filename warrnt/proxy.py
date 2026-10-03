"""The node: identity -> actor class -> order -> policy on parameters -> brake -> receipt.

:class:`MCPProxy` is the single object that decides. Everything the HTTP layer does is
translate a request into a call here and serialise the answer.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from . import gates as gate_registry
from .breakglass import BreakGlassRegistry
from .budget import BudgetLedger
from .catalog import Catalog
from .controlplane import ActionStore, HoldRefused, params_view
from .gates import GateContext
from .actions import listing as class_listing
from .actors import ACTOR_SEED, ActorProfile, ActorRegistry
from .models import AgentState, Decision, DECISION_TEXT, Warrant
from .policy import PolicyEngine, strip_pii
from .registry import AppendOnlyRegistry
from .seed import SEED_SPECS
from .semantic import SemanticJudge
from .signatures import SignatureFeed
from .upstream import ExecutionCounter, build_upstream
from .warrants import WarrantIssuer, refresh_state, remaining


def _clock() -> str:
    return time.strftime("%H:%M:%S")


def _receipt_row(entry: dict) -> dict[str, Any]:
    """Console-shaped view of a receipt: a screen can render it without knowing the schema."""
    decision = entry.get("decision")
    text = DECISION_TEXT[Decision(decision)] if decision in Decision._value2member_map_ else decision
    return {
        "t": entry.get("t"), "decision": decision, "agent": entry.get("agent"),
        "tool": entry.get("tool"), "warrant": entry.get("warrant"),
        "reason": entry.get("reason"), "hash": entry["hash"][:8],
        "what": f"<code>{entry.get('tool')}</code> {entry.get('agent')} → {text}",
        "meta": f"order {entry.get('warrant')} · {entry.get('reason')}",
    }


class MCPProxy:
    def __init__(self, issuer: WarrantIssuer, registry: AppendOnlyRegistry,
                 engine: Optional[PolicyEngine] = None, upstream=None,
                 now=None, actors: Optional[list[ActorProfile]] = None,
                 catalog=None, budget=None, semantic=None,
                 store_dir: Optional[str] = None):
        self.issuer = issuer
        self.registry = registry
        self.engine = engine or PolicyEngine()
        # The register of actor classes. It answers the question the warrant cannot: may
        # this kind of actor call this tool at all, whatever the user's rights are.
        self.actors = ActorRegistry(actors if actors is not None else list(ACTOR_SEED))
        # The control plane (PR-14): one canonical Action per intercepted call, plus the one
        # state the kernel cannot hold by itself - a call paused for a person to decide. When
        # a store directory is given, the ledger is persisted there and reloaded on restart,
        # so a pending hold and its receipt survive the process (contract TASK.2).
        self._store_dir = store_dir
        self._actions_path = os.path.join(store_dir, "actions.jsonl") if store_dir else None
        self._node_state_path = os.path.join(store_dir, "node_state.json") if store_dir else None
        self.actions = ActionStore(path=self._actions_path)
        self.counter = ExecutionCounter()
        self.upstream = upstream or build_upstream(self.counter)
        # The kernel loads its gates from the plugin package and never names one itself:
        # adding a gate is adding a file under warrnt/plugins/, not editing this module.
        gate_registry.load()
        self._now = now or time.time
        # The control catalog (D3) and the spend ledger (D7). The kernel holds them and passes
        # them to the gates; it reads no setting and makes no decision of its own.
        self.catalog = catalog if catalog is not None else Catalog.load()
        self.budget = budget if budget is not None else BudgetLedger(self.catalog, now=self._now)
        # The attack-signature feed (D8): outside the codebase, owned by operations, re-read the
        # same way the catalog is. A feed that cannot be read is carried as an error rather than
        # raised here - the gate that uses it decides what an unreadable feed means.
        self.signatures = SignatureFeed.load(self._feed_path())
        # The semantic judge (4.2). Built from the catalog's own block: model, endpoint, timeout.
        # It is constructed even when the control is off - constructing it costs nothing, and the
        # gate is what decides whether to ask. Nothing here reaches the network.
        self.semantic = semantic if semantic is not None else SemanticJudge(**self._semantic_args())
        # Break-glass: the one thing that can lower a *policy* pause, and only that. It is
        # signed with the same key as an order, it is single-use, and it owes a review.
        self.breakglass = BreakGlassRegistry(sign=self.issuer.sign, now=self._now,
                                             registry=self.registry)
        self.agents: dict[str, AgentState] = {}
        self.warrants: dict[str, Warrant] = {}
        self.anchor: Any = None
        # stats["revoked"]  - orders pulled by the operator (known the moment /revoke lands)
        # stats["last_stop"] - seconds from that pull to the node refusing the agent's next
        #                      outbound call; None until a stopped agent actually tries again
        self.stats: dict[str, Any] = {"revoked": 0, "last_stop": None, "stopped_agent": None}
        self._revoke_t0: dict[str, float] = {}
        # A revocation is durable: pulling a warrant is a decision, and a restart must not
        # offer the halted agent a fresh chance. Reloaded here before the first request.
        self._revoked: dict[str, float] = {}
        if self._node_state_path:
            self._load_node_state()

    # ------------------------------------------------------------------ persistence
    def _load_node_state(self) -> None:
        """Reload the durable part of the node: which agents were halted.

        Only the fact and its timestamp are kept - the warrant itself is re-issued from the
        seed at boot, so nothing stale is trusted from disk beyond "this one was pulled".
        """
        try:
            with open(self._node_state_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            self._revoked = {}
            return
        self._revoked = {str(k): float(v) for k, v in (data.get("revoked") or {}).items()}

    def _save_node_state(self) -> None:
        if not self._node_state_path:
            return
        tmp = self._node_state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"revoked": self._revoked}, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._node_state_path)
        os.chmod(self._node_state_path, 0o600)

    def _apply_revocations(self) -> None:
        """After the seed is (re)issued, put the recorded halts back on the agents.

        This is what makes a revocation survive a restart *and* what makes the reverse true:
        a hold that was pending when the agent was halted comes back already expired, never
        approved (R2).
        """
        for agent_id, t0 in self._revoked.items():
            agent = self.agents.get(agent_id)
            if agent is None:
                continue
            agent.state = "halted"
            agent.last = "chain stopped · warrant revoked"
            warrant = self.warrants.get(agent.warrant)
            if warrant is not None:
                warrant.state = "revoked"
                warrant.revoked_at = t0
            self._revoke_t0[agent_id] = t0

    # ------------------------------------------------------------------- seed
    def issue_all(self, reset_registry: bool = True, reason: str = "",
                  actor: str = "") -> Optional[dict[str, Any]]:
        self.agents.clear()
        self.warrants.clear()
        rotation: Optional[dict[str, Any]] = None
        if reset_registry:
            # A reset rotates the chain instead of erasing it: the closed segment is
            # archived and the rotation is recorded (finding V2).
            rotation = self.registry.reset(reason=reason, actor=actor)
        for spec in SEED_SPECS:
            warrant = self.issuer.issue(spec)
            self.warrants[warrant.id] = warrant
            self.agents[warrant.agent] = AgentState(
                id=warrant.agent, role=warrant.role, warrant=warrant.id,
                token=self.issuer.token_for(warrant.agent, warrant.id),
            )
        self.stats = {"revoked": 0, "last_stop": None, "stopped_agent": None}
        self._revoke_t0 = {}
        self.counter.clear()
        self.budget.clear()
        # A reset re-issues the orders; an open bypass must not survive it.
        self.breakglass.grants.clear()
        self.breakglass._seq = 0
        # A plain re-issue (boot) restores the recorded halts; an explicit reset is an
        # operator act that clears them, exactly as it always did.
        if not reset_registry:
            self._apply_revocations()
        return rotation

    def _feed_path(self) -> str:
        """The feed lives beside the catalog that names it, unless it is an absolute path."""
        named = str(getattr(self.catalog, "signatures_path", "") or "").strip()
        if not named:
            return ""
        path = Path(named)
        catalog_path = getattr(self.catalog, "path", None)
        if not path.is_absolute() and catalog_path is not None:
            return str(Path(catalog_path).parent / path)
        return str(path)

    def _semantic_args(self) -> dict:
        """Only the keys the judge knows; the catalog may carry more than the judge needs."""
        block = dict(getattr(self.catalog, "semantic", None) or {})
        allowed = {"model", "endpoint", "timeout_ms"}
        return {k: v for k, v in block.items() if k in allowed}

    def _expire_holds_of_halted_agents(self) -> int:
        """A hold cannot outlive its order, across a restart too (R2).

        If the process stopped while an agent was halted and an action was waiting on a
        person, the action comes back ``expired`` - a state, never a decision - with no
        upstream contact. It is never approved: a restart must not decide for a human.
        """
        expired = 0
        for row in self.actions.listing():
            if row.get("state") != "pending":
                continue
            agent = self.agents.get(row["agent"])
            if agent is not None and agent.state == "halted":
                action = self.actions.get(row["action_id"])
                if action is None:
                    continue
                action.state = "expired"
                action.upstream_contacted = False
                action.values = {}
                action.kept_for_hold = False
                # The chain says why the hold died, and it is the same decision word the
                # resolve path uses: revoked. No execution happened.
                receipt = self.registry.append(
                    t=_clock(), decision=Decision.revoked.value, agent=action.agent,
                    tool=action.tool, warrant=action.warrant,
                    reason=f"hold {action.action_id} expired · agent halted",
                    params="", rows_after=0, ts=self._now())
                action.receipt = receipt["hash"][:8]
                self.actions.save(action)
                expired += 1
        return expired


    # -------------------------------------------------------------- interception
    def intercept(self, agent_id: str, token: str, tool: str,
                  params: dict[str, Any] | None,
                  run_id: str = "") -> tuple[Decision, str, dict[str, Any], dict, bool]:
        """Return ``(decision, reason, detail, receipt, executed)``.

        ``executed`` is True only when the upstream was actually invoked - the proof that a
        deny leaves the perimeter untouched.
        """
        agent = self.agents.get(agent_id)
        if agent is None or agent.token != token:
            self._receipt(Decision.deny, agent_id or "<anonymous>", tool, "-",
                          f"unknown agent identity or bad token", params)
            return Decision.deny, "unknown agent identity or bad token", {}, {}, False

        warrant = self.warrants.get(agent.warrant)
        if warrant is not None and warrant.agent != agent_id:
            # Identity is scoped: a token minted for one agent never authorises another's
            # warrant, even if both are held by the same node.
            decision, reason = Decision.deny, "identity/warrant binding mismatch · token not scoped to this order"
            detail = {"warrant": agent.warrant, "agent": agent_id}
        elif agent.state == "halted":
            decision, reason = Decision.revoked, f"agent halted · warrant {agent.warrant} pulled"
            detail = {"warrant": agent.warrant}
        else:
            # The chains live in the registry, not here: the kernel only asks. The gates
            # read in the order a person would ask them - what kind of act is this
            # (act_class), who is standing at the gate (actor_scope), what does the order
            # allow (order_policy) - and a class can only raise what follows it.
            # D9: the catalog is re-read when its mtime moves, so an operator's edit is obeyed
            # by the NEXT call. A parse happens only when the file actually changed.
            self.catalog.reload()
            # The feed follows the same discipline: re-read when its file moves, so a shape
            # published five minutes ago is already in force on the next call (D9).
            self.signatures.reload()
            ctx = GateContext(agent_id=agent_id, agent=agent, warrant=warrant, tool=tool,
                              params=params or {}, actors=self.actors, engine=self.engine,
                              breakglass=self.breakglass, catalog=self.catalog,
                              budget=self.budget, signatures=self.signatures,
                              semantic=self.semantic)
            decision, reason, detail = gate_registry.run(ctx)
            # A control in `monitor` strictness refuses nothing, but its shadow verdict belongs
            # on the record - otherwise "monitoring" and "not installed" look identical.
            shadow = {k: v for k, v in ctx.extra.items() if k.endswith("_monitor")}
            if shadow:
                detail = {**detail, **shadow}
                # ... and on the reason too, because that is what the receipt and the console
                # render. A control that is monitoring and one that is not installed must not
                # look the same on the record.
                marks = "; ".join(f"{k}: would deny · {v.get('reason', '')}"
                                  for k, v in sorted(shadow.items()))
                reason = f"{reason} · {marks}" if reason else marks
            if detail.get("break_glass"):
                # A grant is single-use, and the spending is what makes it so: the claim is
                # atomic, so when two calls race for one grant exactly one of them proceeds
                # and the other is refused (finding V5). Either way the receipt carries the
                # grant id, so the chain shows who opened the door and when.
                if self.breakglass.claim(detail["break_glass"], tool) is None:
                    decision, reason = Decision.deny, "break-glass grant already spent · single use"
                    detail = {**detail, "grant_spent": detail.get("break_glass", ""),
                              "break_glass": "", "break_glass_by": ""}

        agent.last = f"{tool} · {DECISION_TEXT.get(decision, decision.value)}"
        receipt = self._receipt(decision, agent_id, tool, agent.warrant, reason, params,
                                detail=detail)

        # One canonical Action per intercepted call (PR-14). The API, the console and any
        # answer read THIS object, so a screen can never disagree with the kernel. Values
        # are not kept - keys and a digest only (finding V3), except inside an explicit hold.
        profile = self.actors.get(agent_id)
        action = self.actions.record(
            run_id=run_id or f"run-{agent_id}",
            agent=agent_id,
            actor=(f"{profile.id} ({profile.kind.value})" if profile else ""),
            tool=tool, action_class=str(detail.get("class") or ""),
            warrant=agent.warrant,
            warrant_state=(refresh_state(warrant, self._now()) if warrant else "none"),
            parameters=params_view(params),
            policy_result=str(detail.get("policy_result") or detail.get("policy")
                              or detail.get("rule") or detail.get("guard")
                              or detail.get("decider_text") or ""),
            decision=decision.value, reason=reason, receipt=receipt["hash"][:8],
            ts=self._now(),
        )

        if decision is Decision.revoked:
            # The halted agent just tried to act again: this receipt *is* the observation.
            # Measure it here so the console can show a real time-to-stop without the client
            # having to report anything back.
            self._note_stop(agent_id)

        if decision is not Decision.allow and decision is not Decision.redact:
            if decision is Decision.human:
                # A real hold, not a label: the request is kept (in memory only) so a named
                # person can release it, and nothing is sent upstream until they do. The
                # class that raised it was a person's act - the machine may not decide it.
                action.state, action.kept_for_hold = "pending", True
                action.values = dict(params or {})
                # Persist the held row with its values (mode 0600): a restart must be able
                # to hand this exact action back for a person to decide (contract TASK.2).
                self.actions.save(action)
                detail = {**detail, "held": True, "action_id": action.action_id,
                          "class_decider": str(detail.get("decider_text") or "")}
            return decision, reason, {**detail, "action_id": action.action_id,
                                      "receipt": receipt["hash"][:8],
                                      "rows_after": 0}, receipt, False

        # Exactly two decisions execute: allow, and redact - where the personal fields the
        # rule names are taken out of the payload *before* the upstream is called, so the
        # upstream never sees them. The removal is part of the record, not a silent edit.
        exec_params = params or {}
        if decision is Decision.redact:
            exec_params, removed = strip_pii(params, detail.get("redacted") or [])
            detail = {**detail, "redacted": removed, "upstream_params": exec_params}

        # The upstream is invoked here and nowhere else. If it fails after being invoked, the
        # attempt is still a thing that happened to the outside world, so it is recorded as a
        # receipt of its own - a chain that only records successes would go quiet exactly when
        # the story gets interesting (finding V6).
        outcome, rows = "ok", 0
        try:
            result = self.upstream.call(tool, exec_params)   # executed ONLY here
            rows = int(result.get("rows", 0))
        except Exception as exc:                             # noqa: BLE001 - the record survives it
            result, outcome = None, "error"
            detail = {**detail, "upstream_error": f"{type(exc).__name__}: {exc}"[:200]}
        # Charge the spend whether the call succeeded or failed: an attempt that reached the
        # upstream is a thing that happened, and a budget that only counts successes can be
        # walked around by making the calls fail.
        self.budget.record(agent_id, tool, int(((result or {}).get("tokens") or 0)))
        receipt2 = self.registry.append(
            t=_clock(), decision=decision.value, agent=agent_id, tool=tool,
            warrant=agent.warrant,
            reason=reason, params="", rows_after=rows, ts=self._now(),
            exec_hash=receipt["hash"], outcome=outcome,
        )
        action.upstream_contacted = True
        action.receipt = receipt2["hash"][:8]
        action.execution_result = {"rows": rows, "outcome": outcome}
        if decision is Decision.redact:
            action.execution_result["redacted"] = detail.get("redacted", [])
        if result is None:
            return (decision, reason,
                    {**detail, "action_id": action.action_id,
                     "receipt": receipt2["hash"][:8], "rows_after": 0}, receipt2, True)
        return (decision, reason,
                {**detail, "action_id": action.action_id,
                 "receipt": receipt2["hash"][:8], "rows_after": rows,
                 "result": result}, receipt2, True)

    # --------------------------------------------------------------- human hold
    def resolve_hold(self, action_id: str, approve: bool, by: str) -> dict[str, Any]:
        """A named person releases or refuses a held action. WARRNT still runs the call.

        Approve: the upstream is invoked here, with the parameters the hold kept, and the
        chain records the human decision first and the execution after it. Deny: nothing is
        invoked, and the receipt says so. Either way the action keeps its ``action_id``, so
        API, console, receipt and answer all point at the same call.
        """
        action = self.actions.get(action_id)
        if action is None:
            raise HoldRefused(f"unknown action {action_id}")
        if action.state == "expired":
            # Already expired (its agent was halted). An attempt to decide it now is refused,
            # but it reads the same way it always did: not executed, still a state.
            return {"action": action.public(), "executed": False,
                    "receipt": action.receipt, "outcome": "expired"}
        if action.state != "pending":
            raise HoldRefused(f"action {action_id} is {action.state}, not pending")
        if not by.strip():
            raise HoldRefused("a person's name is required: an anonymous decision is not a decision")

        agent = self.agents.get(action.agent)
        if agent is None or agent.state == "halted":
            # A hold cannot outlive its order: the brake wins over the pending decision.
            action.state, action.decided_by, action.decided_ts = "expired", by, self._now()
            action.values, action.kept_for_hold = {}, False
            receipt = self.registry.append(
                t=_clock(), decision=Decision.revoked.value, agent=action.agent,
                tool=action.tool, warrant=action.warrant,
                reason=f"hold {action_id} expired · agent halted before {by} decided",
                params="", rows_after=0, ts=self._now())
            action.receipt = receipt["hash"][:8]
            self.actions.save(action)
            return {"action": action.public(), "executed": False,
                    "receipt": action.receipt, "outcome": "expired"}

        if not approve:
            receipt = self.registry.append(
                t=_clock(), decision=Decision.deny.value, agent=action.agent,
                tool=action.tool, warrant=action.warrant,
                reason=f"human denied by {by} · action {action_id} · upstream never contacted",
                params="", rows_after=0, ts=self._now())
            action.state, action.decided_by, action.decided_ts = "denied", by, self._now()
            action.receipt = receipt["hash"][:8]
            action.values, action.kept_for_hold = {}, False
            self.stats["denied"] = self.stats.get("denied", 0) + 1
            self.actions.save(action)
            return {"action": action.public(), "executed": False,
                    "receipt": action.receipt, "outcome": "denied"}


        # The human decision is its own receipt, written before the call it authorises.
        human_receipt = self.registry.append(
            t=_clock(), decision=Decision.allow.value, agent=action.agent,
            tool=action.tool, warrant=action.warrant,
            reason=f"human approved by {by} · action {action_id} released",
            params="", rows_after=0, ts=self._now())
        outcome, rows, result = "ok", 0, None
        try:
            result = self.upstream.call(action.tool, action.values)   # the only other call site
            rows = int(result.get("rows", 0))
        except Exception as exc:                                      # noqa: BLE001
            outcome = "error"
            action.execution_result = {"upstream_error": f"{type(exc).__name__}: {exc}"[:200]}
        receipt = self.registry.append(
            t=_clock(), decision=Decision.allow.value, agent=action.agent, tool=action.tool,
            warrant=action.warrant,
            reason=f"executed after human approval by {by} · action {action_id}",
            params="", rows_after=rows, ts=self._now(),
            exec_hash=human_receipt["hash"], outcome=outcome)
        action.upstream_contacted = True
        action.state, action.decided_by, action.decided_ts = "approved", by, self._now()
        action.receipt = receipt["hash"][:8]
        action.execution_result = {**action.execution_result, "rows": rows, "outcome": outcome}
        action.values, action.kept_for_hold = {}, False
        self.actions.save(action)
        self.stats["allowed"] = self.stats.get("allowed", 0) + 1
        return {"action": action.public(), "executed": True, "receipt": action.receipt,
                "outcome": outcome, "rows": rows, "result": result}

    # ------------------------------------------------------------------- brake
    def revoke(self, agent_id: str) -> Optional[float]:
        """Pull the warrant and halt the agent chain. Returns the revoke timestamp."""
        agent = self.agents.get(agent_id)
        if agent is None or agent.state == "halted":
            return None
        t0 = self._now()
        agent.state = "halted"
        warrant = self.warrants.get(agent.warrant)
        if warrant:
            warrant.state = "revoked"
            warrant.revoked_at = t0
        self.registry.append(
            t=_clock(), decision=Decision.revoked.value, agent=agent_id, tool="/revoke",
            warrant=agent.warrant, reason="warrant pulled by operator",
            params="", rows_after=0, ts=t0,
        )
        agent.last = "chain stopped · warrant revoked"
        self.stats["revoked"] += 1
        self._revoke_t0[agent_id] = t0
        # Durable: the halt must survive a restart, so the next process reloads it and a
        # pending hold on this agent comes back expired rather than be released by a later
        # process (R2). A hold cannot outlive its order - not even within this process.
        self._revoked[agent_id] = t0
        self._save_node_state()
        self._expire_holds_of_halted_agents()
        return t0


    def _note_stop(self, agent_id: str) -> Optional[float]:
        """Record time-to-stop the first time a halted agent is refused after the pull.

        Silent by design: the refusal receipt is already in the chain, so the latency needs
        no line of its own. Idempotent per agent - a stopped agent that keeps retrying must
        not keep moving the number.
        """
        t0 = self._revoke_t0.get(agent_id)
        if t0 is None or self.stats.get("stopped_agent") == agent_id:
            return self.stats.get("last_stop")
        latency = max(0.0, self._now() - t0)
        self.stats["last_stop"] = latency
        self.stats["stopped_agent"] = agent_id
        return latency

    def observe_stop(self, agent_id: str, observed: float | None = None) -> Optional[float]:
        """Called when the running agent itself notices the revocation. Measures latency."""
        agent = self.agents.get(agent_id)
        t0 = self._revoke_t0.get(agent_id)
        if agent is None or t0 is None or self.stats.get("stopped_agent") == agent_id:
            return None
        latency = max(0.0, (observed or self._now()) - t0)
        self.stats["last_stop"] = latency
        self.stats["stopped_agent"] = agent_id
        self.registry.append(
            t=_clock(), decision=Decision.revoked.value, agent=agent_id, tool="agent-loop",
            warrant=agent.warrant, reason="stop observed on next outbound call",
            params="", rows_after=0, ts=observed or self._now(),
        )
        return latency

    # ------------------------------------------------------------------ helpers
    def _receipt(self, decision: Decision, agent: str, tool: str, warrant: str,
                 reason: str, params: dict[str, Any] | None,
                 detail: dict[str, Any] | None = None) -> dict:
        import hashlib, json

        # The chain records WHICH request this was, never its values: a receipt that
        # carried the payload would make the control layer the largest PII store in the
        # building (finding V3). Keys and a digest are enough to tie the decision to the
        # request in the source system.
        raw = json.dumps(params or {}, sort_keys=True, ensure_ascii=False)
        return self.registry.append(
            t=_clock(), decision=decision.value, agent=agent, tool=tool, warrant=warrant,
            reason=reason,
            param_keys=",".join(sorted((params or {}).keys()))[:200],
            params_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            params="",
            rows_after=0, ts=self._now(),
        )

    # ------------------------------------------------------------------- state
    def state(self, limit: int = 60) -> dict[str, Any]:
        agents, warrants = [], []
        for agent in self.agents.values():
            warrant = self.warrants.get(agent.warrant)
            agents.append({
                "id": agent.id, "role": agent.role, "state": agent.state,
                "warrant": agent.warrant, "last": agent.last,
                "ttl": int(round(remaining(warrant, self._now()))) if warrant else 0,
                "ttl0": warrant.ttl if warrant else 0,
            })
        for warrant in self.warrants.values():
            warrants.append({
                "id": warrant.id, "agent": warrant.agent, "scope": warrant.scope,
                "ttl": int(round(remaining(warrant, self._now()))), "ttl0": warrant.ttl,
                "state": refresh_state(warrant, self._now()),
                "sig": warrant.sig[:16], "sig_ok": self.issuer.signature_ok(warrant),
            })
        receipts = [_receipt_row(e) for e in self.registry.recent(limit)]
        return {
            "revoked": self.stats["revoked"], "last_stop": self.stats["last_stop"],
            "agents": agents, "warrants": warrants, "receipts": receipts,
            "actors": self.actors.listing(),
            "actions": class_listing(),
            # The control plane (PR-14): the canonical Action log, and the holds waiting on
            # a person. Same object the API returns and the console renders.
            "action_log": self.actions.listing(limit=20),
            "control": {"counts": self.actions.counts(), "pending": self.actions.pending()},
            "executor_calls": self.counter.snapshot(), "chain": self.registry.verify(),
            "breakglass": self.breakglass.snapshot(),
        }
