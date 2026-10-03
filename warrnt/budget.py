"""Budget and resource governance: what an agent has spent, against the catalog's ceilings.

The brief asks for budget enforcement in the same breath as the controls, and rule D7 says a
budget that is only *displayed* is not implemented. So this is a pre-flight control: the ceiling
is checked before the order is consulted, and a call that would exceed it never runs.

Two ceilings are tracked, because both are named by the brief - request count (resource access)
and tokens (spend on a model). Both are windows, so a runaway loop is stopped inside one window
rather than after the fact.

Ceilings resolve most-specific-first: ``per_tool`` beats ``per_agent`` beats ``default``. A
ledger with no ceilings configured allows everything and records the spend anyway, which is what
makes ``monitor`` strictness useful on day one.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class Ceiling:
    requests: Optional[int] = None
    tokens: Optional[int] = None
    window_s: int = 3600
    source: str = "none"


class BudgetLedger:
    """Per-agent spend in a sliding window, checked before a call and recorded after it."""

    def __init__(self, catalog=None, now: Optional[Callable[[], float]] = None) -> None:
        self.catalog = catalog
        self._now = now or time.time
        self._spend: dict[tuple[str, str], deque[tuple[float, int]]] = {}

    # ------------------------------------------------------------------ ceilings
    def ceilings(self, agent: str, tool: str) -> Ceiling:
        table = (self.catalog.budgets if self.catalog else {}) or {}
        default = table.get("default") or {}
        merged: dict[str, Any] = dict(default)
        source = "default" if default else "none"
        for scope, key in (("per_agent", agent), ("per_tool", tool)):
            spec = (table.get(scope) or {}).get(key)
            if spec:
                merged.update(spec)
                source = f"{scope}:{key}"
        return Ceiling(requests=merged.get("requests"), tokens=merged.get("tokens"),
                       window_s=int(merged.get("window_s", 3600)), source=source)

    # ------------------------------------------------------------------ window
    def _prune(self, key: tuple[str, str], window_s: int, now: float) -> None:
        bucket = self._spend.get(key)
        if bucket is None:
            return
        cutoff = now - window_s
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

    def spend(self, agent: str, tool: str) -> dict[str, Any]:
        """What the agent has spent in the current window - for the console and the receipt."""
        cap = self.ceilings(agent, tool)
        now = self._now()
        self._prune((agent, tool), cap.window_s, now)
        rows = list(self._spend.get((agent, tool), ()))
        return {"agent": agent, "tool": tool, "requests": len(rows),
                "tokens": sum(t for _, t in rows), "window_s": cap.window_s,
                "ceiling": cap.requests, "token_ceiling": cap.tokens, "source": cap.source}

    # ------------------------------------------------------------------ control
    def check(self, agent: str, tool: str) -> tuple[bool, str, dict[str, Any]]:
        """Pre-flight. Returns ``(allowed, reason, detail)`` - a refusal names the ceiling hit."""
        cap = self.ceilings(agent, tool)
        if cap.requests is None and cap.tokens is None:
            # Enforced nowhere, recorded anyway: that is what makes `monitor` strictness useful
            # on day one, and what lets a team decide where a ceiling belongs.
            return True, "", {"budget": "no ceiling configured", "budget_agent": agent,
                              "budget_tool": tool, "budget_source": "none",
                              "budget_requests": len(self._spend.get((agent, tool), ()))}
        now = self._now()
        self._prune((agent, tool), cap.window_s, now)
        rows = list(self._spend.get((agent, tool), ()))
        used_requests, used_tokens = len(rows), sum(t for _, t in rows)
        detail = {"budget_agent": agent, "budget_tool": tool, "budget_requests": used_requests,
                  "budget_tokens": used_tokens, "budget_window_s": cap.window_s,
                  "budget_source": cap.source, "budget_limit_requests": cap.requests,
                  "budget_limit_tokens": cap.tokens}
        if cap.requests is not None and used_requests >= cap.requests:
            return False, (f"budget exhausted · {used_requests}/{cap.requests} calls in "
                           f"{cap.window_s}s ({cap.source})"), detail
        if cap.tokens is not None and used_tokens >= cap.tokens:
            return False, (f"budget exhausted · {used_tokens}/{cap.tokens} tokens in "
                           f"{cap.window_s}s ({cap.source})"), detail
        return True, "", detail

    def record(self, agent: str, tool: str, tokens: int = 0) -> None:
        """Charge a call that actually ran. Called by the kernel, never by a gate."""
        self._spend.setdefault((agent, tool), deque()).append((self._now(), int(tokens or 0)))

    def snapshot(self) -> dict[str, Any]:
        """Every tracked (agent, tool) - the management view of resource consumption."""
        return {f"{a}:{t}": self.spend(a, t) for (a, t) in sorted(self._spend)}

    def clear(self) -> None:
        self._spend.clear()
