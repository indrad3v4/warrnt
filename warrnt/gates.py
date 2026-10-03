"""The gate registry: the kernel asks the registry, not a list of imports.

The node is a microkernel (HeeksForGeeks' pattern: a minimal core that coordinates, and the
real work in modules outside it). What makes it a *plugin registry* rather than a modular
monolith is this file:

  * a gate is an object with a name, an order and a ``check(ctx)``;
  * every gate lives in its own module under ``warrnt/plugins/`` and registers itself;
  * the kernel discovers the modules with ``pkgutil`` and iterates what it finds - it never
    names a gate in its import list, so adding a gate is adding a file;
  * service management is real: ``register(..., replace=True)`` swaps a gate at runtime and
    ``unregister()`` takes one out, both without touching the kernel.

A gate returns ``None`` to pass, or ``(decision, reason, detail)`` to end the pipeline.
The last gate must always decide - a pipeline that runs off the end is a bug, not a default.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .models import Decision

Outcome = Optional[tuple[Decision, str, dict[str, Any]]]


@dataclass
class GateContext:
    """Everything a gate may look at. No gate reads global state."""

    agent_id: str
    agent: Any
    warrant: Any
    tool: str
    params: dict[str, Any]
    actors: Any = None          # ActorRegistry - injected by the kernel
    engine: Any = None          # PolicyEngine - injected by the kernel
    breakglass: Any = None      # BreakGlassRegistry - injected by the kernel
    catalog: Any = None         # Catalog - the one control source (D3), injected by the kernel
    budget: Any = None          # BudgetLedger - spend ceilings (D7), injected by the kernel
    signatures: Any = None      # SignatureFeed - the attack feed (D8), injected by the kernel
    semantic: Any = None        # SemanticJudge - the local model (4.2), injected by the kernel
    cls: Any = None             # filled by the act_class gate, read by the ones after it
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Gate:
    name: str
    check: Callable[[GateContext], Outcome]
    order: int


_REGISTRY: dict[str, Gate] = {}
_LOADED = False


def register(gate: Gate, replace: bool = False) -> Gate:
    """Add a gate. ``replace=True`` is the runtime swap (service management)."""
    if gate.name in _REGISTRY and not replace:
        raise ValueError(
            f"gate {gate.name!r} is already registered - pass replace=True to swap it")
    _REGISTRY[gate.name] = gate
    return gate


def unregister(name: str) -> Optional[Gate]:
    """Take a gate out at runtime. Returns the gate, or None if it was not there."""
    return _REGISTRY.pop(name, None)


def ordered() -> list[Gate]:
    return sorted(_REGISTRY.values(), key=lambda g: (g.order, g.name))


def names() -> list[str]:
    return [g.name for g in ordered()]


def clear() -> None:
    _REGISTRY.clear()


def load() -> list[str]:
    """Import every module under ``warrnt.plugins`` once; each registers itself."""
    global _LOADED
    if _LOADED:
        return names()
    from . import plugins
    for mod in pkgutil.iter_modules(plugins.__path__):
        importlib.import_module(f"{plugins.__name__}.{mod.name}")
    _LOADED = True
    return names()


def run(ctx: GateContext) -> tuple[Decision, str, dict[str, Any]]:
    """Ask the gates in order; the first one that answers decides."""
    for gate in ordered():
        out = gate.check(ctx)
        if out is not None:
            ctx.extra["decided_by"] = gate.name
            return out
    raise RuntimeError(
        "no gate decided - the registry must end with a gate that always decides; "
        f"registered: {names()}")
