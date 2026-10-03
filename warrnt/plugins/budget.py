"""Gate 15: is this agent still inside its budget?

Pre-flight, and deliberately before the order is read: a call that would exceed a ceiling is
refused without the policy engine being consulted, so the refusal cannot be argued away by a
rule. ``monitor`` strictness still records the spend and the shadow verdict without changing the
outcome - that is what makes a rollout possible without a flag buried in the engine.
"""
from ..gates import Gate, GateContext, Outcome, register
from ..models import Decision


def _check(ctx: GateContext) -> Outcome:
    catalog = getattr(ctx, "catalog", None)
    ledger = getattr(ctx, "budget", None)
    if ledger is None or (catalog is not None and not catalog.consulted("budget")):
        return None

    allowed, reason, detail = ledger.check(ctx.agent_id, ctx.tool)
    if allowed:
        return None
    if catalog is not None and not catalog.acts("budget"):
        # monitor: the shadow verdict rides along in the receipt, nothing is refused
        ctx.extra["budget_monitor"] = {**detail, "would_have_been": "deny", "reason": reason}
        return None
    return Decision.deny, reason, detail


register(Gate("budget", _check, order=15))
