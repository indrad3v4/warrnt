"""Gate 19: the semantic inbound check (brief 4.2).

The half that needs a model. Off by default in the catalog, because a node without a local model
must lose nothing (D4) - but when the operator turns it on, an unreachable model is a **refusal**,
never a pass: "I could not judge this" is not "this is fine".

The gate holds no policy of its own. The threshold and the strictness come from the catalog, so
the same setting that turns the judge on and off also says how sure it has to be.
"""
from ..gates import Gate, GateContext, Outcome, register
from ..models import Decision


def _check(ctx: GateContext) -> Outcome:
    catalog = getattr(ctx, "catalog", None)
    judge = getattr(ctx, "semantic", None)
    if catalog is None or judge is None or not catalog.consulted("semantic_judge"):
        return None

    threshold = catalog.threshold("semantic_judge", 0.6)
    verdict = judge.score(ctx.tool, ctx.agent_id, ctx.params)
    detail = {"control": "semantic_judge", "threshold": threshold,
              "class": str(ctx.cls) if ctx.cls else "", **verdict.as_detail()}
    acts = catalog.acts("semantic_judge")

    if verdict.unavailable:
        reason = (f"semantic judge unavailable ({judge.model} at {judge.endpoint}) · "
                  f"{verdict.error}")
        if not acts:
            ctx.extra["semantic_judge_monitor"] = {**detail, "would_have_been": "deny",
                                                   "reason": reason}
            return None
        # Fail closed, and say which failure it was: a node that passes silently when its model
        # is down has the cost of a judge and none of the benefit.
        return Decision.deny, reason, {**detail, "unavailable_refusal": True}

    name, score = verdict.worst
    if score < threshold:
        return None

    reason = (f"semantic judge: {name} {score:.2f} ≥ {threshold:.2f} ({judge.model}, "
              f"{verdict.ms} ms)")
    if not acts:
        ctx.extra["semantic_judge_monitor"] = {**detail, "would_have_been": "deny",
                                               "reason": reason, "category": name,
                                               "score": score}
        return None
    return Decision.deny, reason, {**detail, "category": name, "score": score}


register(Gate("semantic_judge", _check, order=19))
