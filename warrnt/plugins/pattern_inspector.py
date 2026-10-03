"""Gate 17: the deterministic inbound check (brief 4.2.1).

Content, not labels: the node used to recognise personal data because a caller wrote
``fields: ["email", "pesel"]``, which only catches the caller who labels the data. This gate
looks at what is actually in the payload.

It sits after the budget (a call that cannot afford to happen is refused before anything is
read) and before every judgement that needs a model, because a decision that can be made by
looking must never wait on an inference (D4).

  * a secret or an attack marker in the content -> refused
  * a personal detail -> taken out of the payload, and the call still runs
  * ``monitor`` strictness -> recorded as a shadow verdict and nothing is changed
"""
from .. import patterns as P
from ..gates import Gate, GateContext, Outcome, register
from ..models import Decision


def _reason(findings: list[P.Finding], verb: str) -> str:
    """Cite the pattern and where it fired - never the excerpt."""
    kinds: dict[str, int] = {}
    for f in findings:
        kinds[f.kind] = kinds.get(f.kind, 0) + 1
    counted = ", ".join(f"{n} {kind}" for kind, n in sorted(kinds.items()))
    where = ", ".join(sorted({f"{f.pid} at {f.path}" for f in findings})[:4])
    return f"pattern inspector: {counted} · {where} · {verb}"


def _check(ctx: GateContext) -> Outcome:
    catalog = getattr(ctx, "catalog", None)
    if catalog is None or not catalog.consulted("pattern_inspector"):
        return None

    try:
        lib = P.library(getattr(catalog, "patterns", None))
    except Exception as exc:  # noqa: BLE001 - a broken pattern is a refusal, not an allow
        return (Decision.deny,
                f"pattern inspector: the catalog's patterns do not compile · {exc}"[:200],
                {"control": "pattern_inspector", "catalog_error": str(exc)[:160]})

    findings = P.scan(ctx.params, lib)
    if not findings:
        return None

    detail = {
        "control": "pattern_inspector",
        "findings_total": len(findings),
        "patterns_fired": sorted({f.pid for f in findings}),
        "severity": P.worst(findings),
        "findings": [f.as_detail() for f in findings][:12],
        "class": str(ctx.cls) if ctx.cls else "",
    }

    if not catalog.acts("pattern_inspector"):
        ctx.extra["pattern_inspector_monitor"] = {
            **detail, "would_have_been": "deny", "reason": _reason(findings, "would be refused")}
        return None

    blocking = [f for f in findings if f.kind in P.BLOCK_KINDS or f.severity == "high"]
    if blocking:
        return (Decision.deny, _reason(blocking, "refused before the upstream"),
                {**detail, "blocked": [f.as_detail() for f in blocking]})

    touched = P.redact_in_place(ctx.params, findings, lib)
    return (Decision.redact, _reason(findings, "stripped, the call still runs"),
            {**detail, "redacted": touched, "redacted_in_content": True})


register(Gate("pattern_inspector", _check, order=17))
