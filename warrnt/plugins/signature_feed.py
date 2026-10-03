"""Gate 18: the external attack-signature feed (brief 4.4).

The deterministic inbound check again, but against shapes published outside this repository.
Kept here as its own gate rather than folded into the pattern inspector because it answers a
different question and has a different owner: the inspector is the node's own judgement about
secrets and personal data, this is the operations team's list of known attacks, with a version.

The failure mode that matters: a control that is switched ON but whose feed cannot be read must
refuse. "I could not check" is not "I checked", and a node that silently stops checking when a
file goes missing is worse than one that never checked at all.
"""
from ..gates import Gate, GateContext, Outcome, register
from ..models import Decision

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2}


def _worst(matches) -> str:
    return max((m.sig.severity for m in matches),
               key=lambda s: _SEV_ORDER.get(s, 0), default="low")


def _check(ctx: GateContext) -> Outcome:
    catalog = getattr(ctx, "catalog", None)
    feed = getattr(ctx, "signatures", None)
    if catalog is None or feed is None or not catalog.consulted("signature_feed"):
        return None

    base = {"control": "signature_feed", "feed_version": feed.version,
            "feed_source": feed.source, "feed_count": len(feed.signatures),
            "feed_path": str(feed.path or "")}

    if not feed.ok:
        reason = f"signature feed unusable · {feed.error or 'the feed holds no signatures'}"
        if not catalog.acts("signature_feed"):
            ctx.extra["signature_feed_monitor"] = {**base, "would_have_been": "deny",
                                                   "reason": reason}
            return None
        return Decision.deny, reason, base

    matches = feed.match({"tool": ctx.tool, "agent": ctx.agent_id, "params": ctx.params})
    if not matches:
        return None

    fired = sorted({m.sig.sid for m in matches})
    where = ", ".join(sorted({f"{m.sig.sid} at {m.at}" for m in matches})[:4])
    detail = {**base, "matches": [m.as_detail() for m in matches][:12],
              "signatures_fired": fired, "severity": _worst(matches),
              "class": str(ctx.cls) if ctx.cls else ""}

    if not catalog.acts("signature_feed"):
        ctx.extra["signature_feed_monitor"] = {
            **detail, "would_have_been": "deny",
            "reason": f"feed {feed.version}: {', '.join(fired)} · would be refused"}
        return None

    return (Decision.deny,
            f"attack signature feed {feed.version}: {', '.join(fired)} · {where} · "
            f"refused before the upstream", detail)


register(Gate("signature_feed", _check, order=18))
