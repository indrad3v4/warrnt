"""The actor register: who is standing at the gate, and what they may never do.

A warrant answers "what was this agent authorised to do, and for how long". This register
answers the earlier and blunter question: **what may this class of actor do at all** -
independently of the rights of the user on whose behalf it acts.

That distinction is the whole point. An operator with full entitlement can still be told
no here, and so can the bank's own service identity: the limit is a property of the actor,
not of the requester. A warrant cannot widen it, and no role can argue it away, because the
check runs before the order is even read.

Four kinds are registered, because four kinds of actor reach the gate today:

* ``operator-human``    - a person driving the console;
* ``autonomous-system`` - a scheduled loop acting for a group of agents;
* ``chatbot``           - a conversational front end;
* ``mcp-supplier``      - a third-party connector offered by a server vendor.

A block is not a failure: it is the answer. A refusal is written to the same hash-chained
registry as an allow, with a reason a human can read and show to someone else.
"""
from __future__ import annotations

from enum import Enum
from fnmatch import fnmatchcase
from typing import Any, Optional

from pydantic import BaseModel, Field

from .models import Decision


class ActorKind(str, Enum):
    operator_human = "operator-human"
    autonomous_system = "autonomous-system"
    chatbot = "chatbot"
    mcp_supplier = "mcp-supplier"


KIND_TEXT = {
    ActorKind.operator_human: "human operator at the console",
    ActorKind.autonomous_system: "autonomous system - pre-defined operations for a group of agents",
    ActorKind.chatbot: "chatbot - conversational front end",
    ActorKind.mcp_supplier: "MCP server supplier - third-party connector",
}


class ActorProfile(BaseModel):
    """One actor at the gate.

    ``cannot`` is absolute and glob-aware (``payments.*``): no warrant widens it, because it
    is not about what this call was authorised to do - it is about who is asking. ``data_denied``
    names data classes the actor has no entitlement to at all, whatever it may call.
    """

    id: str
    kind: ActorKind
    label: str = ""
    cannot: list[str] = Field(default_factory=list)
    data_denied: list[str] = Field(default_factory=list)
    note: str = ""


class ActorRegistry:
    """The register, and the one question it answers: may this actor call this tool?"""

    def __init__(self, profiles: list[ActorProfile]):
        self.profiles: dict[str, ActorProfile] = {p.id: p for p in profiles}

    def get(self, actor_id: str) -> Optional[ActorProfile]:
        return self.profiles.get(actor_id)

    def check(self, actor_id: str, tool: str,
              params: dict[str, Any] | None = None) -> Optional[tuple[Decision, str, dict[str, Any]]]:
        """Return a refusal, or ``None`` when the register has nothing to say.

        ``None`` is not a licence: it means this actor's own limits do not decide the call,
        so the warrant still has to. The register never allows anything on its own.
        """
        profile = self.profiles.get(actor_id)
        if profile is None:
            return None
        for pattern in profile.cannot:
            if fnmatchcase(tool, pattern):
                return (Decision.deny,
                        f"actor-class limit - {profile.kind.value} '{actor_id}' may never call "
                        f"{tool} (rule '{pattern}'): the limit is on the actor, not on the rights "
                        f"of the user on whose behalf it acts",
                        {"actor": actor_id, "kind": profile.kind.value, "rule": pattern,
                         "gate": "actor-register"})
        denied = self._data_hits(profile, params or {})
        if denied:
            return (Decision.deny,
                    f"entitlement gate - {profile.kind.value} '{actor_id}' is not entitled to "
                    f"{', '.join(denied)}: no warrant grants data a caller has no entitlement to",
                    {"actor": actor_id, "kind": profile.kind.value,
                     "data_denied": denied, "gate": "actor-register"})
        return None

    @staticmethod
    def _data_hits(profile: ActorProfile, params: dict[str, Any]) -> list[str]:
        """Data classes named by the parameters of the call - not by the caller's intention."""
        denied = {d.strip().lower() for d in profile.data_denied}
        if not denied:
            return []
        hits: list[str] = []
        for key, value in params.items():
            words: list[Any] = [key]
            words.extend(value if isinstance(value, (list, tuple)) else [value])
            for word in words:
                text = str(word).strip().lower()
                if text in denied and text not in hits:
                    hits.append(text)
        return hits

    def listing(self) -> list[dict[str, Any]]:
        """Console-shaped rows: one line per actor, with what it may never do."""
        return [{"id": p.id, "kind": p.kind.value, "label": p.label or p.id,
                 "cannot": list(p.cannot), "data_denied": list(p.data_denied), "note": p.note}
                for p in sorted(self.profiles.values(), key=lambda x: (x.kind.value, x.id))]

    @staticmethod
    def kinds() -> list[str]:
        return [k.value for k in ActorKind]


# The seed register: the three demo agents, plus the two actors that surround them - the
# human at the console and the supplier's connector. Declared in code on purpose (this is
# one node, not a platform): editing this list is how you change who may stand at the gate.
ACTOR_SEED: list[ActorProfile] = [
    ActorProfile(
        id="fin-reconcile", kind=ActorKind.autonomous_system, label="finance reconcile loop",
        cannot=["crm.*", "infra.*"],
        note="scheduled loop: reads payments and transfers within the signed limit; the CRM and "
             "the infrastructure are not its world at all",
    ),
    ActorProfile(
        id="support-copilot", kind=ActorKind.chatbot, label="support chat front end",
        cannot=["payments.transfer", "infra.*"],
        note="talks to customers and reads the ticket table; moving money or touching the "
             "platform is never a conversation it may have",
    ),
    ActorProfile(
        id="deploy-agent", kind=ActorKind.autonomous_system, label="platform deploy loop",
        cannot=["payments.*", "crm.*"],
        note="plans and (with a human) deploys; customer records and money are outside its world",
    ),
    ActorProfile(
        id="vendor-mcp-bridge", kind=ActorKind.mcp_supplier, label="vendor MCP connector",
        cannot=["payments.*", "crm.*", "infra.*"],
        data_denied=["pesel", "card", "iban"],
        note="a third-party server vendor's connector: entitled to its own catalogue, and to "
             "nothing else - not to the bank's systems, not to identity data",
    ),
    ActorProfile(
        id="risk-operator", kind=ActorKind.operator_human, label="human operator at the console",
        cannot=[],
        note="a person: no tool is forbidden to the human, and no action is taken without a "
             "warrant - the two gates stay separate",
    ),
]
