"""The actor register: limits that live on the actor, not on the user's rights.

The warrant tests ask "was this call authorised". These ask the earlier question: may this
kind of actor stand at the gate at all - and the answer must not move when a valid warrant
is presented.
"""
from warrnt.actors import ACTOR_SEED, ActorKind, ActorProfile, ActorRegistry


def _call(client, tokens, agent, tool, args=None):
    return client.post("/mcp",
                       json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": tool, "arguments": args or {}}},
                       headers={"X-WARRNT-Agent": agent, "X-WARRNT-Token": tokens[agent]})


# --------------------------------------------------------------- the register itself

def test_the_four_actor_kinds_from_the_brief_are_all_registered():
    """Operators, autonomous systems, chatbots, supplier connectors - four, and only four."""
    assert set(ActorRegistry.kinds()) == {"operator-human", "autonomous-system",
                                          "chatbot", "mcp-supplier"}
    assert {a.kind.value for a in ACTOR_SEED} == set(ActorRegistry.kinds())


def test_class_limits_are_glob_aware():
    reg = ActorRegistry([ActorProfile(id="a", kind=ActorKind.chatbot, cannot=["payments.*"])])
    assert reg.check("a", "payments.transfer") is not None
    assert reg.check("a", "payments.read") is not None
    assert reg.check("a", "crm.read") is None


def test_an_unknown_actor_is_left_to_the_identity_gate():
    """The register says nothing about strangers; it must not become a second identity check."""
    reg = ActorRegistry([ActorProfile(id="a", kind=ActorKind.chatbot, cannot=["payments.*"])])
    assert reg.check("stranger", "payments.transfer") is None


def test_the_register_never_allows_anything_itself():
    """No limits means "not my decision" - the warrant still has to speak."""
    reg = ActorRegistry([ActorProfile(id="a", kind=ActorKind.operator_human)])
    assert reg.check("a", "anything.at.all") is None


def test_the_supplier_connector_is_denied_identity_data_by_parameter():
    """A vendor's connector may call its own tools; pesel in the arguments still stops it."""
    reg = ActorRegistry([ActorProfile(id="vendor-mcp-bridge", kind=ActorKind.mcp_supplier,
                                      data_denied=["pesel", "card"])])
    block = reg.check("vendor-mcp-bridge", "catalog.read", {"fields": ["pesel", "city"]})
    assert block is not None and block[0].value == "deny"
    assert block[2]["data_denied"] == ["pesel"]
    assert reg.check("vendor-mcp-bridge", "catalog.read", {"fields": ["city"]}) is None


# ------------------------------------------------------------------ at the node (HTTP)

def test_a_demo_agent_cannot_reach_outside_its_world(client, tokens):
    """deploy-agent asking to read payments: refused by class, and nothing runs upstream."""
    before = client.get("/state").json()["executor_calls"]
    reply = _call(client, tokens, "deploy-agent", "payments.read", {})
    body = reply.json()
    assert body["error"]["data"]["decision"] == "deny"
    assert body["error"]["data"]["gate"] == "actor-register"
    assert body["error"]["data"]["executed"] is False
    assert "actor-class limit" in body["error"]["message"]
    assert client.get("/state").json()["executor_calls"] == before   # nothing ran


def test_a_valid_warrant_does_not_widen_an_actor_class(client, tokens):
    """fin-reconcile may transfer 42 000 within its signed order - unless its class changes.

    The only moving part here is the actor register: same agent, same signed warrant, same
    parameters. If the answer changes, it changed because of who is asking, not because of
    what was authorised.
    """
    allowed = _call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 42000})
    assert allowed.json()["result"]["decision"] == "allow"

    proxy = client.app.state.proxy
    proxy.actors = ActorRegistry([ActorProfile(id="fin-reconcile", kind=ActorKind.chatbot,
                                               cannot=["payments.transfer"])])
    stopped = _call(client, tokens, "fin-reconcile", "payments.transfer", {"amount_pln": 42000})
    body = stopped.json()
    assert body["error"]["data"]["decision"] == "deny"
    assert body["error"]["data"]["gate"] == "actor-register"
    assert body["error"]["data"]["executed"] is False
    assert "the limit is on the actor" in body["error"]["message"]


def test_a_class_refusal_is_receipted_and_the_chain_still_verifies(client, tokens):
    """The register's answer is written down like any other: the reason names the actor class."""
    _call(client, tokens, "support-copilot", "infra.deploy", {"env": "prod"})
    row = client.get("/receipts").json()[-1]
    assert row["decision"] == "deny" and row["agent"] == "support-copilot"
    assert "actor-class limit" in row["reason"] and "chatbot" in row["reason"]
    assert "the limit is on the actor" in row["reason"]
    assert client.get("/verify").json()["ok"] is True


def test_the_register_is_readable_by_the_console(client):
    body = client.get("/actors").json()
    assert set(body["kinds"]) == {"operator-human", "autonomous-system", "chatbot", "mcp-supplier"}
    ids = {a["id"] for a in body["actors"]}
    assert {"fin-reconcile", "support-copilot", "deploy-agent", "vendor-mcp-bridge",
            "risk-operator"} <= ids
    assert {"id", "kind", "label", "cannot", "data_denied", "note"} == set(body["actors"][0])
    assert client.get("/state").json()["actors"] == body["actors"]


def test_a_human_operator_is_forbidden_nothing_but_still_needs_an_order():
    """The two gates stay separate: the register binds the human to nothing, the warrant does."""
    reg = ActorRegistry(ACTOR_SEED)
    assert reg.check("risk-operator", "infra.deploy", {"env": "prod"}) is None
