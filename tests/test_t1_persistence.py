"""TASK.2 + AC2 + AC3 + R2 - the registry survives a restart, and so does a revocation.

The kernel's store is pointed at a directory (TENET_STATE_DIR, else WARRNT_HOME, else
./state). These tests boot the app twice against the same directory and prove the pending
action, its id and its receipt are still there - and that a revoked agent's hold comes back
expired, never approved.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from warrnt.api import create_app
from warrnt.config import Settings

ADMIN = "test-admin-token"


def make_settings(tmp_path) -> Settings:
    return Settings(
        home=tmp_path,
        registry_path=tmp_path / "receipts.jsonl",
        key_path=tmp_path / "issuer.key",
        anchor_path=tmp_path / "anchors.jsonl",
        upstream_url="", host="127.0.0.1", port=0, dev=True, admin_token=ADMIN,
    )


def call(client, agent: str, tool: str, args: dict | None = None, run: str = "") -> dict:
    row = next(a for a in client.get("/agents").json() if a["id"] == agent)
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": tool, "arguments": args or {}}},
        headers={"x-warrnt-agent": agent, "x-warrnt-token": row["token"],
                 "x-warrnt-run": run or f"run-{agent}"},
    ).json()


# ------------------------------------------------------------------ AC3: the restart
def test_pending_action_survives_a_restart(tmp_path):
    settings = make_settings(tmp_path)

    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c1:
        held = call(c1, "deploy-agent", "infra.deploy", {"target": "prod"})
        action_id = held["error"]["data"]["action_id"]
        receipt = c1.get(f"/api/actions/{action_id}").json()["receipt"]
        assert c1.get(f"/api/actions/{action_id}").json()["state"] == "pending"

    # A fresh process, the same store dir.
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c2:
        one = c2.get(f"/api/actions/{action_id}").json()
        assert one["action_id"] == action_id, "the id is identical across the restart"
        assert one["state"] == "pending"
        assert one["receipt"] == receipt
        assert one["upstream_contacted"] is False
        # The receipt chain is intact across the restart, not restarted.
        assert c2.get("/health").json()["chain"]["ok"] is True


def test_restart_does_not_re_mint_an_id(tmp_path):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c1:
        first = call(c1, "support-copilot", "crm.read", {"table": "tickets"})
        assert "result" in first

    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c2:
        nxt = call(c2, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
        assert nxt == "A-0002", "the sequence continues from the highest id on disk"


# ------------------------------------------------------------------ AC2: same revoke
def test_revoke_alias_matches_the_plain_path(tmp_path):
    """The alias is a thin wrapper: same state change, same receipt shape."""
    plain_dir = tmp_path / "plain"
    alias_dir = tmp_path / "alias"
    plain_dir.mkdir()
    alias_dir.mkdir()

    with TestClient(create_app(settings=make_settings(plain_dir)),
                    headers={"X-WARRNT-Admin": ADMIN}) as a:
        assert a.post("/revoke", json={"agent": "deploy-agent"}).status_code == 200
        plain_state = next(x for x in a.get("/state").json()["agents"]
                           if x["id"] == "deploy-agent")

    with TestClient(create_app(settings=make_settings(alias_dir)),
                    headers={"X-WARRNT-Admin": ADMIN}) as b:
        r = b.post("/api/agents/deploy-agent/revoke")
        assert r.status_code == 200 and r.json()["state"] == "halted"
        alias_state = next(x for x in b.get("/state").json()["agents"]
                           if x["id"] == "deploy-agent")

    assert alias_state["state"] == plain_state["state"] == "halted"
    assert alias_state["warrant"] == plain_state["warrant"]


def test_revoke_alias_writes_the_same_receipt_kind(client):
    client.post("/api/agents/deploy-agent/revoke")
    receipts = client.get("/state").json()["receipts"]
    row = next(r for r in receipts if r["agent"] == "deploy-agent" and r["tool"] == "/revoke")
    assert row["decision"] == "revoked"


def test_revoke_alias_refuses_unknown_and_double_revoke(client):
    assert client.post("/api/agents/deploy-agent/revoke").status_code == 200
    assert client.post("/api/agents/deploy-agent/revoke").status_code == 409
    assert client.post("/api/agents/nobody/revoke").status_code == 409


# ----------------------------------------------------- R2: revocation across a restart
def test_revoked_agent_expires_a_pending_action_across_a_restart(tmp_path):
    """Order 1: create a hold, restart, then revoke - the hold becomes expired, not approved."""
    settings = make_settings(tmp_path)

    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c1:
        action_id = call(c1, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
        assert c1.get(f"/api/actions/{action_id}").json()["state"] == "pending"

    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c2:
        # The pending action came back pending across the restart.
        assert c2.get(f"/api/actions/{action_id}").json()["state"] == "pending"
        # Now revoke via the alias.
        assert c2.post("/api/agents/deploy-agent/revoke").status_code == 200
        one = c2.get(f"/api/actions/{action_id}").json()
        assert one["state"] == "expired", "a state, never a decision"
        assert one["decision"] == "human", "the decision space is unchanged by expiry"
        assert one["upstream_contacted"] is False
        assert c2.get("/state").json()["executor_calls"].get("infra.deploy", 0) == 0


def test_a_hold_the_brake_ended_records_when_it_died(tmp_path):
    """The boot path that expires a halted agent's holds stamps WHEN it died (Amendment 2).

    A note on how this is reached, because it is not an everyday path: both ``POST /revoke`` and
    its alias expire a pending hold eagerly through ``resolve_hold``, which already stamps
    ``decided_ts``. The boot path exists for the case a crash leaves behind - the halt persisted,
    the hold's expiry never run - and that is what this test constructs: the hold is real (created
    through the API), the halt is applied the way a restart would find it, and the method the boot
    calls is invoked directly.

    What it pins: the expiry carries a clock like a person's decision does, and ``decided_by`` is
    never invented - the kernel ended this row, and a name in that field would be a lie in the
    record.
    """
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        action_id = call(c, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
        before = c.get(f"/api/actions/{action_id}").json()
        assert before["state"] == "pending" and before["decided_ts"] == 0.0

        kernel = c.app.state.proxy
        # As a restart finds it: the agent is halted, and the hold was never resolved.
        kernel.agents["deploy-agent"].state = "halted"
        assert kernel._expire_holds_of_halted_agents() == 1, "the boot expiry found the hold"

        after = c.get(f"/api/actions/{action_id}").json()
        assert after["state"] == "expired", "a state, never a decision"
        assert after["decided_ts"] > 0, "the kernel stamped WHEN the hold died"
        assert after["decided_by"] == before["decided_by"], "no decider is invented for a brake"
        assert after["upstream_contacted"] is False
        assert "values" not in after, "a row that can no longer execute carries no values"

def test_hold_expires_on_restart_after_revoke_first(tmp_path):
    """Order 2: revoke first, restart - the hold is still expired, never approved by restart."""
    settings = make_settings(tmp_path)

    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c1:
        action_id = call(c1, "deploy-agent", "infra.deploy")["error"]["data"]["action_id"]
        assert c1.post("/api/agents/deploy-agent/revoke").status_code == 200

    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c2:
        agent = next(x for x in c2.get("/api/agents").json() if x["id"] == "deploy-agent")
        assert agent["state"] == "halted", "the halt survived the restart"
        # The hold was pending when the agent halted; it comes back expired.
        one = c2.get(f"/api/actions/{action_id}").json()
        assert one["state"] == "expired", "a restart must not decide for a human"
        assert one["upstream_contacted"] is False
        assert c2.get("/state").json()["executor_calls"].get("infra.deploy", 0) == 0
        # And a later approve on the expired hold is refused: it does not execute.
        out = c2.post(f"/api/actions/{action_id}/approve", json={"by": "Indra"}).json()
        assert out["executed"] is False and out["state"] == "expired"
        assert c2.get("/state").json()["executor_calls"].get("infra.deploy", 0) == 0

