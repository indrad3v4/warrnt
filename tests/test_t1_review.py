"""R1 + R3 - the operator review's two hard requirements.

R1: held values never sit on disk in the clear. The actions file is mode 0600, and a row
carries ``values`` only while the action can still execute; a decided, denied, redacted,
revoked or expired row carries none.

R3: the store is a tolerant reader. A corrupt/truncated last line does not raise and does
not lose the valid prefix, and the id sequence continues from the max valid id - a restart
must not re-mint an id that already exists.
"""
from __future__ import annotations

import json
import os
import stat

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


def _rows(actions_path) -> list[dict]:
    out = []
    for line in actions_path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# ------------------------------------------------------------------ R1: file mode 0600
def test_actions_file_is_created_with_mode_0600(tmp_path):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        call(c, "deploy-agent", "infra.deploy", {"target": "prod"})
    actions_path = tmp_path / "actions.jsonl"
    mode = stat.S_IMODE(os.stat(actions_path).st_mode)
    # POSIX file modes do not exist on Windows: chmod is a no-op there and st_mode reports 666,
    # so this is red on a Windows checkout of an otherwise green master. The claim under test is
    # "the store is written private where private is a thing" - the same guard test_warrants.py
    # already uses for the issuer's key.
    if os.name != "nt":
        assert mode == 0o600, oct(mode)
    else:
        assert actions_path.exists()


def test_allowed_action_row_carries_no_values(tmp_path):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        call(c, "support-copilot", "crm.read",
             {"table": "tickets", "fields": ["subject", "email"]})
    rows = _rows(tmp_path / "actions.jsonl")
    assert rows, "the call left a row"
    assert all("values" not in r for r in rows), "a decided row carries no values"


def test_pending_hold_row_keeps_values_and_drops_them_after_decision(tmp_path):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        held = call(c, "deploy-agent", "infra.deploy", {"target": "prod"})["error"]["data"]
        action_id = held["action_id"]
        rows = {r["action_id"]: r for r in _rows(tmp_path / "actions.jsonl")}
        assert rows[action_id]["state"] == "pending"
        assert rows[action_id]["values"] == {"target": "prod"}

        # Decide it - the values must not survive on disk.
        c.post(f"/api/actions/{action_id}/deny", json={"by": "Indra"})
        rows = {r["action_id"]: r for r in _rows(tmp_path / "actions.jsonl")}
        assert rows[action_id]["state"] == "denied"
        assert "values" not in rows[action_id], "a denied row must carry no values"


def test_expired_action_row_has_no_values(tmp_path):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        action_id = call(c, "deploy-agent", "infra.deploy",
                         {"target": "prod"})["error"]["data"]["action_id"]
        c.post("/api/agents/deploy-agent/revoke")
    rows = {r["action_id"]: r for r in _rows(tmp_path / "actions.jsonl")}
    assert rows[action_id]["state"] == "expired"
    assert "values" not in rows[action_id], "an expired row must carry no values"


# ------------------------------------------------------------------ R3: tolerant reader
def test_truncated_last_line_is_skipped_and_the_app_still_starts(tmp_path):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        call(c, "support-copilot", "crm.read", {"table": "tickets"})
        call(c, "deploy-agent", "infra.deploy", {"target": "prod"})

    actions_path = tmp_path / "actions.jsonl"
    valid = actions_path.read_text()
    # A half-written line, exactly what a crash leaves behind.
    actions_path.write_text(valid + '{"action_id": "A-0003", "agent": "deploy-ag')

    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        listed = c.get("/api/actions").json()["actions"]
        assert len(listed) == 2, "the valid prefix loaded, the bad line was skipped"
        # The sequence continues from the max valid id (A-0002), not from zero.
        nxt = call(c, "support-copilot", "crm.read",
                   {"table": "tickets"})["result"]
        assert nxt["action_id"] == "A-0003", "no id is re-minted after a corrupt line"


def test_corrupt_last_line_never_raises_on_construction(tmp_path):
    settings = make_settings(tmp_path)
    actions_path = tmp_path / "actions.jsonl"
    tmp_path.mkdir(exist_ok=True)
    actions_path.write_text('{"action_id": "A-0001", "run_id": "r", "agent": "a", "tool": "t",'
                            ' "state": "decided", "ts": 1.0}\nnot json at all\n')
    # Must not raise.
    with TestClient(create_app(settings=settings), headers={"X-WARRNT-Admin": ADMIN}) as c:
        assert c.get("/api/actions").status_code == 200
