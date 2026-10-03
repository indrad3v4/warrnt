"""The exportable audit (brief 4.5).

The security team asked for evidence they can take away and verify without this node. So the
tests check the three things that make an export evidence rather than a screenshot: the chain
links are in it, the controls that were in force are named, and nothing the caller sent is in
it - an export that leaks the payload is a new incident, not a report about the old one.
"""
from __future__ import annotations

import csv
import io
import json
import pathlib

from fastapi.testclient import TestClient

from warrnt.api import create_app
from warrnt.config import Settings

SECRET_IN_PARAMS = "please-note-the-card-4111111111111111-and-AKIAIOSFODNN7EXAMPLE"


def client(tmp_path) -> TestClient:
    settings = Settings(home=tmp_path, registry_path=tmp_path / "receipts.jsonl",
                        key_path=tmp_path / "issuer.key", anchor_path=tmp_path / "anchors.jsonl",
                        upstream_url="", host="127.0.0.1", port=0, dev=True,
                        admin_token="operator-token")
    return TestClient(create_app(settings=settings))


def call(c, agent="support-copilot", tool="crm.read", params=None):
    tokens = {a["id"]: a["token"] for a in c.get("/agents").json()}
    return c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": tool,
                                           "arguments": params or {"table": "tickets"}}},
                  headers={"X-WARRNT-Agent": agent, "X-WARRNT-Token": tokens[agent]})


def traffic(c):
    call(c, tool="crm.read")
    call(c, tool="crm.bulk_export", params={"table": "tickets", "rows": 12000})
    call(c, agent="deploy-agent", tool="infra.plan", params={"env": "prod"})


# ------------------------------------------------------------------ json
def test_the_json_export_is_self_contained_evidence(tmp_path):
    with client(tmp_path) as c:
        traffic(c)
        rows = c.get("/receipts").json()
        export = c.get("/export").json()

        assert export["rows_total"] == len(rows)
        assert export["chain"]["ok"] is True and export["chain"]["length"] >= len(rows)
        assert export["anchor"]["verdict"]["ok"] is True, "the export carries the anchor verdict"
        assert export["node"] == "warrnt" and export["exported_at"]
        assert "not a chain" in export["note"] or "filtered" in export["note"]


def test_the_export_names_the_revisions_that_were_in_force(tmp_path):
    with client(tmp_path) as c:
        call(c)
        controls = c.get("/export").json()["controls_in_force"]
        assert controls["catalog_version"] >= 1
        assert controls["signature_feed"]["version"], "a refusal cites a feed revision - so does an export"
        assert controls["signature_feed"]["ok"] is True
        named = {c["name"] for c in controls["controls"]}
        assert {"pattern_inspector", "signature_feed", "semantic_judge"} <= named, \
            "the export names every control it carried, and how strictly each acted"


# ------------------------------------------------------------------ csv
def test_the_csv_export_has_a_header_and_one_row_per_receipt(tmp_path):
    with client(tmp_path) as c:
        traffic(c)
        rows = c.get("/receipts").json()
        r = c.get("/export?format=csv")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
        assert "attachment" in r.headers["content-disposition"]

        parsed = list(csv.reader(io.StringIO(r.text)))
        header, body = parsed[0], parsed[1:]
        assert header[:7] == ["seq", "t", "ts", "decision", "agent", "tool", "warrant"]
        assert len(body) == len(rows)
        assert [int(line[0]) for line in body] == list(range(1, len(body) + 1))


def test_the_exported_rows_still_chain(tmp_path):
    """The point of the export: a reader can recompute the links without the node."""
    with client(tmp_path) as c:
        traffic(c)
        rows = list(csv.DictReader(io.StringIO(c.get("/export?format=csv").text)))
        assert len(rows) >= 3
        for earlier, later in zip(rows, rows[1:]):
            assert later["prev_hash"] == earlier["receipt_hash"], \
                "each exported row names the receipt it follows"
        assert rows[0]["prev_hash"].strip("0") == "", "the first row follows genesis"


def test_jsonl_is_one_object_per_line(tmp_path):
    with client(tmp_path) as c:
        call(c)
        body = c.get("/export?format=jsonl").text.strip()
        lines = [json.loads(line) for line in body.splitlines()]
        assert lines and all("hash" in row for row in lines)


# ------------------------------------------------------------------ filters
def test_the_filters_narrow_the_rows_and_never_the_chain(tmp_path):
    with client(tmp_path) as c:
        traffic(c)
        everything = c.get("/export").json()
        one_agent = c.get("/export?agent=deploy-agent").json()

        assert one_agent["rows_total"] < everything["rows_total"]
        assert all(r["agent"] == "deploy-agent" for r in one_agent["receipts"])
        assert one_agent["chain"]["length"] == everything["chain"]["length"], \
            "a filtered view of a chain is still a whole chain"
        assert one_agent["filter"]["agent"] == "deploy-agent"

        denied = c.get("/export?decision=deny").json()
        assert denied["rows_total"] >= 1
        assert all(r["decision"] == "deny" for r in denied["receipts"])

        limited = c.get("/export?limit=1").json()
        assert limited["rows_total"] == 1


def test_a_format_nobody_supports_is_refused_with_a_reason(tmp_path):
    with client(tmp_path) as c:
        call(c)
        r = c.get("/export?format=pdf")
        assert r.status_code == 400
        assert "csv" in r.json()["error"] and "json" in r.json()["error"]


# ------------------------------------------------------------------ what must NOT be in it
def test_the_export_never_carries_the_parameter_values(tmp_path):
    """Finding V3, applied to the artefact most likely to be emailed around."""
    with client(tmp_path) as c:
        call(c, params={"table": "tickets", "note": SECRET_IN_PARAMS})
        as_json = c.get("/export").text
        as_csv = c.get("/export?format=csv").text
        assert "4111111111111111" not in as_json and "AKIAIOSFODNN7EXAMPLE" not in as_json
        assert "4111111111111111" not in as_csv and "AKIAIOSFODNN7EXAMPLE" not in as_csv
        assert "sha256" in as_json or "params_sha256" in as_json, \
            "the caller gets a digest they can match against their own record"
