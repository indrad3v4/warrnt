"""Budget and resource governance (D7, brief section 4.3).

A budget that is only displayed is not implemented, so these tests pin both halves: the ledger's
arithmetic, and the gate refusing a call *before* the order is consulted.
"""
from __future__ import annotations

from pathlib import Path

from warrnt.budget import BudgetLedger
from warrnt.catalog import Catalog

ROOT = Path(__file__).resolve().parent.parent

# Local on purpose: importing tests.conftest resolves to whatever `tests` package is on
# sys.path first, which is not necessarily this repository's.
ADMIN_TOKEN = "operator-token"


def catalog_with(tmp_path, budgets):
    path = tmp_path / "catalog.yaml"
    import yaml
    path.write_text(yaml.safe_dump({"version": 1,
                                    "controls": {"budget": {"enabled": True,
                                                            "strictness": "block"}},
                                    "budgets": budgets}), encoding="utf-8")
    return Catalog.load(path)


def test_ceilings_resolve_most_specific_first(tmp_path):
    cat = catalog_with(tmp_path, {
        "default": {"requests": 100, "window_s": 60},
        "per_agent": {"report-bot": {"requests": 10}},
        "per_tool": {"crm.bulk_export": {"requests": 2}},
    })
    led = BudgetLedger(cat, now=lambda: 1000.0)
    assert led.ceilings("anyone", "anything").requests == 100
    assert led.ceilings("report-bot", "anything").requests == 10
    assert led.ceilings("report-bot", "crm.bulk_export").requests == 2, "per_tool wins"
    assert led.ceilings("report-bot", "crm.bulk_export").source == "per_tool:crm.bulk_export"


def test_a_call_under_the_ceiling_is_allowed_and_at_it_is_refused(tmp_path):
    cat = catalog_with(tmp_path, {"per_tool": {"crm.read": {"requests": 2, "window_s": 3600}}})
    led = BudgetLedger(cat, now=lambda: 1000.0)

    allowed, _, _ = led.check("support-copilot", "crm.read")
    assert allowed, "an unspent budget allows"
    led.record("support-copilot", "crm.read")

    allowed, _, _ = led.check("support-copilot", "crm.read")
    assert allowed, "1 of 2 spent still allows"
    led.record("support-copilot", "crm.read")

    allowed, reason, detail = led.check("support-copilot", "crm.read")
    assert not allowed, "the ceiling is a ceiling"
    assert "budget exhausted" in reason and "2/2" in reason
    assert detail["budget_requests"] == 2 and detail["budget_limit_requests"] == 2
    assert detail["budget_source"] == "per_tool:crm.read"


def test_agents_do_not_share_a_budget(tmp_path):
    cat = catalog_with(tmp_path, {"per_agent": {"report-bot": {"requests": 1, "window_s": 3600}}})
    led = BudgetLedger(cat, now=lambda: 1000.0)
    led.record("report-bot", "crm.read")
    assert not led.check("report-bot", "crm.read")[0]
    assert led.check("support-copilot", "crm.read")[0], "another agent is another budget"
    assert led.check("support-copilot", "crm.read")[2]["budget_source"] == "none"


def test_the_window_forgets_old_spend(tmp_path):
    cat = catalog_with(tmp_path, {"default": {"requests": 1, "window_s": 60}})
    clock = {"t": 1000.0}
    led = BudgetLedger(cat, now=lambda: clock["t"])
    led.record("a", "t")
    assert not led.check("a", "t")[0]
    clock["t"] += 61
    assert led.check("a", "t")[0], "a sliding window, not a lifetime cap"


def test_tokens_are_counted_alongside_requests(tmp_path):
    cat = catalog_with(tmp_path, {"default": {"requests": 1000, "tokens": 100, "window_s": 3600}})
    led = BudgetLedger(cat, now=lambda: 1000.0)
    led.record("a", "t", tokens=60)
    assert led.check("a", "t")[0]
    led.record("a", "t", tokens=40)
    allowed, reason, _ = led.check("a", "t")
    assert not allowed and "tokens" in reason


def test_no_ceiling_configured_means_nothing_is_enforced(tmp_path):
    cat = catalog_with(tmp_path, {})
    led = BudgetLedger(cat, now=lambda: 1000.0)
    for _ in range(50):
        assert led.check("a", "t")[0]
        led.record("a", "t")
    assert led.spend("a", "t")["ceiling"] is None, "recorded, not enforced - which monitor mode needs"


def test_the_snapshot_is_the_management_view(tmp_path):
    cat = catalog_with(tmp_path, {"default": {"requests": 5, "window_s": 3600}})
    led = BudgetLedger(cat, now=lambda: 1000.0)
    led.record("fin-reconcile", "payments.read", tokens=10)
    snap = led.snapshot()
    assert "fin-reconcile:payments.read" in snap
    assert snap["fin-reconcile:payments.read"]["tokens"] == 10


# ------------------------------------------------------------------ through the kernel
def _app_with_catalog(tmp_path, monkeypatch, budgets):
    import yaml
    from warrnt.api import create_app
    from warrnt.config import Settings

    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump({"version": 1,
                                    "controls": {"budget": {"enabled": True,
                                                            "strictness": "block"}},
                                    "budgets": budgets}), encoding="utf-8")
    monkeypatch.setenv("WARRNT_CATALOG", str(path))
    settings = Settings(home=tmp_path, registry_path=tmp_path / "receipts.jsonl",
                        key_path=tmp_path / "issuer.key", anchor_path=tmp_path / "anchors.jsonl",
                        upstream_url="", host="127.0.0.1", port=0, dev=True,
                        admin_token=ADMIN_TOKEN)
    return create_app(settings=settings), ADMIN_TOKEN


def test_a_call_over_budget_is_refused_before_the_upstream(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    app, admin = _app_with_catalog(tmp_path, monkeypatch,
                                   {"per_tool": {"crm.read": {"requests": 1, "window_s": 3600}}})
    with TestClient(app, headers={"X-WARRNT-Admin": admin}) as c:
        tokens = {a["id"]: a["token"] for a in c.get("/agents").json()}
        call = lambda: c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                            "params": {"name": "crm.read",
                                                       "arguments": {"table": "tickets", "limit": 5}}},
                              headers={"X-WARRNT-Agent": "support-copilot",
                                       "X-WARRNT-Token": tokens["support-copilot"]})
        first = call().json()
        assert "result" in first and first["result"]["decision"] == "allow"
        assert c.get("/state").json()["executor_calls"].get("crm.read") == 1

        second = call().json()
        assert "error" in second, "the ceiling is a refusal, not a note"
        assert second["error"]["code"] == -32001
        assert "budget exhausted" in second["error"]["message"]
        assert c.get("/state").json()["executor_calls"].get("crm.read") == 1, "nothing else ran"

        spend = c.get("/api/budget").json()["spend"]
        assert spend["support-copilot:crm.read"]["requests"] == 1


def test_monitor_strictness_records_a_shadow_verdict_and_refuses_nothing(tmp_path, monkeypatch):
    import yaml
    from fastapi.testclient import TestClient
    from warrnt.config import Settings
    from warrnt.api import create_app

    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump({
        "version": 1,
        "controls": {"budget": {"enabled": True, "strictness": "monitor"}},
        "budgets": {"per_tool": {"crm.read": {"requests": 1, "window_s": 3600}}},
    }), encoding="utf-8")
    monkeypatch.setenv("WARRNT_CATALOG", str(path))
    settings = Settings(home=tmp_path, registry_path=tmp_path / "receipts.jsonl",
                        key_path=tmp_path / "issuer.key", anchor_path=tmp_path / "anchors.jsonl",
                        upstream_url="", host="127.0.0.1", port=0, dev=True, admin_token=ADMIN_TOKEN)
    app = create_app(settings=settings)
    with TestClient(app, headers={"X-WARRNT-Admin": ADMIN_TOKEN}) as c:
        tokens = {a["id"]: a["token"] for a in c.get("/agents").json()}
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "crm.read", "arguments": {"table": "tickets", "limit": 1}}}
        hdr = {"X-WARRNT-Agent": "support-copilot", "X-WARRNT-Token": tokens["support-copilot"]}
        for _ in range(3):
            reply = c.post("/mcp", json=body, headers=hdr).json()
            assert "result" in reply, "monitor never refuses"
        receipts = c.get("/receipts").json()
        shadows = [r for r in receipts if "budget_monitor" in r.get("reason", "")]
        assert shadows, "a monitored control has to leave a trace, or monitoring is indistinguishable from absence"
