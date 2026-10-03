"""The gate registry is real, not a story in the docs.

These tests are the proof of the microkernel claim: the kernel coordinates and never names a
gate, gates come from a plugin package, and a gate can be added, swapped or removed while the
node runs. If any of this stops being true, the architecture claim in
``docs/triz-python-architecture.md`` becomes false - so it is a test, not a paragraph.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

from warrnt import gates
from warrnt.gates import Gate, GateContext, register, unregister
from warrnt.models import Decision
from warrnt.proxy import MCPProxy
from warrnt.registry import AppendOnlyRegistry
from warrnt.warrants import WarrantIssuer

KERNEL = pathlib.Path(__file__).resolve().parents[1] / "warrnt" / "proxy.py"


def _proxy(tmp_path) -> MCPProxy:
    p = MCPProxy(WarrantIssuer(key=b"gate-registry-test-key"),
                 AppendOnlyRegistry(str(tmp_path / "chain.jsonl")))
    p.issue_all()
    return p


def test_the_gates_come_from_the_plugin_package_in_a_fixed_order():
    assert gates.load() == ["act_class", "budget", "pattern_inspector", "signature_feed", "semantic_judge",
                                          "actor_scope", "break_glass", "order_policy"]
    assert [g.order for g in gates.ordered()] == sorted(g.order for g in gates.ordered())


def test_every_gate_is_a_named_object_with_a_check():
    for gate in gates.ordered():
        assert isinstance(gate, Gate)
        assert gate.name and callable(gate.check)


def test_the_kernel_names_no_gate_of_its_own():
    """The load-bearing half of the claim: no call sites for classify/apply_class/actors."""
    src = KERNEL.read_text()
    for call in ("classify(", "apply_class(", "engine.evaluate(", "actors.check("):
        assert call not in src, f"the kernel still decides by hand: {call}"
    assert "gate_registry.run(" in src, "the kernel must ask the registry"
    assert "from .plugins" not in src and "import plugins" not in src.split("gates as gate_registry")[0]


def test_a_gate_dropped_into_the_package_is_discovered_and_consulted(tmp_path):
    """Adding a gate = adding a file. Nothing in the kernel changes."""
    pkg = pathlib.Path(gates.__file__).parent / "plugins"
    extra = pkg / "zz_probe.py"
    extra.write_text(
        "from ..gates import Gate, register\n"
        "from ..models import Decision\n"
        "def _check(ctx):\n"
        "    if ctx.tool == 'probe.echo':\n"
        "        return Decision.deny, 'blocked by the probe gate', {'probe': True}\n"
        "    return None\n"
        "register(Gate('zz_probe', _check, order=5))\n"
    )
    gates._LOADED = False
    sys.modules.pop("warrnt.plugins.zz_probe", None)
    try:
        names = gates.load()
        assert "zz_probe" in names and names[0] == "zz_probe", names
        proxy = _proxy(tmp_path)
        agent = proxy.agents["support-copilot"]
        decision, reason, detail, _receipt, executed = proxy.intercept(
            "support-copilot", agent.token, "probe.echo", {})
        assert decision is Decision.deny and detail.get("probe") is True and executed is False
        # an unrelated tool goes past the probe gate untouched
        decision2, _r, _d, _rec, _e = proxy.intercept(
            "support-copilot", agent.token, "crm.read", {"table": "tickets", "limit": 5})
        assert decision2 is Decision.allow
    finally:
        extra.unlink()
        unregister("zz_probe")
        gates._LOADED = False
        sys.modules.pop("warrnt.plugins.zz_probe", None)
        gates.load()


def test_a_gate_can_be_swapped_at_runtime(tmp_path):
    seen = {}

    def _check(ctx):
        seen["asked"] = ctx.tool
        return None

    register(Gate("order_policy", _check, order=30), replace=True)
    try:
        proxy = _proxy(tmp_path)
        agent = proxy.agents["support-copilot"]
        # the swapped gate passes, so the pipeline runs off the end - loud, not silent
        with pytest.raises(RuntimeError, match="no gate decided"):
            proxy.intercept("support-copilot", agent.token, "crm.read", {"table": "t", "limit": 1})
        assert seen["asked"] == "crm.read"
    finally:
        gates._LOADED = False
        unregister("order_policy")
        sys.modules.pop("warrnt.plugins.order_policy", None)
        gates.load()
        assert gates.names() == ["act_class", "budget", "pattern_inspector", "signature_feed", "semantic_judge",
                                          "actor_scope", "break_glass", "order_policy"]


def test_a_duplicate_gate_name_is_refused_unless_it_is_a_deliberate_swap():
    def _check(ctx):
        return None

    with pytest.raises(ValueError, match="already registered"):
        register(Gate("act_class", _check, order=99))
    register(Gate("act_class", _check, order=99), replace=True)
    swapped = [g for g in gates.ordered() if g.name == "act_class"][0]
    assert swapped.order == 99, "the swap took effect at runtime"
    # put the real gate back: drop the stand-in, then let discovery import the module again
    unregister("act_class")
    gates._LOADED = False
    sys.modules.pop("warrnt.plugins.act_class", None)
    gates.load()
    assert gates.names() == ["act_class", "budget", "pattern_inspector", "signature_feed", "semantic_judge",
                                          "actor_scope", "break_glass", "order_policy"]
