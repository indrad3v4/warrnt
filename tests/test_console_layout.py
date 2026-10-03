"""The console's layout invariants, enforced by the node's own test run.

The console is the surface a reviewer actually looks at, and its defects were structural rather
than visual: `<footer>` swallowing four sections inside its own flex row, a body grid that
declared four rows while the document had eight children, and a kill-switch column with
`min-height:0` that let the revoke button be painted over the target selector. None of that shows
up in a content check, and all of it shows up here.

scripts/console_layout_check.py holds the rules (and runs in the submission's CI); this makes the
node's own `pytest` fail when `warrnt/console.html` breaks one of them.
"""
from __future__ import annotations

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONSOLE = ROOT / "warrnt" / "console.html"


def guard():
    spec = importlib.util.spec_from_file_location(
        "console_layout_check", ROOT / "scripts" / "console_layout_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_console_holds_every_layout_invariant():
    checker = guard()
    checker.results.clear()
    exit_code = checker.main(CONSOLE)
    failed = [name for name, verdict, _ in checker.results if verdict == "FAIL"]
    assert exit_code == 0 and not failed, f"layout invariants broken: {failed}"


def test_the_kill_switch_cannot_be_painted_over_the_target_selector():
    """The defect that started this: min-height:0 collapsed the button's container."""
    source = CONSOLE.read_text(encoding="utf-8")
    block = source.split(".killmid{", 1)[1].split("}", 1)[0]
    assert "min-height:0" not in block
    assert "min-height:112px" in block


def test_the_console_publishes_a_verdict_a_sweep_can_read():
    """Without this, an automated viewport sweep cannot judge the page it just loaded."""
    source = CONSOLE.read_text(encoding="utf-8")
    for field in ("dataset.ok", "dataset.revokeOverTarget", "dataset.mode"):
        assert field in source, f"the QA hook must publish {field}"
