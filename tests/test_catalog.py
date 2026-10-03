"""The catalog is the single control source (D3) and it is re-read while the node runs (D9).

These tests pin the two things a reviewer will try: change a value in the file and see the next
call obey it, and turn a control down without editing Python.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from warrnt.catalog import Catalog, Control, KNOWN_CONTROLS, STRICTNESS

ROOT = Path(__file__).resolve().parent.parent


def test_the_shipped_catalog_loads_and_covers_the_known_controls():
    cat = Catalog.load(ROOT / "catalog.yaml")
    assert cat.path.name == "catalog.yaml"
    for name in KNOWN_CONTROLS:
        assert cat.control(name).name == name, f"{name} must resolve even when absent"
    assert cat.allowed_models, "the permitted-model list is a control, not a preference"
    assert cat.budgets.get("default"), "a default ceiling is what makes budgets enforceable"


def test_the_three_profiles_load_and_actually_differ():
    strict = Catalog.load(ROOT / "catalog.strict.yaml")
    balanced = Catalog.load(ROOT / "catalog.yaml")
    permissive = Catalog.load(ROOT / "catalog.permissive.yaml")

    # the loud end: the semantic judge is consulted and the ceilings are tight
    assert strict.consulted("semantic_judge") and strict.acts("semantic_judge")
    assert strict.budgets["default"]["requests"] < balanced.budgets["default"]["requests"]

    # the quiet end: the same controls, watching instead of acting
    assert permissive.consulted("budget") and not permissive.acts("budget")
    assert permissive.consulted("pattern_inspector")


def test_strictness_means_the_same_thing_for_every_control():
    assert Control("c", strictness="off").consulted is False
    assert Control("c", strictness="off").acts is False
    assert Control("c", strictness="monitor").consulted is True
    assert Control("c", strictness="monitor").acts is False, "monitor may never change an outcome"
    assert Control("c", strictness="redact").acts is True
    assert Control("c", strictness="block").acts is True


def test_a_typo_fails_at_boot_rather_than_at_demo_time():
    with pytest.raises(ValueError, match="strictness"):
        Control("c", strictness="enforce")
    with pytest.raises(ValueError, match="threshold"):
        Control("c", threshold=1.5)
    with pytest.raises(ValueError, match="threshold"):
        Control("c", threshold=-0.1)


def test_the_catalog_is_re_read_only_when_the_file_changes(tmp_path):
    path = tmp_path / "catalog.yaml"
    path.write_text("version: 1\ncontrols:\n  semantic_judge: {enabled: true, strictness: block,"
                    " threshold: 0.9}\n", encoding="utf-8")
    cat = Catalog.load(path)
    assert cat.threshold("semantic_judge") == 0.9
    assert cat.reloads == 1

    assert cat.reload() is False, "an unchanged file is not re-parsed"
    assert cat.reloads == 1

    path.write_text("version: 1\ncontrols:\n  semantic_judge: {enabled: false, strictness: off,"
                    " threshold: 0.2}\n", encoding="utf-8")
    assert cat.reload() is True, "a changed file is obeyed on the next call"
    assert cat.threshold("semantic_judge") == 0.2
    assert cat.consulted("semantic_judge") is False


def test_a_missing_catalog_is_loud_but_a_json_catalog_works(tmp_path):
    with pytest.raises(FileNotFoundError):
        Catalog.load(tmp_path / "absent.yaml")

    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"version": 2, "controls": {"budget": {"strictness": "monitor"}},
                                "budgets": {"default": {"requests": 3}}}), encoding="utf-8")
    cat = Catalog.load(path)
    assert cat.version == 2
    assert cat.strictness("budget") == "monitor"
    assert cat.budgets["default"]["requests"] == 3


def test_a_bare_off_is_not_mistaken_for_false(tmp_path):
    """`strictness: off` is a YAML 1.1 boolean - the parser must read the meaning, not raise."""
    path = tmp_path / "catalog.yaml"
    path.write_text("version: 1\ncontrols:\n  budget: {strictness: off}\n"
                    "  semantic_judge: {strictness: on}\n", encoding="utf-8")
    cat = Catalog.load(path)
    assert cat.strictness("budget") == "off"
    assert cat.consulted("budget") is False
    assert cat.strictness("semantic_judge") == "block"


def test_every_strictness_the_parser_accepts_is_one_it_understands():
    assert set(STRICTNESS) == {"off", "monitor", "redact", "block"}
