"""The control catalog: one file that says which controls run, how strictly, and on what budget.

D3 says one catalog is the single source of truth and D9 says an operator may edit it while the
node is running. This module is what makes both true: the file is re-read when its mtime moves,
so the next call already obeys a threshold that was changed a second ago - no restart.

``strictness`` is the knob a reviewer turns, and it means the same thing for every control:

  off      the control is not consulted at all
  monitor  consulted and recorded, but it can never change an outcome - a shadow rollout
  redact   acts by stripping, and the call still executes
  block    acts by refusing

Everything a control needs to know lives here rather than in code: per-control ``threshold``,
the ``allowed_models`` list, ``budgets`` ceilings, and the ``patterns`` the inspectors compile.
A rule that cannot be expressed in the catalog means the catalog is wrong (D3).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .config import REPO_ROOT

STRICTNESS = ("off", "monitor", "redact", "block")
# a control that does not appear in the file still has a name and a default
KNOWN_CONTROLS = ("action_taxonomy", "actor_scope", "budget", "pattern_inspector",
                  "signature_feed", "semantic_judge", "order_policy")


def _strictness(value: Any) -> str:
    """Normalise the strictness knob.

    ``off`` is a YAML 1.1 boolean, so PyYAML turns a bare ``strictness: off`` into ``False``
    before this module ever sees it. That is a trap for exactly the person the catalog exists
    for - an operator editing the file mid-demo - so the parser reads the meaning instead of
    refusing the file: ``False``/``"false"`` mean *off*, ``True``/``"true"`` mean *block*.
    """
    if value is True:
        return "block"
    if value is False or value is None:
        return "off"
    text = str(value).strip().lower()
    if text in ("false", "no", "none", ""):
        return "off"
    if text in ("true", "yes"):
        return "block"
    return text


@dataclass(frozen=True)
class Control:
    """One control's settings. Validated on construction, so a typo fails at boot."""

    name: str
    enabled: bool = True
    strictness: str = "block"
    threshold: Optional[float] = None
    note: str = ""

    def __post_init__(self) -> None:
        if self.strictness not in STRICTNESS:
            raise ValueError(f"control {self.name!r}: strictness {self.strictness!r} is not one "
                             f"of {STRICTNESS}")
        if self.threshold is not None and not 0.0 <= float(self.threshold) <= 1.0:
            raise ValueError(f"control {self.name!r}: threshold must be between 0 and 1, "
                             f"got {self.threshold}")

    @property
    def consulted(self) -> bool:
        """Is the control asked at all?"""
        return self.enabled and self.strictness != "off"

    @property
    def acts(self) -> bool:
        """May the control change an outcome, or is it only watching?"""
        return self.enabled and self.strictness in ("redact", "block")


def _read(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # noqa: PLC0415 - optional, so the core stays stdlib
        except ImportError as exc:            # pragma: no cover - depends on the install
            raise RuntimeError(
                f"{path.name} is YAML but PyYAML is not installed - either "
                f"`pip install pyyaml` or ship the same file as JSON") from exc
        return yaml.safe_load(text) or {}
    return json.loads(text)


@dataclass
class Catalog:
    """The loaded catalog, with mtime-based reload."""

    path: Path
    controls: dict[str, Control] = field(default_factory=dict)
    allowed_models: list[str] = field(default_factory=list)
    budgets: dict[str, Any] = field(default_factory=dict)
    patterns: dict[str, list[str]] = field(default_factory=dict)
    signatures_path: Optional[str] = None
    semantic: dict[str, Any] = field(default_factory=dict)
    version: int = 1
    raw: dict[str, Any] = field(default_factory=dict)
    reloads: int = 0
    _stamp: float = 0.0

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Catalog":
        target = Path(path or os.environ.get("WARRNT_CATALOG") or (REPO_ROOT / "catalog.yaml"))
        cat = cls(path=target)
        cat.reload(force=True)
        return cat

    def reload(self, force: bool = False) -> bool:
        """Re-read when the file changed. Returns True when it actually re-read.

        Called per intercepted call, so a demo can edit the file mid-run - the point of D9 -
        without paying for a parse on every request.
        """
        try:
            stamp = self.path.stat().st_mtime
        except OSError:
            if force:
                raise FileNotFoundError(f"catalog not found: {self.path}")
            return False
        if not force and stamp == self._stamp:
            return False

        data = _read(self.path)
        controls: dict[str, Control] = {}
        for name in KNOWN_CONTROLS:
            # A known control the file does not mention is OFF, not armed. Pre-seeding these as
            # enabled/block is what made a one-line catalog arm every other control - including
            # the semantic judge, which then refused every call because no model was installed.
            # A config file means what it says; the shipped catalogs state every control.
            controls[name] = Control(name=name, enabled=False, strictness="off")
        for name, spec in (data.get("controls") or {}).items():
            spec = spec or {}
            if not isinstance(spec, dict):
                raise ValueError(f"control {name!r} must be a mapping, got {type(spec).__name__}")
            controls[name] = Control(
                name=name, enabled=bool(spec.get("enabled", True)),
                strictness=_strictness(spec.get("strictness", "block")),
                threshold=spec.get("threshold"), note=str(spec.get("note", "")))

        self.controls = controls
        self.allowed_models = list(data.get("allowed_models") or [])
        self.budgets = dict(data.get("budgets") or {})
        self.patterns = {k: list(v or []) for k, v in (data.get("patterns") or {}).items()}
        self.signatures_path = data.get("signatures_path")
        self.semantic = dict(data.get("semantic") or {})
        self.version = int(data.get("version", 1))
        self.raw = data
        self._stamp = stamp
        self.reloads += 1
        return True

    # ------------------------------------------------------------------ reading
    def control(self, name: str) -> Control:
        """A control this file does not mention is not consulted.

        The alternative - defaulting an absent control to armed - reads as fail-closed but
        behaves as fail-closed to nothing: a catalog that lists one control would silently arm
        every other one, including any that needs a dependency the operator never installed. A
        config file means what it says; the shipped catalogs state every control.
        """
        return self.controls.get(name) or Control(name=name, enabled=False, strictness="off")

    def strictness(self, name: str) -> str:
        return self.control(name).strictness

    def consulted(self, name: str) -> bool:
        return self.control(name).consulted

    def acts(self, name: str) -> bool:
        return self.control(name).acts

    def threshold(self, name: str, default: float = 0.5) -> float:
        value = self.control(name).threshold
        return default if value is None else float(value)

    def summary(self) -> dict[str, Any]:
        """What the console and ``GET /api/catalog`` show: the knobs, without the whole file."""
        return {
            "path": str(self.path), "version": self.version, "reloads": self.reloads,
            "controls": [
                {"name": c.name, "enabled": c.enabled, "strictness": c.strictness,
                 "threshold": c.threshold, "note": c.note}
                for c in sorted(self.controls.values(), key=lambda c: c.name)
            ],
            "allowed_models": self.allowed_models,
            "budgets": self.budgets,
            "semantic_enabled": self.consulted("semantic_judge"),
        }
