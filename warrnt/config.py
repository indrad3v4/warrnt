"""Configuration. Env only - one node has no config server.

TENET_STATE_DIR     store directory for the persistence layer (actions, node state).
                    Takes precedence over WARRNT_HOME; unset -> WARRNT_HOME -> ``./state``.
WARRNT_HOME         state directory (default: ``./state`` under the repo root)
WARRNT_ISSUER_KEY   signing key (default: generated at <home>/issuer.key)
WARRNT_UPSTREAM     real MCP endpoint to front; unset -> in-process sandbox
WARRNT_HOST/PORT    bind address for ``warrnt serve``
WARRNT_ADMIN_TOKEN  operator token for mutating routes (unset -> one is generated and
                    printed once at startup; mutating routes answer 401 without it)
WARRNT_CATALOG      the control catalog (default: ``catalog.yaml`` at the repo root) - the
                    single source of truth for controls, thresholds, allowed models and
                    budgets (D3). Re-read while the node runs, so an edit is obeyed by the
                    next call (D9).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    home: Path
    registry_path: Path
    key_path: Path
    anchor_path: Path
    upstream_url: str
    host: str
    port: int
    dev: bool
    admin_token: str

    @classmethod
    def load(cls, home: str | os.PathLike | None = None) -> "Settings":
        # TENET_STATE_DIR is the store directory the persistence layer writes to. It is the
        # narrowest knob: unset, the node keeps its existing WARRNT_HOME (or ./state), so an
        # operator who sets nothing sees exactly the old behaviour.
        base = Path(home) if home else Path(
            os.environ.get("TENET_STATE_DIR")
            or os.environ.get("WARRNT_HOME")
            or REPO_ROOT / "state")
        return cls(
            home=base,
            registry_path=base / "receipts.jsonl",
            key_path=base / "issuer.key",
            anchor_path=Path(os.environ.get("WARRNT_ANCHOR", "")) if os.environ.get("WARRNT_ANCHOR")
            else base / "anchors.jsonl",
            upstream_url=os.environ.get("WARRNT_UPSTREAM", "").strip(),
            host=os.environ.get("WARRNT_HOST", "0.0.0.0"),
            port=int(os.environ.get("WARRNT_PORT", "8099")),
            dev=os.environ.get("WARRNT_DEV", "").strip() in ("1", "true", "yes"),
            admin_token=os.environ.get("WARRNT_ADMIN_TOKEN", "").strip(),
        )
