"""The external attack-signature feed (brief 4.4).

Known shapes, kept outside the codebase on purpose (D8): the operations team owns this file, and
swapping it must not need a redeploy. The node re-reads it when it changes, exactly as it does
the catalog.

Two things make this a *feed* rather than a list of regexes in a module:

  * **provenance.** Every signature carries where it came from, and the feed carries a version.
    A refusal written by this gate can say *which* published shape it matched and *which*
    revision of the feed it read - a decision nobody can cite is a decision nobody can review.
  * **it can be replaced while the node runs.** ``reload()`` follows the file's mtime, and
    ``fetch()`` pulls a new revision from a URL and refuses to install a feed that does not
    parse, has no version, or is larger than any sane feed.

A feed that is named by the catalog but cannot be read does not silently disable the control:
the gate refuses, because "I could not check" is not "I checked".
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_FEED_BYTES = 2 * 1024 * 1024        # a feed far past this is a mistake or an attack
KINDS = ("injection", "exfiltration", "tool_abuse", "ssrf", "unknown")
SEVERITIES = ("low", "medium", "high")
DEFAULT_NAME = "signatures.yaml"

from .patterns import mask, _walk  # noqa: E402 - the same masking rule, one implementation


@dataclass(frozen=True)
class Signature:
    sid: str
    kind: str
    severity: str
    rx: re.Pattern
    note: str
    source: str
    scope: str = "any"      # any | content | call - see SignatureFeed.match

    def as_detail(self) -> dict[str, str]:
        return {"id": self.sid, "kind": self.kind, "severity": self.severity,
                "note": self.note, "source": self.source}


@dataclass(frozen=True)
class Match:
    sig: Signature
    at: str
    masked: str

    def as_detail(self) -> dict[str, str]:
        return {**self.sig.as_detail(), "at": self.at, "excerpt": self.masked}


def _read(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml
    except ImportError:                                  # pragma: no cover - yaml is a dependency
        return json.loads(text)
    return yaml.safe_load(text) or {}


def parse(data: dict[str, Any], origin: str) -> list[Signature]:
    """Turn the feed into signatures, or refuse it. Every failure here is loud."""
    version = str(data.get("version") or "").strip()
    if not version:
        raise ValueError(f"{origin}: the feed has no 'version'. A refusal that cites a shape "
                         f"must be able to cite the revision it saw")
    entries = data.get("signatures")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{origin}: 'signatures' must be a non-empty list")
    out: list[Signature] = []
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{origin}: signature #{i} is not a mapping")
        sid = str(entry.get("id") or "").strip()
        if not sid:
            raise ValueError(f"{origin}: signature #{i} has no 'id'")
        if sid in seen:
            raise ValueError(f"{origin}: duplicate signature id {sid!r}")
        seen.add(sid)
        pattern = entry.get("pattern")
        if not pattern:
            raise ValueError(f"{origin}: signature {sid} has no 'pattern'")
        rx = re.compile(str(pattern))                    # raises on a bad pattern, on purpose
        kind = str(entry.get("kind") or "unknown").lower()
        if kind not in KINDS:
            raise ValueError(f"{origin}: signature {sid} has unknown kind {kind!r}")
        severity = str(entry.get("severity") or "medium").lower()
        if severity not in SEVERITIES:
            raise ValueError(f"{origin}: signature {sid} has unknown severity {severity!r}")
        scope = str(entry.get("scope") or "any").lower()
        if scope not in ("any", "content", "call"):
            raise ValueError(f"{origin}: signature {sid} has unknown scope {scope!r} "
                             f"(any | content | call)")
        out.append(Signature(sid, kind, severity, rx, str(entry.get("note") or ""),
                             str(entry.get("source") or data.get("source") or origin), scope))
    return out


class SignatureFeed:
    """The feed as the kernel holds it: loaded once, re-read when the file moves."""

    def __init__(self, data: dict[str, Any] | None, path: Path | None,
                 stamp: float | None, signatures: list[Signature] | None = None,
                 error: str = "") -> None:
        self.path = path
        self._stamp = stamp
        self.error = error
        self.reloads = 1
        self.data = data or {}
        self.signatures = signatures or []
        self.version = str(self.data.get("version") or "")
        self.source = str(self.data.get("source") or "")
        self.updated = str(self.data.get("updated") or "")
        self.loaded_at = time.time()

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "SignatureFeed":
        """Load a feed. A missing file yields an empty feed with the reason recorded - the
        caller decides whether that is a refusal; this class never invents signatures."""
        target = Path(path or os.environ.get("WARRNT_SIGNATURES") or DEFAULT_NAME)
        try:
            stamp = target.stat().st_mtime
            data = _read(target)
            sigs = parse(data, str(target))
            return cls(data, target, stamp, sigs)
        except FileNotFoundError:
            return cls({}, target, None, [], error=f"feed not found at {target}")
        except Exception as exc:  # noqa: BLE001 - the reason travels with the feed
            return cls({}, target, None, [], error=f"{type(exc).__name__}: {exc}")

    def reload(self, force: bool = False) -> bool:
        """Re-read only when the file actually moved."""
        if self.path is None:
            return False
        try:
            stamp = self.path.stat().st_mtime
        except OSError:
            return False
        if not force and self._stamp is not None and stamp == self._stamp:
            return False
        fresh = SignatureFeed.load(self.path)
        self.data, self.signatures, self._stamp = fresh.data, fresh.signatures, fresh._stamp
        self.version, self.source = fresh.version, fresh.source
        self.updated, self.error, self.loaded_at = fresh.updated, fresh.error, fresh.loaded_at
        self.reloads += 1
        return True

    # ------------------------------------------------------------------ use
    @property
    def ok(self) -> bool:
        return bool(self.signatures) and not self.error

    def match(self, payload: Any) -> list[Match]:
        """Every place a known shape appears, with where and which shape - never the text.

        ``scope`` keeps the feed out of the decisions that belong to other gates. A signature
        scoped to ``content`` fires only inside the parameters, so a rule about a destructive
        tool named *in content* cannot pre-empt the gate that decides whether the *call* is
        allowed - which is how a refusal ends up in the wrong place with the wrong reason.
        """
        found: list[Match] = []
        for path, text in _walk(payload, "call"):
            if not text:
                continue
            in_content = path.startswith("call.params")
            for sig in self.signatures:
                if sig.scope == "content" and not in_content:
                    continue
                if sig.scope == "call" and in_content:
                    continue
                hit = sig.rx.search(text)
                if hit is not None:
                    found.append(Match(sig, path, mask(hit.group(0))))
        return found

    def summary(self) -> dict[str, Any]:
        return {"path": str(self.path) if self.path else "", "version": self.version,
                "source": self.source, "updated": self.updated, "count": len(self.signatures),
                "loaded_at": self.loaded_at, "reloads": self.reloads, "ok": self.ok,
                "error": self.error,
                "kinds": {k: sum(1 for s in self.signatures if s.kind == k) for k in KINDS
                          if any(s.kind == k for s in self.signatures)}}


def fetch(url: str, dest: str | os.PathLike, timeout: float = 10.0) -> SignatureFeed:
    """Pull a feed from somewhere and install it, or leave the old one alone.

    An update that cannot be validated never reaches the disk: a bad feed must not be able to
    disarm a running node, and it must not be able to arm it with shapes nobody reviewed.
    """
    target = Path(dest)
    if not str(url).startswith(("http://", "https://", "file://")):
        raise ValueError(f"refusing to fetch a feed from {url!r}: http(s) or file only")
    req = urllib.request.Request(url, headers={"User-Agent": "warrnt-feed/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:      # noqa: S310 - scheme checked
        raw = resp.read(MAX_FEED_BYTES + 1)
    if len(raw) > MAX_FEED_BYTES:
        raise ValueError(f"feed at {url} is larger than {MAX_FEED_BYTES} bytes - refused")
    text = raw.decode("utf-8")
    data = json.loads(text) if target.suffix.lower() == ".json" else None
    if data is None:
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:                                          # pragma: no cover
            data = json.loads(text)
    parse(data or {}, url)                       # validate BEFORE it replaces anything
    target.write_text(text, encoding="utf-8")
    return SignatureFeed.load(target)
