"""The deterministic half of content inspection (brief 4.2.1).

Until now this node matched personal data by *field name* - ``fields: ["email", "pesel"]`` was
recognised because someone had written the names down. That only covers the caller who is
polite enough to label the data, and it misses the rest: a secret pasted into a free-text note,
an IBAN inside a ticket body, an instruction to "ignore all previous instructions" buried in a
retrieved document. This module is the half that needs no model and no labels: patterns over the
content itself.

Two rules shape everything here:

  * **the value never leaves.** A finding carries a masked excerpt - a prefix and a length -
    never the secret it found. A control that logs what it caught has moved the leak, not
    stopped it.
  * **no false positives on shape alone.** A number that looks like a payment card is only one
    if it passes Luhn; an eleven-digit number is only a PESEL if its checksum agrees. Bare
    shapes would block honest work, and a control that cries wolf gets switched off.

The library is data: built-ins below, plus whatever the operator adds under ``patterns:`` in the
catalog. A pattern that does not compile fails its call loudly - a typo must not silently
disable a control.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

# Kinds decide the default answer, in the plugin: a secret or an attack marker is refused, a
# personal detail is taken out and the call still runs.
BLOCK_KINDS = ("secret", "injection")
SEVERITIES = ("low", "medium", "high")


def mask(value: str) -> str:
    """A prefix and a length - enough to recognise a leak, not enough to be one."""
    text = str(value)
    if len(text) <= 4:
        return "…" + str(len(text))
    return text[:4] + "…" + str(len(text))


@dataclass(frozen=True)
class Pattern:
    pid: str
    kind: str
    severity: str
    rx: re.Pattern
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ("secret", "personal", "injection"):
            raise ValueError(f"pattern {self.pid}: unknown kind {self.kind!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"pattern {self.pid}: unknown severity {self.severity!r}")


@dataclass(frozen=True)
class Finding:
    pid: str
    kind: str
    severity: str
    path: str
    masked: str

    def as_detail(self) -> dict[str, str]:
        """What goes on the record: where, and which pattern - never what."""
        return {"pattern": self.pid, "kind": self.kind, "severity": self.severity,
                "at": self.path, "excerpt": self.masked}


def _c(pid: str, kind: str, severity: str, rx: str, note: str = "") -> Pattern:
    return Pattern(pid, kind, severity, re.compile(rx), note)


# --------------------------------------------------------------------- checksums
def luhn(digits: str) -> bool:
    """A payment-card number passes Luhn or it is just a long number."""
    nums = [int(d) for d in re.sub(r"\D", "", digits)]
    if len(nums) < 12:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def pesel_ok(digits: str) -> bool:
    text = re.sub(r"\D", "", digits)
    if len(text) != 11:
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    total = sum(int(text[i]) * weights[i] for i in range(10))
    return (10 - total % 10) % 10 == int(text[10])


def iban_ok(text: str) -> bool:
    """ISO 13616: rearrange, letters to numbers, mod 97 must be 1."""
    compact = re.sub(r"\s+", "", text).upper()
    if not (15 <= len(compact) <= 34) or not compact.isalnum():
        return False
    if not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rotated = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rotated)
    return int(digits) % 97 == 1


# --------------------------------------------------------------------- the library
BUILTIN: tuple[Pattern, ...] = (
    # secrets first: these are refusals, not edits
    _c("secret.aws_access_key", "secret", "high", r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    _c("secret.github_token", "secret", "high",
       r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b", "GitHub token"),
    _c("secret.private_key", "secret", "high",
       r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "a private key block"),
    _c("secret.jwt", "secret", "high",
       r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "a signed JWT"),
    _c("secret.slack_token", "secret", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    _c("secret.generic_assignment", "secret", "high",
       r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*[\"\']?[A-Za-z0-9_\-]{16,}",
       "a credential-shaped assignment"),
    # personal data: taken out, the call still runs
    _c("personal.email", "personal", "medium",
       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "an email address"),
    _c("personal.iban", "personal", "medium",
       r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", "an IBAN (checksum verified)"),
    _c("personal.card", "personal", "high",
       r"\b(?:\d[ -]?){13,19}\b", "a payment card (Luhn verified)"),
    _c("personal.pesel", "personal", "medium", r"\b\d{11}\b", "a PESEL (checksum verified)"),
    # attack markers in content: refused
    _c("injection.ignore_instructions", "injection", "high",
       r"(?i)\b(?:ignore|disregard|forget)\b[^.]{0,40}\b(?:previous|prior|above|earlier)\b[^.]{0,20}\b(?:instruction|prompt|rule|direction)",
       "an instruction to drop prior instructions"),
    _c("injection.reveal_prompt", "injection", "high",
       r"(?i)\b(?:reveal|show|print|repeat|leak)\b[^.]{0,30}\b(?:system\s+prompt|your\s+instructions|hidden\s+rules|initial\s+prompt)",
       "an attempt to read the system prompt"),
    _c("injection.role_override", "injection", "high",
       r"(?i)\b(?:you are now|act as|pretend to be|developer mode|jailbreak|DAN mode)\b",
       "an attempt to replace the role"),
    _c("injection.new_instructions", "injection", "medium",
       r"(?i)\b(?:new|updated|revised)\s+instructions\s*[:\-]", "instructions injected mid-content"),
    _c("injection.exfiltrate", "injection", "high",
       r"(?i)\b(?:send|post|exfiltrate|upload|email|forward)\b[^.]{0,40}\b(?:to|at)\b[^.]{0,30}\b(?:https?://|@)",
       "an instruction to send data outward"),
)

# Which kinds a checksum gate applies to: the pattern fires, the validator decides.
_VALIDATORS = {
    "personal.card": lambda s: luhn(s),
    "personal.pesel": lambda s: pesel_ok(s),
    "personal.iban": lambda s: iban_ok(s),
}

MAX_FINDINGS = 200

# The catalog names its sections the way a person would ("secrets", "personal_data"); the kinds
# below are what the plugin switches on. A section nobody recognises is refused rather than
# folded into a default - a pattern under a name the node does not understand would otherwise be
# loaded with a severity nobody chose.
_KIND_ALIASES = {
    "secrets": "secret", "secret": "secret",
    "personal_data": "personal", "personal": "personal", "pii": "personal",
    "injection": "injection", "injections": "injection", "attacks": "injection",
}


def library(extra: dict[str, list[dict[str, Any]]] | None = None) -> list[Pattern]:
    """Built-ins plus whatever the catalog adds.

    ``extra`` is the catalog's ``patterns:`` mapping - ``{kind: [{id, pattern, severity}, ...]}``
    - so an operator can add a house pattern without touching this file. A pattern that does not
    compile raises, and the caller turns that into a refusal rather than an allow.
    """
    out = list(BUILTIN)
    for section, entries in (extra or {}).items():
        kind = _KIND_ALIASES.get(str(section).lower())
        if kind is None:
            raise ValueError(
                f"catalog patterns section {section!r} is not one of "
                f"{sorted(set(_KIND_ALIASES))} - refusing rather than guessing a severity")
        for entry in entries or []:
            if isinstance(entry, str):
                entry = {"id": f"{kind}.custom", "pattern": entry}
            pid = str(entry.get("id") or f"{kind}.custom")
            rx = entry.get("pattern")
            if not rx:
                raise ValueError(f"catalog pattern {pid!r} has no 'pattern'")
            out.append(Pattern(pid, _KIND_ALIASES.get(str(entry.get("kind") or kind).lower(), kind),
                               str(entry.get("severity") or "medium"), re.compile(str(rx)),
                               str(entry.get("note") or "from the catalog")))
    return out


def _walk(node: Any, path: str) -> Iterable[tuple[str, str]]:
    """Every string in the payload, with the path that leads to it."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, (list, tuple, set)):
        for i, value in enumerate(node):
            yield from _walk(value, f"{path}[{i}]")
    elif isinstance(node, (int, float, bool)):
        yield path, str(node)


def scan(params: Any, lib: Iterable[Pattern] | None = None) -> list[Finding]:
    """Look at the content, not the labels. Returns findings, capped and masked."""
    patterns = list(lib if lib is not None else BUILTIN)
    found: list[Finding] = []
    for path, text in _walk(params, "params"):
        if not text:
            continue
        for pat in patterns:
            hit = pat.rx.search(text)
            if hit is None:
                continue
            check = _VALIDATORS.get(pat.pid)
            if check is not None and not check(hit.group(0)):
                continue
            found.append(Finding(pat.pid, pat.kind, pat.severity, path, mask(hit.group(0))))
            if len(found) >= MAX_FINDINGS:
                return found
    return found


def redact_in_place(params: Any, findings: list[Finding],
                    lib: Iterable[Pattern] | None = None) -> list[str]:
    """Take the matched content out of the payload the upstream will see.

    Returns the top-level parameter names that changed. The masking happens on the object the
    kernel is holding, which is the same object it hands to the upstream, so there is no window
    in which the unredacted payload is still reachable.
    """
    if not findings:
        return []
    patterns = list(lib if lib is not None else BUILTIN)
    pids = {f.pid for f in findings}
    active = [(p, _VALIDATORS.get(p.pid)) for p in patterns if p.pid in pids]
    touched: list[str] = []

    def walk(node: Any, top: str) -> Any:
        if isinstance(node, str):
            text = node
            for pat, check in active:
                def sub(m, _p=pat, _c=check):
                    if _c is not None and not _c(m.group(0)):
                        return m.group(0)
                    if top and top not in touched:
                        touched.append(top)
                    return f"[REDACTED:{_p.kind}]"
                text = pat.rx.sub(sub, text)
            return text
        if isinstance(node, dict):
            return {k: walk(v, top or str(k)) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, top) for v in node]
        if isinstance(node, tuple):
            return tuple(walk(v, top) for v in node)
        return node

    if isinstance(params, dict):
        for key, value in list(params.items()):
            params[key] = walk(value, str(key))
    return sorted(touched)


def worst(findings: list[Finding]) -> str:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return max((f.severity for f in findings), key=lambda s: order.get(s, 0), default="low")
