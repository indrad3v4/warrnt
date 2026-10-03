#!/usr/bin/env python3
"""Static layout guard for the console (index.html).

Why a static check and not a screenshot test: the defects this guards against are not a matter
of taste, they are structural, and each one is a rule that a file can be asked about without a
browser. What went wrong in review was:

  * `<footer>` was never closed where it should be, so four sections ended up INSIDE it. A flex
    footer then laid them out beside its own counters and crushed one column to 55px;
  * `body` declared four grid rows while the document had grown eight children, so five of them
    shared one `auto` row and were placed on top of each other;
  * `.killmid` carried `min-height:0`, so in a short tile the 56px revoke button collapsed its
    container and was painted over the target selector above it.

Every check below fails on the file as it was before the fix, and passes after it. That is the
point: a guard that cannot fail is decoration.

    python3 scripts/console_layout_check.py [path/to/index.html]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, PASS if ok else FAIL, detail))


def tracks(template: str) -> list[str]:
    """Split a grid-template-rows value into tracks, expanding repeat(n, ...)."""
    out: list[str] = []
    for item in re.findall(r"repeat\([^)]*\)|[^\s]+", template):
        m = re.match(r"repeat\(\s*(\d+)\s*,\s*(.+?)\s*\)$", item)
        if m:
            out.extend([m.group(2)] * int(m.group(1)))
        else:
            out.append(item)
    return out


VOID = {"br", "img", "input", "hr", "meta", "link", "source", "path", "circle"}
NESTED = {"div", "span", "section", "header", "footer", "main", "aside", "nav", "table",
          "thead", "tbody", "tr", "td", "th", "p", "h1", "h2", "h3", "pre", "form", "label",
          "select", "button", "ul", "ol", "li", "article", "figure"}


def flow_children(body: str) -> list[str]:
    """The elements a grid actually places: body-level children that are not scripts or
    out-of-flow overlays. Counting every nested div would swamp the comparison, so track depth.
    """
    out: list[str] = []
    depth = 0
    for m in re.finditer(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>", body):
        closing, tag, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if tag in VOID or attrs.rstrip().endswith("/"):
            continue
        if closing:
            depth = max(0, depth - 1)
            continue
        if depth == 0 and tag in NESTED:
            hidden = ("position:fixed" in attrs or 'id="ins"' in attrs or 'id="qa-report"' in attrs)
            # Not a `continue`: skipping the tag must not also skip the depth increment, or the
            # skipped element's own children get counted as body-level children.
            if not hidden:
                out.append(tag)
        if tag not in ("script", "style"):
            depth += 1
    return out


def main(path: Path) -> int:
    if not path.exists():
        print(f"{FAIL}  no such file: {path}")
        return 1
    src = path.read_text(encoding="utf-8")
    body = src.split("<body", 1)[1] if "<body" in src else src
    # Scripts and styles must go before any tag counting: the JS builds markup inside string
    # literals ("'<td>'"), which have no closing tags and would drag the depth counter with them.
    body_for_layout = re.sub(r"<script\b.*?</script>", "", body, flags=re.S)
    body_for_layout = re.sub(r"<style\b.*?</style>", "", body_for_layout, flags=re.S)

    # 1. every flow child gets a declared grid row -------------------------------------------
    m = re.search(r"body\s*\{[^}]*?grid-template-rows\s*:\s*([^;]+);", src, re.S)
    declared = tracks(m.group(1)) if m else []
    children = flow_children(body_for_layout)
    check("body declares a grid row for every flow child",
          bool(declared) and len(declared) >= len(children),
          f"{len(declared)} rows declared, {len(children)} flow children")

    # 2. children that must be last sit last -------------------------------------------------
    if "<footer" in body and 'class="taxo"' in body:
        last_taxo = body.rfind('class="taxo"')
        footer_at = body.find("<footer")
        check("the footer is the last flow child, not an envelope",
              footer_at > last_taxo,
              f"footer at {footer_at}, last section at {last_taxo}")
        check("the footer closes once, and after the last section",
              body.count("</footer>") == 1 and body.rfind("</footer>") > last_taxo,
              f"</footer> appears {body.count('</footer>')}x")
    else:
        check("the footer is the last flow child, not an envelope", True, "no footer/sections")

    # 3. the kill switch cannot collapse -----------------------------------------------------
    km = re.search(r"\.killmid\s*\{([^}]*)\}", src)
    km_body = km.group(1) if km else ""
    floor = re.search(r"min-height\s*:\s*(\d+)\s*px", km_body)
    check("the kill switch has a floor, so the button cannot overlap the selector",
          bool(floor) and int(floor.group(1)) >= 40 and "min-height:0" not in km_body,
          f"min-height={floor.group(1) + 'px' if floor else 'none'} (a 56px button needs room)")

    # 4. a responsive mode exists, and it can scroll ------------------------------------------
    medias = re.findall(r"@media([^{]+)\{", src)
    responsive = [c for c in medias if "max-width" in c or "max-height" in c]
    check("a responsive block covers narrow AND short viewports",
          any("max-width" in c for c in responsive) and any("max-height" in c for c in responsive),
          f"{len(responsive)} responsive block(s): {'; '.join(c.strip()[:46] for c in responsive)}")

    blocks = re.findall(r"@media[^{]+\{(.*?)\n\}", src, re.S)
    scrollable = sum(1 for b in blocks if re.search(r"overflow\s*:\s*(auto|scroll)", b))
    check("below the design size the page may scroll instead of hiding content",
          scrollable >= 1,
          f"{len(blocks)} media block(s), {scrollable} with overflow:auto")

    # 5. truncated text stays reachable ------------------------------------------------------
    renderers = [seg for seg in re.split(r"function\s+render", src) if "<td" in seg]
    titled = sum(1 for seg in renderers if 'title="' in seg)
    check("table cells that can truncate carry a title",
          titled >= 2, f"{titled} renderer(s) with a title attribute on their cells")

    # 6. the page can be judged without a human looking at it --------------------------------
    check("the QA hook publishes a machine-readable verdict",
          "dataset.ok" in src and "dataset.revokeOverTarget" in src,
          "needed by scripts/console_layout_sweep.py and by F12")

    width = max((len(n) for n, _, _ in results), default=0)
    for name, verdict, detail in results:
        print(f"{verdict}  {name.ljust(width)}  {detail}")
    failed = [r for r in results if r[1] == FAIL]
    print(f"\n{len(results) - len(failed)}/{len(results)} layout invariants hold in {path.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("index.html")
    raise SystemExit(main(target))
