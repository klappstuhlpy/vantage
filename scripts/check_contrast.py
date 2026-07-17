"""WCAG contrast audit for the Vantage token palettes.

Parses the real tokens.css so the audit cannot drift from the shipped values:
change a color token, re-run this, and it tells you what broke.

    python scripts/check_contrast.py [path/to/tokens.css]

Text pairs must clear 4.5:1 (AA); control boundaries 3:1 (AA non-text). Exits
non-zero on any failure, so it can be wired into CI unchanged.
"""

import re
import sys
from pathlib import Path

DEFAULT = Path(__file__).resolve().parent.parent / "static" / "css" / "tokens.css"
CSS = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT).read_text(encoding="utf-8")


def blocks(selector: str) -> dict:
    """Pull the --var: value pairs out of the first rule matching `selector`."""
    idx = CSS.find(selector)
    if idx < 0:
        raise SystemExit(f"selector not found: {selector}")
    body = CSS[CSS.index("{", idx) + 1 : CSS.index("}", idx)]
    return dict(re.findall(r"(--[\w-]+):\s*([^;]+);", body))


def srgb_to_lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_color: str) -> float:
    h = hex_color.strip().lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * srgb_to_lin(r) + 0.7152 * srgb_to_lin(g) + 0.0722 * srgb_to_lin(b)


def ratio(fg: str, bg: str) -> float:
    a, b = luminance(fg), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def audit(name: str, sel: str, accents: dict) -> int:
    t = blocks(sel)
    fails = 0
    print(f"\n=== {name} " + "=" * (46 - len(name)))

    # Text on each surface: AA 4.5. All three ink steps are real text somewhere
    # (--ink-3 renders chart axes, log timestamps, field hints, placeholders),
    # so all three are held to the text bar, not the 3:1 glyph bar.
    text_pairs = [
        (ink, bg) for ink in ("--ink-1", "--ink-2", "--ink-3") for bg in ("--bg-0", "--bg-1", "--bg-2", "--bg-3")
    ]
    # Status text sits on its own soft tint over a card; check against the card.
    text_pairs += [(s, "--bg-1") for s in ("--ok", "--warn", "--down", "--idle", "--info", "--acc")]
    for fg, bg in text_pairs:
        r = ratio(t[fg], t[bg])
        ok = r >= 4.5
        fails += not ok
        print(f"  {'OK ' if ok else 'FAIL'} {r:5.2f}  text  {fg:8} on {bg}")

    # Non-text (WCAG 1.4.11, 3:1): the boundary that identifies a control.
    # --line-1/--line-2 are decorative rules and overlay edges, which the SC
    # exempts; --line-ctl is the one every input/switch/checkbox/outline button
    # uses, so it is the one that must clear the bar — against every surface it
    # can neighbour, including --bg-3 (inputs inside a modal) and --bg-2 (its
    # own fill), not just the card it usually sits on.
    for fg, bg, kind in [
        ("--line-ctl", "--bg-0", "border"),
        ("--line-ctl", "--bg-1", "border"),
        ("--line-ctl", "--bg-2", "border"),
        ("--line-ctl", "--bg-3", "border"),
        ("--acc", "--bg-1", "glyph"),
        ("--acc", "--bg-3", "glyph"),
    ]:
        r = ratio(t[fg], t[bg])
        ok = r >= 3.0
        fails += not ok
        print(f"  {'OK ' if ok else 'FAIL'} {r:5.2f}  {kind:6} {fg:8} on {bg}")

    # Text on an accent-filled button.
    r = ratio(t["--ink-on-acc"], t["--acc"])
    ok = r >= 4.5
    fails += not ok
    print(f"  {'OK ' if ok else 'FAIL'} {r:5.2f}  text  --ink-on-acc on --acc")

    # Every accent preset must clear 3:1 as a glyph on the card surface and
    # carry legible text when filled.
    for preset, sel2 in accents.items():
        a = blocks(sel2)
        r = ratio(a["--acc"], t["--bg-1"])
        ok = r >= 3.0
        fails += not ok
        print(f"  {'OK ' if ok else 'FAIL'} {r:5.2f}  accent[{preset}] glyph on --bg-1")
        r = ratio(t["--ink-on-acc"], a["--acc"])
        ok = r >= 4.5
        fails += not ok
        print(f"  {'OK ' if ok else 'FAIL'} {r:5.2f}  accent[{preset}] --ink-on-acc on fill")
    return fails


dark_accents = {p: f":root[data-accent='{p}']" for p in ("phosphor", "amber", "ion", "ember")}
light_accents = {p: f":root[data-theme='light'][data-accent='{p}']" for p in ("phosphor", "amber", "ion", "ember")}

total = audit("DARK", ":root[data-theme='dark']", dark_accents)
total += audit("LIGHT", ":root[data-theme='light']", light_accents)

print(f"\n{'ALL PASS' if total == 0 else str(total) + ' FAILURES'}")
raise SystemExit(1 if total else 0)
