"""Build the Vantage Lucide SVG sprite.

Fetches a curated icon subset from lucide-static (pinned) and emits a single
<svg><symbol/>...</svg> sprite. Stroke presentation attributes are deliberately
dropped from each symbol so the `.icon` CSS class controls stroke width/color
by inheritance through the <use> shadow tree.
"""

import re
import sys
import urllib.request
from pathlib import Path

VERSION = "0.469.0"
BASE = f"https://cdn.jsdelivr.net/npm/lucide-static@{VERSION}/icons"

ICONS = [
    # nav
    "layout-dashboard", "activity", "heart-pulse", "container", "camera",
    "route", "badge-check", "brick-wall", "shield", "key-round", "spray-can",
    # `terminal` is SSH; `square-terminal` is Scripts — a boxed glyph so two
    # console-ish nav rows don't read as the same destination.
    "terminal", "square-terminal", "archive", "database", "scroll-text", "bell",
    "user-cog",
    # status
    "circle-check", "triangle-alert", "circle-x", "circle-dashed", "circle-help",
    "circle-alert", "info", "check", "ban", "shield-check",
    # actions
    "plus", "minus", "pencil", "trash-2", "refresh-cw", "play", "pause", "square",
    "rotate-ccw", "download", "upload", "search", "x", "copy", "eye", "eye-off",
    "external-link", "filter", "settings", "log-out", "user", "menu",
    "ellipsis", "list-restart", "power",
    # chevrons / disclosure
    "chevron-right", "chevron-down", "chevron-left", "chevron-up",
    "chevrons-left", "chevrons-right", "arrow-right", "arrow-up", "arrow-down",
    # theme + layout
    "sun", "moon", "monitor", "panel-left-close", "panel-left-open",
    "grid-2x2", "sliders-horizontal", "layout-grid", "grip-vertical",
    # resources
    "cpu", "memory-stick", "hard-drive", "network", "server", "wifi",
    "gauge", "thermometer",
    # misc
    "file-text", "folder", "clock", "calendar", "lock", "lock-open", "zap",
    "git-branch", "inbox", "radar", "globe", "map-pin", "fingerprint",
    "loader-circle", "corner-down-right", "history", "table", "code", "maximize",
    # alert sinks — one glyph each, so the cards are scannable without reading
    "mail", "message-square", "webhook", "smartphone",
]


def fetch(name: str) -> str:
    with urllib.request.urlopen(f"{BASE}/{name}.svg", timeout=30) as r:
        return r.read().decode("utf-8")


def inner(svg: str, name: str) -> str:
    m = re.search(r"<svg[^>]*>(.*)</svg>", svg, re.S)
    if not m:
        raise ValueError(f"{name}: no <svg> body")
    body = m.group(1).strip()
    body = re.sub(r"\s+", " ", body)
    body = re.sub(r">\s+<", "><", body)
    if not body:
        raise ValueError(f"{name}: empty body")
    return body


def main() -> int:
    out = Path(sys.argv[1])
    parts, failed = [], []
    for name in ICONS:
        try:
            parts.append(f'<symbol id="{name}" viewBox="0 0 24 24">{inner(fetch(name), name)}</symbol>')
        except Exception as e:  # noqa: BLE001 — report and continue; a missing icon must be visible
            failed.append(f"{name}: {e}")
    sprite = (
        "<!-- Lucide icons (ISC) — vendored subset, generated. "
        f"lucide-static@{VERSION}. Stroke styling comes from the .icon CSS class. -->\n"
        '<svg xmlns="http://www.w3.org/2000/svg" style="display:none">\n  '
        + "\n  ".join(parts)
        + "\n</svg>\n"
    )
    out.write_text(sprite, encoding="utf-8", newline="\n")
    print(f"wrote {out} — {len(parts)}/{len(ICONS)} icons, {out.stat().st_size} bytes")
    if failed:
        print("FAILED:\n  " + "\n  ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
