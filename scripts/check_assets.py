"""Verify every /static/... reference in the frontend resolves to a real file,
and every icon reference resolves to a real sprite symbol.

    python scripts/check_assets.py

Askama compile-checks templates against their context structs, but it has no
idea whether `/static/js/pages/proxy.js` exists — a missing asset is a silent
404 and a page stuck on "Loading…" forever. That is not hypothetical: proxy.js
and ssh.js were referenced by three shipping pages and had never been written.

This closes that gap. It walks templates, CSS and JS, extracts every /static
URL, and fails if the file isn't on disk. Exits non-zero, so it can go in CI.

It also checks *inside* the sprite. A `<use href="…/sprite.svg#code">` naming a
symbol that isn't in the sprite renders nothing at all — a button with a label
and a blank space where its glyph should be, with no console error and no 404,
because the file it points at exists. The DB Studio DDL button shipped exactly
that way: correct markup, `code` never added to the generator's ICONS list.
File-level checking cannot see it, so symbol-level checking lives here too.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPRITE = ROOT / "static/icons/sprite.svg"

# Quoted or url(...)-wrapped absolute asset paths. The sprite's "#icon" fragment
# is stripped here — it addresses a symbol inside the file, not a separate file
# — and is checked separately by check_symbols().
PATTERN = re.compile(r"""['"(]\s*(/static/[A-Za-z0-9_./-]+)""")

# Markup references: <use href="/static/icons/sprite.svg#NAME">.
USE_PATTERN = re.compile(r"sprite\.svg#([A-Za-z0-9_-]+)")

# JS references, which never spell the path: `icon('NAME')` for a bare glyph,
# and `icon: 'NAME'` for the option-object form used by emptyState() and the
# palette's KIND table. Both feed the same <use href> at runtime.
JS_ICON_PATTERN = re.compile(r"""\bicon\(\s*['"]([a-z0-9-]+)['"]""")
JS_ICON_OPT_PATTERN = re.compile(r"""\bicon:\s*['"]([a-z0-9-]+)['"]""")

SYMBOL_PATTERN = re.compile(r'<symbol id="([A-Za-z0-9_-]+)"')

# Page wiring: `document.getElementById('x')` against `id="x"` in a template.
# Most page modules run this at import time and immediately call
# `.addEventListener` on the result, so a renamed or missing element is a
# TypeError that stops the whole module — every later feature on the page dies
# with it, silently, on that page only.
GET_BY_ID_PATTERN = re.compile(r"""getElementById\(\s*['"]([A-Za-z0-9_-]+)['"]""")
HTML_ID_PATTERN = re.compile(r'id="([A-Za-z0-9_-]+)"')
# Elements the JS builds itself (`h('div', { id: 'x' })`) are legitimately
# absent from every template — they exist only once that code has run.
JS_MADE_ID_PATTERN = re.compile(r"""\bid:\s*['"]([A-Za-z0-9_-]+)['"]""")


def check_symbols(sources: list[Path]) -> int:
    """Every referenced sprite symbol must exist in the sprite."""
    if not SPRITE.exists():
        print(f"\nsprite missing: {SPRITE.relative_to(ROOT)}")
        return 1

    have = set(SYMBOL_PATTERN.findall(SPRITE.read_text(encoding="utf-8")))

    refs: dict[str, set[str]] = {}
    for f in sources:
        text = f.read_text(encoding="utf-8")
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        names = USE_PATTERN.findall(text)
        # Only .js files use the helper forms; a CSS or HTML file matching
        # `icon: 'foo'` would be a class name or a comment, not a glyph.
        if f.suffix == ".js":
            names += JS_ICON_PATTERN.findall(text) + JS_ICON_OPT_PATTERN.findall(text)
        for name in names:
            refs.setdefault(name, set()).add(rel)

    unknown = [(n, sorted(s)) for n, s in sorted(refs.items()) if n not in have]

    print(f"checked {len(refs)} distinct icon references against {len(have)} sprite symbols")
    if not unknown:
        print("OK — all resolve")
        return 0

    print(f"\n{len(unknown)} ICON(S) NOT IN THE SPRITE:")
    for name, srcs in unknown:
        print(f"  {name}  (add it to ICONS in scripts/build_sprite.py and regenerate)")
        for s in srcs:
            print(f"      <- {s}")
    return 1


def check_element_ids(sources: list[Path]) -> int:
    """Every getElementById target must exist in a template or be JS-built."""
    js = [f for f in sources if f.suffix == ".js"]
    defined = set()
    for f in sources:
        if f.suffix == ".html":
            defined |= set(HTML_ID_PATTERN.findall(f.read_text(encoding="utf-8")))
    for f in js:
        defined |= set(JS_MADE_ID_PATTERN.findall(f.read_text(encoding="utf-8")))

    refs: dict[str, set[str]] = {}
    for f in js:
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        for name in GET_BY_ID_PATTERN.findall(f.read_text(encoding="utf-8")):
            refs.setdefault(name, set()).add(rel)

    unknown = [(n, sorted(s)) for n, s in sorted(refs.items()) if n not in defined]

    print(f"checked {len(refs)} element ids against {len(defined)} defined")
    if not unknown:
        print("OK — all resolve")
        return 0

    print(f"\n{len(unknown)} ELEMENT ID(S) NOT IN ANY TEMPLATE:")
    for name, srcs in unknown:
        print(f"  {name}")
        for s in srcs:
            print(f"      <- {s}")
    return 1


def main() -> int:
    sources = [
        *sorted(ROOT.glob("templates/**/*.html")),
        *sorted(ROOT.glob("static/css/**/*.css")),
        *sorted(ROOT.glob("static/js/**/*.js")),
    ]

    refs: dict[str, set[str]] = {}
    for f in sources:
        for m in PATTERN.finditer(f.read_text(encoding="utf-8")):
            path = m.group(1).split("#")[0]
            refs.setdefault(path, set()).add(str(f.relative_to(ROOT)).replace("\\", "/"))

    missing = [(p, sorted(s)) for p, s in sorted(refs.items()) if not (ROOT / p.lstrip("/")).exists()]

    print(f"checked {len(refs)} distinct /static references across {len(sources)} files")
    if missing:
        print(f"\n{len(missing)} MISSING:")
        for path, srcs in missing:
            print(f"  {path}")
            for s in srcs:
                print(f"      <- {s}")
    else:
        print("OK — all resolve")

    # All three checks always run: a broken path, a broken icon and a broken
    # element id are independent failures, and reporting only the first would
    # hide the others.
    return (1 if missing else 0) | check_symbols(sources) | check_element_ids(sources)


if __name__ == "__main__":
    raise SystemExit(main())
