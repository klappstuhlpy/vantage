"""Verify every /static/... reference in the frontend resolves to a real file.

    python scripts/check_assets.py

Askama compile-checks templates against their context structs, but it has no
idea whether `/static/js/pages/proxy.js` exists — a missing asset is a silent
404 and a page stuck on "Loading…" forever. That is not hypothetical: proxy.js
and ssh.js were referenced by three shipping pages and had never been written.

This closes that gap. It walks templates, CSS and JS, extracts every /static
URL, and fails if the file isn't on disk. Exits non-zero, so it can go in CI.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Quoted or url(...)-wrapped absolute asset paths. The sprite's "#icon" fragment
# is stripped — it addresses a symbol inside the file, not a separate file.
PATTERN = re.compile(r"""['"(]\s*(/static/[A-Za-z0-9_./-]+)""")


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
    if not missing:
        print("OK — all resolve")
        return 0

    print(f"\n{len(missing)} MISSING:")
    for path, srcs in missing:
        print(f"  {path}")
        for s in srcs:
            print(f"      <- {s}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
