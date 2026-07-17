#!/usr/bin/env python3
"""Verify the frontend's ES-module import graph.

Node can't catch these without running the page: a named import that doesn't
exist is a runtime SyntaxError in the browser, on the one page that uses it,
which is exactly the class of bug that shipped the old `security.js` and
`proxy.js` as 404s for months.

Checks, per module:
  1. every relative import path resolves to a file on disk
  2. every named import is actually exported by that file
  3. every named import is referenced somewhere in the body (dead imports)

Exit code is non-zero on any finding, so this is CI-ready.

Usage:  python scripts/check_imports.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JS_DIR = ROOT / "static" / "js"

# import { a, b as c } from './x.js'   |   import x from './x.js'
IMPORT_RE = re.compile(
    r"^\s*import\s+(?:(?P<named>\{[^}]*\})|(?P<default>[\w$]+))\s+from\s+['\"](?P<path>[^'\"]+)['\"]",
    re.MULTILINE,
)
# export function f | export const f | export class F | export let f
EXPORT_DECL_RE = re.compile(
    r"^\s*export\s+(?:async\s+)?(?:function|const|let|var|class)\s+(?P<name>[\w$]+)",
    re.MULTILINE,
)
# export { a, b as c }
EXPORT_LIST_RE = re.compile(r"^\s*export\s*\{(?P<body>[^}]*)\}", re.MULTILINE)


def strip_comments(src: str) -> str:
    """Remove block/line comments and string literals.

    Crude but sufficient: we only need identifier occurrences, and a comment
    mentioning an import by name would otherwise mask a genuinely dead one.
    """
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"(?<!:)//[^\n]*", "", src)
    return src


def exports_of(path: Path) -> set[str]:
    src = strip_comments(path.read_text(encoding="utf-8"))
    names = {m.group("name") for m in EXPORT_DECL_RE.finditer(src)}
    for m in EXPORT_LIST_RE.finditer(src):
        for part in m.group("body").split(","):
            part = part.strip()
            if not part:
                continue
            # `a as b` exports b
            names.add(part.split(" as ")[-1].strip())
    return names


def parse_named(clause: str) -> list[tuple[str, str]]:
    """'{ a, b as c }' -> [(imported, local), ...]"""
    out = []
    for part in clause.strip("{} \n").split(","):
        part = part.strip()
        if not part:
            continue
        if " as " in part:
            imported, local = (s.strip() for s in part.split(" as "))
        else:
            imported = local = part
        out.append((imported, local))
    return out


def main() -> int:
    problems: list[str] = []
    files = sorted(JS_DIR.rglob("*.js"))

    for f in files:
        raw = f.read_text(encoding="utf-8")
        body = strip_comments(raw)
        rel = f.relative_to(ROOT).as_posix()

        for m in IMPORT_RE.finditer(raw):
            spec = m.group("path")
            if not spec.startswith("."):
                continue  # bare specifier: not ours to resolve

            target = (f.parent / spec).resolve()
            if not target.exists():
                problems.append(f"{rel}\n    imports {spec!r} -> no such file")
                continue

            named = m.group("named")
            if not named:
                continue

            available = exports_of(target)
            for imported, local in parse_named(named):
                if imported not in available:
                    problems.append(
                        f"{rel}\n    imports {{{imported}}} from {spec!r},"
                        f" which does not export it"
                    )
                    continue

                # Count references outside the import statement itself.
                without_imports = IMPORT_RE.sub("", body)
                if not re.search(rf"\b{re.escape(local)}\b", without_imports):
                    problems.append(f"{rel}\n    imports {{{local}}} but never uses it")

    print(f"checked {len(files)} modules")
    if problems:
        print(f"\n{len(problems)} PROBLEM(S):")
        for p in problems:
            print(f"  {p}")
        return 1

    print("OK - every import resolves and is used")
    return 0


if __name__ == "__main__":
    sys.exit(main())
