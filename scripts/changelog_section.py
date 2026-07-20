#!/usr/bin/env python3
"""Extract one release's body from CHANGELOG.md.

The release workflow pipes this into the GitHub Release body, and the dashboard
renders that body as the release notes on the settings page. So the changelog
format is a runtime dependency, not just a docs convention — the contract lives
in .claude/CHANGELOG_GUIDE.md: releases are `## [X.Y.Z]` headings, optionally
followed by ` - YYYY-MM-DD`.

    python scripts/changelog_section.py 0.5.0
    python scripts/changelog_section.py --self-check
"""
import re
import sys
from pathlib import Path

HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\]")


def section(text, version):
    """The body between `## [version]` and the next `## ` heading, or None."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        m = HEADING.match(line)
        if m and m.group("version") == version:
            start = i + 1
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start, len(lines)):
        if lines[j].startswith("## "):
            end = j
            break
    return "\n".join(lines[start:end]).strip()


def self_check():
    sample = """# Changelog

Intro prose that belongs to no release.

## [Unreleased]

## [0.5.0] - 2026-07-21

### Added

- A thing.

## [0.4.2]

### Fixed

- Another thing.
"""
    assert section(sample, "0.5.0") == "### Added\n\n- A thing.", "dated heading"
    assert section(sample, "0.4.2") == "### Fixed\n\n- Another thing.", "undated heading"
    # An empty Unreleased is empty, not absent — the caller distinguishes them.
    assert section(sample, "Unreleased") == "", "empty section"
    assert section(sample, "9.9.9") is None, "missing version"
    # A prefix of a real version must not match it.
    assert section(sample, "0.5") is None, "partial version must not match"
    print("self-check OK")


def main():
    argv = sys.argv[1:]
    if "--self-check" in argv:
        self_check()
        return 0
    if not argv:
        print("usage: changelog_section.py <version> [--file PATH]", file=sys.stderr)
        return 2

    version = argv[0].lstrip("v")
    path = Path(argv[argv.index("--file") + 1]) if "--file" in argv else Path("CHANGELOG.md")
    if not path.is_file():
        print(f"no changelog at {path}", file=sys.stderr)
        return 1

    body = section(path.read_text(encoding="utf-8"), version)
    if body is None:
        # Exit non-zero so a release never ships with a silently empty body: an
        # absent section means the changelog was not updated for this tag.
        print(f"no changelog section for {version}", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
