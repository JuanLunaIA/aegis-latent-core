#!/usr/bin/env python3
"""Extract one exact, non-empty stable-version section from CHANGELOG.md."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

STABLE_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
SECTION = re.compile(r"(?ms)^## \[(?P<version>[^]]+)\][^\n]*\n(?P<body>.*?)(?=^## |\Z)")


def extract_release_notes(changelog: str, version: str) -> str:
    """Return the unique non-empty section for an exact stable version."""

    if STABLE_VERSION.fullmatch(version) is None:
        raise ValueError(f"invalid stable release version: {version!r}")
    matches = [
        match.group("body").strip()
        for match in SECTION.finditer(changelog)
        if match.group("version") == version
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one CHANGELOG section for {version}, found {len(matches)}"
        )
    if not matches[0]:
        raise ValueError(f"CHANGELOG section for {version} is empty")
    return matches[0] + "\n"


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changelog", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        notes = extract_release_notes(args.changelog.read_text(encoding="utf-8"), args.version)
        args.output.write_text(notes, encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"release notes extraction refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
