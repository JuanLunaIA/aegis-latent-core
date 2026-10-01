# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Hash every existing data-room file so an investor can check what they were shown.

    python tools/raise/data_room_manifest.py [--out FILE] [--ref REF]

Reads ``tools/sales/data_room.json`` (the Phase 1 source of truth), checks each listed path
in the git tree at ``--ref`` (default ``HEAD``), and prints a table of path, size and SHA-256.
Rows marked ``missing-human`` are listed as missing, never filled. Exit 2 if a path that the
index calls "exists" is not in the tree. The manifest is produced on demand for a given
commit and is not committed, because it would go stale with the next commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "tools" / "sales" / "data_room.json"


def _blob(ref: str, path: str) -> bytes | None:
    done = subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed git argv, shell=False
        ["git", "show", f"{ref}:{path}"], cwd=ROOT, capture_output=True, check=False
    )
    return done.stdout if done.returncode == 0 else None


def build(ref: str) -> tuple[list[str], list[str]]:
    rows = json.loads(INDEX.read_text(encoding="utf-8"))["rows"]
    lines, errors = ["| Document | Path | Bytes | SHA-256 |", "|---|---|---|---|"], []
    for row in rows:
        if row["status"] != "exists":
            lines.append(f"| {row['doc']} | MISSING-HUMAN ({row.get('reg', 'n/a')}) | | |")
            continue
        for path in row["paths"]:
            data = _blob(ref, path)
            if data is None:
                errors.append(path)
                lines.append(f"| {row['doc']} | {path} | NOT IN TREE | |")
            else:
                lines.append(
                    f"| {row['doc']} | {path} | {len(data)} | {hashlib.sha256(data).hexdigest()} |"
                )
    return lines, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    lines, errors = build(args.ref)
    commit = subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed git argv, shell=False
        ["git", "rev-parse", args.ref], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    text = f"Data-room manifest at commit `{commit}`\n\n" + "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        print(text)
    if errors:
        print("missing from tree: " + ", ".join(errors), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
