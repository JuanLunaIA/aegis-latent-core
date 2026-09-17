#!/usr/bin/env python3
"""Truncate a torn trailing line from a JSONL evidence WAL, under explicit consent.

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

**Why this exists.** A process killed between `write()` and the newline leaves a
partial last line. Replay reaches it, cannot parse it, sets `wal_corrupt`, and
every governed endpoint then refuses with `503` — correctly, because appending
onto a prefix you failed to read back produces records that each verify while
the chain as a whole does not. That refusal is the right default and this tool
does not change it. What was missing is a *supported* way back, which otherwise
becomes an operator editing an evidence file by hand under incident pressure.

**What it will do:** remove the final line of a WAL when that line is the only
one that does not parse.

**What it refuses to do, and these are the whole point:**

* It will not touch a WAL whose first unparseable line is anywhere but the end.
  A bad line in the middle is not a torn tail — it is either real corruption or
  tampering, and truncating to it would silently discard every valid record
  after it. That case is a refusal, not a repair.
* It will not modify anything without `--apply`. The default is a dry run that
  reports what it would do and exits non-zero, so a pipeline cannot repair a
  ledger by accident.
* It will not proceed without writing a byte-for-byte backup first.
* It will not report success unless the truncated file replays cleanly
  afterwards — the repair is verified, not assumed.

**What it does not establish.** That the removed record never happened. A torn
line means a commit was in flight when the process died; whether the governed
response was emitted is not knowable from the WAL alone. The removed bytes are
preserved in the backup precisely so that question stays answerable, and
`--apply` prints the removed line's digest so the removal itself is auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path


def _parses(raw: str) -> bool:
    """Whether one WAL line is a readable record.

    Deliberately weaker than full replay: this decides *torn or not torn*, and
    a line that is valid JSON with the wrong shape is not a torn write. Letting
    the shape check live in the ledger keeps one definition of a valid node.
    """
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return isinstance(value, dict)


def scan(wal_path: Path) -> tuple[list[str], int | None]:
    """Return ``(lines, index_of_first_unparseable)``.

    The index is into ``lines``; ``None`` means every non-blank line parses.
    """
    if not wal_path.is_file():
        raise SystemExit(f"error: no WAL at {wal_path}")
    lines = wal_path.read_text(encoding="utf-8", errors="surrogateescape").splitlines(keepends=True)
    for index, raw in enumerate(lines):
        if raw.strip() and not _parses(raw):
            return lines, index
    return lines, None


def _last_content_index(lines: list[str]) -> int | None:
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip():
            return index
    return None


def repair(wal_path: Path, *, apply: bool, backup: Path | None = None) -> int:
    """Return a process exit code. ``0`` only when nothing is wrong or a repair succeeded."""
    lines, bad = scan(wal_path)

    if bad is None:
        print(f"{wal_path}: {len(lines)} lines, all parse — nothing to repair")
        return 0

    last = _last_content_index(lines)
    if bad != last:
        print(
            f"{wal_path}: line {bad + 1} does not parse, but it is NOT the last record "
            f"(last content is line {(last or 0) + 1}).",
            file=sys.stderr,
        )
        print(
            "REFUSING. A bad line in the middle is not a torn tail: it is corruption or "
            "tampering, and truncating here would discard every valid record after it. "
            "Investigate before touching this file.",
            file=sys.stderr,
        )
        return 2

    removed = lines[bad]
    digest = hashlib.sha256(removed.encode("utf-8", "surrogateescape")).hexdigest()
    print(f"{wal_path}: line {bad + 1} is a torn trailing record ({len(removed)} bytes)")
    print(f"  sha256 of the line to remove: {digest}")
    print(f"  records retained: {bad}")

    if not apply:
        print("\nDRY RUN — nothing was modified. Re-run with --apply to repair.")
        return 1

    target = backup or wal_path.with_suffix(
        wal_path.suffix + f".bak-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
    )
    shutil.copy2(wal_path, target)
    print(f"  backup written: {target}")

    wal_path.write_text("".join(lines[:bad]), encoding="utf-8", errors="surrogateescape")

    _, still_bad = scan(wal_path)
    if still_bad is not None:
        print(
            f"error: {wal_path} still has an unparseable line at {still_bad + 1} after "
            f"truncation. The original is at {target}; restore it and investigate.",
            file=sys.stderr,
        )
        return 3

    print("  repaired; every remaining line parses")
    print(
        "\nNOTE: this removed a record that was mid-commit. Whether its governed response "
        "reached a caller is not knowable from the WAL alone — the removed bytes are in the "
        "backup so that question stays answerable. Verify the chain with the ledger's own "
        "verify_integrity before resuming traffic."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Remove a torn trailing line from a JSONL evidence WAL. Refuses when the "
            "unparseable line is not the last one. Dry run unless --apply is given."
        )
    )
    parser.add_argument("--wal", type=Path, required=True, help="path to the JSONL WAL")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually truncate; without this the tool only reports and exits non-zero",
    )
    parser.add_argument(
        "--backup", type=Path, help="where to copy the original (default: alongside, timestamped)"
    )
    args = parser.parse_args(argv)
    return repair(args.wal, apply=args.apply, backup=args.backup)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
