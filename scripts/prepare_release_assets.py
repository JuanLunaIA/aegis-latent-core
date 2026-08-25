#!/usr/bin/env python3
"""Flatten downloaded release artifacts and generate SHA-256 sidecars."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

PAYLOAD_SUFFIXES = (".whl", ".tar.gz")


def prepare_release_assets(source: Path, destination: Path) -> tuple[Path, ...]:
    """Copy uniquely named payloads and write deterministic digest sidecars."""

    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"artifact input is not a directory: {source}")
    destination = destination.resolve()
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise ValueError(f"artifact output must be absent or empty: {destination}")
    candidates = tuple(
        sorted(
            path
            for path in source.rglob("*")
            if path.is_file() and not path.is_symlink() and path.name.endswith(PAYLOAD_SUFFIXES)
        )
    )
    if not candidates:
        raise ValueError("no wheel or source archive was downloaded")
    names = [path.name for path in candidates]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"duplicate release asset names: {duplicates}")
    destination.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for source_path in candidates:
        output = destination / source_path.name
        shutil.copyfile(source_path, output)
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        sidecar = destination / f"{output.name}.sha256"
        sidecar.write_text(f"{digest}  {output.name}\n", encoding="ascii")
        outputs.extend((output, sidecar))
    return tuple(outputs)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        outputs = prepare_release_assets(args.input, args.output)
    except (OSError, ValueError) as exc:
        print(f"release asset preparation refused: {exc}", file=sys.stderr)
        return 2
    for output in outputs:
        print(f"{output.name}\t{output.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
