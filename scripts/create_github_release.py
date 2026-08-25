#!/usr/bin/env python3
"""Create one GitHub Release through the create-only gh CLI surface."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 - fixed gh executable, argv-only invocation, no shell
import sys
from collections.abc import Sequence
from pathlib import Path

STABLE_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
ASSET_SUFFIXES = (".whl", ".tar.gz", ".sha256")


def _release_assets(directory: Path) -> tuple[Path, ...]:
    """Return a closed, sorted set of regular release assets."""

    directory = directory.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError(f"asset directory is not a directory: {directory}")
    assets = tuple(
        sorted(
            path
            for path in directory.iterdir()
            if path.is_file() and not path.is_symlink() and path.name.endswith(ASSET_SUFFIXES)
        )
    )
    payloads = tuple(path for path in assets if not path.name.endswith(".sha256"))
    if not payloads:
        raise ValueError("asset directory contains no wheel or source archive")
    asset_names = {path.name for path in assets}
    missing_hashes = [path.name for path in payloads if f"{path.name}.sha256" not in asset_names]
    if missing_hashes:
        raise ValueError(f"release assets are missing SHA-256 sidecars: {missing_hashes}")
    return assets


def build_create_command(
    *, tag: str, version: str, notes_file: Path, asset_directory: Path
) -> tuple[str, ...]:
    """Build the only permitted GitHub Release command."""

    if STABLE_VERSION.fullmatch(version) is None or tag != f"v{version}":
        raise ValueError("tag must exactly equal v<stable-version>")
    notes_file = notes_file.resolve(strict=True)
    if (
        not notes_file.is_file()
        or notes_file.is_symlink()
        or not notes_file.read_text(encoding="utf-8").strip()
    ):
        raise ValueError("release notes must be a non-empty regular UTF-8 file")
    assets = _release_assets(asset_directory)
    return (
        "gh",
        "release",
        "create",
        tag,
        *(str(path) for path in assets),
        "--verify-tag",
        "--title",
        f"Aegis Latent Core {tag}",
        "--notes-file",
        str(notes_file),
    )


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--notes-file", required=True, type=Path)
    parser.add_argument("--asset-directory", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        command = build_create_command(
            tag=args.tag,
            version=args.version,
            notes_file=args.notes_file,
            asset_directory=args.asset_directory,
        )
        completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed gh argv, no shell
            command,
            check=False,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"release creation refused: {exc}", file=sys.stderr)
        return 2
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
