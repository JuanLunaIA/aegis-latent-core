#!/usr/bin/env python3
"""Create one GitHub Release through a create-only, integrity-checked gh CLI surface."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess  # nosec B404 - fixed gh executable, argv-only invocation, no shell
import sys
from collections.abc import Sequence
from pathlib import Path

try:
    from scripts.prepare_release_assets import CHECKSUMS_NAME, MANIFEST_NAME, PAYLOAD_SUFFIXES
except ModuleNotFoundError:
    from prepare_release_assets import CHECKSUMS_NAME, MANIFEST_NAME, PAYLOAD_SUFFIXES

STABLE_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_sidecar(path: Path, expected_name: str) -> str:
    parts = path.read_text(encoding="ascii").strip().split("  ", maxsplit=1)
    if len(parts) != 2 or not SHA256.fullmatch(parts[0]) or parts[1] != expected_name:
        raise ValueError(f"malformed SHA-256 sidecar: {path.name}")
    return parts[0]


def _release_assets(directory: Path) -> tuple[Path, ...]:
    """Return a closed, verified set of release assets."""

    directory = directory.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError(f"asset directory is not a directory: {directory}")
    files = tuple(
        sorted(path for path in directory.iterdir() if path.is_file() and not path.is_symlink())
    )
    payloads = tuple(path for path in files if path.name.endswith(PAYLOAD_SUFFIXES))
    if not payloads:
        raise ValueError("asset directory contains no release payload")

    expected_names = {CHECKSUMS_NAME, MANIFEST_NAME, f"{MANIFEST_NAME}.sha256"}
    expected_names.update(path.name for path in payloads)
    expected_names.update(f"{path.name}.sha256" for path in payloads)
    actual_names = {path.name for path in files}
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        unexpected = sorted(actual_names - expected_names)
        raise ValueError(f"release asset set mismatch; missing={missing}, unexpected={unexpected}")

    expected_manifest_assets: list[dict[str, object]] = []
    checksum_lines: list[str] = []
    for payload in payloads:
        digest = _sha256(payload)
        sidecar_digest = _parse_sidecar(directory / f"{payload.name}.sha256", payload.name)
        if sidecar_digest != digest:
            raise ValueError(f"SHA-256 sidecar mismatch: {payload.name}")
        expected_manifest_assets.append(
            {"bytes": payload.stat().st_size, "name": payload.name, "sha256": digest}
        )
        checksum_lines.append(f"{digest}  {payload.name}")

    manifest = directory / MANIFEST_NAME
    try:
        manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"invalid release manifest: {exc}") from exc
    expected_manifest = {
        "assets": expected_manifest_assets,
        "schema": "aegis-release-assets-v1",
    }
    if manifest_data != expected_manifest:
        raise ValueError("release manifest does not match payload bytes")

    manifest_digest = _sha256(manifest)
    manifest_sidecar_digest = _parse_sidecar(directory / f"{MANIFEST_NAME}.sha256", MANIFEST_NAME)
    if manifest_sidecar_digest != manifest_digest:
        raise ValueError("release manifest SHA-256 sidecar mismatch")
    checksum_lines.append(f"{manifest_digest}  {MANIFEST_NAME}")
    expected_checksums = "\n".join(sorted(checksum_lines)) + "\n"
    if (directory / CHECKSUMS_NAME).read_text(encoding="ascii") != expected_checksums:
        raise ValueError("SHA256SUMS does not match release payloads and manifest")

    return files


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


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
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
