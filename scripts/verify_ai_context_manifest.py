#!/usr/bin/env python3
"""Verify the deterministic manifest for the advisory AI context pack."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from types import ModuleType


def _load_generator(root: Path) -> ModuleType:
    path = root / "scripts/generate_ai_context_manifest.py"
    spec = importlib.util.spec_from_file_location("aegis_ai_context_manifest_generator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load manifest generator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    generator = _load_generator(root)
    manifest_path = root / generator.MANIFEST_PATH
    try:
        actual = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = generator.build_manifest(root)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"AI context manifest verification failed: {exc}")
        return 1

    errors: list[str] = []
    if actual != expected:
        errors.append("manifest content differs from deterministic governed-file hashes")
    if actual.get("manifest_self_hash") != "excluded_to_avoid_circularity":
        errors.append("manifest must explicitly exclude its own hash")
    paths = [entry.get("path") for entry in actual.get("files", [])]
    if generator.MANIFEST_PATH in paths:
        errors.append("manifest must not hash itself")
    if len(paths) != len(set(paths)):
        errors.append("manifest paths must be unique")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(
        f"AI context manifest verified: {len(paths)} files; source anchor {generator.SOURCE_ANCHOR}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
