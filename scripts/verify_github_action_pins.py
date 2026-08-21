#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Fail when a remote GitHub Action is not pinned to a full commit SHA."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USES_RE = re.compile(r"\buses:\s*(?P<target>[^\s#]+)")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    failures: list[str] = []
    remote_count = 0
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_RE.search(line)
            if match is None:
                continue
            target = match.group("target")
            if target.startswith("./"):
                continue
            remote_count += 1
            _repository, separator, revision = target.rpartition("@")
            if not separator or SHA_RE.fullmatch(revision) is None:
                failures.append(f"{path.relative_to(ROOT)}:{line_number}: {target}")

    if failures:
        print("Remote GitHub Actions without a full 40-character SHA:")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(f"github_action_sha_pins=PASS remote_references={remote_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
