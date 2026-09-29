# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""A short run of the kill-and-recover harness: no acknowledged commit may be lost."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_killed_committer_loses_no_acknowledged_commit(tmp_path: Path):
    report = tmp_path / "report.json"
    result = subprocess.run(  # noqa: S603  # nosec B603 - this interpreter and a fixed script, shell=False
        [
            sys.executable, str(ROOT / "tools/qualification/wal_crash_soak.py"),
            "--rounds", "3", "--wal", str(tmp_path / "wal.jsonl"), "--json", str(report),
        ],
        capture_output=True, text=True, cwd=ROOT, timeout=180,
    )  # fmt: skip
    assert result.returncode == 0, result.stdout[-1500:]
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["rounds"] == 3
    assert data["acknowledged_lost"] == 0
    assert data["all_rounds_valid"] is True
