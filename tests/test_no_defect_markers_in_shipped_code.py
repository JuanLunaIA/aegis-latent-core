# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Shipped code carries no unresolved defect markers (MISSION ORDER final rule).

`SECURITY_AUDIT_REPORT.md` claimed "many `FIXME` and `TODO` markers present
across the codebase — technical debt hotspots" and told the reader to target the
markers "listed in `TODO_ISSUES.md`". Measured on 2026-09-21: no marker remains
in any shipped directory, and `TODO_ISSUES.md` is not in the tree. Both
statements were corrected in the report; this gate is what keeps the correction
true.

Scope is deliberate. The gate walks shipped code only — the directories whose
contents are deployed or published. It does not walk `scripts/` or `tools/`,
where the words legitimately appear in detector patterns
(`scripts/verify_docs.py`'s `PLACEHOLDER_RE`, `scripts/audit_documentation_corpus.py`)
and in comments explaining those detectors, nor `tests/`, where fixtures must be
able to spell the markers to test the detectors.

Open work belongs in the registers, not in a comment: a marker found here is
either fixed or moved to `docs/ROADMAP.md` as an `AUD-*` row with a reason.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Directories whose contents ship. A marker in any of these is a defect.
SHIPPED_DIRECTORIES = (
    "aegis",
    "aegis_server",
    "aegis_rust_v2/src",
    "sdk/python/src",
    "sdk/typescript/src",
    "dashboard/src",
    "config",
    "deploy",
)

MARKER = re.compile(r"(?<![\w-])(TODO|FIXME|HACK)(?![\w-])")

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".lock"}


def _shipped_files() -> list[Path]:
    files: list[Path] = []
    for relative in SHIPPED_DIRECTORIES:
        root = REPO_ROOT / relative
        if not root.is_dir():
            continue
        files.extend(
            path
            for path in sorted(root.rglob("*"))
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in SKIP_SUFFIXES
        )
    return files


def _markers_in(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    return [
        f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()[:120]}"
        for number, line in enumerate(text.splitlines(), start=1)
        if MARKER.search(line)
    ]


def test_shipped_code_has_no_defect_markers() -> None:
    """Any hit is either resolved or registered — never left as a comment."""
    offenders: list[str] = []
    for path in _shipped_files():
        offenders.extend(_markers_in(path))
    assert not offenders, (
        "unresolved defect markers in shipped code — resolve them, or move them to "
        "docs/ROADMAP.md as an AUD-* row with a reason:\n" + "\n".join(offenders)
    )


def test_the_scan_actually_walks_a_non_empty_shipped_set() -> None:
    """A silently-empty walk would make the gate above vacuous."""
    files = _shipped_files()
    assert len(files) > 100, f"only {len(files)} shipped files were walked"
    names = {path.name for path in files}
    assert "app.py" in names, sorted(names)[:20]
    assert "wal.rs" in names, sorted(names)[:20]


def test_the_marker_detector_fires() -> None:
    """Negative control: the detector must find a marker when one is present."""
    assert MARKER.search("x = 1  # TODO: rotate this")
    assert MARKER.search("// FIXME(bounds) delimit before hashing")
    assert MARKER.search("HACK: temporary")
    # ...and must not fire on the words as parts of identifiers or prose.
    assert not MARKER.search("TODOLIST = []")
    assert not MARKER.search("aegis_fixme_counter")
    assert not MARKER.search("FIXMEs are tracked in the register")
