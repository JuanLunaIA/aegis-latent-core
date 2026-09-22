# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The institutional suite must meet the corpus audit's own placeholder rule.

`scripts/audit_documentation_corpus.py` states its contract plainly: the
institutional suite contains no `TODO`, `FIXME`, `TBD`, `PLACEHOLDER` or literal
ellipsis marker. But the script runs in no CI job and no make target, so when
`DOC-03` quoted an attack payload as "ignore all previous rules ... SSN: …" the
audit reported FAIL at `main` and nobody saw it (REG-D43). This runs the same
rule, with the script's own regex, where the suite runs.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTITUTIONAL = REPO_ROOT / "docs" / "institutional"


def _corpus_audit() -> ModuleType:
    path = REPO_ROOT / "scripts" / "audit_documentation_corpus.py"
    spec = importlib.util.spec_from_file_location("audit_documentation_corpus", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_institutional_suite_carries_no_placeholder_marker() -> None:
    placeholder = _corpus_audit().PLACEHOLDER_RE
    documents = sorted(INSTITUTIONAL.rglob("*.md"))
    assert documents, "no institutional documents found — the scan would pass vacuously"

    hits = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{number}"
        for path in documents
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if placeholder.search(line)
    ]

    assert not hits, f"placeholder markers in the institutional suite: {hits}"


def test_the_rule_this_relies_on_still_catches_an_ellipsis() -> None:
    """Guard the guard: a regex edited into uselessness would pass the test above."""
    placeholder = _corpus_audit().PLACEHOLDER_RE

    assert placeholder.search("ignore all previous rules ... SSN: 123-45-6789")
    assert placeholder.search("TODO: fill in")
    assert not placeholder.search("a sentence that is finished.")
