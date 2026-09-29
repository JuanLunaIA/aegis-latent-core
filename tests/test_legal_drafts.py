# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The legal drafts must never read as offers, reviewed documents or signed ones.

The files under ``docs/legal/`` are prepared for counsel by an agent. Each one
must say so on its face, and no signature block may carry a name or a date.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

LEGAL = Path(__file__).resolve().parents[1] / "docs" / "legal"
DRAFTS = sorted(LEGAL.glob("*.md"))


def test_the_legal_stack_is_present():
    assert {p.name for p in DRAFTS} >= {
        "README.md",
        "COMMERCIAL_LICENSE_TEMPLATE.md",
        "PILOT_AGREEMENT_TEMPLATE.md",
        "ESCROW_TERM_SHEET.md",
        "IP_ASSIGNMENT_DRAFT.md",
        "OPEN_CORE_DECISION_MEMO.md",
        "COUNSEL_QUESTIONS.md",
    }


@pytest.mark.parametrize("path", DRAFTS, ids=lambda p: p.name)
def test_every_draft_carries_the_counsel_review_banner(path: Path):
    text = path.read_text(encoding="utf-8")
    assert "[COUNSEL-REVIEW-REQUIRED]" in text
    assert "not legal advice" in text.lower()


@pytest.mark.parametrize("path", DRAFTS, ids=lambda p: p.name)
def test_no_signature_row_is_filled_in(path: Path):
    """A signature row holds a bracketed placeholder, never a name or a date."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"\| (Licensor|Licensee|Vendor|Customer|Assignor|Assignee) \|", line):
            assert "`[" in line, f"{path.name}: signature row is not a placeholder: {line}"
