"""
tests/test_safe_harbor_detector_count.py — the detector count the corpus quotes.

Four documents state a number of Safe Harbor-associated detector categories in
prose, and `docs/compliance/HIPAA_TECHNICAL_INPUTS.md` goes further and lists the
category labels one by one. Prose drifts from code silently: three other files
had settled on "twenty" while the list held seventeen, and nothing failed.

This pins the number and the labels to `_SAFE_HARBOR_PATTERNS` so that adding or
removing a detector breaks here, next to a message naming every document that has
to move with it. It asserts a count, not a coverage property — seventeen pattern
categories are not the eighteen identifiers of 45 CFR 164.514(b)(2), and
`docs/privacy/PII_REDACTION_BOUNDARIES.md` is the boundary for what this scrubber
does and does not establish.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from aegis.core.phi_deidentifier import _SAFE_HARBOR_PATTERNS

#: The labels `docs/compliance/HIPAA_TECHNICAL_INPUTS.md` enumerates.
DOCUMENTED_CATEGORIES = frozenset(
    {
        "ACCOUNT",
        "ADDRESS",
        "BIOMETRIC",
        "DATE",
        "DEVICE_ID",
        "EMAIL",
        "HEALTH_PLAN_ID",
        "IP_ADDRESS",
        "LICENSE",
        "MRN",
        "NAME",
        "NPI",
        "PHONE",
        "SSN",
        "URL",
        "VIN",
        "ZIP",
    }
)

#: Every document that states the count in prose. Listed here so a failure names
#: them rather than leaving the next reader to grep for a spelled-out number.
DOCUMENTS_STATING_THE_COUNT = (
    "docs/compliance/HIPAA_TECHNICAL_INPUTS.md",
    "docs/corporate/CORPORATE_FAQ.md",
    "docs/privacy/DATA_PROCESSING_CHECKLIST.md",
    "docs/privacy/PII_REDACTION_BOUNDARIES.md",
    "docs/architecture/ARCHITECTURE.md",
    "docs/CLAIMS_MATRIX.md",
)


def test_detector_count_matches_the_documented_seventeen() -> None:
    assert len(_SAFE_HARBOR_PATTERNS) == len(DOCUMENTED_CATEGORIES) == 17, (
        f"_SAFE_HARBOR_PATTERNS holds {len(_SAFE_HARBOR_PATTERNS)} detectors; the corpus "
        f"states seventeen. Update the count in every one of: "
        f"{', '.join(DOCUMENTS_STATING_THE_COUNT)}"
    )


def test_detector_labels_match_the_documented_list() -> None:
    actual = {pattern.label for pattern in _SAFE_HARBOR_PATTERNS}
    assert actual == DOCUMENTED_CATEGORIES, (
        "the detector labels and the list in docs/compliance/HIPAA_TECHNICAL_INPUTS.md "
        f"have diverged; only in code: {sorted(actual - DOCUMENTED_CATEGORIES)}; "
        f"only in docs: {sorted(DOCUMENTED_CATEGORIES - actual)}"
    )
