# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Locator shim for claim CLM-122, which describes the published 5.0.2 tree.

The Apache-2.0 metadata tests that lived here were replaced by
``tests/test_license_policy.py`` when v5.0.3 moved the tree to the commercial
licence.  ``CLM-122`` still cites this path because it records the terms of the
*5.0.2* release, which cannot be revoked; the documentation verifier resolves
locators by path, so this module keeps that citation honest without asserting
anything about the current tree.  The current-tree assertions live in the policy
test and in ``scripts/apply_license_headers.py --check``.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_the_published_5_0_2_terms_are_recorded() -> None:
    transition = (ROOT / "docs/legal/LICENSE_TRANSITION_5.0.2.md").read_text(encoding="utf-8")
    assert "Apache License, Version 2.0" in transition
    assert "5.0.2" in transition


def test_the_current_licence_is_not_apache() -> None:
    licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "AEGIS COMMERCIAL LICENSE 1.0" in licence
    assert "Licensed under the Apache License" not in licence
