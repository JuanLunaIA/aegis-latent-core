# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""The public-claim scanner must fail on the claims that cost a launch."""

from __future__ import annotations

from tools.truth.scan_public_claims import scan_text


def test_flags_open_source_for_current_product() -> None:
    hits = scan_text("Aegis is open source under the AGPLv3.")
    assert any(h.code == "OPEN_SOURCE_CURRENT" for h in hits)


def test_allows_historical_license_sentence() -> None:
    hits = scan_text("Release 5.0.2 remains Apache-2.0; earlier releases keep their terms.")
    assert not any(h.code == "OPEN_SOURCE_CURRENT" for h in hits)


def test_flags_stale_published_version() -> None:
    hits = scan_text("The current release is 5.0.1.")
    assert any(h.code == "STALE_CURRENT_VERSION" for h in hits)


def test_flags_a_certification_that_is_not_held() -> None:
    hits = scan_text("Aegis is SOC 2 Type II certified.")
    assert any(h.code == "CERTIFICATION_CLAIM" for h in hits)


def test_allows_a_negated_certification() -> None:
    hits = scan_text("There is no SOC 2 report and no ISO 27001 certificate.")
    assert not any(h.code == "CERTIFICATION_CLAIM" for h in hits)


def test_flags_an_unbacked_sla() -> None:
    hits = scan_text("Enterprise includes 99.99% SLA and 24/7 staffed support.")
    assert any(h.code == "UNBACKED_FEATURE" for h in hits)


def test_allows_a_no_sla_sentence() -> None:
    hits = scan_text("Email support, no SLA; there is no 24/7 staffed support.")
    assert not any(h.code == "UNBACKED_FEATURE" for h in hits)
