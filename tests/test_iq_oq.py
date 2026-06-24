# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for GxP IQ/OQ qualification scripts — Domain 2.3."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile

import pytest

from tools.qualification.iq_checks import IQCheck, IQProtocol, IQReport
from tools.qualification.oq_checks import OQCheck, OQProtocol, OQReport


# ── IQ: report structure ──────────────────────────────────────────────────────


def test_iq_run_all_returns_report():
    report = IQProtocol().run_all()
    assert isinstance(report, IQReport)


def test_iq_report_passed_is_bool():
    report = IQProtocol().run_all()
    assert isinstance(report.passed, bool)


def test_iq_report_has_report_id():
    report = IQProtocol().run_all()
    assert report.report_id
    assert report.report_id.startswith("IQ-")


def test_iq_report_has_generated_at():
    report = IQProtocol().run_all()
    # Should be ISO 8601
    assert "T" in report.generated_at
    assert report.generated_at.endswith("+00:00") or report.generated_at.endswith("Z")


def test_iq_report_has_checks():
    report = IQProtocol().run_all()
    assert len(report.checks) > 0
    for chk in report.checks:
        assert isinstance(chk, IQCheck)


def test_iq_all_check_ids_follow_pattern():
    report = IQProtocol().run_all()
    pattern = re.compile(r"^IQ-\d{3}$")
    for chk in report.checks:
        assert pattern.match(chk.check_id), f"Bad check_id: {chk.check_id!r}"


def test_iq_check_ids_unique():
    report = IQProtocol().run_all()
    ids = [c.check_id for c in report.checks]
    assert len(ids) == len(set(ids)), "Duplicate check IDs found"


def test_iq_to_json_is_valid_json():
    report = IQProtocol().run_all()
    j = report.to_json()
    data = json.loads(j)  # raises if invalid
    assert "report_id" in data
    assert "checks" in data
    assert "passed" in data


def test_iq_to_json_contains_all_checks():
    report = IQProtocol().run_all()
    data = json.loads(report.to_json())
    assert len(data["checks"]) == len(report.checks)


def test_iq_to_text_contains_check_ids():
    report = IQProtocol().run_all()
    text = report.to_text()
    for chk in report.checks:
        assert chk.check_id in text, f"{chk.check_id} missing from to_text() output"


def test_iq_to_text_contains_pass_or_fail():
    report = IQProtocol().run_all()
    text = report.to_text()
    assert "PASS" in text or "FAIL" in text


def test_iq_summary_is_one_line():
    report = IQProtocol().run_all()
    summary = report.summary()
    assert "\n" not in summary


def test_iq_summary_contains_counts():
    report = IQProtocol().run_all()
    summary = report.summary()
    # Should contain something like "7/8"
    assert "/" in summary


# ── IQ-001: Python version ────────────────────────────────────────────────────


def test_iq_python_version_check_id():
    chk = IQProtocol().check_python_version()
    assert chk.check_id == "IQ-001"


def test_iq_python_version_passes_on_311():
    chk = IQProtocol().check_python_version()
    # The test environment must be >= 3.11
    if sys.version_info >= (3, 11):
        assert chk.passed


def test_iq_python_version_category():
    chk = IQProtocol().check_python_version()
    assert chk.category == "python_version"


# ── IQ-002: Package installed ─────────────────────────────────────────────────


def test_iq_package_installed_check_id():
    chk = IQProtocol().check_package_installed()
    assert chk.check_id == "IQ-002"


def test_iq_package_installed_passes():
    # aegis is installed in the test environment
    chk = IQProtocol().check_package_installed()
    assert chk.passed, f"aegis not importable: {chk.evidence}"


# ── IQ-004: Signing key ───────────────────────────────────────────────────────


def test_iq_signing_key_configured_check_id():
    chk = IQProtocol().check_signing_key_configured()
    assert chk.check_id == "IQ-004"


def test_iq_signing_key_passes_with_valid_key(monkeypatch):
    valid_hex_key = "ab" * 32  # 64 hex chars = 32 bytes
    monkeypatch.setenv("AEGIS_SIGNING_KEY", valid_hex_key)
    chk = IQProtocol().check_signing_key_configured()
    assert chk.passed


def test_iq_signing_key_fails_without_key(monkeypatch):
    monkeypatch.delenv("AEGIS_SIGNING_KEY", raising=False)
    chk = IQProtocol().check_signing_key_configured()
    assert not chk.passed


def test_iq_signing_key_fails_with_short_key(monkeypatch):
    monkeypatch.setenv("AEGIS_SIGNING_KEY", "ab" * 15)  # only 30 hex chars
    chk = IQProtocol().check_signing_key_configured()
    assert not chk.passed


def test_iq_signing_key_evidence_never_contains_key(monkeypatch):
    secret = "deadbeef" * 8  # 64 hex chars
    monkeypatch.setenv("AEGIS_SIGNING_KEY", secret)
    chk = IQProtocol().check_signing_key_configured()
    # The actual secret value must not appear in evidence
    assert secret not in chk.evidence


# ── IQ-006: Key separation ────────────────────────────────────────────────────


def test_iq_api_keys_separate_check_id():
    chk = IQProtocol().check_api_keys_separate_from_signing()
    assert chk.check_id == "IQ-006"


def test_iq_api_keys_separate_fails_when_same(monkeypatch):
    same = "ff" * 32
    monkeypatch.setenv("AEGIS_API_KEYS", same)
    monkeypatch.setenv("AEGIS_SIGNING_KEY", same)
    chk = IQProtocol().check_api_keys_separate_from_signing()
    assert not chk.passed


def test_iq_api_keys_separate_passes_when_different(monkeypatch):
    monkeypatch.setenv("AEGIS_API_KEYS", "aaa" + "b" * 61)
    monkeypatch.setenv("AEGIS_SIGNING_KEY", "bb" * 32)
    chk = IQProtocol().check_api_keys_separate_from_signing()
    assert chk.passed


def test_iq_api_keys_separate_passes_when_one_absent(monkeypatch):
    monkeypatch.delenv("AEGIS_API_KEYS", raising=False)
    monkeypatch.delenv("AEGIS_SIGNING_KEY", raising=False)
    chk = IQProtocol().check_api_keys_separate_from_signing()
    assert chk.passed


# ── OQ: report structure ──────────────────────────────────────────────────────


def test_oq_run_all_returns_report():
    report = OQProtocol().run_all()
    assert isinstance(report, OQReport)


def test_oq_report_passed_is_bool():
    report = OQProtocol().run_all()
    assert isinstance(report.passed, bool)


def test_oq_report_has_checks():
    report = OQProtocol().run_all()
    assert len(report.checks) > 0
    for chk in report.checks:
        assert isinstance(chk, OQCheck)


def test_oq_to_json_is_valid_json():
    report = OQProtocol().run_all()
    j = report.to_json()
    data = json.loads(j)
    assert "report_id" in data
    assert "checks" in data


def test_oq_to_text_contains_check_ids():
    report = OQProtocol().run_all()
    text = report.to_text()
    for chk in report.checks:
        assert chk.check_id in text


# ── OQ-001: WAF injection blocking ───────────────────────────────────────────


def test_oq_waf_blocks_injection():
    chk = OQProtocol().check_waf_blocks_injection()
    assert chk.check_id == "OQ-001"
    assert chk.passed, f"WAF injection check failed: {chk.evidence}"


# ── OQ-002: Audit chain integrity ────────────────────────────────────────────


def test_oq_audit_chain_integrity():
    chk = OQProtocol().check_audit_chain_integrity()
    assert chk.check_id == "OQ-002"
    assert chk.passed, f"Audit chain integrity check failed: {chk.evidence}"


def test_oq_audit_chain_duration_is_positive():
    chk = OQProtocol().check_audit_chain_integrity()
    assert chk.duration_ms >= 0.0


# ── OQ-006: WAL permissions ───────────────────────────────────────────────────


def test_oq_wal_permissions():
    chk = OQProtocol().check_wal_permissions()
    assert chk.check_id == "OQ-006"
    assert chk.passed, f"WAL permissions check failed: {chk.evidence}"
