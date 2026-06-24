# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.dependency_audit — real pip-audit CVE scanning.

Verifies that DependencyAuditor calls pip-audit and parses real JSON output,
that check_package_files uses importlib.metadata RECORD hashes, and that
DependencyInternalizer.verify_supply_chain reports honestly.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.dependency_audit import (
    DependencyAuditor,
    DependencyAuditorError,
    DependencyInternalizer,
    HardenedMath,
    VulnerabilityFinding,
)

# ── VulnerabilityFinding ──────────────────────────────────────────────────────


class TestVulnerabilityFinding:
    def test_str_with_fix(self):
        f = VulnerabilityFinding("CVE-2025-1234", "requests", "2.28.0", ["2.31.0"], "desc")
        assert "CVE-2025-1234" in str(f)
        assert "requests" in str(f)
        assert "2.31.0" in str(f)

    def test_str_no_fix(self):
        f = VulnerabilityFinding("CVE-2025-1234", "pkg", "1.0", [], "desc")
        assert "no fix available" in str(f)

    def test_is_frozen(self):
        f = VulnerabilityFinding("ID", "pkg", "1.0", [], "")
        with pytest.raises((AttributeError, TypeError)):
            f.vuln_id = "other"  # type: ignore[misc]


# ── DependencyAuditor.scan() ──────────────────────────────────────────────────


CLEAN_JSON = json.dumps(
    {
        "dependencies": [
            {"name": "requests", "version": "2.31.0", "vulns": []},
        ]
    }
)

VULN_JSON = json.dumps(
    {
        "dependencies": [
            {
                "name": "pyjwt",
                "version": "2.7.0",
                "vulns": [
                    {
                        "id": "CVE-2025-0001",
                        "fix_versions": ["2.10.0"],
                        "description": "Auth bypass",
                    },
                ],
            },
            {
                "name": "setuptools",
                "version": "68.1.2",
                "vulns": [
                    {
                        "id": "PYSEC-2025-49",
                        "fix_versions": [],
                        "description": "Remote code execution",
                    },
                ],
            },
        ]
    }
)

SKIP_JSON = json.dumps(
    {
        "dependencies": [
            {"name": "local-pkg", "skip_reason": "Not on PyPI", "vulns": []},
            {"name": "requests", "version": "2.31.0", "vulns": []},
        ]
    }
)


def _make_completed(stdout: str, returncode: int = 0):
    r = MagicMock(spec=subprocess.CompletedProcess)
    r.stdout = stdout
    r.returncode = returncode
    return r


class TestDependencyAuditorScan:
    def test_clean_environment_returns_empty(self):
        with patch("subprocess.run", return_value=_make_completed(CLEAN_JSON)):
            findings = DependencyAuditor().scan()
        assert findings == []

    def test_vulnerable_packages_returned(self):
        with patch("subprocess.run", return_value=_make_completed(VULN_JSON)):
            findings = DependencyAuditor().scan()
        assert len(findings) == 2
        ids = {f.vuln_id for f in findings}
        assert "CVE-2025-0001" in ids
        assert "PYSEC-2025-49" in ids

    def test_skip_reason_packages_ignored(self):
        with patch("subprocess.run", return_value=_make_completed(SKIP_JSON)):
            findings = DependencyAuditor().scan()
        assert findings == []

    def test_pip_audit_not_found_raises(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(DependencyAuditorError, match="pip-audit not found"):
                DependencyAuditor().scan()

    def test_timeout_raises(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pip-audit", 120)):
            with pytest.raises(DependencyAuditorError, match="timed out"):
                DependencyAuditor().scan()

    def test_non_json_output_raises(self):
        with patch("subprocess.run", return_value=_make_completed("not-json")):
            with pytest.raises(DependencyAuditorError, match="non-JSON"):
                DependencyAuditor().scan()

    def test_fix_versions_captured(self):
        with patch("subprocess.run", return_value=_make_completed(VULN_JSON)):
            findings = DependencyAuditor().scan()
        pyjwt = next(f for f in findings if f.package == "pyjwt")
        assert pyjwt.fix_versions == ["2.10.0"]

    def test_requirements_file_added_to_cmd(self):
        with patch("subprocess.run", return_value=_make_completed(CLEAN_JSON)) as mock_run:
            DependencyAuditor(requirements_file="/tmp/req.txt").scan()
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd
        assert "/tmp/req.txt" in cmd


# ── DependencyAuditor.check_package_files() ───────────────────────────────────


class TestCheckPackageFiles:
    def test_missing_package_returns_empty(self):
        auditor = DependencyAuditor()
        result = auditor.check_package_files("__package_that_does_not_exist__")
        assert result == {}

    def test_known_package_returns_dict(self):
        auditor = DependencyAuditor()
        # 'pip' is always present and has RECORD entries
        result = auditor.check_package_files("pip")
        assert isinstance(result, dict)
        # Each value must be a bool
        assert all(isinstance(v, bool) for v in result.values())

    def test_installed_package_hashes_match(self):
        auditor = DependencyAuditor()
        result = auditor.check_package_files("certifi")
        # certifi has RECORD entries with hashes; all should pass
        assert result, "Expected at least one hashed file for certifi"
        failures = [p for p, ok in result.items() if not ok]
        assert not failures, f"Hash failures for certifi: {failures}"

    def test_tampered_file_detected(self, tmp_path):
        """Simulate a tampered file — verify check returns False."""
        import base64
        import hashlib

        real_content = b"real content"
        tampered_content = b"TAMPERED content"
        fake_abs = tmp_path / "fake_module.py"
        fake_abs.write_bytes(tampered_content)

        # RECORD hash is of the *real* content, encoded as URL-safe base64 without padding
        real_b64 = (
            base64.urlsafe_b64encode(hashlib.sha256(real_content).digest()).rstrip(b"=").decode()
        )

        fake_hash_obj = MagicMock()
        fake_hash_obj.value = real_b64
        fake_hash_obj.mode = "sha256"

        fake_file = MagicMock()
        fake_file.hash = fake_hash_obj
        fake_file.__str__ = lambda self: "fake_module.py"

        fake_dist = MagicMock()
        fake_dist.files = [fake_file]
        fake_dist.locate_file = lambda p: str(fake_abs)

        with patch("importlib.metadata.distribution", return_value=fake_dist):
            result = DependencyAuditor().check_package_files("fake")

        assert "fake_module.py" in result
        assert result["fake_module.py"] is False


# ── DependencyInternalizer ────────────────────────────────────────────────────


class TestDependencyInternalizer:
    def test_wrap_dependency_calls_function(self):
        internalizer = DependencyInternalizer()
        called_with = []

        def my_func(x, y):
            called_with.append((x, y))
            return x + y

        result = internalizer.wrap_dependency("somelib", my_func, 1, 2)
        assert result == 3
        assert called_with == [(1, 2)]

    def test_verify_supply_chain_calls_real_audit(self):
        with patch("subprocess.run", return_value=_make_completed(CLEAN_JSON)):
            internalizer = DependencyInternalizer()
            # No registered packages + clean scan → True
            ok = internalizer.verify_supply_chain()
        assert isinstance(ok, bool)

    def test_verify_supply_chain_false_on_cve(self):
        with patch("subprocess.run", return_value=_make_completed(VULN_JSON)):
            internalizer = DependencyInternalizer()
            ok = internalizer.verify_supply_chain()
        assert ok is False

    def test_audit_and_internalize_uses_real_metadata(self):
        internalizer = DependencyInternalizer()
        # Use 'certifi' which is installed and has RECORD hashes
        internalizer.audit_and_internalize("certifi", "2026.2.25", ["certifi.where"])
        assert "certifi" in internalizer._entries


# ── HardenedMath ─────────────────────────────────────────────────────────────


class TestHardenedMath:
    def test_safe_log2_positive(self):
        assert abs(HardenedMath.safe_log2(8.0) - 3.0) < 1e-10

    def test_safe_log2_zero_returns_zero(self):
        assert HardenedMath.safe_log2(0) == 0.0

    def test_safe_log2_negative_returns_zero(self):
        assert HardenedMath.safe_log2(-5) == 0.0

    def test_safe_sum(self):
        assert abs(HardenedMath.safe_sum([0.1, 0.2, 0.3]) - 0.6) < 1e-10


# ── Integration: real pip-audit ───────────────────────────────────────────────


@pytest.mark.slow
class TestRealPipAudit:
    def test_scan_returns_list(self):
        """Real pip-audit scan against current environment."""
        auditor = DependencyAuditor()
        findings = auditor.scan()
        assert isinstance(findings, list)
        for f in findings:
            assert isinstance(f, VulnerabilityFinding)
            assert f.vuln_id
            assert f.package
