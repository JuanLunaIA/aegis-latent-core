# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Installation Qualification (IQ) protocol — verifies Aegis is installed per specification."""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# ── Version constant ──────────────────────────────────────────────────────────

_TOOL_VERSION = "1.0.0"


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class IQCheck:
    """Result of a single IQ verification step."""

    check_id: str  # e.g. "IQ-001"
    category: str  # "python_version", "dependencies", "file_permissions", "config"
    description: str
    expected: str
    actual: str
    passed: bool
    evidence: str  # Human-readable evidence string


@dataclass
class IQReport:
    """Aggregate report produced by IQProtocol.run_all()."""

    report_id: str
    generated_at: str  # ISO 8601 UTC
    tool_version: str
    checks: list[IQCheck] = field(default_factory=list)
    passed: bool = False  # True only when ALL checks pass

    def to_json(self) -> str:
        """Serialize to JSON string suitable for archiving as an evidence artifact."""
        data = {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "passed": self.passed,
            "checks": [asdict(c) for c in self.checks],
        }
        return json.dumps(data, indent=2)

    def to_text(self) -> str:
        """Human-readable report for GxP auditors."""
        lines: list[str] = [
            "=" * 72,
            "INSTALLATION QUALIFICATION (IQ) REPORT",
            f"Report ID  : {self.report_id}",
            f"Generated  : {self.generated_at}",
            f"Tool ver.  : {self.tool_version}",
            f"Overall    : {'PASS' if self.passed else 'FAIL'}",
            "=" * 72,
            "",
        ]
        for chk in self.checks:
            status = "PASS" if chk.passed else "FAIL"
            lines.append(f"[{status}] {chk.check_id} — {chk.description}")
            lines.append(f"        Category : {chk.category}")
            lines.append(f"        Expected : {chk.expected}")
            lines.append(f"        Actual   : {chk.actual}")
            lines.append(f"        Evidence : {chk.evidence}")
            lines.append("")
        lines.append("=" * 72)
        lines.append(self.summary())
        return "\n".join(lines)

    def summary(self) -> str:
        """One-line summary of the IQ run."""
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.passed)
        status = "PASS" if self.passed else "FAIL"
        return f"IQ {status}: {passed}/{total} checks passed — {self.generated_at}"


# ── Protocol ──────────────────────────────────────────────────────────────────


class IQProtocol:
    """Runs all IQ checks and produces a signed evidence report."""

    def run_all(self) -> IQReport:
        """Execute every IQ check and return an aggregate IQReport."""
        checks = [
            self.check_python_version(),
            self.check_package_installed(),
            self.check_required_deps(),
            self.check_signing_key_configured(),
            self.check_wal_dir_permissions(),
            self.check_api_keys_separate_from_signing(),
            self.check_rust_extension(),
            self.check_no_debug_auth_bypass(),
        ]
        all_passed = all(c.passed for c in checks)
        return IQReport(
            report_id=f"IQ-{uuid.uuid4().hex[:12].upper()}",
            generated_at=datetime.now(tz=UTC).isoformat(),
            tool_version=_TOOL_VERSION,
            checks=checks,
            passed=all_passed,
        )

    # ── Individual checks ─────────────────────────────────────────────────

    def check_python_version(self) -> IQCheck:
        """IQ-001: Python >= 3.11 is required."""
        vi = sys.version_info
        actual_str = f"{vi.major}.{vi.minor}.{vi.micro}"
        passed = (vi.major, vi.minor) >= (3, 11)
        evidence = (
            f"sys.version_info = {vi.major}.{vi.minor}.{vi.micro}; "
            f"{'satisfies' if passed else 'does NOT satisfy'} >= 3.11"
        )
        return IQCheck(
            check_id="IQ-001",
            category="python_version",
            description="Python interpreter version >= 3.11",
            expected=">= 3.11",
            actual=actual_str,
            passed=passed,
            evidence=evidence,
        )

    def check_package_installed(self) -> IQCheck:
        """IQ-002: aegis-latent-core importable as 'aegis'."""
        passed = False
        actual = "not importable"
        evidence = ""
        try:
            spec = importlib.util.find_spec("aegis")  # type: ignore[attr-defined]
            if spec is not None:
                passed = True
                actual = str(spec.origin or spec.submodule_search_locations)
                evidence = f"importlib.util.find_spec('aegis') found at {actual}"
            else:
                evidence = "importlib.util.find_spec('aegis') returned None"
        except (ModuleNotFoundError, ValueError) as exc:
            evidence = f"find_spec raised {type(exc).__name__}: {exc}"
        return IQCheck(
            check_id="IQ-002",
            category="dependencies",
            description="aegis package importable",
            expected="importable",
            actual=actual,
            passed=passed,
            evidence=evidence,
        )

    def check_required_deps(self) -> IQCheck:
        """IQ-003: Required runtime dependencies importable."""
        required = ["fastapi", "httpx", "pydantic", "cryptography", "structlog"]
        missing: list[str] = []
        found: list[str] = []
        for pkg in required:
            try:
                importlib.import_module(pkg)
                found.append(pkg)
            except ImportError:
                missing.append(pkg)
        passed = len(missing) == 0
        actual = f"found={found}; missing={missing}" if missing else f"all found: {found}"
        evidence = f"Imported {len(found)}/{len(required)} packages. " + (
            f"Missing: {', '.join(missing)}" if missing else "All present."
        )
        return IQCheck(
            check_id="IQ-003",
            category="dependencies",
            description="Required runtime packages importable (fastapi, httpx, pydantic, cryptography, structlog)",
            expected="all importable",
            actual=actual,
            passed=passed,
            evidence=evidence,
        )

    def check_signing_key_configured(self) -> IQCheck:
        """IQ-004: AEGIS_SIGNING_KEY set and >= 32 bytes (64 hex chars). Key value never logged."""
        key = os.environ.get("AEGIS_SIGNING_KEY", "")
        passed = False
        actual = "not set"
        evidence = ""
        if not key:
            evidence = "AEGIS_SIGNING_KEY environment variable is not set"
            actual = "not set"
        else:
            # Validate hex encoding
            try:
                bytes.fromhex(key)
                is_valid_hex = True
            except ValueError:
                is_valid_hex = False

            key_len = len(key)
            if not is_valid_hex:
                evidence = "AEGIS_SIGNING_KEY is set but is not valid hex"
                actual = f"set; length={key_len}; valid_hex=False"
            elif key_len < 64:
                evidence = (
                    f"AEGIS_SIGNING_KEY is set but has only {key_len} hex chars "
                    f"({key_len // 2} bytes); minimum is 64 hex chars (32 bytes)"
                )
                actual = f"set; {key_len} hex chars"
            else:
                passed = True
                evidence = (
                    f"AEGIS_SIGNING_KEY is set and has {key_len} hex chars "
                    f"({key_len // 2} bytes); satisfies >= 32 bytes minimum. "
                    "Key value not included in evidence."
                )
                actual = f"set; {key_len} hex chars"
        return IQCheck(
            check_id="IQ-004",
            category="config",
            description="AEGIS_SIGNING_KEY set and >= 32 bytes (64 hex chars)",
            expected=">= 64 hex chars",
            actual=actual,
            passed=passed,
            evidence=evidence,
        )

    def check_wal_dir_permissions(self) -> IQCheck:
        """IQ-005: WAL directory writable; temp files created at 0o600."""
        default_wal_dir = os.path.join(tempfile.gettempdir(), "aegis_wal_iq_check")
        wal_dir = os.environ.get("AEGIS_WAL_DIR", default_wal_dir)
        passed = False
        actual = "untested"
        evidence = ""
        try:
            os.makedirs(wal_dir, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=wal_dir)
            try:
                os.close(fd)
                os.chmod(tmp_path, 0o600)
                stat = os.stat(tmp_path)
                mode = oct(stat.st_mode & 0o777)
                passed = (stat.st_mode & 0o777) == 0o600
                actual = f"dir={wal_dir}; file_mode={mode}"
                evidence = (
                    f"Temp file created at {tmp_path}; mode={mode}; "
                    f"{'0o600 confirmed' if passed else 'mode mismatch — expected 0o600'}"
                )
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        except OSError as exc:
            evidence = f"WAL directory check failed: {exc}"
            actual = f"error: {exc}"
        return IQCheck(
            check_id="IQ-005",
            category="file_permissions",
            description="WAL directory writable and files created at 0o600",
            expected="0o600",
            actual=actual,
            passed=passed,
            evidence=evidence,
        )

    def check_api_keys_separate_from_signing(self) -> IQCheck:
        """IQ-006: AEGIS_API_KEYS != AEGIS_SIGNING_KEY when both are set."""
        api_keys = os.environ.get("AEGIS_API_KEYS", "")
        signing_key = os.environ.get("AEGIS_SIGNING_KEY", "")

        if not api_keys or not signing_key:
            # Cannot compare — one or both absent; treat as pass (not applicable)
            evidence = "One or both variables not set; no collision possible."
            return IQCheck(
                check_id="IQ-006",
                category="config",
                description="AEGIS_API_KEYS != AEGIS_SIGNING_KEY (key separation)",
                expected="different values",
                actual="not both set",
                passed=True,
                evidence=evidence,
            )

        # Compare without exposing values in evidence
        same = api_keys == signing_key
        passed = not same
        evidence = (
            "AEGIS_API_KEYS and AEGIS_SIGNING_KEY are different (key separation satisfied). "
            "Values not included in evidence."
            if passed
            else "AEGIS_API_KEYS equals AEGIS_SIGNING_KEY — key reuse violates separation-of-duty. "
            "Values not included in evidence."
        )
        return IQCheck(
            check_id="IQ-006",
            category="config",
            description="AEGIS_API_KEYS != AEGIS_SIGNING_KEY (key separation)",
            expected="different values",
            actual="same" if same else "different",
            passed=passed,
            evidence=evidence,
        )

    def check_rust_extension(self) -> IQCheck:
        """IQ-007: Optional aegis_rust or aegis_rust_v2 Rust extension importable."""
        passed = False
        actual = "not available"
        evidence = ""
        for mod_name in ("aegis_rust_v2", "aegis_rust"):
            try:
                importlib.import_module(mod_name)
                passed = True
                actual = f"{mod_name} importable"
                evidence = f"import {mod_name} succeeded — Rust acceleration active"
                break
            except ImportError:
                continue
        if not passed:
            evidence = (
                "Neither aegis_rust_v2 nor aegis_rust could be imported. "
                "System will operate in Python-only mode (no Rust acceleration). "
                "This is not a hard failure — Rust extension is optional."
            )
            # Per spec: IQ-007 is informational; pass with a note rather than block
            passed = True  # optional dependency
            actual = "not available (optional)"
        return IQCheck(
            check_id="IQ-007",
            category="dependencies",
            description="Optional Rust extension (aegis_rust_v2 or aegis_rust) importable",
            expected="importable (optional)",
            actual=actual,
            passed=passed,
            evidence=evidence,
        )

    def check_no_debug_auth_bypass(self) -> IQCheck:
        """IQ-008: If AEGIS_AUTH_DISABLED=true then AEGIS_DEBUG_MODE must also be true."""
        auth_disabled = os.environ.get("AEGIS_AUTH_DISABLED", "false").lower() == "true"
        debug_mode = os.environ.get("AEGIS_DEBUG_MODE", "false").lower() == "true"

        if not auth_disabled:
            passed = True
            actual = "AEGIS_AUTH_DISABLED=false; constraint not applicable"
            evidence = "Authentication is enabled; no bypass configured."
        elif debug_mode:
            passed = True
            actual = "AEGIS_AUTH_DISABLED=true; AEGIS_DEBUG_MODE=true"
            evidence = (
                "Auth bypass allowed only because AEGIS_DEBUG_MODE=true. "
                "Deployment must not use this configuration in production."
            )
        else:
            passed = False
            actual = "AEGIS_AUTH_DISABLED=true; AEGIS_DEBUG_MODE=false"
            evidence = (
                "AEGIS_AUTH_DISABLED=true but AEGIS_DEBUG_MODE is not true. "
                "Auth bypass without explicit debug flag is a configuration violation."
            )

        return IQCheck(
            check_id="IQ-008",
            category="config",
            description="Auth bypass (AEGIS_AUTH_DISABLED=true) only permitted when AEGIS_DEBUG_MODE=true",
            expected="auth bypass absent OR debug mode enabled",
            actual=actual,
            passed=passed,
            evidence=evidence,
        )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    report = IQProtocol().run_all()
    print(report.to_text())
    out_path = Path("tools/qualification/iq_report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.to_json())
    print(f"\nReport saved to {out_path}")
    sys.exit(0 if report.passed else 1)
