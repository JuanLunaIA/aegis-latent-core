# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.docs import verify_documentation

ROOT = Path(__file__).resolve().parents[1]


def _write_document(path: Path, claim: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Fixture\n\n"
        "Last verified: 2026-08-23\n\n"
        "Release baseline: source fixture\n\n"
        f"{claim}\n\n"
        "## Related documents\n\n"
        "None.\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    ("claim", "category"),
    [
        ("Aegis is SOC 2 compliant and certified.", "certification or compliance"),
        ("The ML-DSA implementation is constant-time.", "constant-time cryptography"),
        (
            "Aegis delivers billion-scale decisions with millisecond latency.",
            "billion-scale millisecond performance",
        ),
        ("This deployment is production-ready.", "production capacity or readiness"),
        ("Aegis v4.0.0 has been published and released.", "v4 external publication or release"),
    ],
)
def test_strict_mode_rejects_unqualified_high_risk_claims(
    tmp_path: Path, claim: str, category: str
) -> None:
    path = tmp_path / "README.md"
    _write_document(path, claim)

    findings = verify_documentation.check_document(path, tmp_path, strict=True)

    assert any(finding.severity == "ERROR" and category in finding.message for finding in findings)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "claim",
    [
        "Aegis is not certified or compliant; mappings only support customer assessment.",
        "No constant-time claim is approved for the ML-DSA implementation.",
        "No billion-scale result with millisecond latency is claimed by this benchmark.",
        "This repository is not production-ready and does not establish production capacity.",
        "Aegis v4.0.0 is unreleased and has not been published externally.",
    ],
)
def test_strict_mode_allows_explicit_scoped_disclaimers(tmp_path: Path, claim: str) -> None:
    path = tmp_path / "README.md"
    _write_document(path, claim)

    findings = verify_documentation.check_document(path, tmp_path, strict=True)

    assert not [finding for finding in findings if finding.severity == "ERROR"]


def test_default_mode_preserves_warning_only_claim_compatibility(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    _write_document(path, "The ML-DSA implementation is constant-time.")

    findings = verify_documentation.check_document(path, tmp_path)

    assert not [finding for finding in findings if finding.severity == "ERROR"]
    assert any(finding.severity == "WARNING" for finding in findings)


def test_strict_mode_rejects_affirmative_claim_in_table(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    _write_document(
        path,
        "| Capability | Status |\n"
        "|---|---|\n"
        "| Release | Aegis v4.0.0 has been published and released. |",
    )

    findings = verify_documentation.check_document(path, tmp_path, strict=True)

    assert any(
        finding.severity == "ERROR" and "v4 external publication" in finding.message
        for finding in findings
    )


def test_strict_mode_allows_claim_in_explicit_limitation_column(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    _write_document(
        path,
        "| Measurement | What it cannot establish |\n"
        "|---|---|\n"
        "| Timing sample | Proof of constant-time execution or production capacity |",
    )

    findings = verify_documentation.check_document(path, tmp_path, strict=True)

    assert not [finding for finding in findings if finding.severity == "ERROR"]


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "claim",
    [
        "Is Aegis production-ready?\n\nYes.",
        "Aegis is\nproduction-ready.",
        "No unsupported mode is enabled. Aegis is production-ready.",
    ],
)
def test_strict_mode_rejects_question_multiline_and_unrelated_negation_bypasses(
    tmp_path: Path, claim: str
) -> None:
    path = tmp_path / "README.md"
    _write_document(path, claim)

    findings = verify_documentation.check_document(path, tmp_path, strict=True)

    assert any(
        finding.severity == "ERROR" and "production capacity or readiness" in finding.message
        for finding in findings
    )


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "claim",
    [
        "Configure `production-ready` mode only after local review.",
        "~~~text\nAegis is production-ready.\n~~~",
    ],
)
def test_strict_mode_ignores_inline_and_tilde_fenced_code(tmp_path: Path, claim: str) -> None:
    path = tmp_path / "README.md"
    _write_document(path, claim)

    findings = verify_documentation.check_document(path, tmp_path, strict=True)

    assert not [finding for finding in findings if finding.severity == "ERROR"]


def test_strict_cli_exits_nonzero_and_emits_machine_readable_failure(tmp_path: Path) -> None:
    for relative in verify_documentation.REQUIRED_FILES:
        _write_document(tmp_path / relative, "This source contract has bounded claims.")
    _write_document(tmp_path / "README.md", "Aegis v4.0.0 has been published and released.")

    completed = subprocess.run(  # noqa: S603 - fixed local executable and arguments
        [
            sys.executable,
            str(ROOT / "tools/docs/verify_documentation.py"),
            "--root",
            str(tmp_path),
            "--strict",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    report = json.loads(completed.stdout)
    assert report["strict"] is True
    assert report["status"] == "FAIL"
    assert report["errors"] == 1
    assert "v4 external publication or release" in report["findings"][0]["message"]
