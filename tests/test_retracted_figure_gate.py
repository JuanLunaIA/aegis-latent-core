# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""AUD-06 (REG-D10): the retracted backpressure pair must not survive as a
citation — and the gate that enforces it must fail on one.

The register (`UC-018`) retracts the ``v3.1.0`` 10,000-record / p99
1,189.89 ms backpressure pair: no artifact in this tree produces it. The sweep
that removed the pair from thirteen documents is only durable if
``scripts/verify_claims.py`` fails when it comes back, so these tests exercise
the check on synthetic documents rather than trusting a green run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_gate():
    path = Path(__file__).resolve().parents[1] / "scripts" / "verify_claims.py"
    spec = importlib.util.spec_from_file_location("verify_claims_gate", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before executing: the module defines frozen dataclasses, and the
    # dataclass machinery looks its own module up in sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def test_unmarked_citation_is_reported(tmp_path: Path) -> None:
    (tmp_path / "doc.md").write_text(
        "The backpressure run recorded p99 1,189.89 ms under the injected seam.\n", encoding="utf-8"
    )
    findings = gate.check_retracted_figures(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule == "retracted-figure-cited"
    assert findings[0].claim == "UC-018"
    assert "doc.md:1" in findings[0].detail


def test_unmarked_ten_thousand_record_claim_is_reported(tmp_path: Path) -> None:
    (tmp_path / "doc.md").write_text(
        "It recorded 10,000 durable commits with zero failures.\n", encoding="utf-8"
    )
    assert len(gate.check_retracted_figures(tmp_path)) == 1


def test_marked_retraction_is_allowed(tmp_path: Path) -> None:
    (tmp_path / "doc.md").write_text(
        "The 10,000-record / p99 1,189.89 ms pair is retracted (`UC-018`).\n", encoding="utf-8"
    )
    assert gate.check_retracted_figures(tmp_path) == []


def test_wrapped_paragraph_is_one_unit(tmp_path: Path) -> None:
    """Prose that wraps must not split a citation from its retraction."""
    (tmp_path / "doc.md").write_text(
        "The claims register retracts it (`UC-018`). A reader cannot re-derive the\n"
        "p99 1,189.89 ms figure from the repository.\n",
        encoding="utf-8",
    )
    assert gate.check_retracted_figures(tmp_path) == []


def test_table_rows_are_checked_individually(tmp_path: Path) -> None:
    """A retraction on one row must not cover an unmarked citation on the next."""
    (tmp_path / "doc.md").write_text(
        "| Row | Value | Note |\n"
        "|---|---|---|\n"
        "| Old run | p99 1,189.89 ms | retracted (`UC-018`) |\n"
        "| Same run | max 3,208.869 ms, p99 1,189.89 ms | measured |\n",
        encoding="utf-8",
    )
    findings = gate.check_retracted_figures(tmp_path)
    assert len(findings) == 1
    assert "doc.md:4" in findings[0].detail


def test_exempt_audit_report_is_skipped(tmp_path: Path) -> None:
    """The audit report quotes the defective text as its evidence."""
    (tmp_path / "AUDIT_REPORT_v5.0.1_PREP.md").write_text(
        "**Defect.** The prospectus cites p99 1,189.89 ms with no producer artifact.\n",
        encoding="utf-8",
    )
    assert gate.check_retracted_figures(tmp_path) == []


def test_artifact_backed_figures_are_not_flagged(tmp_path: Path) -> None:
    """The in-tree run's own numbers stay citable."""
    (tmp_path / "doc.md").write_text(
        "The in-tree run recorded 2,500 durable commits with p99 836.3514210795984 ms.\n"
        "Offered load was 10,000 RPS for 0.25 s.\n",
        encoding="utf-8",
    )
    assert gate.check_retracted_figures(tmp_path) == []
