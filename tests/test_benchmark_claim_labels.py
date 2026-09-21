"""The benchmark harnesses must not make claims the corpus prohibits (AUD-26).

``docs/benchmarks/BENCHMARK_METHOD.md`` says no RPS figure is claimed for any
environment and lists "zero overhead" as prohibited phrasing, while the harnesses
printed ``[PROVEN]`` on host-specific numbers and framed themselves as validating a
"zero forensic latency" claim. Two surfaces contradicted the rules that govern them,
and nothing checked.

These tests check the surfaces, and the retained artifacts the docs now cite:

* no absolute-claim label and no prohibited phrase in any harness;
* every harness prints the shared provenance banner before its numbers, and that
  banner says what the numbers are and are not;
* the group-commit reports cited by ``PR_FINAL_ENTERPRISE_HARDENING.md`` are
  committed, parse, and carry the provenance fields their schema promises.

Run: ``pytest tests/test_benchmark_claim_labels.py``.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from benchmarks import PROVENANCE_NOTE, print_provenance

ROOT = Path(__file__).resolve().parent.parent
HARNESS_DIRS = (ROOT / "benchmarks", ROOT / "tools" / "benchmarks")
RETAINED = ROOT / "evidence" / "execution_2026-09-21"

#: Labels that read as a claim about every environment. ``[MEASURED HERE]`` is the
#: replacement: it says what the number is (an observation) and where it holds.
FORBIDDEN_LABELS = ("[PROVEN]",)

#: Phrasings ``BENCHMARK_METHOD.md`` prohibits, in the surfaces that generate claims.
FORBIDDEN_PHRASES = ("zero forensic latency", "zero-forensic-latency", "zero overhead")


def _harness_sources() -> list[Path]:
    return sorted(
        path
        for directory in HARNESS_DIRS
        for path in directory.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def test_no_harness_prints_an_absolute_claim_label() -> None:
    hits = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in _harness_sources()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if any(label in line for label in FORBIDDEN_LABELS)
    ]
    assert not hits, f"absolute-claim labels in harnesses: {hits}"


def test_no_harness_uses_a_prohibited_claim_phrase() -> None:
    hits = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in _harness_sources()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if any(phrase in line.lower() for phrase in FORBIDDEN_PHRASES)
    ]
    assert not hits, f"prohibited claim phrasing in harnesses: {hits}"


def test_every_harness_prints_the_provenance_banner() -> None:
    missing = []
    for path in sorted((ROOT / "benchmarks").glob("bench_*.py")):
        text = path.read_text(encoding="utf-8")
        main = text.split('if __name__ == "__main__":', 1)
        if len(main) != 2 or "print_provenance(" not in main[1]:
            missing.append(path.name)
    assert not missing, f"harnesses that print numbers without a provenance banner: {missing}"


def test_the_banner_states_what_the_numbers_are_and_are_not(
    capsys: pytest.CaptureFixture[str],
) -> None:
    print_provenance("test_harness")
    out = capsys.readouterr().out
    for field in ("host", "cpus", "python", "generated", "caveat"):
        assert field in out, f"the banner lost its {field} line"
    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", out), "the banner has no UTC date"
    assert "No RPS figure is claimed for any environment" in out
    assert "No RPS figure is claimed for any environment" in PROVENANCE_NOTE


def test_the_harnesses_do_not_cite_a_convention_the_repository_does_not_have() -> None:
    # The [PROVEN] legend cited "CLAUDE.md I-03"; no such rule exists in the tree.
    hits = [
        str(path.relative_to(ROOT))
        for path in _harness_sources()
        if "CLAUDE.md I-03" in path.read_text(encoding="utf-8")
    ]
    assert not hits, f"dangling convention citation: {hits}"


def test_the_cited_group_commit_reports_are_retained_and_carry_their_provenance() -> None:
    reports = sorted(RETAINED.glob("group_commit_report_run*.json"))
    assert len(reports) == 3, f"expected three retained runs, found {[p.name for p in reports]}"
    for report in reports:
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["schema"] == "aegis-group-commit-report-v1"
        assert re.fullmatch(r"[0-9a-f]{40}", data["commit_sha"]), f"{report.name} has no revision"
        assert re.match(r"\d{4}-\d{2}-\d{2}T", data["generated_at_utc"])
        for field in ("cpu_count", "machine", "platform", "python"):
            assert field in data["environment"], f"{report.name} lost environment.{field}"
        limits = " ".join(data["limitations"])
        assert "No capacity, SLA or production-readiness claim is made or implied." in limits
        assert data["delta"]["fsync_calls_before"] > data["delta"]["fsync_calls_after"] > 0


def test_the_document_that_cites_the_reports_cites_paths_that_exist() -> None:
    cited = re.findall(
        r"evidence/execution_2026-09-21/[\w.\-]+",
        (ROOT / "PR_FINAL_ENTERPRISE_HARDENING.md").read_text(encoding="utf-8"),
    )
    assert cited, "PR_FINAL_ENTERPRISE_HARDENING.md no longer cites a retained artifact"
    for relative in cited:
        assert (ROOT / relative).exists(), f"{relative} is cited and does not exist"
