# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Behavioural tests for the documentation verifiers.

``scripts/verify_docs.py`` decides whether prose asserts a prohibited claim or
merely names one in order to deny it. That judgement was tuned three times
against real boundary statements in this corpus, and each relaxation risks
turning the checker into one that always passes.

These tests pin both directions: the checker must stay silent on documents
doing the right thing, and must still fail on documents doing the wrong one. A
checker that only ever passes is worse than no checker, because it is trusted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verify_docs = _load("_verify_docs_under_test", "scripts/verify_docs.py")
verify_claims = _load("_verify_claims_under_test", "scripts/verify_claims.py")


def _corpus(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write a miniature corpus and return its root."""
    for relative, body in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


def _rules(findings) -> set[str]:
    return {f.rule for f in findings}


# ── The checker must fire on real assertions ─────────────────────────────────


@pytest.mark.parametrize(
    ("sentence", "phrase"),
    [
        ("Aegis is fully compliant with SOC 2.", "fully compliant"),
        ("Evidence produced by the gateway is legally admissible.", "legally admissible"),
        ("The audit log is immutable by default.", "immutable by default"),
        ("The platform is production-ready today.", "production-ready"),
        ("Our WAF offers guaranteed prevention of injection.", "guaranteed prevention"),
        ("The scrubber removes all PII from every payload.", "removes all pii"),
        ("This is a revolutionary approach to governance.", "revolutionary"),
        ("We are HIPAA compliant across every deployment.", "hipaa compliant"),
    ],
)
def test_asserted_prohibited_phrases_are_flagged(tmp_path, sentence, phrase):
    """An affirmative assertion must fail, whatever the phrasing around it."""
    root = _corpus(tmp_path, {"README.md": f"# Doc\n\n## Overview\n\n{sentence}\n"})
    findings = verify_docs.check_prohibited_phrases(
        "README.md", (root / "README.md").read_text().splitlines()
    )
    assert "prohibited-phrase" in _rules(findings), (
        f"{phrase!r} asserted in {sentence!r} was not flagged; the checker has gone vacuous"
    )


def test_placeholder_left_behind_is_flagged(tmp_path):
    root = _corpus(tmp_path, {"README.md": "# Doc\n\n## Plan\n\nTODO: write this section.\n"})
    findings = verify_docs.check_placeholders(
        root / "README.md", "README.md", (root / "README.md").read_text().splitlines()
    )
    assert "placeholder" in _rules(findings)


def test_duplicate_status_callout_and_pricing_are_flagged(tmp_path):
    root = _corpus(
        tmp_path,
        {
            "README.md": (
                "# Doc\n\n"
                "Current release candidate: v4.0.2 source.\n"
                "Current release candidate: v4.0.2 source.\n"
                "Pricing starts at $50k/year.\n"
            )
        },
    )
    rules = _rules(verify_docs.check_readme_shape(root))
    assert "duplicate-status-callout" in rules
    assert "pricing-in-readme" in rules


def test_broken_relative_link_is_flagged(tmp_path):
    root = _corpus(tmp_path, {"README.md": "# Doc\n\nSee [gone](docs/NOPE.md).\n"})
    findings = verify_docs.check_links(
        root, root / "README.md", "README.md", (root / "README.md").read_text().splitlines()
    )
    assert "broken-link" in _rules(findings)


def test_missing_internal_marker_is_flagged(tmp_path):
    root = _corpus(tmp_path, {"docs/COMMERCIAL_STRATEGY_US.md": "# Strategy\n\nBody.\n"})
    assert "missing-internal-marker" in _rules(verify_docs.check_internal_markers(root))


# ── The checker must stay silent on correct boundary prose ───────────────────


@pytest.mark.parametrize(
    "sentence",
    [
        "Aegis is not fully compliant with any framework, and no certification exists.",
        "No claim of legal admissibility, non-repudiation, or certification is approved.",
        "Out of the threat model by design: guaranteed prevention of prompt injection.",
        "Pause the purchase if a proposal uses “production-ready” without a named artifact.",
        "The scrubber does not remove all PII; it matches specific patterns.",
    ],
)
def test_denials_are_not_flagged(tmp_path, sentence):
    """Naming a prohibited phrase in order to deny it is the correct behaviour."""
    root = _corpus(tmp_path, {"README.md": f"# Doc\n\n## Overview\n\n{sentence}\n"})
    findings = verify_docs.check_prohibited_phrases(
        "README.md", (root / "README.md").read_text().splitlines()
    )
    assert "prohibited-phrase" not in _rules(findings), (
        f"denial {sentence!r} was flagged as an assertion"
    )


def test_question_headings_are_not_flagged(tmp_path):
    root = _corpus(tmp_path, {"README.md": "# Doc\n\n## Is Aegis HIPAA compliant?\n\nNo.\n"})
    findings = verify_docs.check_prohibited_phrases(
        "README.md", (root / "README.md").read_text().splitlines()
    )
    assert "prohibited-phrase" not in _rules(findings)


def test_denial_heading_scopes_its_section(tmp_path):
    """A bullet under an exclusion heading inherits the heading's denial."""
    body = (
        "# Doc\n\n"
        "## What is not controlled here\n\n"
        "- Guaranteed prevention of prompt injection.\n"
        "- Legally admissible output.\n"
    )
    root = _corpus(tmp_path, {"README.md": body})
    findings = verify_docs.check_prohibited_phrases(
        "README.md", (root / "README.md").read_text().splitlines()
    )
    assert "prohibited-phrase" not in _rules(findings)


def test_placeholder_reference_is_not_flagged(tmp_path):
    """Talking about markers is not leaving one behind."""
    body = (
        "# Doc\n\n## Audit\n\n"
        "- Create targeted PRs for critical TODO/FIXME markers listed in the tracker.\n"
    )
    root = _corpus(tmp_path, {"README.md": body})
    findings = verify_docs.check_placeholders(
        root / "README.md", "README.md", (root / "README.md").read_text().splitlines()
    )
    assert "placeholder" not in _rules(findings)


def test_fenced_code_is_not_prose(tmp_path):
    body = "# Doc\n\n```bash\n# TODO this is example code\necho production-ready\n```\n"
    root = _corpus(tmp_path, {"README.md": body})
    lines = (root / "README.md").read_text().splitlines()
    assert not verify_docs.check_placeholders(root / "README.md", "README.md", lines)
    assert not verify_docs.check_prohibited_phrases("README.md", lines)


# ── Claims register ──────────────────────────────────────────────────────────


def test_repository_claims_register_is_coherent():
    """The real register must parse and satisfy every structural rule."""
    text = (ROOT / verify_claims.MATRIX).read_text(encoding="utf-8")
    claims, findings = verify_claims.parse_claims(text)
    assert claims, "no claim rows parsed from the register"
    findings += verify_claims.check_claims(claims)
    findings += verify_claims.check_control_register(text, claims)
    assert not findings, [f"{f.rule}: {f.claim}" for f in findings]


def test_claim_without_boundary_is_flagged():
    claim = verify_claims.Claim(
        ident="CLM-001",
        text="Something is true.",
        state="IMPLEMENTED",
        locator="aegis/core/thing.py; tests/test_thing.py",
        boundary="none",
        line=1,
    )
    assert "missing-boundary" in {f.rule for f in verify_claims.check_claims([claim])}


def test_implemented_claim_without_locator_is_flagged():
    claim = verify_claims.Claim(
        ident="CLM-001",
        text="Something is true.",
        state="IMPLEMENTED",
        locator="none",
        boundary="This does not establish anything beyond the stated scope.",
        line=1,
    )
    assert "missing-locator" in {f.rule for f in verify_claims.check_claims([claim])}


def test_roadmap_row_citing_evidence_without_denial_is_flagged():
    """A ROADMAP row that cites source must deny, or it reads as confirmation."""
    claim = verify_claims.Claim(
        ident="CLM-001",
        text="Segments are stored under write-once controls.",
        state="ROADMAP",
        locator="`aegis/storage/s3_worm.py` provides an Object Lock adapter.",
        boundary="The adapter uploads segments and verifies retention metadata on write.",
        line=1,
    )
    assert "roadmap-without-denial" in {f.rule for f in verify_claims.check_claims([claim])}


def test_repository_corpus_passes_every_structural_check():
    """The corpus itself must pass. This is the gate CI runs."""
    assert not verify_docs.run(ROOT), [f.render() for f in verify_docs.run(ROOT)]
