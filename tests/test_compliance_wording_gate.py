# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Wording gate for the compliance-label class (AUD-22 / REG-D26).

The audit found SOC 2 / HIPAA / GDPR names used *as labels* on sample, tooling and
audit surfaces — "seal a SOC2/HIPAA bundle", "SOC2 / HIPAA sealed export bundles",
"Compliance export SOC2/HIPAA" — with no qualifier anywhere near them. The
existing phrase gate in `scripts/verify_docs.py` missed every one, because its
list held sentence forms ("hipaa compliant") and the corpus asserted the claim in
compressed, adjectival and label form instead.

These tests pin both halves of the fix: the phrase list carries the compressed
forms, and it *fires* on them — proven here rather than asserted, by running the
repository's own checker against synthetic lines inside this test, so the negative
control ships with the gate instead of living in an evidence file.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Surfaces the audit named as carrying the claim as a label.
LABEL_SURFACES = (
    "examples/README.md",
    "tools/visualizer/README.md",
    "Samples/README.md",
    "SECURITY_AUDIT_EXECUTION_LOG.md",
    "SECURITY_AUDIT_REPORT.md",
)

COMPRESSED_FORMS = (
    "soc2 certified",
    "soc 2 compliant",
    "soc2 compliant",
    "soc 2 ready",
    "hipaa certified",
    "hipaa-ready",
    "gdpr-compliant",
    "iso 27001 compliant",
    "fedramp compliant",
    "pci-dss compliant",
    "court-admissible",
    "admissible in court",
    "satisfies hipaa",
    "meets soc 2",
)


def _load_verifier():
    """Import scripts/verify_docs.py under an explicit name."""
    path = REPO_ROOT / "scripts/verify_docs.py"
    spec = importlib.util.spec_from_file_location("aegis_verify_docs_for_wording_gate", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_phrase_list_carries_the_compressed_forms() -> None:
    verifier = _load_verifier()
    missing = [phrase for phrase in COMPRESSED_FORMS if phrase not in verifier.PROHIBITED_PHRASES]
    assert not missing, (
        f"the phrase gate lost the compressed compliance forms {missing} — the "
        "label wording the audit found is only caught by these"
    )


def test_bare_regulation_names_are_not_phrases() -> None:
    """A bare "soc 2" would flag every claim-control document that names the
    standard in order to bound it. The assertion is what is forbidden."""
    verifier = _load_verifier()
    for bare in ("soc 2", "soc2", "hipaa", "gdpr", "pci dss"):
        assert bare not in verifier.PROHIBITED_PHRASES


def test_each_compressed_form_fires_when_asserted() -> None:
    verifier = _load_verifier()
    for phrase in COMPRESSED_FORMS:
        findings = verifier.check_prohibited_phrases(
            "docs/SOME_UNREGISTERED_DOC.md",
            [f"The platform is {phrase} across every deployment."],
        )
        assert findings, f"{phrase!r} asserted in prose did not raise a finding"
        assert findings[0].rule == "prohibited-phrase"


def test_a_denial_does_not_fire() -> None:
    """The list must not punish the sentences that exist to deny the claim."""
    verifier = _load_verifier()
    for line in (
        "Aegis is not SOC 2 certified, and no examination is in progress.",
        "Never describe this software as hipaa-ready.",
        "The phrase 'gdpr-compliant' is prohibited; say instead that the software contributes technical inputs.",
    ):
        assert not verifier.check_prohibited_phrases("docs/SOME_UNREGISTERED_DOC.md", [line]), line


def test_the_documentation_surfaces_pass_the_gate_after_the_wording_fix() -> None:
    verifier = _load_verifier()
    findings = verifier.run(REPO_ROOT)
    label_findings = [f for f in findings if f.rule == "prohibited-phrase"]
    assert not label_findings, [f.render() for f in label_findings]


def test_label_surfaces_carry_no_unqualified_compliance_label() -> None:
    """The gate above cannot see a bare "SOC2 / HIPAA" label; this pins the fix
    the audit asked for on the five surfaces that carried one."""
    for relative in LABEL_SURFACES:
        body = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for line in body.splitlines():
            lowered = line.lower()
            if not any(name in lowered for name in ("soc2", "soc 2", "hipaa", "gdpr")):
                continue
            assert any(
                qualifier in lowered
                for qualifier in (
                    "technical inputs",
                    "assessor",
                    "no certification",
                    "not a certification",
                    "programme",
                    "program",
                    "obligations",
                    "determination",
                )
            ), f"{relative}: compliance label without a qualifier: {line.strip()[:140]}"


# --------------------------------------------------------------------------
# The delegated survey (2026-09-21) found the same claim class outside every
# markdown surface, in files no gate read at all: the two generators that emit
# the sample pages, the demo, the export engine's docstring and the operator
# string it serves, the deployment presets and the compose profile list. Fixing
# the generated pages without fixing their generators would have re-emitted the
# label on the next run, so these two rules extend the gate to those surfaces.
# --------------------------------------------------------------------------

COMPLIANCE_TEXT_SURFACES = (
    "examples/demo.py",
    "tools/visualizer/static/index.html",
    "tools/visualizer/generate_samples.py",
    "aegis_server/compliance/exporter.py",
    "aegis_server/main.py",
    "config/presets/fedramp.env",
    "config/presets/healthcare.env",
    "config/presets/judicial.env",
    "deploy/docker/docker-compose.enterprise.yml",
    "aegis/config.py",
    "aegis/core/pci_detector.py",
)

# Rule B: each of those files names a regime, so each must state its boundary
# somewhere a reader of that file meets it. Tokens are matched against the file
# with comment markers, quotes and whitespace runs collapsed, so a boundary
# sentence split across lines or string concatenation still counts.
BOUNDARY_TOKENS = (
    "assessor",
    "technical inputs",
    "no certification",
    "not a certification",
    "not a pci certification",
    "judicial determination",
    "not a compliance determination",
    "asserts certification, authorization, compliance or admissibility",
    "no fedramp authorization",
    "not a hipaa safe harbor",
    "no certification is claimed",
)

REGIME_NAMES = ("soc2", "soc 2", "hipaa", "gdpr", "iso 27001", "fedramp", "pci-dss", "daubert")


def _collapse(text: str) -> str:
    import re

    return re.sub(r"[\"'`#>/\s]+", " ", text).lower()


def test_non_markdown_surfaces_pass_the_phrase_gate() -> None:
    """Rule A, extended past markdown: the shared phrase list runs over the
    generators, the demo, the presets, the compose file and the export engine."""
    verifier = _load_verifier()
    findings = []
    for relative in COMPLIANCE_TEXT_SURFACES:
        path = REPO_ROOT / relative
        assert path.exists(), relative
        lines = path.read_text(encoding="utf-8").splitlines()
        findings.extend(verifier.check_prohibited_phrases(relative, lines))
    assert not findings, [f.render() for f in findings]


def test_every_file_that_names_a_regime_states_its_boundary() -> None:
    """Rule B: a file that names a regime must say, in itself, that what it
    produces is input to an assessment and not the assessment. This is the rule
    that catches a *label* ("SOC2 / HIPAA sealed bundles"), which no phrase gate
    can see."""
    for relative in COMPLIANCE_TEXT_SURFACES:
        body = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert any(name in body.lower() for name in REGIME_NAMES), relative
        collapsed = _collapse(body)
        assert any(token in collapsed for token in BOUNDARY_TOKENS), (
            f"{relative} names a regime but carries no boundary statement; "
            f"expected one of {BOUNDARY_TOKENS}"
        )


def test_python_strings_that_name_a_regime_state_their_own_boundary() -> None:
    """Rule B was file-level, and a live negative control proved that too weak:
    deleting the boundary sentence from `aegis_server/main.py` left another
    boundary token elsewhere in the file and the rule stayed green. The claim
    lives in a *string*, so the rule belongs there: any string constant that
    names a regime must carry its own boundary. Case-sensitive uppercase names,
    because lowercase occurrences in these files are keys and profile names, not
    claims."""
    import ast

    uppercase_names = ("SOC 2", "SOC2", "HIPAA", "GDPR", "FedRAMP", "ISO 27001", "Daubert")
    python_surfaces = [p for p in COMPLIANCE_TEXT_SURFACES if p.endswith(".py")]
    assert python_surfaces, "expected Python surfaces in the list"
    findings = []
    for relative in python_surfaces:
        tree = ast.parse((REPO_ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if not any(name in text for name in uppercase_names):
                    continue
                if text.strip() in ("SOC2", "HIPAA", "GDPR", "FedRAMP", "ISO 27001"):
                    # A data value (a bundle's `format` field, for example), not a
                    # claim: the 13 sample pages render these as tags and the
                    # disclosure lives in the page's demo banner and bootstrap.
                    continue
                if not any(token in _collapse(text) for token in BOUNDARY_TOKENS):
                    findings.append(f"{relative}:{node.lineno}: {text.strip()[:120]}")
    assert not findings, findings


def test_generated_sample_pages_carry_the_qualified_label() -> None:
    """The 13 tracked pages were corrected in place, not regenerated: REG-058
    froze their embedded provenance, so regenerating would have rewritten
    `git_head`/`version` and broken the freeze its own test pins. This asserts
    the pages and their generators now agree, so a later regeneration from the
    corrected generator reproduces the corrected pages."""
    pages = sorted((REPO_ROOT / "Samples").glob("*.html"))
    assert len(pages) == 13, [p.name for p in pages]
    qualified = "Sealed export bundles — SOC 2 / HIPAA assessor inputs"
    for page in pages:
        body = page.read_text(encoding="utf-8")
        assert qualified in body, page.name
        assert "SOC2 / HIPAA sealed export bundles" not in body, page.name
