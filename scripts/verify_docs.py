#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Structural verification for the documentation corpus.

This checks the mechanical rules in ``docs/STYLE_GUIDE.md``: the required
corpus exists, relative links resolve, no placeholders survive, prohibited
assurance language is not asserted, the README states release status once,
internal documents are marked, and files end with a newline.

Division of labour, so the four checkers do not duplicate each other:

* ``scripts/verify_docs.py``  (this file) - structure, links, placeholders,
  prohibited phrasing, README shape, internal markers, newlines.
* ``scripts/verify_claims.py``           - claims-matrix well-formedness and
  claim-to-evidence consistency.
* ``scripts/verify_links.sh``            - link checking across the corpus,
  including anchors.
* ``tools/docs/verify_documentation.py`` - the pre-existing prose-level
  boundary-language linter. Retained, not replaced.

Exit codes: 0 clean, 1 findings, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ── Corpus scope ──────────────────────────────────────────────────────────────

#: Directories excluded from every check.
#: ``evidence/`` holds dated, frozen records; rewriting one to satisfy a linter
#: would destroy the record. ``.aegis_ai_context/`` is generated.
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    ".next",
    "target",
    "htmlcov",
    "evidence",
    ".aegis_ai_context",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

#: Files the corpus must contain. Absence is a P0 finding.
REQUIRED_FILES = (
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "ROADMAP.md",
    "COMMERCIAL.md",
    "DEPLOYMENT_GUIDE.md",
    "docs/INDEX.md",
    "docs/RELEASE_STATUS.md",
    "docs/BOUNDARIES.md",
    "docs/CLAIMS_MATRIX.md",
    "docs/REPOSITORY_MAP.md",
    "docs/STYLE_GUIDE.md",
    "docs/DOCUMENTATION_GOVERNANCE.md",
    "docs/DEVELOPER_QUICKSTART.md",
    "docs/DEVELOPER_INTEGRATIONS_GUIDE.md",
    "docs/PLATFORM_OPERATOR_GUIDE.md",
    "docs/FAQ_SECURITY.md",
    "docs/FAQ_PROCUREMENT.md",
    "docs/architecture/ARCHITECTURE.md",
    "docs/architecture/DECISIONS.md",
    "docs/architecture/FAILURE_SEMANTICS.md",
    "docs/api/MMR_PROOF_V1.md",
    "docs/api/AUDIT_ENDPOINTS.md",
    "docs/api/FORENSIC_EXPORT.md",
    "docs/security/THREAT_MODEL.md",
    "docs/security/SECURITY_CONTROLS.md",
    "docs/security/SECURITY_ARCHITECTURE.md",
    "docs/security/INCIDENT_RESPONSE.md",
    "docs/security/VULNERABILITY_DISCLOSURE.md",
    "docs/operations/STORAGE_REQUIREMENTS.md",
    "docs/operations/BACKUP_RESTORE.md",
    "docs/operations/KEY_ROTATION_RUNBOOK.md",
    "docs/operations/ROLLBACK_RUNBOOK.md",
    "docs/operations/BACKPRESSURE_RUNBOOK.md",
    "docs/operations/MONITORING_ALERTING.md",
    "docs/operations/DEPLOYMENT_PROFILES.md",
    "docs/compliance/COMPLIANCE_MAPPING.md",
    "docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md",
    "docs/compliance/HIPAA_TECHNICAL_INPUTS.md",
    "docs/compliance/MIFID_II_TECHNICAL_INPUTS.md",
    "docs/compliance/ISO_27037_TECHNICAL_INPUTS.md",
    "docs/privacy/DATA_RETENTION.md",
    "docs/privacy/PII_REDACTION_BOUNDARIES.md",
    "docs/privacy/DATA_PROCESSING_CHECKLIST.md",
    "docs/formal/FORMAL_VERIFICATION.md",
    "docs/formal/FORMAL_VERIFICATION_LIMITS.md",
    "docs/benchmarks/BENCHMARK_RESULTS.md",
    "docs/benchmarks/BENCHMARK_METHOD.md",
    "docs/enterprise/ENTERPRISE_READINESS.md",
    "docs/enterprise/PILOT_PLAYBOOK.md",
    "docs/enterprise/PROCUREMENT_CHECKLIST.md",
    "docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md",
    "docs/enterprise/SUPPORT_MODEL.md",
    "docs/assurance/ASSURANCE_ROADMAP.md",
    "docs/assurance/AUDIT_EVIDENCE_INDEX.md",
    "docs/assurance/CONTROL_TO_EVIDENCE_MATRIX.md",
    "docs/institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md",
    "docs/institutional/UNSUPPORTED_CLAIMS.md",
    "docs/institutional/EVIDENCE_GOVERNANCE.md",
    "docs/corporate/EXECUTIVE_SUMMARY.md",
    "docs/corporate/PRODUCT_ONE_PAGER.md",
    "docs/corporate/CORPORATE_FAQ.md",
    "docs/corporate/POSITIONING_AND_MESSAGING.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/ISSUE_TEMPLATE/documentation_issue.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
)

#: Documents whose subject is claim control. They must be able to name a
#: prohibited phrase in order to prohibit it, so phrase checks are relaxed
#: here. They are still checked for placeholders, links and newlines.
CLAIM_CONTROL_FILES = {
    "docs/STYLE_GUIDE.md",
    "docs/DOCUMENTATION_GOVERNANCE.md",
    "docs/CLAIMS_MATRIX.md",
    "docs/BOUNDARIES.md",
    "docs/institutional/UNSUPPORTED_CLAIMS.md",
    "docs/institutional/EVIDENCE_GOVERNANCE.md",
    "docs/institutional/DOCUMENT_CONTROL.md",
    "docs/institutional/CLAIM_EVIDENCE_GRAPH.md",
    "docs/corporate/CORPORATE_FAQ.md",
    "docs/corporate/POSITIONING_AND_MESSAGING.md",
    "docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md",
    "docs/compliance/COMPLIANCE_MAPPING.md",
    "docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md",
    "docs/compliance/HIPAA_TECHNICAL_INPUTS.md",
    "docs/compliance/MIFID_II_TECHNICAL_INPUTS.md",
    "docs/compliance/ISO_27037_TECHNICAL_INPUTS.md",
    "docs/privacy/PII_REDACTION_BOUNDARIES.md",
    "docs/formal/FORMAL_VERIFICATION_LIMITS.md",
    "docs/assurance/ASSURANCE_ROADMAP.md",
    "docs/assurance/CONTROL_TO_EVIDENCE_MATRIX.md",
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
}

#: Documents that must carry the internal marker from STYLE_GUIDE section 9.
INTERNAL_FILES = {
    "docs/COMMERCIAL_STRATEGY_US.md",
    "docs/corporate/POSITIONING_AND_MESSAGING.md",
}

INTERNAL_MARKER = "**INTERNAL DOCUMENT — NOT FOR EXTERNAL DISTRIBUTION**"

# ── Patterns ──────────────────────────────────────────────────────────────────

#: Prohibited assurance and marketing language. Matched case-insensitively on
#: prose only, and only when asserted (see ``_is_negated``).
PROHIBITED_PHRASES = (
    "fully compliant",
    "legally admissible",
    "immutable by default",
    "production-ready",
    "production ready",
    "game-changing",
    "revolutionary",
    "best-in-class",
    "world-class",
    "unmatched",
    "market-leading",
    "top #1",
    "soc 2 certified",
    "iso 27001 certified",
    "hipaa compliant",
    "gdpr compliant",
    "fedramp authorized",
    "pci compliant",
    "guarantees prevention",
    "guaranteed prevention",
    "removes all pii",
    "guaranteed uptime",
)

#: Negation, denial and prohibition markers. A boundary document's whole job is
#: to name a prohibited phrase in order to deny it, so a hit on a line carrying
#: any of these is a denial rather than an assertion. The window is the whole
#: line: denials in this corpus routinely put the negation far from the phrase
#: ("no claim of ... admissibility ... is approved"), and a narrow window
#: produced false positives on exactly the rows that were doing the right thing.
NEGATION_RE = re.compile(
    r"(?:\bnot\b|\bno\b|\bnever\b|\bwithout\b|\bcannot\b|\bcan't\b|\bavoid\b|"
    r"\bprohibit(?:ed|s|ion)?\b|\bforbidden\b|\bunsupported\b|\bfalse\b|"
    r"\bnothing\b|\bexclude[ds]?\b|\brather than\b|\binstead of\b|\bunless\b|"
    r"\brefus(?:e|es|ed)\b|\bden(?:y|ies|ied|ial)\b|\breject(?:s|ed)?\b|"
    r"\bout of scope\b|\bout of the\b|\bnot yet\b|\brequires?\b|\bmust\b|"
    r"\bpause\b|\bbeware\b|\bchallenge\b|\bdisallow(?:ed)?\b|\bwithheld\b)",
    re.IGNORECASE,
)

#: Claim-state tokens. A line carrying one is a row in a claim, boundary or
#: prohibition table, where naming the phrase is the content.
CLAIM_STATE_RE = re.compile(
    r"(?:LEGAL-REVIEW-REQUIRED|ROADMAP|UNSUPPORTED|CONFIGURATION-DEPENDENT|"
    r"Legal-review-required|Prohibited|Forbidden|Out of scope|Not established|"
    r"\bDOC\d+-|\bCLM-|\bmust not\b|\bdo(?:es)? not\b|\bis not\b|\bare not\b)",
    re.IGNORECASE,
)

#: A heading or line that asks a question is not making a claim.
QUESTION_RE = re.compile(r"^\s*#{1,6}\s.*\?\s*$|\?\s*$")

#: A heading that scopes its whole section as denial, exclusion or limitation.
#: Bullets under "What is not controlled here" carry no negation of their own —
#: the heading supplies it — so the section context has to be carried down.
DENIAL_HEADING_RE = re.compile(
    r"(?:\bnot\b|\bno\b|\bnever\b|\bout of scope\b|\bexclusions?\b|\blimits?\b|"
    r"\blimitations?\b|\bboundar(?:y|ies)\b|\bprohibited\b|\bforbidden\b|"
    r"\bunsupported\b|\bdoes not\b|\bdo not\b|\bcannot\b|\bgaps?\b|"
    r"\bwhat .* not\b|\bnever say\b|\bavoid\b|\bcaveats?\b)",
    re.IGNORECASE,
)

HEADING_LINE_RE = re.compile(r"^\s*(#{1,6})\s+(.+?)\s*$")

#: An editorial placeholder marker, as opposed to the same letters occurring
#: inside an identifier or a reference to markers elsewhere. ``TODO:`` at the
#: start of a clause is a placeholder; ``ci-build-placeholder`` is a literal
#: value name and ``critical TODO/FIXME markers listed in ...`` is a reference.
PLACEHOLDER_RE = re.compile(
    r"(?<![\w-])(TODO|TBD|FIXME|XXX)(?![\w-])|(?<![\w-])(Lorem ipsum|Coming soon)(?![\w-])",
    re.IGNORECASE,
)

#: Words that mark a placeholder token as being discussed rather than left behind.
PLACEHOLDER_REFERENCE_RE = re.compile(
    r"(?:\bmarkers?\b|\blisted\b|\bresolve[sd]?\b|\bremove[sd]?\b|\bcontains?\b|"
    r"\bsearch(?:es|ed)?\b|\bgrep\b|\bcheck(?:s|ed)?\b|\bflags?\b|\bforbid(?:s|den)?\b|"
    r"\bno\b|\bnot\b|\bprohibited\b|\bplaceholders?\b)",
    re.IGNORECASE,
)

#: Internal pricing shapes that must never reach README.md.
PRICING_RE = re.compile(
    r"(?:\$\s?\d[\d,]*(?:\.\d+)?\s*(?:k|m|/|per\b)|\bARR\b|\bMRR\b|"
    r"\bprice\s+(?:point|range)\b|\bper[- ]seat\b|\blist price\b)",
    re.IGNORECASE,
)

#: The canonical README status callout marker.
STATUS_CALLOUT_RE = re.compile(r"Current release candidate:", re.IGNORECASE)

LINK_RE = re.compile(r"(?<!\\)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE_RE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    detail: str

    def render(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"  [{self.rule}] {where}\n      {self.detail}"


def _iter_markdown(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*.md"):
        if any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts):
            continue
        out.append(path)
    return sorted(out)


def _strip_code_blocks(lines: list[str]) -> list[tuple[int, str]]:
    """Return (1-indexed line number, text) for prose lines only."""
    return [(number, text) for number, text, _ in _prose_with_headings(lines)]


def _prose_with_headings(lines: list[str]) -> list[tuple[int, str, str]]:
    """Return (line number, prose text, nearest preceding heading).

    The heading travels with the line because denial is often scoped by the
    section rather than by the sentence: a bullet reading "Guaranteed
    prevention of prompt injection." under "What is not controlled here"
    carries no negation of its own, and flagging it would punish the document
    for being well organised.
    """
    out: list[tuple[int, str, str]] = []
    in_fence = False
    heading = ""
    for index, raw in enumerate(lines, start=1):
        if FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_LINE_RE.match(raw)
        if match:
            heading = match.group(2)
        # Inline code is not prose either; a backticked env var is not a claim.
        out.append((index, re.sub(r"`[^`]*`", " ", raw), heading))
    return out


def _is_quoted(text: str, hit_start: int, hit_end: int) -> bool:
    """True when the phrase sits inside quotation marks, i.e. is being named."""
    for opener, closer in (('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’")):
        before = text.rfind(opener, 0, hit_start)
        if before == -1:
            continue
        after = text.find(closer, hit_end)
        if after != -1:
            return True
    return False


def _is_denial(text: str, hit_start: int, hit_end: int, heading: str = "") -> bool:
    """True when the line denies, prohibits, quotes or interrogates the phrase.

    Boundary and claim-control prose must be able to name a prohibited term in
    order to forbid it. Treating every occurrence as an assertion flags exactly
    the rows that are doing the right thing, and a checker that cries wolf gets
    switched off, so the bias here is deliberately toward silence.
    """
    if QUESTION_RE.search(text):
        return True
    if CLAIM_STATE_RE.search(text):
        return True
    if _is_quoted(text, hit_start, hit_end):
        return True
    if heading and DENIAL_HEADING_RE.search(heading):
        return True
    return bool(NEGATION_RE.search(text))


# ── Checks ────────────────────────────────────────────────────────────────────


def check_required_files(root: Path) -> list[Finding]:
    findings = []
    for rel in REQUIRED_FILES:
        if not (root / rel).is_file():
            findings.append(
                Finding(rel, 0, "missing-required-file", "required by the documentation tree")
            )
    return findings


def check_placeholders(path: Path, rel: str, lines: list[str]) -> list[Finding]:
    findings = []
    for line_no, text, heading in _prose_with_headings(lines):
        match = PLACEHOLDER_RE.search(text)
        if not match:
            continue
        # A line that talks *about* placeholder markers - a checker's own rule
        # list, an audit item saying "resolve the TODO markers listed in X" -
        # is not itself a placeholder left behind.
        if PLACEHOLDER_REFERENCE_RE.search(text):
            continue
        if heading and DENIAL_HEADING_RE.search(heading):
            continue
        findings.append(
            Finding(
                rel,
                line_no,
                "placeholder",
                f"{match.group(0)!r} must be resolved, marked "
                "[UNKNOWN_MISSING_PRIMARY_SOURCE], or moved to ROADMAP.md",
            )
        )
    return findings


def check_prohibited_phrases(rel: str, lines: list[str]) -> list[Finding]:
    if rel in CLAIM_CONTROL_FILES:
        return []
    findings = []
    for line_no, text, heading in _prose_with_headings(lines):
        lowered = text.lower()
        for phrase in PROHIBITED_PHRASES:
            start = lowered.find(phrase)
            while start != -1:
                if not _is_denial(text, start, start + len(phrase), heading):
                    findings.append(
                        Finding(
                            rel,
                            line_no,
                            "prohibited-phrase",
                            f"{phrase!r} asserted; see docs/STYLE_GUIDE.md section 3",
                        )
                    )
                    break
                start = lowered.find(phrase, start + 1)
    return findings


def check_links(root: Path, path: Path, rel: str, lines: list[str]) -> list[Finding]:
    findings = []
    for line_no, text in _strip_code_blocks(lines):
        for target in LINK_RE.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            clean = target.split("#", 1)[0]
            if not clean:
                continue
            resolved = (path.parent / clean).resolve()
            if not resolved.exists():
                findings.append(
                    Finding(rel, line_no, "broken-link", f"{target!r} does not resolve")
                )
    return findings


def check_readme_shape(root: Path) -> list[Finding]:
    readme = root / "README.md"
    if not readme.is_file():
        return []
    lines = readme.read_text(encoding="utf-8").splitlines()
    findings = []

    callouts = [n for n, t in _strip_code_blocks(lines) if STATUS_CALLOUT_RE.search(t)]
    if len(callouts) > 1:
        findings.append(
            Finding(
                "README.md",
                callouts[1],
                "duplicate-status-callout",
                f"release status stated {len(callouts)} times (lines {callouts}); "
                "state it once and link docs/RELEASE_STATUS.md",
            )
        )

    for line_no, text in _strip_code_blocks(lines):
        match = PRICING_RE.search(text)
        if match:
            findings.append(
                Finding(
                    "README.md",
                    line_no,
                    "pricing-in-readme",
                    f"{match.group(0)!r} is internal commercial detail; keep it out of README",
                )
            )
    return findings


def check_internal_markers(root: Path) -> list[Finding]:
    findings = []
    for rel in sorted(INTERNAL_FILES):
        path = root / rel
        if not path.is_file():
            continue
        head = path.read_text(encoding="utf-8")[:600]
        if INTERNAL_MARKER not in head:
            findings.append(
                Finding(
                    rel,
                    1,
                    "missing-internal-marker",
                    "internal documents must open with the marker from "
                    "docs/STYLE_GUIDE.md section 9",
                )
            )
    return findings


def check_trailing_newline(path: Path, rel: str) -> list[Finding]:
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        return [Finding(rel, 0, "no-final-newline", "file must end with a newline")]
    return []


def check_non_empty(root: Path) -> list[Finding]:
    findings = []
    for rel in ("docs/CLAIMS_MATRIX.md", "docs/RELEASE_STATUS.md"):
        path = root / rel
        if path.is_file() and len(path.read_text(encoding="utf-8").strip()) < 200:
            findings.append(Finding(rel, 0, "empty-control-document", "must be non-empty"))
    return findings


def run(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_required_files(root)
    findings += check_readme_shape(root)
    findings += check_internal_markers(root)
    findings += check_non_empty(root)

    for path in _iter_markdown(root):
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            findings.append(Finding(rel, 0, "unreadable", "file is not valid UTF-8"))
            continue
        findings += check_placeholders(path, rel, lines)
        findings += check_prohibited_phrases(rel, lines)
        findings += check_links(root, path, rel, lines)
        findings += check_trailing_newline(path, rel)

    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not (root / "README.md").is_file():
        print(f"error: {root} does not look like the repository root", file=sys.stderr)
        return 2

    findings = run(root)

    if args.json:
        print(
            json.dumps(
                {
                    "status": "PASS" if not findings else "FAIL",
                    "count": len(findings),
                    "findings": [f.__dict__ for f in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if findings else 0

    if not findings:
        print("verify_docs: PASS (0 findings)")
        return 0

    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule, []).append(finding)

    print(f"verify_docs: FAIL ({len(findings)} findings)\n")
    for rule in sorted(by_rule):
        group = by_rule[rule]
        print(f"{rule} ({len(group)}):")
        for finding in group:
            print(finding.render())
        print()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
