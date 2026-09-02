#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Claim-control consistency checks for ``docs/CLAIMS_MATRIX.md``.

``scripts/verify_docs.py`` checks that documents are structurally sound. This
checks that the claims register is internally coherent and that the corpus does
not reference claim identifiers the register does not define.

Checks performed:

1. Every claim row parses and carries a recognised evidence state.
2. Claim identifiers are unique and contiguous.
3. ``IMPLEMENTED`` and ``MEASURED`` rows carry an evidence locator.
4. A ``ROADMAP`` row that cites source carries a boundary that denies the
   capability. Citing source on a Roadmap row is legitimate — it explains why
   the capability is not claimed — but without a denial in the boundary a
   reader takes the citation as confirmation that it exists.
5. Every row carries a boundary. A claim without a stated boundary is the
   failure mode this register exists to prevent.
6. Every ``CLM-NNN`` referenced anywhere in the corpus is defined here.
7. Every claim is covered by a control-register range (forbidden phrasing,
   review date, owner).

Exit codes: 0 clean, 1 findings, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

MATRIX = "docs/CLAIMS_MATRIX.md"

VALID_STATES = {
    "IMPLEMENTED",
    "MEASURED",
    "CONFIGURATION-DEPENDENT",
    "ROADMAP",
    "LEGAL-REVIEW-REQUIRED",
}

#: States that must name where the evidence lives.
REQUIRE_LOCATOR = {"IMPLEMENTED", "MEASURED"}

#: Phrases a row uses to say, correctly, that no evidence exists.
NO_EVIDENCE_MARKERS = (
    "no ",
    "none",
    "not applicable",
    "n/a",
    "does not exist",
)

#: A boundary that denies the capability. A ROADMAP row that cites source must
#: carry one, or a reader takes the citation as confirmation.
DENIAL_RE = re.compile(
    r"(?:\bnot\b|\bno\b|\bnever\b|\bonly\b|\bdoes not\b|\bis not\b|\bcannot\b|"
    r"\bwithout\b|\brequires?\b|\bmust\b|\bunless\b|\bpending\b|\bexcept\b)",
    re.IGNORECASE,
)

CLAIM_ROW_RE = re.compile(r"^\|\s*`(CLM-\d{3})`\s*\|(.*)$")
CLAIM_REF_RE = re.compile(r"`?(CLM-\d{3})`?")
RANGE_RE = re.compile(r"`(CLM-\d{3})`\s*[–\-]\s*`(CLM-\d{3})`")
STATE_RE = re.compile(r"`([A-Z][A-Z-]+)`")

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    ".next",
    "target",
    "htmlcov",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
}


@dataclass(frozen=True)
class Finding:
    claim: str
    rule: str
    detail: str

    def render(self) -> str:
        return f"  [{self.rule}] {self.claim}\n      {self.detail}"


@dataclass(frozen=True)
class Claim:
    ident: str
    text: str
    state: str
    locator: str
    boundary: str
    line: int


def _split_row(body: str) -> list[str]:
    """Split a Markdown row body on unescaped pipes, ignoring pipes in code."""
    cells, buf, in_code = [], [], False
    for char in body:
        if char == "`":
            in_code = not in_code
        if char == "|" and not in_code:
            cells.append("".join(buf).strip())
            buf = []
            continue
        buf.append(char)
    cells.append("".join(buf).strip())
    return [c for c in cells if c != ""] or cells


def parse_claims(text: str) -> tuple[list[Claim], list[Finding]]:
    claims: list[Claim] = []
    findings: list[Finding] = []
    for line_no, line in enumerate(text.split("\n"), start=1):
        match = CLAIM_ROW_RE.match(line)
        if not match:
            continue
        ident = match.group(1)
        cells = _split_row(match.group(2))
        if len(cells) < 4:
            findings.append(
                Finding(ident, "malformed-row", f"line {line_no}: expected 4 cells after the ID")
            )
            continue
        claim_text, state_cell, locator, boundary = cells[0], cells[1], cells[2], cells[3]
        state_match = STATE_RE.search(state_cell)
        state = state_match.group(1) if state_match else ""
        claims.append(Claim(ident, claim_text, state, locator, boundary, line_no))
    return claims, findings


def check_claims(claims: list[Claim]) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[str, int] = {}

    for claim in claims:
        if claim.ident in seen:
            findings.append(
                Finding(
                    claim.ident,
                    "duplicate-id",
                    f"also defined at line {seen[claim.ident]}",
                )
            )
        seen[claim.ident] = claim.line

        if claim.state not in VALID_STATES:
            findings.append(
                Finding(
                    claim.ident,
                    "invalid-state",
                    f"{claim.state or '(none)'!r} is not one of {sorted(VALID_STATES)}",
                )
            )
            continue

        locator_lower = claim.locator.lower()
        says_no_evidence = any(locator_lower.startswith(m) for m in NO_EVIDENCE_MARKERS)

        if claim.state in REQUIRE_LOCATOR and (len(claim.locator) < 8 or says_no_evidence):
            findings.append(
                Finding(
                    claim.ident,
                    "missing-locator",
                    f"state {claim.state} requires an evidence locator; got {claim.locator!r}",
                )
            )

        if claim.state == "ROADMAP" and not says_no_evidence and len(claim.locator) > 8:
            # A ROADMAP row legitimately cites source to explain *why* the
            # capability is not claimed — "rotation applies 0o600, which is
            # access restriction, not immutability". What must never happen is
            # a ROADMAP row that cites source and then reads as confirmation,
            # so the boundary has to carry the denial.
            if not DENIAL_RE.search(claim.boundary):
                findings.append(
                    Finding(
                        claim.ident,
                        "roadmap-without-denial",
                        f"ROADMAP row cites evidence ({claim.locator!r}) but its boundary "
                        "does not deny the capability. A reader will take the locator as "
                        "confirmation. State plainly what the cited source does not do.",
                    )
                )

        if len(claim.boundary) < 20:
            findings.append(
                Finding(
                    claim.ident,
                    "missing-boundary",
                    "every claim states what it does not establish",
                )
            )

    numbers = sorted(int(c.ident.split("-")[1]) for c in claims)
    for expected, actual in enumerate(numbers, start=1):
        if expected != actual:
            findings.append(
                Finding(
                    f"CLM-{actual:03d}",
                    "non-contiguous-ids",
                    f"expected CLM-{expected:03d}; renumbering breaks external references",
                )
            )
            break

    return findings


def check_control_register(text: str, claims: list[Claim]) -> list[Finding]:
    covered: set[int] = set()
    for start, end in RANGE_RE.findall(text):
        covered.update(range(int(start.split("-")[1]), int(end.split("-")[1]) + 1))
    findings = []
    for claim in claims:
        number = int(claim.ident.split("-")[1])
        if number not in covered:
            findings.append(
                Finding(
                    claim.ident,
                    "uncovered-by-control-register",
                    "no control-register range supplies forbidden phrasing, review date and owner",
                )
            )
    return findings


def check_corpus_references(root: Path, claims: list[Claim]) -> list[Finding]:
    defined = {c.ident for c in claims}
    findings = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*.md")):
        rel = path.relative_to(root).as_posix()
        if any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts):
            continue
        if rel == MATRIX:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for ident in set(CLAIM_REF_RE.findall(body)):
            if ident not in defined and (rel, ident) not in seen:
                seen.add((rel, ident))
                findings.append(Finding(ident, "undefined-claim-reference", f"referenced by {rel}"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    matrix = root / MATRIX
    if not matrix.is_file():
        print(f"error: {MATRIX} not found under {root}", file=sys.stderr)
        return 2

    text = matrix.read_text(encoding="utf-8")
    claims, findings = parse_claims(text)

    if not claims:
        print(f"error: no claim rows parsed from {MATRIX}", file=sys.stderr)
        return 2

    findings += check_claims(claims)
    findings += check_control_register(text, claims)
    findings += check_corpus_references(root, claims)

    if args.json:
        print(
            json.dumps(
                {
                    "status": "PASS" if not findings else "FAIL",
                    "claims": len(claims),
                    "count": len(findings),
                    "findings": [f.__dict__ for f in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if findings else 0

    if not findings:
        print(f"verify_claims: PASS ({len(claims)} claims, 0 findings)")
        return 0

    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule, []).append(finding)

    print(f"verify_claims: FAIL ({len(claims)} claims, {len(findings)} findings)\n")
    for rule in sorted(by_rule):
        group = by_rule[rule]
        print(f"{rule} ({len(group)}):")
        for finding in group:
            print(finding.render())
        print()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
