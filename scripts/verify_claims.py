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
8. Every path a claim cites as evidence resolves in the tree. A locator naming
   an artifact that is not present is the same failure as no locator at all:
   the reader takes the citation as confirmation that the artifact exists.
9. A figure the claims register retracts does not survive as a citation. A line
   (or, for wrapped prose, a paragraph) that cites a retracted token must also
   carry its retraction, so the only surviving mentions are the retraction
   records themselves. ``UC-018`` retracts the ``v3.1.0`` 10,000-record /
   p99 1,189.89 ms backpressure pair: no artifact in this tree produces it.

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

#: Suffixes that make a backticked token a file locator rather than prose or a
#: dotted symbol name. The set is closed on purpose: `RFC3161Timestamper.verify`
#: is a symbol, and treating every dotted token as a path reports it as a
#: missing file.
LOCATOR_SUFFIXES = frozenset(
    {
        "cfg",
        "cff",
        "csv",
        "html",
        "ini",
        "js",
        "json",
        "jsonl",
        "lock",
        "md",
        "proto",
        "py",
        "rs",
        "sh",
        "sig",
        "smt2",
        "sql",
        "tgz",
        "toml",
        "ts",
        "tsx",
        "txt",
        "whl",
        "yaml",
        "yml",
    }
)

LOCATOR_TOKEN_RE = re.compile(r"`([^`]+)`")
BRACE_GLOB_RE = re.compile(r"\{([^{}]*)\}")
#: `path.py:118`, `path.py:118-140` and `path.py::symbol` all point at a file.
REFERENCE_SUFFIX_RE = re.compile(r"(?:::[A-Za-z_][A-Za-z0-9_]*|:\d[\d,\-]*).*$")

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

#: Tokens the claims register retracts, as ``(token, row)``. A multi-line
#: paragraph is treated as one unit, because wrapped prose splits a citation
#: from its retraction; markdown table rows are treated individually, so a
#: retraction in one row cannot cover an unmarked citation in the next.
RETRACTED_FIGURES: tuple[tuple[str, str], ...] = (
    ("1,189.89", "UC-018"),
    ("1189.89", "UC-018"),
    ("10,000 offered requests", "UC-018"),
    ("10,000 durable", "UC-018"),
)

#: Phrases that mark a retraction. Checked case-insensitively.
RETRACTION_MARKERS: tuple[str, ...] = ("retract", "uc-018", "not citable")

#: Files that record the finding instead of citing the figure: the forensic
#: audit report quotes the defective text verbatim as its evidence.
RETRACTION_EXEMPT_PATHS: tuple[str, ...] = ("AUDIT_REPORT_v5.0.1_PREP.md",)


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
    cells: list[str] = []
    buf: list[str] = []
    in_code = False
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


def _expand_braces(token: str) -> list[str]:
    """Expand one level of ``{a,b}`` so a glob citation can be resolved."""
    match = BRACE_GLOB_RE.search(token)
    if not match:
        return [token]
    expanded: list[str] = []
    for alternative in match.group(1).split(","):
        replaced = token[: match.start()] + alternative + token[match.end() :]
        expanded.extend(_expand_braces(replaced))
    return expanded


def _is_locator_token(token: str) -> bool:
    """True when a backticked token names a path rather than prose or a symbol."""
    token = token.strip()
    if not token or " " in token or token.startswith("http"):
        return False
    if token.endswith("/"):
        return True
    tail = token.rsplit("/", 1)[-1]
    if "." not in tail:
        # `amazon/dynamodb-local` is a container image reference, not a path.
        return False
    return tail.rsplit(".", 1)[-1].lower() in LOCATOR_SUFFIXES


def _locator_resolves(root: Path, token: str) -> bool:
    return (root / token).exists() or (root / "evidence" / "registry" / token).exists()


def _retracted_blocks(body: str) -> list[tuple[int, str]]:
    """Group a document into ``(first line number, text)`` units for check 9.

    Blank lines separate paragraphs; markdown table rows are their own unit.
    """
    blocks: list[tuple[int, str]] = []
    para: list[str] = []
    para_line = 1
    for number, line in enumerate(body.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("|"):
            if para:
                blocks.append((para_line, "\n".join(para)))
                para = []
            blocks.append((number, line))
            continue
        if not stripped:
            if para:
                blocks.append((para_line, "\n".join(para)))
                para = []
            continue
        if not para:
            para_line = number
        para.append(line)
    if para:
        blocks.append((para_line, "\n".join(para)))
    return blocks


def check_retracted_figures(
    root: Path, exempt: tuple[str, ...] = RETRACTION_EXEMPT_PATHS
) -> list[Finding]:
    """A retracted figure must not survive as an unmarked citation."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.md")):
        rel = path.relative_to(root).as_posix()
        if any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts):
            continue
        if rel in exempt:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for start, block in _retracted_blocks(body):
            lowered = block.lower()
            if any(marker in lowered for marker in RETRACTION_MARKERS):
                continue
            for token, row in RETRACTED_FIGURES:
                if token in block:
                    findings.append(
                        Finding(
                            row,
                            "retracted-figure-cited",
                            f"{rel}:{start} cites {token!r} without its retraction "
                            f"({row}) on the same line or paragraph",
                        )
                    )
                    break
    return findings


def check_locator_paths(root: Path, claims: list[Claim]) -> list[Finding]:
    """Every artifact a claim cites must exist, or the citation claims too much.

    The failure mode is the one this register exists to prevent: a reader takes
    a cited path as confirmation that the evidence is there. A locator naming an
    artifact outside the tree -- a release-envelope file, or one that was renamed
    and never followed up -- is reported here instead of being read as present. A
    row with no evidence (see ``NO_EVIDENCE_MARKERS``) is exempt, as are tokens
    naming a symbol rather than a file.
    """
    findings: list[Finding] = []
    for claim in claims:
        if any(claim.locator.lower().startswith(marker) for marker in NO_EVIDENCE_MARKERS):
            continue
        for raw in LOCATOR_TOKEN_RE.findall(claim.locator):
            token = raw.strip()
            if not _is_locator_token(token):
                continue
            for alternative in _expand_braces(token):
                path = REFERENCE_SUFFIX_RE.sub("", alternative).strip()
                if path and not _locator_resolves(root, path):
                    findings.append(
                        Finding(
                            claim.ident,
                            "unresolvable-locator",
                            f"cited evidence path does not resolve: {path!r}. Name an "
                            "artifact that is in the tree, or state in the boundary "
                            "that the cited artifact is not in this tree.",
                        )
                    )
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
    findings += check_locator_paths(root, claims)
    findings += check_retracted_figures(root)

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
