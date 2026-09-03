#!/usr/bin/env python3
"""Validate the Aegis documentation contract without external dependencies."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

REQUIRED_FILES = (
    "README.md",
    "docs/DEVELOPER_QUICKSTART.md",
    "docs/PLATFORM_OPERATOR_GUIDE.md",
    "docs/security/THREAT_MODEL.md",
    "docs/security/WAF_TESTING.md",
    "docs/security/PQC_CONSTANT_TIME.md",
    "docs/BUYER_GUIDE_US.md",
    "docs/PRODUCT_BRIEF_US.md",
    "docs/COMMERCIAL_STRATEGY_US.md",
    "docs/compliance/COMPLIANCE_MAPPING.md",
    "docs/privacy/DATA_RETENTION.md",
    "docs/operations/BACKPRESSURE_RUNBOOK.md",
    "docs/operations/KEY_ROTATION_RUNBOOK.md",
    "docs/operations/ROLLBACK_RUNBOOK.md",
    "docs/architecture/ARCHITECTURE.md",
    "docs/benchmarks/README.md",
    "docs/benchmarks/BENCHMARK_RESULTS.md",
    "docs/CLAIMS_MATRIX.md",
    "docs/performance/SCALING_GUIDE.md",
    "docs/FAQ_TECHNICAL.md",
    "docs/FAQ_PROCUREMENT.md",
    "docs/FAQ_SECURITY.md",
    "COMMERCIAL.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "DEPLOYMENT_GUIDE.md",
)

FORBIDDEN_UNQUALIFIED = (
    re.compile(r"\b(?:SOC 2|HIPAA|FedRAMP|GDPR|EU AI Act)\s+compliant\b", re.IGNORECASE),
    re.compile(r"\b(?:court[- ]admissible|court admissibility)\b", re.IGNORECASE),
    re.compile(r"\b(?:constant[- ]time|constant time)\b", re.IGNORECASE),
    re.compile(r"\b(?:unlimited throughput|zero latency|zero overhead)\b", re.IGNORECASE),
    re.compile(r"\b(?:24/7|mission-critical SLA|sovereign assurance)\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class ClaimRule:
    """A high-risk documentation claim and its explicit boundary language."""

    name: str
    pattern: re.Pattern[str]
    disclaimer: re.Pattern[str]


STRICT_BOUNDARY_LANGUAGE = re.compile(
    r"\b(?:blocked(?: wording)?|blocks?(?: any| the phrase)?|do not use|roadmap|not evidence|not a proof|"
    r"does not (?:prove|establish|claim)|no .{0,40} claim|without a named (?:artifact|scope))\b",
    re.IGNORECASE,
)


STRICT_CLAIM_RULES = (
    ClaimRule(
        "certification or compliance",
        re.compile(
            r"(?:\b(?:SOC 2|HIPAA|FedRAMP|GDPR|EU AI Act)\b.{0,40}"
            r"\b(?:certified|compliant)\b"
            r"|\bAegis\b.{0,40}\b(?:is|is fully|has been)\s+(?:certified|compliant)\b)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:not|never|no|does not|do not|cannot|must not)\b.{0,100}"
            r"\b(?:certif|complian)|\bnot a certification\b",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "constant-time cryptography",
        re.compile(r"\bconstant[- ]time\b", re.IGNORECASE),
        re.compile(
            r"\b(?:no|not|does not|do not|cannot|must not)\b.{0,300}\bconstant[- ]time"
            r"|\bconstant[- ]time\b.{0,60}\b(?:not|blocked|unapproved|unauthorized)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "billion-scale millisecond performance",
        re.compile(
            r"(?:\bbillion(?:-scale)?\b.{0,100}\bmillisecond"
            r"|\bmillisecond\w*\b.{0,100}\bbillion(?:-scale)?\b)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:no|not|does not|do not|cannot|must not)\b.{0,220}"
            r"(?:billion(?:-scale)?.{0,100}millisecond|millisecond\w*.{0,100}billion)",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "production capacity or readiness",
        re.compile(
            r"\b(?:production[- ]ready|ready for production|production capacity)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:\bnot\s+(?:production[- ]ready|ready for production)\b"
            r"|\bnot\s+(?:an?\s+|accepted\s+)?production\s+capacity\b"
            r"|\bno\s+production\s+(?:capacity|readiness)\s+claim\b"
            r"|\b(?:does not|cannot)\s+(?:establish|claim|prove|publish|predict)\s+"
            r"(?:an?\s+)?production\s+"
            r"(?:capacity|readiness)\b)",
            re.IGNORECASE,
        ),
    ),
    ClaimRule(
        "v4 external publication or release",
        re.compile(
            r"(?:\b(?:v?4(?:\.0(?:\.0)?)?|version 4)\b.{0,100}\b(?:published|released)\b"
            r"|\b(?:published|released)\b.{0,100}\b(?:v?4(?:\.0(?:\.0)?)?|version 4)\b)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:not|never|no|unreleased|unpublished|does not|do not|cannot|must not)\b"
            r".{0,160}\b(?:published|released|publication|release|v?4(?:\.0(?:\.0)?)?)\b",
            re.IGNORECASE,
        ),
    ),
)

LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


@dataclass(frozen=True)
class Finding:
    severity: str
    path: str
    line: int
    message: str


def is_external_link(target: str) -> bool:
    parsed = urlparse(target)
    return bool(parsed.scheme or parsed.netloc or target.startswith("mailto:"))


def strip_anchor(target: str) -> str:
    return target.split("#", 1)[0]


def _is_markdown_separator(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def _claim_is_in_boundary_table_column(lines: list[str], line_index: int, claim_start: int) -> bool:
    """Recognize a claim only when its table column is explicitly a limitation."""

    line = lines[line_index]
    if not line.lstrip().startswith("|"):
        return False
    claim_column = line[:claim_start].count("|") - 1
    if claim_column < 0:
        return False
    for index in range(line_index - 1, max(-1, line_index - 50), -1):
        candidate = lines[index]
        if not candidate.lstrip().startswith("|"):
            return False
        if not _is_markdown_separator(candidate):
            continue
        if index == 0:
            return False
        headers = [cell.strip().lower() for cell in lines[index - 1].strip().strip("|").split("|")]
        if claim_column >= len(headers):
            return False
        header = headers[claim_column]
        return any(
            boundary in header
            for boundary in (
                "cannot establish",
                "does not establish",
                "explicit limit",
                "limitation",
                "boundary",
                "non-claim",
                "do not use",
            )
        )
    return False


def _has_immediate_boundary_directive(lines: list[str], line_index: int) -> bool:
    """Accept only the nearest nonblank directive that explicitly scopes following text."""

    for index in range(line_index - 1, max(-1, line_index - 4), -1):
        candidate = lines[index].strip()
        if not candidate:
            continue
        return bool(
            candidate.endswith(":")
            and re.search(r"\b(?:blocked|prohibited|do not use)\b", candidate, re.IGNORECASE)
        )
    return False


def _claim_is_in_explicit_roadmap_row(line: str) -> bool:
    """Recognize a Markdown row whose separate status cell is exactly ROADMAP."""

    if not line.lstrip().startswith("|"):
        return False
    cells = [cell.strip().strip("`").upper() for cell in line.strip().strip("|").split("|")]
    return "ROADMAP" in cells


def _without_inline_code(line: str) -> str:
    """Mask simple Markdown code spans before prose claim analysis."""

    return re.sub(r"`+[^`]*`+", "", line)


def _prose_paragraphs(lines: list[str]) -> list[tuple[int, int, str]]:
    """Return non-code, non-table prose paragraphs with their first line number."""

    paragraphs: list[tuple[int, int, str]] = []
    current: list[tuple[int, str]] = []
    start = 0
    fence: str | None = None

    def flush() -> None:
        nonlocal current, start
        if current:
            paragraphs.append((start, current[-1][0], " ".join(text for _, text in current)))
            current = []
            start = 0

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        marker = (
            "```" if stripped.startswith("```") else "~~~" if stripped.startswith("~~~") else None
        )
        if marker is not None:
            flush()
            fence = None if fence == marker else marker
            continue
        if fence is not None:
            continue
        sanitized = _without_inline_code(line).strip()
        if not sanitized or sanitized.startswith("|") or HEADING_RE.match(sanitized):
            flush()
            continue
        if not current:
            start = number
        current.append((number, sanitized))
    flush()
    return paragraphs


def check_required(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for relative in REQUIRED_FILES:
        path = root / relative
        if not path.is_file():
            findings.append(Finding("ERROR", relative, 0, "required documentation file is missing"))
    return findings


def check_document(path: Path, root: Path, *, strict: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    relative = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    first_content_line = 0
    in_leading_comment = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("<!--"):
            in_leading_comment = True
            if "-->" in stripped[4:]:
                in_leading_comment = False
            continue
        if in_leading_comment:
            if "-->" in stripped:
                in_leading_comment = False
            continue
        # The internal-distribution marker from docs/STYLE_GUIDE.md section 9
        # is a handling notice and sits above the title deliberately, so a
        # reader cannot miss it. Treat it like the legal comments above.
        if stripped.startswith(">") and "INTERNAL DOCUMENT" in stripped:
            continue
        first_content_line = index
        break
    if (
        not lines
        or first_content_line >= len(lines)
        or not lines[first_content_line].startswith("# ")
    ):
        findings.append(
            Finding(
                "ERROR",
                relative,
                first_content_line + 1,
                "document must start with an H1 heading after legal comments",
            )
        )
    if relative == "README.md":
        # Release status lives in exactly one place and README links to it;
        # see docs/DOCUMENTATION_GOVERNANCE.md. Requiring the inline metadata
        # the old README carried would now force the duplication that
        # scripts/verify_docs.py rejects, so require the routing instead.
        # The status label is an alternation because the repository's state
        # moved: "Current release candidate:" was accurate while nothing was
        # published, and "Current release:" is accurate now that v4.1.1 is.
        # Both are accepted so the check survives the next transition in
        # either direction; what it enforces is that README carries a status
        # label at all, not which of the two the current state warrants.
        readme_required: tuple[str | tuple[str, ...], ...] = (
            ("Current release:", "Current release candidate:"),
            "docs/RELEASE_STATUS.md",
            "docs/BOUNDARIES.md",
        )
        for required in readme_required:
            accepted = required if isinstance(required, tuple) else (required,)
            if not any(option in text for option in accepted):
                findings.append(
                    Finding(
                        "ERROR",
                        relative,
                        1,
                        "README must surface status and route onward: missing "
                        + " or ".join(accepted),
                    )
                )
    else:
        for required in ("Last verified:", "Release baseline:", "## Related documents"):
            if required not in text:
                findings.append(
                    Finding(
                        "ERROR", relative, 1, f"missing required metadata or section: {required}"
                    )
                )

    previous_level = 0
    fence: str | None = None
    strict_matches: set[tuple[str, int]] = set()
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        marker = (
            "```" if stripped.startswith("```") else "~~~" if stripped.startswith("~~~") else None
        )
        if marker is not None:
            fence = None if fence == marker else marker
            continue
        if fence is not None:
            continue
        heading = HEADING_RE.match(line)
        if heading:
            level = len(heading.group(1))
            if level > previous_level + 1 and previous_level:
                findings.append(
                    Finding(
                        "ERROR",
                        relative,
                        number,
                        f"heading level jumps from H{previous_level} to H{level}",
                    )
                )
            previous_level = level

        for match in LINK_RE.finditer(line):
            target = match.group(1).strip().strip("<>")
            if not target or is_external_link(target):
                continue
            target_path = strip_anchor(target)
            if not target_path:
                continue
            resolved = (path.parent / target_path).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                findings.append(
                    Finding(
                        "ERROR", relative, number, f"relative link escapes repository: {target}"
                    )
                )
                continue
            if not resolved.exists():
                findings.append(
                    Finding(
                        "ERROR", relative, number, f"relative link target does not exist: {target}"
                    )
                )

        if "TODO" in line or "lorem ipsum" in line.lower():
            findings.append(
                Finding("ERROR", relative, number, "placeholder content is not allowed")
            )

        strict_match = False
        claim_line = _without_inline_code(line)
        if strict and heading is None:
            for rule in STRICT_CLAIM_RULES:
                claim_match = rule.pattern.search(claim_line)
                if claim_match is None:
                    continue
                if (
                    rule.disclaimer.search(claim_line)
                    or STRICT_BOUNDARY_LANGUAGE.search(claim_line)
                    or _claim_is_in_boundary_table_column(lines, number - 1, claim_match.start())
                    or _claim_is_in_explicit_roadmap_row(line)
                    or _has_immediate_boundary_directive(lines, number - 1)
                ):
                    continue
                if rule.name == "constant-time cryptography" and re.search(
                    r"\bconstant[- ]time comparison\b", claim_line, re.IGNORECASE
                ):
                    continue
                strict_match = True
                strict_matches.add((rule.name, number))
                findings.append(
                    Finding(
                        "ERROR",
                        relative,
                        number,
                        f"unqualified {rule.name} claim is prohibited in strict mode",
                    )
                )

        for pattern in FORBIDDEN_UNQUALIFIED:
            if pattern.search(claim_line):
                context = "\n".join(lines[max(0, number - 6) : number]).lower()
                allowed = any(
                    phrase in context
                    for phrase in (
                        "not compliant",
                        "does not claim",
                        "no constant-time",
                        "constant-time claim is blocked",
                        "not a constant-time",
                        "not court-admissible",
                        "not court admissibility",
                        "not 24/7",
                        "not mission-critical",
                        "not sovereign assurance",
                        "not prove",
                        "not a proof",
                        "not authorized",
                        "not automatically",
                        "cannot establish",
                        "proof of",
                        "do not use",
                        "instead of",
                        "does not",
                        "cannot",
                        "without",
                        "no ",
                        "blocked",
                        "blocks any",
                        "blocked without",
                        "must not",
                        "constant-time comparison",
                        "prohibited",
                        "## is ",
                    )
                )
                if not allowed and not strict_match:
                    findings.append(
                        Finding(
                            "WARNING",
                            relative,
                            number,
                            f"claim wording requires boundary review: {pattern.pattern}",
                        )
                    )

    if fence is not None:
        findings.append(Finding("ERROR", relative, len(lines), "unclosed fenced code block"))
    if strict:
        for start, end, paragraph in _prose_paragraphs(lines):
            for rule in STRICT_CLAIM_RULES:
                if (
                    rule.pattern.search(paragraph) is None
                    or rule.disclaimer.search(paragraph)
                    or STRICT_BOUNDARY_LANGUAGE.search(paragraph)
                    or _has_immediate_boundary_directive(lines, start - 1)
                ):
                    continue
                if rule.name == "constant-time cryptography" and re.search(
                    r"\bconstant[- ]time comparison\b", paragraph, re.IGNORECASE
                ):
                    continue
                if any(
                    name == rule.name and start <= line_number <= end
                    for name, line_number in strict_matches
                ):
                    continue
                findings.append(
                    Finding(
                        "ERROR",
                        relative,
                        start,
                        f"unqualified multiline {rule.name} claim is prohibited in strict mode",
                    )
                )

    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="make unqualified high-risk product and release claims fatal",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"ERROR: repository root does not exist: {root}", file=sys.stderr)
        return 2

    findings = check_required(root)
    for relative in REQUIRED_FILES:
        path = root / relative
        if path.is_file():
            findings.extend(check_document(path, root, strict=args.strict))

    errors = [finding for finding in findings if finding.severity == "ERROR"]
    warnings = [finding for finding in findings if finding.severity == "WARNING"]
    result = {
        "root": str(root),
        "required_files": len(REQUIRED_FILES),
        "errors": len(errors),
        "warnings": len(warnings),
        "strict": args.strict,
        "status": "PASS" if not errors else "FAIL",
        "findings": [asdict(finding) for finding in findings],
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
