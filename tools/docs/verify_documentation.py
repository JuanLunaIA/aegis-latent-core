#!/usr/bin/env python3
"""Validate the Aegis documentation contract without external dependencies."""

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


def check_required(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for relative in REQUIRED_FILES:
        path = root / relative
        if not path.is_file():
            findings.append(Finding("ERROR", relative, 0, "required documentation file is missing"))
    return findings


def check_document(path: Path, root: Path) -> list[Finding]:
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
    for required in ("Last verified:", "Release baseline:", "## Related documents"):
        if required not in text:
            findings.append(
                Finding("ERROR", relative, 1, f"missing required metadata or section: {required}")
            )

    previous_level = 0
    in_fence = False
    for number, line in enumerate(lines, start=1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
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

        for pattern in FORBIDDEN_UNQUALIFIED:
            if pattern.search(line):
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
                if not allowed:
                    findings.append(
                        Finding(
                            "WARNING",
                            relative,
                            number,
                            f"claim wording requires boundary review: {pattern.pattern}",
                        )
                    )

    if in_fence:
        findings.append(Finding("ERROR", relative, len(lines), "unclosed fenced code block"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"ERROR: repository root does not exist: {root}", file=sys.stderr)
        return 2

    findings = check_required(root)
    for relative in REQUIRED_FILES:
        path = root / relative
        if path.is_file():
            findings.extend(check_document(path, root))

    errors = [finding for finding in findings if finding.severity == "ERROR"]
    warnings = [finding for finding in findings if finding.severity == "WARNING"]
    result = {
        "root": str(root),
        "required_files": len(REQUIRED_FILES),
        "errors": len(errors),
        "warnings": len(warnings),
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
