#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Normalize a Socket.dev PDF report into machine-readable alert rows.

    python scripts/triage/parse_socket_report.py \
        --input dependency-alerts-report.pdf \
        --output evidence/dependency-scan/2026-09-09/socket-alerts.json

A PDF is a layout format, not a data format: the exported tables wrap package
names mid-token, split column headers across lines, and repeat page furniture.
Reading them by eye does not scale and does not survive the next scan, so this
converts a report once into JSON that `dependency_triage.py --scan-export`
consumes. The JSON is committed as evidence; the PDF is not, because a binary
nobody can diff is a poor record of what a gate was run against.

Two report shapes are recognized, and they mean different things:

**Dependency alerts** (``Row | Alert Type | Category | Severity | Ecosystem |
Package | Version | Dependency | Manifest(s) | File Details``) are alerts
against *this repository's* dependency graph. Every row is this project's to
triage.

**Threat feed** (``Ecosystem | Package | Version | Type | Description |
Created At | Removed At | File Path``) is an ecosystem-wide sample of what the
scanner flagged across a registry. Its rows are **not** alerts against this
repository, and a package appearing there means nothing here unless this
repository actually depends on it. The distinction is recorded in the output
so a reader cannot mistake one for the other.

Wrapping is undone before parsing: a hyphen at a line break rejoins with no
space (``dashboard/package-\\nlock.json``), and a break inside an
underscore-joined identifier leaves a space that is stripped from the package
field (``windows_aarch64_gnu\\nllvm``). Package names in these ecosystems never
contain spaces, which is what makes that safe.

Exit codes: 0 parsed cleanly, 1 rows failed to parse, 2 the input could not be
read. A row that cannot be parsed is a hard failure rather than a skip: the
triage promises every row appears exactly once, and a silent drop breaks that.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

FORMAT: Final[str] = "aegis-scanner-alert-rows-v1"

KIND_DEPENDENCY_ALERTS: Final[str] = "dependency_alerts"
KIND_THREAT_FEED: Final[str] = "threat_feed"

ECOSYSTEMS: Final[str] = "npm|pypi|cargo|golang|maven|nuget|rubygems"
SEVERITIES: Final[str] = "Low|Medium|High|Critical"

#: Alert-type labels the dependency report uses. A row is recognized by one of
#: these following its row number, which is what lets a row be told apart from
#: a version string that happens to start a wrapped line.
ALERT_TYPES: Final[tuple[str, ...]] = (
    "Unmaintained",
    "Deprecated",
    "Install scripts",
    "Minified code",
    "AI-detected potential security risk",
    "Obfuscated code",
    "Potential vulnerability",
    "Network access",
    "Filesystem access",
    "Environment variable access",
    "Shell access",
    "Unpopular package",
    "New author",
    "Known malware",
    "Native code",
    "Debug access",
    "Telemetry",
    "Dynamic require",
    "Uses eval",
    "Bin script confusion",
    "Non-permissive License",
    "Copyleft License",
    "Unidentified License",
    "Socket optimized override available",
    "Long strings",
    "URL strings",
    "Low CVE",
    "Medium CVE",
    "High CVE",
    "Critical CVE",
)

_DEPENDENCY_HEADER = re.compile(
    r"Ro\s*\nw\s*\nAlert Type Category Severity Ecosyste\s*\nm\s*\n"
    r"Package Version Dependency Manifest\(s\) File Details\n"
)
_THREAT_HEADER = re.compile(
    r"Ecosystem Package Version Type Description Created At Removed At File Path\n"
)
_PAGE_FURNITURE = re.compile(r"Page \d+Generated: [^\n]*\n")
_GENERATED_AT = re.compile(r"Generated: ([^\n]+?) UTC")

_DEPENDENCY_ROW = re.compile(
    rf"^(?P<row>\d+\.\d+) (?P<alert>.+?) (?P<severity>{SEVERITIES}) "
    rf"(?P<ecosystem>{ECOSYSTEMS}) (?P<package>.+?) (?P<version>\S+) "
    r"(?P<dependency>Direct|Transitive) (?P<details>.*)$"
)
_THREAT_ROW = re.compile(
    rf"^(?P<ecosystem>{ECOSYSTEMS}) (?P<package>.+?) (?P<version>\d[\w.\-]*) "
    r"(?P<verdict>malware|false_positive|suspicious|anomaly|potential_malware) "
    r"(?P<details>.*)$"
)

#: Category labels that trail the alert type in the combined column.
_CATEGORIES: Final[tuple[str, ...]] = (
    "Supply chain risk",
    "Vulnerability",
    "Maintenance",
    "Quality",
    "License",
)


@dataclass(frozen=True, slots=True)
class AlertRow:
    """One row, normalized. ``row`` is the label the report printed."""

    row: str
    alert_type: str
    category: str
    severity: str
    ecosystem: str
    package: str
    version: str
    dependency: str
    manifests: str
    details: str


def _read_text(path: Path) -> str:
    """Extract text from a PDF, or read a pre-extracted ``.txt`` as-is.

    ``pypdf`` is imported lazily and is deliberately not a project dependency:
    this runs when a new scan arrives, not in CI or at runtime, and an evidence
    gateway should not carry a PDF parser in its lock file.
    """

    if path.suffix.lower() != ".pdf":
        return path.read_text(encoding="utf-8", errors="replace")
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "reading a PDF needs pypdf (`pip install pypdf`), or pass a pre-extracted .txt instead"
        ) from exc
    reader = PdfReader(str(path))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def detect_kind(text: str) -> str:
    if _DEPENDENCY_HEADER.search(text):
        return KIND_DEPENDENCY_ALERTS
    if _THREAT_HEADER.search(text):
        return KIND_THREAT_FEED
    raise ValueError("input matches neither the dependency-alerts nor the threat-feed layout")


def _flatten(text: str) -> str:
    """Undo page layout so a wrapped row becomes one line."""

    text = _PAGE_FURNITURE.sub("\n", text)
    text = _DEPENDENCY_HEADER.sub("\n", text)
    text = _THREAT_HEADER.sub("\n", text)
    # A hyphen or a slash sitting at a line break belongs to the token, not to
    # the column separator: `dashboard/package-\nlock.json` and
    # `aegis_rust_v2/\nCargo.lock` are each one path that the layout split.
    text = text.replace("-\n", "-").replace("/\n", "/")
    return re.sub(r"\s+", " ", text.replace("\n", " "))


def _split_alert_type(combined: str) -> tuple[str, str]:
    """Separate the alert type from the category label that follows it."""

    for category in _CATEGORIES:
        if combined.endswith(" " + category):
            return combined[: -len(category) - 1].strip(), category
        if combined == category:
            return combined, category
    return combined.strip(), ""


def _split_manifests(details: str) -> tuple[str, str]:
    """Split the manifest list from the free-text detail that follows it.

    Manifest paths are the leading run of comma-separated file paths; the
    detail column starts at the first token that is not one.
    """

    tokens = details.split(" ")
    manifests: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        candidate = token.rstrip(",")
        if "/" in candidate and not candidate.startswith("("):
            manifests.append(candidate)
            index += 1
            continue
        break
    return ", ".join(manifests), " ".join(tokens[index:]).strip()


def parse_dependency_alerts(text: str) -> tuple[list[AlertRow], list[str]]:
    flat = _flatten(text)
    boundary = "|".join(re.escape(name) for name in ALERT_TYPES)
    segments = re.split(rf"(?=\b\d+\.\d+ (?:{boundary})\b)", flat)

    rows: list[AlertRow] = []
    unparsed: list[str] = []
    for segment in segments:
        segment = segment.strip()
        if not re.match(r"^\d+\.\d+ ", segment):
            continue
        match = _DEPENDENCY_ROW.match(segment)
        if match is None:
            unparsed.append(segment[:200])
            continue
        alert_type, category = _split_alert_type(match["alert"])
        manifests, details = _split_manifests(match["details"])
        rows.append(
            AlertRow(
                row=match["row"],
                alert_type=alert_type,
                category=category,
                severity=match["severity"],
                ecosystem=match["ecosystem"],
                # A break inside an identifier leaves a space; these
                # ecosystems have no spaces in package names.
                package=re.sub(r"\s+", "", match["package"]),
                version=match["version"],
                dependency=match["dependency"],
                manifests=manifests,
                details=details,
            )
        )
    return rows, unparsed


def parse_threat_feed(text: str) -> tuple[list[AlertRow], list[str]]:
    stripped = _THREAT_HEADER.sub("\n", _PAGE_FURNITURE.sub("\n", text))
    stripped = stripped.replace("-\n", "-")
    segments = re.split(rf"(?m)(?=^(?:{ECOSYSTEMS})\b)", stripped)

    rows: list[AlertRow] = []
    unparsed: list[str] = []
    index = 0
    for segment in segments:
        segment = re.sub(r"\s+", " ", segment).strip()
        if not re.match(rf"^(?:{ECOSYSTEMS})\b", segment):
            continue
        # The verdict wraps as `false_positiv e`; rejoin before matching.
        segment = re.sub(r"\bfalse_positiv e\b", "false_positive", segment)
        segment = re.sub(r"\bpotential_malwar e\b", "potential_malware", segment)
        match = _THREAT_ROW.match(segment)
        if match is None:
            unparsed.append(segment[:200])
            continue
        index += 1
        rows.append(
            AlertRow(
                row=str(index),
                alert_type=match["verdict"],
                category="Threat feed",
                severity="",
                ecosystem=match["ecosystem"],
                package=re.sub(r"\s+", "", match["package"]),
                version=match["version"],
                dependency="",
                manifests="",
                details=match["details"][:400],
            )
        )
    return rows, unparsed


def build_document(path: Path) -> dict[str, Any]:
    text = _read_text(path)
    kind = detect_kind(text)
    generated = _GENERATED_AT.search(text)

    if kind == KIND_DEPENDENCY_ALERTS:
        rows, unparsed = parse_dependency_alerts(text)
        scope = (
            "Alerts raised against this repository's own dependency graph. Every "
            "row is this project's to triage."
        )
    else:
        rows, unparsed = parse_threat_feed(text)
        scope = (
            "An ecosystem-wide sample of packages the scanner flagged across a "
            "registry. These are NOT alerts against this repository; a row "
            "matters here only if this repository actually depends on the "
            "package named."
        )

    return {
        "format": FORMAT,
        "kind": kind,
        "scope": scope,
        "source_file": path.name,
        "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "report_generated_at": generated.group(1).strip() if generated else "",
        "parsed_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "row_count": len(rows),
        "unparsed_count": len(unparsed),
        "unparsed": unparsed,
        "rows": [asdict(row) for row in rows],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--input", required=True, help="the report (.pdf or extracted .txt)")
    parser.add_argument("--output", default="", help="write normalized JSON here")
    args = parser.parse_args(argv)

    source = Path(args.input)
    if not source.is_file():
        print(f"[BLOCKED: input not found: {source}]", file=sys.stderr)
        return 2
    try:
        document = build_document(source)
    except (RuntimeError, ValueError) as exc:
        print(f"[BLOCKED: {exc}]", file=sys.stderr)
        return 2

    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(payload, encoding="utf-8")
        print(
            f"wrote {destination}: {document['row_count']} rows "
            f"({document['kind']}), {document['unparsed_count']} unparsed"
        )
    else:
        print(payload)

    if document["unparsed_count"]:
        for row in document["unparsed"]:
            print(f"UNPARSED: {row}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
