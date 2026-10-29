# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Fail-closed scanner for stale licence, release and assurance claims.

The web build has its own JavaScript scanner because it cannot import Python.
This is the repository-side equivalent: it reads the current public documents
and reports a claim that the checked-out source cannot support.

Exit 0 = no unallowlisted hit. Exit 1 = at least one hit.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Documents that are allowed to describe earlier releases. They are not
#: "current product" surfaces; their statements are pinned to a version and a
#: date by the document itself. This is a scope boundary, not an allowlist.
HISTORICAL_PATHS = (
    "CHANGELOG.md",
    "docs/RELEASE_STATUS.md",
    "docs/legal/LICENSE_TRANSITION_5.0.2.md",
    "docs/legal/LICENSE_TRANSITION_5.0.3.md",
    "docs/CLAIMS_MATRIX.md",
    "docs/PROSPECTUS.md",
    "docs/PROSPECTUS_ES.md",
    "docs/REGISTRY.md",
    "docs/compliance/LICENSE_AUDIT.md",
    "docs/security/DEPENDENCY_RISK_REGISTER.md",
    "docs/security/DEPENDENCY_TRIAGE.md",
    "docs/DOCUMENTATION_INDEX.md",
    "docs/truth/PUBLIC_SURFACE_MAP.md",
    "docs/truth/TRUTH_GATE.md",
    "evidence/",
    "investor_packs/",
    "site/",
)

CERTIFICATION = re.compile(
    r"(?:SOC\s*2\s*(?:Type\s*II\s*)?(?:is\s+)?(?:compliant|certified|attested)"
    r"|ISO(?:/IEC)?\s*27001\s*(?:is\s+)?(?:compliant|certified)"
    r"|HIPAA\s*(?:is\s+)?(?:compliant|certified)"
    r"|FedRAMP\s*(?:is\s+)?(?:authorized|compliant)"
    r"|PCI\s*DSS\s*(?:is\s+)?(?:compliant|certified)"
    r"|is\s+penetration[- ]tested"
    r"|is\s+production[- ]ready"
    r"|admissible in court)",
    re.IGNORECASE,
)

OPEN_SOURCE = re.compile(
    r"(?:(?:is|are|remains|distributed as|licensed under|released under|ships under)\s+"
    r"(?:open[ -]?source|AGPL(?:v3|-3\.0)?)|open[ -]?source\s+under\s+AGPL)",
    re.IGNORECASE,
)

HISTORICAL_LICENSE = re.compile(
    r"(?:5\.0\.[012]|4\.1\.2|earlier|prior|previous|historical|legacy|kept|keeps|shipped|"
    r"was published|published before|pre-5\.0\.3|before 5\.0\.3)",
    re.IGNORECASE,
)

HISTORICAL_RELEASE = re.compile(
    r"(?:was|previous|prior|historical|legacy|kept|keeps|shipped|published before|earlier|up to|through|before)",
    re.IGNORECASE,
)

THIRD_PARTY = re.compile(
    r"(?:sdk|dependency|dependencies|third[- ]party|examples?|apache|license|licence|"
    r"upstream|vendored)",
    re.IGNORECASE,
)

NEGATION = re.compile(
    r"(?:not|no|never|none|without|sin|sem|sans|kein|niet|non|not yet|absent|unimplemented)",
    re.IGNORECASE,
)

STALE_VERSION = re.compile(r"\b(?:5\.0\.[01]|4\.1\.2)\b")

CURRENT_RELEASE = re.compile(
    r"(?:(?:current|latest|most recent|published)\s+release|release\s+is)\b",
    re.IGNORECASE,
)

CURRENT_WORD = re.compile(r"(?:current|latest|most recent|release|published)", re.IGNORECASE)

UNBACKED_FEATURE = re.compile(
    r"(?:SSO\s*/\s*(?:SAML|SCIM|OIDC)|SSO or SAML|IP allowlist"
    r"|(?:99\.9|99\.99)\s*%\s*SLA|\bSLA\b.{0,40}(?:guarantee|commit|24/7)"
    r"|24/7\s*(?:support|staffed))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    code: str
    text: str


def _is_historical_license(text: str) -> bool:
    return bool(HISTORICAL_LICENSE.search(text))


def _is_historical_release(text: str) -> bool:
    return bool(HISTORICAL_RELEASE.search(text))


def _is_negated(text: str) -> bool:
    return bool(NEGATION.search(text))


def scan_text(text: str, path: str = "<memory>") -> list[Hit]:
    """Return every unsupported claim in *text*.

    ``path`` is only used in the hit record. The function is deliberately
    line-oriented: a claim and its qualifier belong in the same sentence, and a
    line break is a useful, conservative boundary.
    """

    hits: list[Hit] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        if (
            CERTIFICATION.search(line)
            and not _is_negated(line)
            and "?" not in line
            and "“" not in line
            and not re.match(r"\s*[-|]\s*[\"“]", line)
        ):
            hits.append(Hit(path, number, "CERTIFICATION_CLAIM", stripped[:240]))

        if OPEN_SOURCE.search(line) and not _is_historical_license(line) and not THIRD_PARTY.search(line):
            if not _is_negated(line):
                hits.append(Hit(path, number, "OPEN_SOURCE_CURRENT", stripped[:240]))

        if STALE_VERSION.search(line) and CURRENT_RELEASE.search(line) and not _is_historical_release(line):
            hits.append(Hit(path, number, "STALE_CURRENT_VERSION", stripped[:240]))

        if (
            UNBACKED_FEATURE.search(line)
            and not _is_negated(line)
            and "?" not in line
            and not re.search(r"(?:implemented|reachable|middleware|tests?/)", line, re.IGNORECASE)
        ):
            hits.append(Hit(path, number, "UNBACKED_FEATURE", stripped[:240]))

    return hits


def _read_allowlist(path: pathlib.Path) -> list[dict[str, str]]:
    """Parse the small, deliberately boring allowlist format.

    The file is YAML-shaped but contains only a flat list of mappings:
        entries:
          - path: docs/example.md
            contains: exact line fragment
            reason: why this line is historical
    A full YAML parser is not a dependency, and a nested format would invite
    blanket exemptions.
    """

    if not path.exists():
        return []
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line == "entries:":
            continue
        if line.startswith("- "):
            if current is not None:
                entries.append(current)
            current = {}
            line = line[2:].strip()
        if current is None or ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip().strip('"').strip("'")
    if current is not None:
        entries.append(current)
    return [e for e in entries if e.get("path") and e.get("contains")]


def _allowed(hit: Hit, entries: Sequence[dict[str, str]]) -> bool:
    for entry in entries:
        if hit.path == entry["path"] and entry["contains"] in hit.text:
            return True
    return False


def _iter_documents(root: pathlib.Path, paths: Iterable[str]) -> Iterable[pathlib.Path]:
    for raw in paths:
        candidate = (root / raw).resolve()
        if not candidate.exists():
            continue
        if candidate.is_file():
            if candidate.suffix in {".md", ".rst", ".txt"}:
                yield candidate
            continue
        for path in sorted(candidate.rglob("*")):
            if path.suffix not in {".md", ".rst", ".txt"}:
                continue
            rel = path.relative_to(root).as_posix()
            if any(rel == item or rel.startswith(item) for item in HISTORICAL_PATHS):
                continue
            if any(part in {".git", ".venv", "node_modules", "target", "__pycache__"} for part in path.parts):
                continue
            yield path


def scan_paths(root: pathlib.Path, paths: Iterable[str], allowlist: Sequence[dict[str, str]] = ()) -> list[Hit]:
    hits: list[Hit] = []
    for path in _iter_documents(root, paths):
        rel = path.relative_to(root).as_posix()
        if any(rel == item or rel.startswith(item) for item in HISTORICAL_PATHS):
            continue
        hits.extend(hit for hit in scan_text(path.read_text(encoding="utf-8", errors="ignore"), rel) if not _allowed(hit, allowlist))
    return hits


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT), help="repository root (default: %(default)s)")
    parser.add_argument("--paths", nargs="+", default=["README.md", "AGENTS.md", "docs"])
    parser.add_argument(
        "--allowlist",
        default="docs/truth/CLAIM_SCANNER_ALLOWLIST.yaml",
        help="allowlist path relative to the repository root",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    root = pathlib.Path(args.root).resolve()
    allowlist = _read_allowlist(root / args.allowlist)
    hits = scan_paths(root, args.paths, allowlist)
    if args.json:
        print(json.dumps([hit.__dict__ for hit in hits], indent=2))
    else:
        for hit in hits:
            print(f"{hit.path}:{hit.line}: {hit.code}: {hit.text}")
    if hits:
        print(f"public-claims: FAIL — {len(hits)} finding(s)", file=sys.stderr)
        return 1
    print("public-claims: PASS — 0 finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
