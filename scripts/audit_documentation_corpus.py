#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Create a deterministic inventory and documentation-integrity audit."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unicodedata
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "evidence" / "documentation_audit_2026-08-20"
INVENTORY_JSON = OUTPUT_DIR / "CORPUS_INVENTORY.json"
AUDIT_MD = OUTPUT_DIR / "CORPUS_AUDIT.md"
TEXT_SUFFIXES = {
    ".cfg",
    ".env",
    ".ini",
    ".json",
    ".lean",
    ".md",
    ".py",
    ".rs",
    ".rst",
    ".sh",
    ".smt2",
    ".tla",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
PLACEHOLDER_RE = re.compile(r"\b(?:TODO|FIXME|TBD|PLACEHOLDER)\b|\.\.\.", re.IGNORECASE)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


def repository_paths() -> list[Path]:
    result = subprocess.run(  # noqa: S603
        ("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"),
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = [Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item]
    return sorted(paths, key=lambda item: item.as_posix())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    files: list[dict[str, object]] = []
    duplicate_index: dict[str, list[str]] = defaultdict(list)
    heading_index: dict[str, list[str]] = defaultdict(list)
    institutional_placeholders: list[dict[str, object]] = []
    utf8_failures: list[str] = []
    non_nfc_files: list[str] = []
    crlf_files: list[str] = []

    for relative in repository_paths():
        absolute = ROOT / relative
        if OUTPUT_DIR in absolute.parents:
            continue
        if not absolute.is_file():
            continue
        data = absolute.read_bytes()
        digest = sha256(data)
        duplicate_index[digest].append(relative.as_posix())
        record: dict[str, object] = {
            "path": relative.as_posix(),
            "sha256": digest,
            "size_bytes": len(data),
            "text": False,
        }
        if relative.suffix.lower() in TEXT_SUFFIXES or relative.name in {
            "Dockerfile",
            "Makefile",
            "LICENSE",
        }:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                utf8_failures.append(relative.as_posix())
            else:
                record["text"] = True
                record["line_count"] = len(text.splitlines())
                record["nfc"] = unicodedata.is_normalized("NFC", text)
                record["lf_only"] = b"\r" not in data
                if not record["nfc"]:
                    non_nfc_files.append(relative.as_posix())
                if not record["lf_only"]:
                    crlf_files.append(relative.as_posix())
                if relative.suffix.lower() == ".md":
                    for line_number, line in enumerate(text.splitlines(), 1):
                        match = HEADING_RE.match(line)
                        if match:
                            normalized = unicodedata.normalize("NFC", match.group(2)).casefold()
                            heading_index[normalized].append(f"{relative.as_posix()}:{line_number}")
                        if relative.as_posix().startswith(
                            "docs/institutional/"
                        ) and PLACEHOLDER_RE.search(line):
                            institutional_placeholders.append(
                                {
                                    "path": relative.as_posix(),
                                    "line": line_number,
                                    "content": line.strip(),
                                }
                            )
        files.append(record)

    exact_duplicates = [
        {"sha256": digest, "paths": paths}
        for digest, paths in sorted(duplicate_index.items())
        if len(paths) > 1 and any((ROOT / path).stat().st_size > 0 for path in paths)
    ]
    repeated_headings = [
        {"heading": heading, "locators": locators}
        for heading, locators in sorted(heading_index.items())
        if len(locators) > 3
    ]
    institutional_files = [
        record for record in files if str(record["path"]).startswith("docs/institutional/")
    ]
    inventory = {
        "schema": "aegis-documentation-corpus-audit-v1",
        "source_commit": subprocess.run(  # noqa: S603
            ("git", "rev-parse", "HEAD"),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "counts": {
            "all_files": len(files),
            "text_files": sum(bool(record["text"]) for record in files),
            "markdown_files": sum(str(record["path"]).endswith(".md") for record in files),
            "institutional_files": len(institutional_files),
            "exact_duplicate_groups": len(exact_duplicates),
            "repeated_heading_groups": len(repeated_headings),
            "utf8_failures": len(utf8_failures),
            "non_nfc_files": len(non_nfc_files),
            "crlf_files": len(crlf_files),
            "institutional_placeholders": len(institutional_placeholders),
        },
        "exact_duplicates": exact_duplicates,
        "repeated_headings": repeated_headings,
        "utf8_failures": utf8_failures,
        "non_nfc_files": non_nfc_files,
        "crlf_files": crlf_files,
        "institutional_placeholders": institutional_placeholders,
        "files": files,
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    INVENTORY_JSON.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    counts = inventory["counts"]
    status = "PASS" if not institutional_placeholders and not utf8_failures else "FAIL"
    report = f"""# Documentation Corpus Audit

**Status:** {status}
**Source commit:** `{inventory["source_commit"]}`
**Scope:** Git-tracked and untracked, non-ignored repository files present at execution time.

## Deterministic counts

| Metric | Count |
|---|---:|
| Files | {counts["all_files"]} |
| UTF-8 text files | {counts["text_files"]} |
| Markdown files | {counts["markdown_files"]} |
| Institutional files | {counts["institutional_files"]} |
| Exact duplicate groups | {counts["exact_duplicate_groups"]} |
| Repeated heading groups | {counts["repeated_heading_groups"]} |
| UTF-8 decode failures in declared text types | {counts["utf8_failures"]} |
| Non-NFC text files | {counts["non_nfc_files"]} |
| CRLF-containing text files | {counts["crlf_files"]} |
| Placeholder markers in institutional documents | {counts["institutional_placeholders"]} |

## Interpretation boundary

Exact-byte duplication and repeated headings are discovery signals, not automatic defects. Repeated operational headings such as Preconditions or Rollback are expected across independent runbooks. Semantic contradiction and regulatory accuracy require claim-level review and are recorded separately in `docs/institutional/CLAIM_EVIDENCE_GRAPH.md` and `docs/institutional/UNSUPPORTED_CLAIMS.md`.

## Falsification criterion

This audit passes only if every declared text file is inventory-addressable and the institutional suite contains no `TODO`, `FIXME`, `TBD`, `PLACEHOLDER`, or literal ellipsis marker. Re-running `python scripts/audit_documentation_corpus.py` must reproduce the same file hashes when repository bytes are unchanged.
"""
    AUDIT_MD.write_text(report, encoding="utf-8", newline="\n")
    print(json.dumps(counts, sort_keys=True))
    print(f"status={status}")


if __name__ == "__main__":
    main()
