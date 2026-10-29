#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Apply the copyright and licence header that each tree actually ships under.

Two profiles exist because the project distributes two things under different
terms: the gateway, the control plane and the dashboard are commercial; the
client SDKs and the examples stay Apache-2.0 so a customer can integrate them
without a licence review.

    python scripts/apply_license_headers.py            # write
    python scripts/apply_license_headers.py --check    # verify, write nothing

The header is three comment lines in the file's own comment style. The tool is
idempotent: a file already carrying its profile is left untouched, a file with a
different profile is rewritten in place, and a bare source file receives one.

Retained evidence and historical snapshots (``evidence/``, ``investor_packs/``,
``site/``) are never rewritten: they record what was published under the terms of
the day, and editing them would falsify that record.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Header:
    """One licence header, as three lines without the comment prefix."""

    copyright: str
    spdx: str
    licence: str


COMMERCIAL = Header(
    copyright="Copyright (c) 2026 Juan Luna. All rights reserved.",
    spdx="SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0",
    licence="Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.",
)

APACHE = Header(
    copyright="Copyright (c) 2026 Juan Luna.",
    spdx="SPDX-License-Identifier: Apache-2.0",
    licence="Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.",
)

PROFILES = {"commercial": COMMERCIAL, "apache": APACHE}

# The pre-5.0.2 block, matched only so it can be migrated in place.
LEGACY_COPYRIGHT = "Copyright (c) 2026 Juan Luna. All rights reserved."
LEGACY_LICENSE_LINE_1 = (
    "Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a"
)
LEGACY_LICENSE_MARKER = "Licensed under the GNU Affero General Public License v3"
LEGACY_LICENSE_LINE_2 = (
    "Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms."
)

HASH = "#"
SLASH = "//"

SKIP_NAMES = {
    "audit_node_pb2.py",
    "apply_license_headers.py",
}

#: Suffixes whose files must carry a header; a missing one is added.
INSERT_SUFFIXES = {".py", ".rs", ".toml", ".sh"}

#: Suffixes that already carry a header in some files. A mismatched header is
#: rewritten, but a file without one is left alone: a leading comment is not
#: always harmless to the tool that reads it.
MIGRATE_SUFFIXES = {
    ".yml", ".yaml", ".ts", ".tsx", ".mjs", ".js", ".cjs", ".md", ".env",
    ".tla", ".smt2", ".lean", ".proto", ".cfg", ".html",
}  # fmt: skip

EXCLUDED_PARTS = {
    ".venv", ".git", "target", "node_modules", "__pycache__", "dist", ".next",
    ".hypothesis", ".mypy_cache", ".pytest_cache", ".ruff_cache", "build",
}  # fmt: skip

HISTORICAL_ROOTS = {"evidence", "investor_packs", "site"}

DOC_HEADER_LINES = 8
HEADER_SCAN_LINES = 80


def profile_for(rel: Path) -> Header:
    """SDKs and examples stay Apache; everything else is commercial."""
    posix = rel.as_posix()
    if posix.startswith(("sdk/", "examples/")):
        return APACHE
    return COMMERCIAL


def _comment_prefix(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith(("//", "/*", "*", ";")):
        return line[: len(line) - len(stripped)]
    if stripped.startswith("#"):
        return line[: len(line) - len(stripped)]
    return ""


def _lead(prefix: str) -> str:
    return f"{prefix} " if prefix else ""


def _block(prefix: str, header: Header) -> str:
    lead = _lead(prefix)
    return (
        f"{lead}{header.copyright}\n"
        f"{lead}{header.spdx}\n"
        f"{lead}{header.licence}\n"
    )


def _insert_python(text: str, block: str) -> str:
    lines = text.splitlines(keepends=True)
    idx = 0
    if lines and lines[0].startswith("#!"):
        idx = 1
    if idx < len(lines) and lines[idx].lstrip().startswith(('"""', "'''")):
        quote = '"""' if '"""' in lines[idx] else "'''"
        if lines[idx].count(quote) >= 2:
            end = idx + 1
        else:
            end = idx + 1
            while end < len(lines):
                if quote in lines[end]:
                    end += 1
                    break
                end += 1
        return "".join(lines[:end]) + "\n" + block + "".join(lines[end:])
    return "".join(lines[:idx]) + block + "".join(lines[idx:])


def _insert_after_prefix_lines(text: str, block: str, prefixes: tuple[str, ...]) -> str:
    lines = text.splitlines(keepends=True)
    idx = 0
    if lines and lines[0].startswith(prefixes):
        while idx < len(lines) and (lines[idx].startswith(prefixes) or lines[idx].strip() == ""):
            idx += 1
    return "".join(lines[:idx]) + block + "".join(lines[idx:])


def _insert(text: str, header: Header, suffix: str, name: str) -> str:
    if suffix == ".py":
        return _insert_python(text, _block(HASH, header))
    if suffix == ".rs":
        return _insert_after_prefix_lines(text, _block(SLASH, header), ("/!", "//", "/*"))
    if suffix == ".toml":
        return _insert_after_prefix_lines(text, _block(HASH, header), ("#",))
    if suffix == ".sh":
        lines = text.splitlines(keepends=True)
        if lines and lines[0].startswith("#!"):
            return lines[0] + _block(HASH, header) + "".join(lines[1:])
        return _block(HASH, header) + text
    if suffix in (".yml", ".yaml"):
        return _insert_after_prefix_lines(text, _block(HASH, header), ("#",))
    if name == "Dockerfile" or name.startswith("Dockerfile"):
        return _block(HASH, header) + text
    return text


def _spdx_index(lines: list[str], limit: int) -> int | None:
    for index in range(min(limit, len(lines))):
        if "SPDX-License-Identifier:" in lines[index]:
            return index
    return None


def _replace_in_line(line: str, marker: str, replacement: str) -> str:
    """Replace text starting at ``marker`` and keep the line ending."""
    at = line.index(marker)
    ending = "\n" if line.endswith("\n") else ""
    return line[:at] + replacement + ending


def _rewrite(text: str, header: Header, top_lines: int | None) -> str | None:
    """Return text with ``header`` applied, or None when there is no header."""
    lines = text.splitlines(keepends=True)
    limit = len(lines) if top_lines is None else min(top_lines, len(lines))
    index = _spdx_index(lines, limit)
    if index is None:
        return None
    prefix = _comment_prefix(lines[index])
    lead = _lead(prefix)
    new = list(lines)
    new[index] = _replace_in_line(
        new[index], "SPDX-License-Identifier:", f"{header.spdx}"
    )
    for offset in (1, 2, 3):
        before = index - offset
        if before >= 0 and "Copyright" in new[before]:
            new[before] = _replace_in_line(new[before], "Copyright", header.copyright)
            break
    licence_at = None
    for offset in (1, 2):
        after = index + offset
        if after < len(new) and "Licensed under" in new[after]:
            licence_at = after
            break
    if licence_at is not None:
        new[licence_at] = _replace_in_line(new[licence_at], "Licensed under", header.licence)
    else:
        new.insert(index + 1, f"{lead}{header.licence}\n")
    return "".join(new)


def _replace_legacy(text: str, header: Header, top_lines: int | None) -> str | None:
    """Swap the pre-5.0.2 AGPL-or-commercial block for ``header``."""
    lines = text.splitlines(keepends=True)
    # A legacy header is always near the top; scanning the whole file would also
    # rewrite a string literal in a test that deliberately contains the old text.
    limit = min(12, top_lines if top_lines is not None else 12, len(lines))
    for index in range(limit):
        if LEGACY_LICENSE_LINE_1 not in lines[index]:
            continue
        prefix = _comment_prefix(lines[index])
        lead = _lead(prefix)
        lines[index] = _replace_in_line(lines[index], LEGACY_LICENSE_LINE_1, header.spdx)
        if index + 1 < len(lines) and LEGACY_LICENSE_LINE_2 in lines[index + 1]:
            lines[index + 1] = _replace_in_line(
                lines[index + 1], LEGACY_LICENSE_LINE_2, header.licence
            )
        if index > 0 and LEGACY_COPYRIGHT in lines[index - 1]:
            lines[index - 1] = _replace_in_line(lines[index - 1], LEGACY_COPYRIGHT, header.copyright)
        else:
            lines.insert(index, f"{lead}{header.copyright}\n")
        return "".join(lines)
    return None


def render(path: Path, *, insert_missing: bool, top_lines: int | None) -> str | None:
    """Return the file's desired text, or None when the tool must not touch it."""
    if path.name in SKIP_NAMES:
        return None
    try:
        original = path.read_text(encoding="utf-8")
    except OSError:
        return None
    header = profile_for(path.relative_to(ROOT))
    migrated = _replace_legacy(original, header, top_lines)
    if migrated is not None:
        return migrated
    rewritten = _rewrite(original, header, top_lines)
    if rewritten is not None:
        return rewritten
    if not insert_missing:
        return original
    return _insert(original, header, path.suffix, path.name)


def _is_header_required(rel: Path) -> bool:
    if rel.suffix in INSERT_SUFFIXES:
        return True
    if rel.name == "Dockerfile" or rel.name.startswith("Dockerfile."):
        return True
    return rel.suffix in {".yml", ".yaml"} and rel.parts[:2] == (".github", "workflows")


def _candidates() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8")
        names = [name for name in out.split("\0") if name]
    except (OSError, subprocess.CalledProcessError):
        names = [
            str(path.relative_to(ROOT))
            for path in ROOT.rglob("*")
            if path.is_file()
            and not any(part in EXCLUDED_PARTS for part in path.relative_to(ROOT).parts)
        ]
    return [ROOT / name for name in sorted(set(names))]


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report without writing")
    args = parser.parse_args()

    changed: list[str] = []
    for path in _candidates():
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS for part in rel.parts) or rel.parts[0] in HISTORICAL_ROOTS:
            continue
        required = _is_header_required(rel)
        if required:
            top = HEADER_SCAN_LINES
        elif rel.suffix in MIGRATE_SUFFIXES:
            top = DOC_HEADER_LINES if rel.suffix in {".md", ".html"} else HEADER_SCAN_LINES
        else:
            continue
        desired = render(path, insert_missing=required, top_lines=top)
        if desired is None:
            continue
        try:
            current = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if desired == current:
            continue
        changed.append(rel.as_posix())
        if not args.check:
            path.write_text(desired, encoding="utf-8")

    if args.check:
        if changed:
            print(f"headers: FAIL — {len(changed)} file(s) do not carry their profile")
            for name in changed[:20]:
                print(f"  {name}")
            if len(changed) > 20:
                print(f"  … and {len(changed) - 20} more")
            return 1
        print("headers: OK")
        return 0

    print(f"headers: updated {len(changed)} file(s)")
    for name in changed[:40]:
        print(f"  {name}")
    if len(changed) > 40:
        print(f"  … and {len(changed) - 40} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
