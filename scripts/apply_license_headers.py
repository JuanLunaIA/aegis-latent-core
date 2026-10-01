#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Apply copyright + Apache-2.0 headers to source files.

The header is exactly three comment lines, in the file's own comment style::

    Copyright (c) 2026 Juan Luna.
    SPDX-License-Identifier: Apache-2.0
    Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.

It stays at three lines on purpose: every ``file:line`` reference in the
documentation and in the retained evidence keeps pointing at the same code.

The tool is idempotent and handles three situations per file:

1. CURRENT HEADER present: left untouched.
2. LEGACY HEADER present (the pre-5.0.2 AGPLv3-or-commercial block, with its
   "All rights reserved." copyright line): replaced in place, so the line count
   does not change.
3. BARE FILE (no header): inserts the full block, positioned after any shebang
   and/or module docstring.

Releases up to and including ``5.0.1`` were published under the licence stated
in their own ``LICENSE`` file. This tool changes the source tree only; it does
not and cannot change the terms of anything already published.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Ownership constants — single source of truth.
# ---------------------------------------------------------------------------
COPYRIGHT_YEAR = "2026"
COPYRIGHT_HOLDER = "Juan Luna"
COPYRIGHT_TEXT = f"Copyright (c) {COPYRIGHT_YEAR} {COPYRIGHT_HOLDER}."

SPDX_LINE = "SPDX-License-Identifier: Apache-2.0"
LICENSE_LINE = "Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE."

#: Present in every file that carries the current header.
LICENSE_MARKER = SPDX_LINE

# The pre-5.0.2 header, matched only so it can be replaced in place.
LEGACY_COPYRIGHT = "Copyright (c) 2026 Juan Luna. All rights reserved."
LEGACY_LICENSE_LINE_1 = (
    "Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a"
)
LEGACY_LICENSE_MARKER = "Licensed under the GNU Affero General Public License v3"
LEGACY_LICENSE_LINE_2 = "Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms."


def _block(prefix: str) -> str:
    """Render the full copyright + license block for a given comment prefix."""
    return f"{prefix} {COPYRIGHT_TEXT}\n{prefix} {SPDX_LINE}\n{prefix} {LICENSE_LINE}\n"


HASH = "#"
SLASH = "//"

SKIP_NAMES = {
    "audit_node_pb2.py",
    "apply_license_headers.py",
}


def _has_license(text: str) -> bool:
    return LICENSE_MARKER in text


def _has_legacy_license(text: str) -> bool:
    return LEGACY_LICENSE_MARKER in text


def _has_copyright(text: str) -> bool:
    for line in text.splitlines():
        if COPYRIGHT_TEXT in line and "All rights reserved" not in line:
            return True
    return False


def _detect_prefix(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith("//"):
        return SLASH
    return HASH


def _swap(line: str, old: str, new: str) -> str:
    """Replace ``old`` by ``new`` inside ``line``, keeping what surrounds it.

    What surrounds the text is the file's own comment syntax (``# ``, ``// ``,
    ``; ``, ``(* ``, a closing `` *)``), so one routine serves every file type.
    """
    before, _, after = line.partition(old)
    return before + new + after


def _replace_legacy_block(text: str, *, top_lines: int | None = None) -> str:
    """Swap the legacy three-line block for the current one, keeping its position.

    The legacy block is the copyright line, the AGPLv3 line and the commercial
    line, consecutive. Each is rewritten in place, so the line count and the
    comment syntax are unchanged. A stray legacy copyright line elsewhere in the
    file is dropped so the holder is named once, not twice.

    ``top_lines`` limits the search to the top of the file. Documents that quote
    the old header while describing it must not be rewritten; a real header
    sits at the top.
    """
    lines = text.splitlines(keepends=True)
    limit = len(lines) if top_lines is None else min(top_lines, len(lines))
    replaced = False
    for i in range(limit):
        if LEGACY_LICENSE_LINE_1 not in lines[i]:
            continue
        lines[i] = _swap(lines[i], LEGACY_LICENSE_LINE_1, SPDX_LINE)
        if i + 1 < len(lines) and LEGACY_LICENSE_LINE_2 in lines[i + 1]:
            lines[i + 1] = _swap(lines[i + 1], LEGACY_LICENSE_LINE_2, LICENSE_LINE)
        if i > 0 and LEGACY_COPYRIGHT in lines[i - 1]:
            lines[i - 1] = _swap(lines[i - 1], LEGACY_COPYRIGHT, COPYRIGHT_TEXT)
        else:
            # No copyright line directly above the licence line: add one in the
            # same comment syntax (everything the licence line has before its text).
            leader = lines[i].partition(SPDX_LINE)[0]
            lines.insert(i, f"{leader}{COPYRIGHT_TEXT}\n")
        replaced = True
        break
    if not replaced:
        return text
    return "".join(line for line in lines if LEGACY_COPYRIGHT not in line)


def _insert_python(text: str, block: str) -> str:
    lines = text.splitlines(keepends=True)
    idx = 0
    if lines and lines[0].startswith("#!"):
        idx = 1
    # After a module docstring, if present.
    if idx < len(lines) and lines[idx].lstrip().startswith(('"""', "'''")):
        quote = '"""' if '"""' in lines[idx] else "'''"
        # single-line docstring
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
    return block + text


def _insert_after_prefix_lines(text: str, block: str, prefixes: tuple[str, ...]) -> str:
    lines = text.splitlines(keepends=True)
    idx = 0
    if lines and lines[0].startswith(prefixes):
        while idx < len(lines) and (lines[idx].startswith(prefixes) or lines[idx].strip() == ""):
            idx += 1
    return "".join(lines[:idx]) + block + "".join(lines[idx:])


def process_file(
    path: Path, *, insert_missing: bool = True, top_lines: int | None = None
) -> str | None:
    """Returns a short status string if the file was modified, else None.

    ``insert_missing=False`` migrates a legacy header but never adds one to a
    file that has none (used for deployment manifests, where a leading comment
    is not always harmless to the tool that renders the file).

    ``top_lines`` restricts the migration to a header at the top of the file.
    """
    if path.name in SKIP_NAMES:
        return None
    try:
        original = path.read_text(encoding="utf-8")
    except OSError:
        return None

    if _has_license(original) and _has_copyright(original):
        return None

    if _has_legacy_license(original):
        updated = _replace_legacy_block(original, top_lines=top_lines)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            return "migrated"
        return None

    if not insert_missing:
        return None

    suffix = path.suffix
    name = path.name

    # Bare file: build a full block in the right comment style.
    if suffix == ".py":
        updated = _insert_python(original, _block(HASH))
    elif suffix == ".rs":
        updated = _insert_after_prefix_lines(original, _block(SLASH), ("/!", "//", "/*"))
    elif suffix == ".toml":
        updated = _insert_after_prefix_lines(original, _block(HASH), ("#",))
    elif suffix in (".sh",):
        lines = original.splitlines(keepends=True)
        if lines and lines[0].startswith("#!"):
            updated = lines[0] + _block(HASH) + "".join(lines[1:])
        else:
            updated = _block(HASH) + original
    elif suffix in (".yml", ".yaml"):
        updated = _insert_after_prefix_lines(original, _block(HASH), ("#",))
    elif name == "Dockerfile" or name.startswith("Dockerfile"):
        updated = _block(HASH) + original
    else:
        return None
    status = "header+"

    if updated != original:
        path.write_text(updated, encoding="utf-8")
        return status
    return None


#: Suffixes whose files must carry the header; a missing one is added.
INSERT_SUFFIXES = {".py", ".rs", ".toml", ".sh"}

#: Suffixes that already carry a header in some files. A legacy header is
#: migrated, but a file without one is left alone: a leading comment is not
#: always harmless to the tool that reads the file.
MIGRATE_SUFFIXES = {
    ".yml", ".yaml", ".ts", ".tsx", ".mjs", ".js", ".cjs", ".md", ".env",
    ".tla", ".smt2", ".lean", ".proto", ".cfg", ".html",
}  # fmt: skip

EXCLUDED_PARTS = {".venv", ".git", "target", "node_modules", "__pycache__", "dist", ".next"}

#: Retained evidence and generated artefacts record a past state; rewriting
#: their text would falsify the record. They are regenerated, not migrated.
HISTORICAL_ROOTS = {"evidence", "investor_packs", "site"}

#: A real header sits at the top of a document; a quote of one does not.
DOC_HEADER_LINES = 8


def _candidate_files() -> list[Path]:
    """Files git tracks or would track, so ignored build output is never touched."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8")
        names = [n for n in out.split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [
            str(p.relative_to(ROOT))
            for p in ROOT.rglob("*")
            if p.is_file() and not any(part in EXCLUDED_PARTS for part in p.relative_to(ROOT).parts)
        ]
    return [ROOT / n for n in sorted(set(names))]


def _is_header_required(rel: Path) -> bool:
    name = rel.name
    if rel.suffix in INSERT_SUFFIXES or name == "Dockerfile" or name.startswith("Dockerfile."):
        return True
    return rel.suffix in {".yml", ".yaml"} and rel.parts[:2] == (".github", "workflows")


def main() -> None:
    changed: list[tuple[str, str]] = []
    for path in _candidate_files():
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS for part in rel.parts) or rel.parts[0] in HISTORICAL_ROOTS:
            continue
        if _is_header_required(rel):
            status = process_file(path)
        elif rel.suffix in MIGRATE_SUFFIXES:
            top = DOC_HEADER_LINES if rel.suffix in {".md", ".html"} else None
            status = process_file(path, insert_missing=False, top_lines=top)
        else:
            continue
        if status:
            changed.append((status, str(rel)))
    print(f"Updated {len(changed)} files")
    for status, name in sorted(changed, key=lambda t: t[1]):
        print(f"  [{status}] {name}")


if __name__ == "__main__":
    main()
