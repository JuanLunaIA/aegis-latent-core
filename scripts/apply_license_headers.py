#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Apply copyright + AGPLv3 / Commercial dual-license headers to source files.

This tool is idempotent and runs in two modes per file:

1. BARE FILE (no license header): inserts the full copyright + dual-license
   block, positioned after any shebang and/or module docstring.
2. EXISTING LICENSE, MISSING COPYRIGHT: inserts only the copyright line
   immediately above the existing "Licensed under ..." line, matching the
   file's comment style.

Files that already carry both a copyright line naming the holder and the
license marker are left untouched.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Ownership constants — single source of truth.
# ---------------------------------------------------------------------------
COPYRIGHT_YEAR = "2026"
COPYRIGHT_HOLDER = "Juan Luna"
COPYRIGHT_TEXT = f"Copyright (c) {COPYRIGHT_YEAR} {COPYRIGHT_HOLDER}. All rights reserved."

LICENSE_LINE_1 = "Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a"
LICENSE_LINE_2 = "Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms."

LICENSE_MARKER = "Licensed under the GNU Affero General Public License v3"


def _block(prefix: str) -> str:
    """Render the full copyright + license block for a given comment prefix."""
    return (
        f"{prefix} {COPYRIGHT_TEXT}\n"
        f"{prefix} {LICENSE_LINE_1}\n"
        f"{prefix} {LICENSE_LINE_2}\n"
    )


def _copyright_line(prefix: str) -> str:
    return f"{prefix} {COPYRIGHT_TEXT}\n"


HASH = "#"
SLASH = "//"

SKIP_NAMES = {
    "audit_node_pb2.py",
    "apply_license_headers.py",
}


def _has_license(text: str) -> bool:
    return LICENSE_MARKER in text


def _has_copyright(text: str) -> bool:
    for line in text.splitlines():
        if "Copyright" in line and COPYRIGHT_HOLDER in line:
            return True
    return False


def _detect_prefix(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith("//"):
        return SLASH
    return HASH


def _inject_copyright_above_license(text: str) -> str:
    """File already has the license block but no copyright line."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if LICENSE_MARKER in line:
            prefix = _detect_prefix(line)
            lines.insert(i, _copyright_line(prefix))
            return "".join(lines)
    return text  # marker vanished; nothing to do


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
        while idx < len(lines) and (
            lines[idx].startswith(prefixes) or lines[idx].strip() == ""
        ):
            idx += 1
    return "".join(lines[:idx]) + block + "".join(lines[idx:])


def process_file(path: Path) -> str | None:
    """Returns a short status string if the file was modified, else None."""
    if path.name in SKIP_NAMES:
        return None
    try:
        original = path.read_text(encoding="utf-8")
    except OSError:
        return None

    has_license = _has_license(original)
    has_copyright = _has_copyright(original)

    if has_license and has_copyright:
        return None

    suffix = path.suffix
    name = path.name

    # Case 1: license present, copyright missing — minimal injection.
    if has_license and not has_copyright:
        updated = _inject_copyright_above_license(original)
        status = "copyright+"
    else:
        # Case 2: build a full block in the right comment style.
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


def main() -> None:
    patterns = (
        "**/*.py",
        "**/*.rs",
        "**/*.toml",
        "**/*.sh",
        "**/Dockerfile",
        "**/Dockerfile.*",
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
    )
    changed: list[tuple[str, str]] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in ROOT.glob(pattern):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            rel = path.relative_to(ROOT)
            if any(
                part in {".venv", ".git", "target", "node_modules", "__pycache__"}
                for part in rel.parts
            ):
                continue
            status = process_file(path)
            if status:
                changed.append((status, str(rel)))
    print(f"Updated {len(changed)} files")
    for status, name in sorted(changed, key=lambda t: t[1]):
        print(f"  [{status}] {name}")


if __name__ == "__main__":
    main()
