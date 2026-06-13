#!/usr/bin/env python3
"""Apply AGPLv3 / Commercial dual-license headers to source files."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PY_HEADER = (
    "# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a\n"
    "# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.\n"
)

RS_HEADER = (
    "// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a\n"
    "// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.\n"
)

PROTO_HEADER = (
    "// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a\n"
    "// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.\n"
)

TLA_HEADER = (
    "(* Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a\n"
    "   Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms. *)\n"
)

SH_HEADER = (
    "# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a\n"
    "# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.\n"
)

DOCKER_HEADER = (
    "# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a\n"
    "# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.\n"
)

SKIP_NAMES = {
    "audit_node_pb2.py",
    "apply_license_headers.py",
}

MARKERS = (
    "Licensed under the GNU Affero General Public License v3",
    "SPDX-License-Identifier: AGPL-3.0",
)


def _has_license(text: str) -> bool:
    return any(m in text for m in MARKERS)


def _insert_python(text: str) -> str:
    if _has_license(text):
        return text
    lines = text.splitlines(keepends=True)
    idx = 0
    if lines and lines[0].startswith("#!"):
        idx = 1
    if idx < len(lines) and lines[idx].startswith('"""'):
        end = idx + 1
        while end < len(lines):
            if '"""' in lines[end] and not (end == idx and lines[end].count('"""') >= 2):
                if lines[end].strip().endswith('"""'):
                    end += 1
                    break
            end += 1
        return "".join(lines[:end]) + "\n" + PY_HEADER + "".join(lines[end:])
    if idx < len(lines) and lines[idx].startswith("'''"):
        end = idx + 1
        while end < len(lines):
            if "'''" in lines[end]:
                end += 1
                break
            end += 1
        return "".join(lines[:end]) + "\n" + PY_HEADER + "".join(lines[end:])
    return PY_HEADER + text


def _insert_line_comment(text: str, header: str, prefixes: tuple[str, ...]) -> str:
    if _has_license(text):
        return text
    lines = text.splitlines(keepends=True)
    idx = 0
    if lines and lines[idx].startswith(prefixes):
        while idx < len(lines) and (
            lines[idx].startswith(prefixes) or lines[idx].strip() == ""
        ):
            idx += 1
    return header + "".join(lines[idx:] if idx else lines)


def process_file(path: Path) -> bool:
    if path.name in SKIP_NAMES:
        return False
    suffix = path.suffix
    try:
        original = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if _has_license(original):
        return False

    if suffix == ".py":
        updated = _insert_python(original)
    elif suffix == ".rs":
        updated = _insert_line_comment(original, RS_HEADER, ("/!", "//", "/*"))
    elif suffix == ".proto":
        updated = PROTO_HEADER + original
    elif suffix == ".tla":
        updated = TLA_HEADER + original
    elif suffix == ".sh":
        lines = original.splitlines(keepends=True)
        if lines and lines[0].startswith("#!"):
            updated = lines[0] + SH_HEADER + "".join(lines[1:])
        else:
            updated = SH_HEADER + original
    elif path.name == "Dockerfile":
        updated = DOCKER_HEADER + original
    else:
        return False

    if updated != original:
        path.write_text(updated, encoding="utf-8")
        return True
    return False


def main() -> None:
    patterns = ("**/*.py", "**/*.rs", "**/*.proto", "**/*.tla", "**/*.sh", "**/Dockerfile")
    changed: list[str] = []
    for pattern in patterns:
        for path in ROOT.glob(pattern):
            rel = path.relative_to(ROOT)
            if any(part in {".venv", ".git", "target", "node_modules"} for part in rel.parts):
                continue
            if process_file(path):
                changed.append(str(rel))
    print(f"Updated {len(changed)} files")
    for name in sorted(changed):
        print(f"  {name}")


if __name__ == "__main__":
    main()
