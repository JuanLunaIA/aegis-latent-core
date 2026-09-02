#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#
# Relative-link and heading-anchor checking across the Markdown corpus.
#
# scripts/verify_docs.py already checks that relative link targets exist. This
# goes further and resolves in-document and cross-document heading anchors,
# which is where link rot usually hides: a renamed section leaves the file
# present and the link broken, so a file-existence check passes and the reader
# still lands nowhere.
#
# External URLs are NOT fetched. Network checks make the gate flaky and turn a
# third party's outage into a failed build; treat external link review as a
# human task.
#
# Usage:
#   bash scripts/verify_links.sh [--root DIR]
#
# Exit codes: 0 clean, 1 broken links found, 2 the check could not run.

set -euo pipefail

ROOT="."
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="${2:?--root needs a directory}"; shift 2 ;;
    -h|--help) sed -n '6,22p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ ! -f "${ROOT}/README.md" ]; then
  echo "error: ${ROOT} does not look like the repository root" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 2
fi

python3 - "$ROOT" <<'PYTHON'
import re
import sys
import unicodedata
from pathlib import Path

root = Path(sys.argv[1]).resolve()

EXCLUDED = {
    ".git", ".venv", "node_modules", ".next", "target", "htmlcov",
    "evidence", ".aegis_ai_context", "dist", "build", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

LINK_RE = re.compile(r"(?<!\\)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
HTML_ANCHOR_RE = re.compile(r'<a\s+[^>]*(?:name|id)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def slugify(text: str) -> str:
    """GitHub's heading-anchor algorithm, closely enough for link checking."""
    text = re.sub(r"<[^>]+>", "", text)          # strip inline HTML
    text = re.sub(r"`([^`]*)`", r"\1", text)      # unwrap inline code
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # unwrap links
    text = re.sub(r"[*_~]", "", text)             # strip emphasis
    text = unicodedata.normalize("NFKD", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def markdown_files() -> list[Path]:
    return sorted(
        p for p in root.rglob("*.md")
        if not any(part in EXCLUDED for part in p.relative_to(root).parts)
    )


def prose_lines(path: Path) -> list[tuple[int, str]]:
    out, in_fence = [], False
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append((number, raw))
    return out


# Anchor index: every heading slug and explicit HTML anchor per file.
anchors: dict[Path, set[str]] = {}
for path in markdown_files():
    found: set[str] = set()
    counts: dict[str, int] = {}
    for _, line in prose_lines(path):
        heading = HEADING_RE.match(line)
        if heading:
            slug = slugify(heading.group(2))
            # GitHub disambiguates repeats with -1, -2, ...
            index = counts.get(slug, 0)
            found.add(slug if index == 0 else f"{slug}-{index}")
            counts[slug] = index + 1
        found.update(HTML_ANCHOR_RE.findall(line))
    anchors[path] = found

findings: list[str] = []
checked = 0

for path in markdown_files():
    rel = path.relative_to(root).as_posix()
    for number, line in prose_lines(path):
        for target in LINK_RE.findall(line):
            if target.startswith(("http://", "https://", "mailto:", "tel:")):
                continue
            checked += 1
            file_part, _, anchor = target.partition("#")

            if not file_part:
                if anchor and anchor not in anchors[path]:
                    findings.append(
                        f"{rel}:{number}: in-document anchor '#{anchor}' has no matching heading"
                    )
                continue

            resolved = (path.parent / file_part).resolve()
            if not resolved.exists():
                findings.append(f"{rel}:{number}: '{target}' does not resolve")
                continue

            if anchor and resolved.suffix == ".md":
                if resolved not in anchors:
                    continue  # excluded from the corpus; do not judge its anchors
                if anchor not in anchors[resolved]:
                    findings.append(
                        f"{rel}:{number}: '{target}' resolves, but anchor "
                        f"'#{anchor}' has no matching heading in that file"
                    )

if findings:
    print(f"verify_links: FAIL ({len(findings)} of {checked} relative links broken)\n")
    for finding in findings:
        print(f"  {finding}")
    print("\nExternal URLs are not fetched by this gate; review those by hand.")
    sys.exit(1)

print(f"verify_links: PASS ({checked} relative links and anchors resolved)")
PYTHON
