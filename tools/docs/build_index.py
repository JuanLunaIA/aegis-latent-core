#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Generate ``docs/DOCUMENTATION_INDEX.md`` from the documentation tree.

The index is a derived artifact: every Markdown page under ``docs/`` is
listed once, grouped by its directory, with the page's H1 and its first
paragraph. Links in the index are relative to the index file itself, and
every one is resolved before the file is written, so a page that cannot be
linked is a generation error rather than a broken entry.

Determinism is a hard requirement: the output carries no timestamps, no
host paths, no absolute paths, and the ordering is fixed (directories
first, then pages, both sorted case-insensitively with an exact-match
tie-breaker). Running the script twice on the same tree produces
byte-identical output.

Self-verification:

    python tools/docs/build_index.py           # regenerate
    python tools/docs/build_index.py --check   # fail if committed index is stale

Exit codes: 0 current/generated, 1 stale or missing index, 2 cannot run.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

INDEX_NAME = "DOCUMENTATION_INDEX.md"

#: Directories never walked, mirroring the other documentation checkers.
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    ".next",
    "target",
    "htmlcov",
    "evidence",
    ".aegis_ai_context",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

#: Longest opening-paragraph summary kept per page. Truncation happens on a
#: word boundary and never mid-link, so a quoted ``/v1/...`` path stays whole.
SUMMARY_LIMIT = 240
TRUNCATION_MARKER = "\u2026"

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
H1_RE = re.compile(r"^#\s+(.+?)\s*$")
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
MARKDOWN_LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
HORIZONTAL_RULE_RE = re.compile(r"^([-*_])(?:\s*\1){2,}\s*$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True)
class Page:
    """One Markdown page and the two fields the index publishes."""

    relative: str
    title: str
    summary: str | None


@dataclass
class BrokenLink:
    """A relative link in an indexed page whose target does not resolve."""

    page: str
    line: int
    target: str


@dataclass
class BuildResult:
    """Rendered index plus the counters quoted in its header."""

    content: str
    pages: list[Page] = field(default_factory=list)
    directories: int = 0
    links_checked: int = 0
    broken: list[BrokenLink] = field(default_factory=list)
    missing_h1: list[str] = field(default_factory=list)


def iter_pages(docs_dir: Path, output: Path) -> list[Path]:
    """Return every Markdown page under *docs_dir*, excluding the index itself."""

    pages: list[Path] = []
    for path in docs_dir.rglob("*.md"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(docs_dir).parts
        if any(part in EXCLUDED_DIRS for part in relative_parts):
            continue
        if path.resolve() == output.resolve():
            continue
        pages.append(path)
    return sorted(pages, key=lambda item: item.relative_to(docs_dir).as_posix())


def _skip_comment(lines: list[str], index: int, in_comment: bool) -> tuple[int, bool]:
    """Advance past an HTML comment starting at *index*; return (next, in_comment)."""

    text = lines[index].strip()
    if in_comment:
        if "-->" in text:
            return index + 1, False
        return index + 1, True
    if text.startswith("<!--"):
        # A one-line comment (``<!-- ... -->``) closes on the same line.
        return index + 1, "-->" not in text[4:]
    return index, False


def extract_heading(text: str) -> str | None:
    """Return the page's first H1, skipping a leading comment block."""

    lines = text.splitlines()
    in_comment = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if in_comment or stripped.startswith("<!--"):
            _, in_comment = _skip_comment(lines, index, in_comment)
            continue
        match = H1_RE.match(line)
        if match:
            return match.group(1).strip()
        if not stripped.startswith(">"):
            # Content before any H1 means there is no leading H1 to publish.
            return None
    return None


def extract_first_paragraph(text: str) -> str | None:
    """Return the first prose paragraph after the H1, or ``None``."""

    lines = text.splitlines()
    h1_index: int | None = None
    in_comment = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if in_comment or stripped.startswith("<!--"):
            _, in_comment = _skip_comment(lines, index, in_comment)
            continue
        if H1_RE.match(line):
            h1_index = index
            break

    if h1_index is None:
        return None

    index = h1_index + 1
    in_comment = False
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            index += 1
            continue
        if in_comment or stripped.startswith("<!--"):
            index, in_comment = _skip_comment(lines, index, in_comment)
            continue
        if HEADING_RE.match(lines[index]) or HORIZONTAL_RULE_RE.match(stripped):
            index += 1
            continue
        if FENCE_RE.match(stripped) or stripped.startswith("|"):
            # A code block or a table opens the page: no prose paragraph.
            return None
        break

    block: list[str] = []
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or HEADING_RE.match(lines[index]) or FENCE_RE.match(lines[index]):
            break
        if stripped.startswith("|"):
            break
        block.append(re.sub(r"^>\s?", "", stripped))
        index += 1

    paragraph = " ".join(block).strip()
    return paragraph or None


def summarize(paragraph: str | None) -> str | None:
    """Flatten a paragraph to index prose, deterministically bounded."""

    if paragraph is None:
        return None
    text = MARKDOWN_LINK_RE.sub(r"\1", paragraph)
    text = text.replace("`", "").replace("**", "").replace("__", "")
    text = re.sub(r"\s+", " ", text).strip()
    text = text.replace("[", r"\[").replace("]", r"\]")
    if len(text) > SUMMARY_LIMIT:
        cut = text[:SUMMARY_LIMIT].rsplit(" ", 1)[0].rstrip(" ,;:")
        if cut:
            text = cut + TRUNCATION_MARKER
    return text or None


def normalize_title(title: str) -> str:
    """Make an H1 safe as the label of a Markdown link."""

    text = title.replace("`", "").replace("**", "").replace("__", "")
    text = re.sub(r"\s+", " ", text).strip()
    return text.replace("[", r"\[").replace("]", r"\]") or "Untitled"


def resolve_links(page_path: Path, docs_dir: Path, root: Path) -> tuple[int, list[BrokenLink]]:
    """Count relative links in *page_path* and return those that do not resolve."""

    relative_page = page_path.relative_to(docs_dir).as_posix()
    checked = 0
    broken: list[BrokenLink] = []
    in_fence = False
    for number, line in enumerate(page_path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            # Link-shaped text inside a fence is sample output, not a link.
            continue
        for match in LINK_RE.finditer(line):
            target = match.group(1).strip().strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue
            checked += 1
            resolved = (page_path.parent / path_part).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                broken.append(BrokenLink(relative_page, number, target))
                continue
            if not resolved.exists():
                broken.append(BrokenLink(relative_page, number, target))
    return checked, broken


def group_pages(pages: list[Page]) -> list[tuple[str, list[Page]]]:
    """Group pages by directory, root first, then lexicographic (case-insensitive)."""

    grouped: dict[str, list[Page]] = {}
    for page in pages:
        directory = page.relative.rsplit("/", 1)[0] if "/" in page.relative else ""
        grouped.setdefault(directory, []).append(page)

    def order(name: str) -> tuple[int, str, str]:
        return (0 if name == "" else 1, name.casefold(), name)

    result: list[tuple[str, list[Page]]] = []
    for directory in sorted(grouped, key=order):
        entries = sorted(grouped[directory], key=lambda page: (page.relative.casefold(), page.relative))
        result.append((directory, entries))
    return result


def _doc_link(docs_dir: Path, name: str, label: str) -> str:
    """Link to a sibling document only when it exists, so the index cannot dangle."""

    if (docs_dir / name).is_file():
        return f"[{label}]({name})"
    return label


def render(result: BuildResult, docs_dir: Path) -> str:
    """Render the index body from a populated :class:`BuildResult`."""

    lines: list[str] = [
        "# Generated Documentation Index",
        "",
        "<!-- Generated by tools/docs/build_index.py. Do not edit by hand. -->",
        "<!-- Regenerate: python tools/docs/build_index.py -->",
        "<!-- Verify:     python tools/docs/build_index.py --check -->",
        "",
        "Every Markdown page under `docs/`, grouped by its directory, with the page H1 and",
        "its opening paragraph. Links are relative to this file and were resolved when the",
        "index was generated. The index records what the documentation set contains; it",
        "does not establish publication, deployment, or external acceptance. See",
        f"{_doc_link(docs_dir, 'RELEASE_STATUS.md', 'Release Status')} and "
        f"{_doc_link(docs_dir, 'BOUNDARIES.md', 'Boundaries')}.",
        "",
        f"- Pages indexed: {len(result.pages)}",
        f"- Directory groups: {result.directories}",
        f"- Relative links in indexed pages: {result.links_checked}",
        f"- Broken relative links in indexed pages: {len(result.broken)}",
        "",
    ]

    for directory, entries in group_pages(result.pages):
        heading = "docs/" if directory == "" else f"docs/{directory}/"
        lines.append(f"## {heading}")
        lines.append("")
        for page in entries:
            link = page.relative
            summary = page.summary
            if summary:
                lines.append(f"- **[{page.title}]({link})** \u2014 {summary}")
            else:
                lines.append(f"- **[{page.title}]({link})** \u2014 No opening paragraph.")
        lines.append("")

    if result.missing_h1:
        lines.append("## Pages without an H1")
        lines.append("")
        for relative in sorted(result.missing_h1):
            lines.append(f"- `{relative}`")
        lines.append("")

    if result.broken:
        lines.append("## Broken relative links")
        lines.append("")
        for link in sorted(result.broken, key=lambda item: (item.page, item.line, item.target)):
            lines.append(f"- `{link.page}:{link.line}` \u2192 `{link.target}`")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def build(root: Path, docs_dir: Path, output: Path) -> BuildResult:
    """Walk the docs tree and return the rendered index plus its counters."""

    result = BuildResult(content="")
    for path in iter_pages(docs_dir, output):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(docs_dir).as_posix()
        heading = extract_heading(text)
        if heading is None:
            result.missing_h1.append(relative)
            heading = path.stem
        summary = summarize(extract_first_paragraph(text))
        checked, broken = resolve_links(path, docs_dir, root)
        result.links_checked += checked
        result.broken.extend(broken)
        result.pages.append(Page(relative, normalize_title(heading), summary))

    result.directories = len({page.relative.rsplit("/", 1)[0] if "/" in page.relative else "" for page in result.pages})
    result.content = render(result, docs_dir)
    return result


def index_broken_links(content: str, index_dir: Path) -> list[str]:
    """Return every relative link in the rendered index that does not resolve."""

    broken: list[str] = []
    for match in LINK_RE.finditer(content):
        target = match.group(1).strip().strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        path_part = target.split("#", 1)[0]
        if path_part and not (index_dir / path_part).resolve().exists():
            broken.append(target)
    return broken


def _summary_line(result: BuildResult) -> str:
    return (
        f"{len(result.pages)} pages, {result.directories} directory groups, "
        f"{result.links_checked} relative links, {len(result.broken)} broken"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (default: the checkout containing this script)",
    )
    parser.add_argument(
        "--docs-dir",
        default="docs",
        help="documentation directory relative to the root (default: docs)",
    )
    parser.add_argument(
        "--out",
        default=f"docs/{INDEX_NAME}",
        help=f"index path relative to the root (default: docs/{INDEX_NAME})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 when the committed index differs from the generated one",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    docs_dir = (root / args.docs_dir).resolve()
    output = (root / args.out).resolve()
    if not root.is_dir() or not docs_dir.is_dir():
        print(f"ERROR: documentation directory does not exist: {docs_dir}", file=sys.stderr)
        return 2
    if not output.is_relative_to(docs_dir):
        print(f"ERROR: index path must live under {docs_dir}: {output}", file=sys.stderr)
        return 2

    result = build(root, docs_dir, output)
    if not result.pages:
        print(f"ERROR: no Markdown pages found under {docs_dir}", file=sys.stderr)
        return 2

    index_broken = index_broken_links(result.content, output.parent)
    if index_broken:
        print("ERROR: generated index contains unresolved links:", file=sys.stderr)
        for target in sorted(set(index_broken)):
            print(f"  {target}", file=sys.stderr)
        return 2

    if args.check:
        if not output.is_file():
            print(f"DOCS_INDEX:1 index is missing: {output.relative_to(root).as_posix()}")
            print("  regenerate with: python tools/docs/build_index.py")
            return 1
        expected = result.content.encode("utf-8")
        committed_bytes = output.read_bytes()
        if committed_bytes == expected:
            print(f"DOCS_INDEX:0 index current: {_summary_line(result)}")
            return 0
        committed = committed_bytes.decode("utf-8", errors="replace")
        print(f"DOCS_INDEX:1 index is stale: {output.relative_to(root).as_posix()}")
        diff = list(
            difflib.unified_diff(
                committed.splitlines(),
                result.content.splitlines(),
                fromfile="committed",
                tofile="generated",
                n=1,
                lineterm="",
            )
        )
        for line in diff[:40]:
            print(f"  {line}")
        if len(diff) > 40:
            print(f"  ... {len(diff) - 40} more diff lines")
        if not diff:
            print("  content matches but bytes differ (line endings or encoding)")
        print("  regenerate with: python tools/docs/build_index.py")
        return 1

    output.write_text(result.content, encoding="utf-8", newline="\n")
    print(f"wrote {output.relative_to(root).as_posix()}: {_summary_line(result)}")
    if result.missing_h1:
        print(f"  pages without an H1: {', '.join(sorted(result.missing_h1))}")
    if result.broken:
        print(f"  broken links recorded in the index: {len(result.broken)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
