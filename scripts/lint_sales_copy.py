# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Reject banned superlatives in sales-facing copy (Mission XVI, PD-XV-2).

Banned: guaranteed, unbreakable, certified, 100%, military-grade. A term is
allowed only inside a sentence that negates or quotes it ("not certified",
"no certification", "Do not use: ..."), because the claims discipline names
these words in order to refuse them.

    python scripts/lint_sales_copy.py            # default sales surface
    python scripts/lint_sales_copy.py PATH ...   # explicit files or directories

Exit 0 when clean, 1 when a finding exists. It reads text only; it does not judge
whether the remaining sentences are true. ``scripts/verify_claims.py`` and
``tools/docs/verify_documentation.py`` do that.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BANNED = re.compile(
    r"\b(guarantee[sd]?|unbreakable|certified|military[- ]grade)\b|(?<![\w.])100\s?%",
    re.IGNORECASE,
)
NEGATION = re.compile(
    r"\b(not|no|never|without|cannot|can't|isn't|aren't|wasn't|don't|doesn't|didn't|nor|"
    r"neither|refuse[sd]?|reject(?:s|ed)?|banned|forbidden|blocked|unsupported|non)\b|do not use|we do not claim",
    re.IGNORECASE,
)
DEFAULT_TARGETS = (
    "README.md",
    "docs/PROVE_IT.md",
    "docs/commercial",
    "site",
    "tools/sales",
)
SUFFIXES = {".md", ".html", ".txt"}


def _files(targets: Iterable[Path]) -> Iterator[Path]:
    for target in targets:
        if target.is_dir():
            yield from sorted(p for p in target.rglob("*") if p.suffix in SUFFIXES)
        elif target.is_file():
            yield target


def _sentences(text: str) -> Iterator[tuple[int, str]]:
    """Yield (line number, sentence) pairs, splitting each line on sentence ends."""
    for number, line in enumerate(text.splitlines(), start=1):
        for sentence in re.split(r"(?<=[.!?;])\s+|\s+[|—]\s+", line):
            if sentence.strip():
                yield number, sentence


_NON_COPY = re.compile(r"<(style|script)\b.*?</\1>", re.IGNORECASE | re.DOTALL)


def _blank_non_copy(text: str) -> str:
    """Blank <style>/<script> bodies but keep line numbers, since CSS such as
    ``width:100%`` is layout, not copy."""
    return _NON_COPY.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def lint_text(text: str) -> list[tuple[int, str, str]]:
    findings: list[tuple[int, str, str]] = []
    text = _blank_non_copy(text)
    for number, sentence in _sentences(text):
        for match in BANNED.finditer(sentence):
            if NEGATION.search(sentence):
                continue
            findings.append((number, match.group(0), sentence.strip()[:120]))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args(argv)
    targets = args.paths or [ROOT / name for name in DEFAULT_TARGETS]
    total = 0
    scanned = 0
    for path in _files(targets):
        scanned += 1
        for number, term, sentence in lint_text(path.read_text(encoding="utf-8", errors="replace")):
            total += 1
            shown = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
            print(f"{shown}:{number}: banned term {term!r}: {sentence}")
    print(f"lint_sales_copy: {'FAIL' if total else 'PASS'} ({scanned} files, {total} findings)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
