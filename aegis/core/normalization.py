"""
aegis.core.normalization — Canonical normalization of inputs.
Prevents bypasses via Unicode obfuscation, whitespace manipulation, and encoding tricks.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import re
import unicodedata
from typing import Any


def canonical_normalize(data: Any) -> Any:
    """
    Recursively normalizes a payload to a canonical form.
    - Unicode normalization (NFKC) to flatten visually similar characters.
    - Whitespace collapsing to prevent hidden bypasses.
    - Stripping non-printable control characters.
    """
    if isinstance(data, str):
        # 1. Unicode NFKC Normalization
        # This flattens characters like 'ℌ' (U+210C) to 'H' (U+0048)
        normalized = unicodedata.normalize("NFKC", data)

        # 2. Strip control characters (except newline/tab)
        # \x00-\x1F and \x7F are standard control chars
        normalized = "".join(ch for ch in normalized if ord(ch) >= 32 or ch in "\n\r\t")

        # 3. Collapse multiple whitespaces into single spaces
        normalized = re.sub(r"[ \t\f\v]+", " ", normalized)

        return normalized.strip()

    elif isinstance(data, dict):
        return {k: canonical_normalize(v) for k, v in data.items()}

    elif isinstance(data, list):
        return [canonical_normalize(i) for i in data]

    return data
