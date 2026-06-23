# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.homoglyph_normalizer — Homoglyph normalization beyond NFKC.

NFKC normalization catches many Unicode compatibility equivalents, but leaves
a large class of visual lookalike substitutions untouched.  Attackers exploit
this gap by replacing ASCII letters with visually identical Cyrillic, Greek,
or other script characters that survive NFKC unchanged.

Example attacks that bypass NFKC:
  * ``аlert(1)``   — Cyrillic 'а' (U+0430) looks identical to Latin 'a'
  * ``ηello``      — Greek η (U+03B7) resembles 'n'
  * ``ρayload``    — Greek ρ (U+03C1) resembles 'p'
  * ``jаilbreak``  — Cyrillic а mixed into an otherwise ASCII word

This module provides:

* :class:`HomoglyphNormalizer` — maps lookalike chars to their ASCII base
  character using a compiled, maintainable mapping table.
* :func:`normalize` — module-level convenience function.

The mapping table covers:
  * Cyrillic characters that have visually identical Latin equivalents.
  * Greek lowercase and uppercase characters commonly confused with Latin.
  * Mathematical / letterlike Unicode characters (e.g., ℊ, ℬ).
  * Latin Extended characters that NFKC does not fully decompose.
  * Fullwidth Latin letters (U+FF01–U+FF5E).

Usage::

    normalizer = HomoglyphNormalizer()
    clean = normalizer.normalize("аlert(1)")     # Cyrillic а → Latin a
    # clean == "alert(1)"

    # Normalize before WAF scanning
    for form in decode_pipeline.all_forms(text):
        waf.scan(normalizer.normalize(form))
"""

from __future__ import annotations

import unicodedata

# ── Homoglyph mapping table ────────────────────────────────────────────────────
# Maps lookalike Unicode codepoints → their ASCII equivalents.
# Organized by source script for auditability.

_CYRILLIC_TO_LATIN: dict[str, str] = {
    # Lowercase Cyrillic
    "а": "a",  # U+0430 CYRILLIC SMALL LETTER A
    "е": "e",  # U+0435 CYRILLIC SMALL LETTER IE
    "о": "o",  # U+043E CYRILLIC SMALL LETTER O
    "р": "p",  # U+0440 CYRILLIC SMALL LETTER ER
    "с": "c",  # U+0441 CYRILLIC SMALL LETTER ES
    "х": "x",  # U+0445 CYRILLIC SMALL LETTER HA
    "і": "i",  # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ѕ": "s",  # U+0455 CYRILLIC SMALL LETTER DZE (resembles s)
    "ԁ": "d",  # U+0501 CYRILLIC SMALL LETTER KOMI DE
    "ɡ": "g",  # U+0261 LATIN SMALL LETTER SCRIPT G (also Unicode Latin Ext.)
    # Uppercase Cyrillic
    "А": "A",  # U+0410 CYRILLIC CAPITAL LETTER A
    "В": "B",  # U+0412 CYRILLIC CAPITAL LETTER VE
    "Е": "E",  # U+0415 CYRILLIC CAPITAL LETTER IE
    "К": "K",  # U+041A CYRILLIC CAPITAL LETTER KA
    "М": "M",  # U+041C CYRILLIC CAPITAL LETTER EM
    "Н": "H",  # U+041D CYRILLIC CAPITAL LETTER EN
    "О": "O",  # U+041E CYRILLIC CAPITAL LETTER O
    "Р": "P",  # U+0420 CYRILLIC CAPITAL LETTER ER
    "С": "C",  # U+0421 CYRILLIC CAPITAL LETTER ES
    "Т": "T",  # U+0422 CYRILLIC CAPITAL LETTER TE
    "Х": "X",  # U+0425 CYRILLIC CAPITAL LETTER HA
    "І": "I",  # U+0406 CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
}

_GREEK_TO_LATIN: dict[str, str] = {
    # Lowercase Greek — characters that visually match ASCII
    "α": "a",  # U+03B1 GREEK SMALL LETTER ALPHA
    "β": "b",  # U+03B2 GREEK SMALL LETTER BETA (resembles b)
    "ε": "e",  # U+03B5 GREEK SMALL LETTER EPSILON
    "ζ": "z",  # U+03B6 GREEK SMALL LETTER ZETA (resembles z)
    "η": "n",  # U+03B7 GREEK SMALL LETTER ETA (resembles n)
    "ι": "i",  # U+03B9 GREEK SMALL LETTER IOTA
    "κ": "k",  # U+03BA GREEK SMALL LETTER KAPPA
    "ν": "v",  # U+03BD GREEK SMALL LETTER NU (resembles v)
    "ο": "o",  # U+03BF GREEK SMALL LETTER OMICRON
    "ρ": "p",  # U+03C1 GREEK SMALL LETTER RHO (resembles p)
    "τ": "t",  # U+03C4 GREEK SMALL LETTER TAU
    "υ": "u",  # U+03C5 GREEK SMALL LETTER UPSILON (resembles u)
    "χ": "x",  # U+03C7 GREEK SMALL LETTER CHI (resembles x)
    "ω": "w",  # U+03C9 GREEK SMALL LETTER OMEGA (resembles w)
    # Uppercase Greek — visually matching ASCII
    "Α": "A",  # U+0391 GREEK CAPITAL LETTER ALPHA
    "Β": "B",  # U+0392 GREEK CAPITAL LETTER BETA
    "Ε": "E",  # U+0395 GREEK CAPITAL LETTER EPSILON
    "Η": "H",  # U+0397 GREEK CAPITAL LETTER ETA
    "Ι": "I",  # U+0399 GREEK CAPITAL LETTER IOTA
    "Κ": "K",  # U+039A GREEK CAPITAL LETTER KAPPA
    "Μ": "M",  # U+039C GREEK CAPITAL LETTER MU
    "Ν": "N",  # U+039D GREEK CAPITAL LETTER NU
    "Ο": "O",  # U+039F GREEK CAPITAL LETTER OMICRON
    "Ρ": "P",  # U+03A1 GREEK CAPITAL LETTER RHO
    "Τ": "T",  # U+03A4 GREEK CAPITAL LETTER TAU
    "Υ": "Y",  # U+03A5 GREEK CAPITAL LETTER UPSILON
    "Χ": "X",  # U+03A7 GREEK CAPITAL LETTER CHI
    "Ζ": "Z",  # U+0396 GREEK CAPITAL LETTER ZETA
}

_FULLWIDTH_TO_ASCII: dict[str, str] = {
    # Fullwidth ASCII variants U+FF01 – U+FF5E → U+0021 – U+007E
    chr(cp): chr(cp - 0xFF01 + 0x21)
    for cp in range(0xFF01, 0xFF5F)
    if 0x20 <= (cp - 0xFF01 + 0x21) <= 0x7E
}

_LETTERLIKE_TO_ASCII: dict[str, str] = {
    # Letterlike / mathematical symbols that resemble plain ASCII letters
    "ℬ": "B",  # U+212C SCRIPT CAPITAL B
    "ℰ": "E",  # U+2130 SCRIPT CAPITAL E
    "ℱ": "F",  # U+2131 SCRIPT CAPITAL F
    "ℋ": "H",  # U+210B SCRIPT CAPITAL H
    "ℐ": "I",  # U+2110 SCRIPT CAPITAL I
    "ℒ": "L",  # U+2112 SCRIPT CAPITAL L
    "ℳ": "M",  # U+2133 SCRIPT CAPITAL M
    "ℛ": "R",  # U+211B SCRIPT CAPITAL R
    "ℊ": "g",  # U+210A SCRIPT SMALL G
    "ℎ": "h",  # U+210E PLANCK CONSTANT (resembles italic h)
    "ℓ": "l",  # U+2113 SCRIPT SMALL L
    "ℴ": "o",  # U+2134 SCRIPT SMALL O
    "ℕ": "N",  # U+2115 DOUBLE-STRUCK CAPITAL N
    "ℤ": "Z",  # U+2124 DOUBLE-STRUCK CAPITAL Z
    "ℚ": "Q",  # U+211A DOUBLE-STRUCK CAPITAL Q
    "ℝ": "R",  # U+211D DOUBLE-STRUCK CAPITAL R
    "ℂ": "C",  # U+2102 DOUBLE-STRUCK CAPITAL C
}

# Combined mapping (evaluated once at module import)
_HOMOGLYPH_TABLE: dict[str, str] = {
    **_CYRILLIC_TO_LATIN,
    **_GREEK_TO_LATIN,
    **_FULLWIDTH_TO_ASCII,
    **_LETTERLIKE_TO_ASCII,
}

# Total number of mapped codepoints (exposed for tests)
HOMOGLYPH_TABLE_SIZE: int = len(_HOMOGLYPH_TABLE)

# Translation table for str.translate — O(1) per character
_TRANSLATE_TABLE: dict[int, str] = {ord(src): dst for src, dst in _HOMOGLYPH_TABLE.items()}


class HomoglyphNormalizer:
    """Homoglyph-aware text normalizer for WAF evasion resistance.

    Applies normalization in two stages:

    1. **NFKC** — standard Unicode compatibility decomposition + canonical
       composition, handled by Python's :func:`unicodedata.normalize`.
    2. **Homoglyph mapping** — replaces Cyrillic/Greek/letterlike codepoints
       with their ASCII equivalents using :attr:`_HOMOGLYPH_TABLE`.

    Both stages run in a single pass (O(n) in string length).

    Parameters
    ----------
    extra_mappings:
        Additional ``{lookalike_char: ascii_char}`` mappings to supplement
        the built-in table.  Useful for product-specific evasion patterns.
    apply_nfkc:
        Whether to apply NFKC normalization before homoglyph substitution.
        Default ``True``.  Disable if the caller already applied NFKC.
    """

    def __init__(
        self,
        extra_mappings: dict[str, str] | None = None,
        apply_nfkc: bool = True,
    ) -> None:
        self._apply_nfkc = apply_nfkc
        if extra_mappings:
            table = dict(_TRANSLATE_TABLE)
            table.update({ord(k): v for k, v in extra_mappings.items()})
            self._table: dict[int, str] = table
        else:
            self._table = _TRANSLATE_TABLE

    @property
    def mapping_count(self) -> int:
        """Number of codepoints in the active homoglyph table."""
        return len(self._table)

    def normalize(self, text: str) -> str:
        """Return *text* with homoglyphs replaced by their ASCII equivalents.

        Parameters
        ----------
        text:
            Input string (may contain homoglyphs or mixed-script content).

        Returns
        -------
        str
            Normalized string suitable for WAF pattern matching.
        """
        if not text:
            return text
        if self._apply_nfkc:
            text = unicodedata.normalize("NFKC", text)
        return text.translate(self._table)

    def normalize_bulk(self, texts: list[str]) -> list[str]:
        """Normalize a list of strings in one call."""
        return [self.normalize(t) for t in texts]

    def has_homoglyphs(self, text: str) -> bool:
        """Return True if *text* contains any mapped homoglyph codepoints.

        Checks after NFKC (if enabled) to avoid false positives from
        codepoints that NFKC resolves on its own.
        """
        if self._apply_nfkc:
            text = unicodedata.normalize("NFKC", text)
        return any(ord(ch) in self._table for ch in text)


def normalize(text: str) -> str:
    """Module-level convenience wrapper — normalize *text* using the default table."""
    return HomoglyphNormalizer().normalize(text)
