# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Real-time PHI de-identification — NIST SP 800-188 Safe Harbor method.

Scrubs the 18 HIPAA Safe Harbor identifier categories from text using
pre-compiled regex patterns.  No external NLP dependencies are required;
the module is a pure-Python, stateless, thread-safe scrubber suitable for
the hot request/response path.

Usage::

    from aegis.core.phi_deidentifier import PHIDeidentifier

    scrubber = PHIDeidentifier()          # compile once, reuse everywhere
    result = scrubber.scrub("Call me at 555-123-4567 or john@example.com")
    # result.text  → "Call me at [REDACTED:PHONE] or [REDACTED:EMAIL]"
    # result.hits  → {"PHONE": 1, "EMAIL": 1}
    # result.method → "safe_harbor_regex"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple


class _Pattern(NamedTuple):
    label: str
    pattern: str
    flags: int = re.IGNORECASE


# NIST SP 800-188 / HIPAA Safe Harbor identifier patterns.
# Each entry carries the category label used in the REDACTED token.
#
# ORDER IS CRITICAL: label-anchored patterns (NPI, MRN, LICENSE…) must appear
# BEFORE their generic numeric counterparts (PHONE, ZIP, ACCOUNT…) so that the
# more specific labelled form claims the match before the plain-number fallback
# fires and obscures the diagnostic label.
_SAFE_HARBOR_PATTERNS: list[_Pattern] = [
    # ── 14. Web URLs (before IP, avoids URL paths being matched as IPs) ──
    _Pattern(
        "URL",
        r"https?://[^\s\"'<>)\]]+",
        re.IGNORECASE,
    ),
    # ── 6. Email addresses ───────────────────────────────────────────────
    _Pattern(
        "EMAIL",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    ),
    # ── 7. Social Security Numbers ───────────────────────────────────────
    # Match all SSN-format strings (NNN-NN-NNNN) regardless of area-code
    # validity: Safe Harbor scrubbing favours recall over precision.
    _Pattern(
        "SSN",
        r"\b\d{3}[- ]\d{2}[- ]\d{4}\b",
    ),
    # ── 18. NPI (before PHONE — 10-digit NPI would otherwise be swallowed) ─
    _Pattern(
        "NPI",
        r"\b(?:NPI)\s*[:#]?\s*\d{10}\b",
        re.IGNORECASE,
    ),
    # ── 8. Medical Record Numbers (MRN) (before ZIP / plain numbers) ─────
    # Matches: MRN: X, MRN#X, Medical Record Number: X, Medical Record No: X,
    #          MR No: X, MR Number: X, MR#X, MR: X
    _Pattern(
        "MRN",
        r"\b(?:MRN\s*[:#]?|Medical\s+Record(?:\s+No(?:\.)?)?(?:\s+Number)?\s*[:#]?|MR\s*(?:No\.?|Number|#|:))\s*\d{5,10}\b",
        re.IGNORECASE,
    ),
    # ── 9. Health plan beneficiary numbers ───────────────────────────────
    _Pattern(
        "HEALTH_PLAN_ID",
        r"\b(?:HPBN|HIC|NBI|Member\s+ID|Beneficiary\s+(?:No|Number|ID))\s*[:#]?\s*[A-Z0-9]{6,12}\b",
        re.IGNORECASE,
    ),
    # ── 11. Certificate / License numbers (before generic number patterns) ─
    _Pattern(
        "LICENSE",
        r"\b(?:License|Lic\.|Cert(?:ificate)?|DEA)\s*(?:No\.?|Number|#|:)?\s*[A-Z0-9]{5,12}\b",
        re.IGNORECASE,
    ),
    # ── 13. Device identifiers (before PHONE) ────────────────────────────
    _Pattern(
        "DEVICE_ID",
        r"\b(?:S/N|Serial\s+(?:No\.?|Number)|SN)\s*[:#]?\s*[A-Z0-9\-]{6,20}\b",
        re.IGNORECASE,
    ),
    # ── 10. Account numbers (credit card — before PHONE) ─────────────────
    _Pattern(
        "ACCOUNT",
        r"\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2}|3(?:0[0-5]|[68]\d)\d)"
        r"[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{0,4}\b",
    ),
    # ── 4 & 5. Phone/Fax numbers ─────────────────────────────────────────
    _Pattern(
        "PHONE",
        r"(?<!\d)(?:\+?1[\s\-\.]?)?(?:\(\d{3}\)|\d{3})[\s\-\.]?\d{3}[\s\-\.]?\d{4}(?!\d)",
    ),
    # ── 1. Names — Title + name heuristic ────────────────────────────────
    _Pattern(
        "NAME",
        r"\b(?:Dr\.|Mr\.|Mrs\.|Ms\.|Prof\.|Rev\.|Capt\.|Lt\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b",
        re.UNICODE,
    ),
    # ── 2. Geographic sub-state data — street addresses ───────────────────
    _Pattern(
        "ADDRESS",
        r"\b\d{1,5}\s+[A-Za-z0-9 ]+(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|"
        r"Dr(?:ive)?|Ln|Lane|Ct|Court|Pl|Place|Way|Pkwy|Hwy|Highway)\b",
        re.IGNORECASE,
    ),
    # ── 3. Dates (not year-only) — MM/DD/YYYY, YYYY-MM-DD, Month DD YYYY ─
    _Pattern(
        "DATE",
        r"\b(?:"
        r"\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}"  # 01/23/1990 or 1-23-90
        r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?"
        r"|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
        r"\s+\d{1,2}(?:st|nd|rd|th)?[,\s]+\d{4}"  # January 23, 1990
        r"|\d{4}-\d{2}-\d{2}"  # ISO 8601: 1990-01-23
        r")\b",
        re.IGNORECASE,
    ),
    # ── 2b. ZIP codes (after DATE to avoid year-month confusion) ──────────
    _Pattern("ZIP", r"\b\d{5}(?:-\d{4})?\b"),
    # ── 12. Vehicle identifiers (VIN — 17-char, after other patterns) ────
    _Pattern(
        "VIN",
        r"\b[A-HJ-NPR-Z0-9]{17}\b",
    ),
    # ── 15. IP addresses (after URL) ─────────────────────────────────────
    _Pattern(
        "IP_ADDRESS",
        r"\b(?:"
        r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
        r"|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"  # IPv6
        r")\b",
    ),
    # ── 16 & 17. Biometric / photograph references (keyword-based) ────────
    _Pattern(
        "BIOMETRIC",
        r"\b(?:fingerprint|retina\s+scan|iris\s+scan|voice\s+print|facial\s+recognition"
        r"|DNA\s+profile|biometric\s+(?:record|data|identifier))\b",
        re.IGNORECASE,
    ),
]


@dataclass
class ScrubResult:
    """Result of a PHI scrub operation."""

    text: str
    hits: dict[str, int] = field(default_factory=dict)
    method: str = "safe_harbor_regex"

    @property
    def phi_detected(self) -> bool:
        return bool(self.hits)

    @property
    def total_hits(self) -> int:
        return sum(self.hits.values())


class PHIDeidentifier:
    """Stateless, thread-safe PHI scrubber for the NIST SP 800-188 Safe Harbor categories.

    Compile once at application start-up; call ``scrub()`` on every text fragment.
    """

    def __init__(self) -> None:
        self._compiled: list[tuple[str, re.Pattern[str]]] = []
        for p in _SAFE_HARBOR_PATTERNS:
            self._compiled.append((p.label, re.compile(p.pattern, p.flags)))

    def scrub(self, text: str) -> ScrubResult:
        """Scrub PHI from *text* and return a :class:`ScrubResult`.

        Each detected entity is replaced with ``[REDACTED:<LABEL>]``.
        Replacements are applied in pattern-declaration order (most specific
        patterns first) to avoid partial matches shadowing longer ones.
        """
        if not text:
            return ScrubResult(text=text)

        hits: dict[str, int] = {}
        current = text
        for label, rx in self._compiled:
            def _replace(m: re.Match, _label: str = label) -> str:  # noqa: E731
                hits[_label] = hits.get(_label, 0) + 1
                return f"[REDACTED:{_label}]"

            current = rx.sub(_replace, current)

        return ScrubResult(text=current, hits=hits)

    def scrub_messages(self, messages: list[dict]) -> tuple[list[dict], dict[str, int]]:
        """Scrub PHI from the ``content`` field of each message dict (in-place copy).

        Returns a new list of message dicts (originals are not mutated) and
        a merged hit counter across all messages.
        """
        total_hits: dict[str, int] = {}
        scrubbed: list[dict] = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str) and content:
                result = self.scrub(content)
                new_msg = dict(msg)
                new_msg["content"] = result.text
                for k, v in result.hits.items():
                    total_hits[k] = total_hits.get(k, 0) + v
                scrubbed.append(new_msg)
            else:
                scrubbed.append(msg)
        return scrubbed, total_hits
