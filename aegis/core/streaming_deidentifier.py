# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Bounded incremental PHI/PCI redaction for streamed text.

The deidentifier retains a finite suffix so bounded identifiers split across
provider chunks are matched before any of their characters are released.  It
is a deterministic regex interceptor, not a certification of HIPAA Safe Harbor
or Expert Determination.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from aegis.core.pci_detector import (
    _CVV,
    _PAN_CANDIDATE,
    _TRACK1,
    _TRACK2,
    CardBrand,
    _mask_pan,
    detect_brand,
    luhn_valid,
)
from aegis.core.phi_deidentifier import _SAFE_HARBOR_PATTERNS


class StreamingDeidentificationError(ValueError):
    """Raised when a sensitive candidate exceeds the finite stream grammar."""


@dataclass(frozen=True)
class StreamRedactionStats:
    """Bounded, non-sensitive redaction counters."""

    entity_hits: dict[str, int]

    @property
    def total_hits(self) -> int:
        return sum(self.entity_hits.values())


@dataclass(frozen=True)
class _Match:
    start: int
    end: int
    replacement: str
    label: str
    priority: int


class StreamingDeidentifier:
    """Incrementally redact supported identifiers with a finite holdback.

    ``feed`` may return an empty string while text remains in the holdback.
    ``flush`` must be called exactly once at normal stream termination.
    Memory retained by this object is bounded to roughly twice ``window_chars``;
    an overlong URL or magnetic-track candidate fails closed.
    """

    def __init__(
        self,
        *,
        window_chars: int = 128,
        enable_phi: bool = True,
        enable_pci: bool = True,
    ) -> None:
        if window_chars < 64 or window_chars > 4096:
            raise ValueError("window_chars must be in [64, 4096]")
        self.window_chars = window_chars
        self.enable_phi = enable_phi
        self.enable_pci = enable_pci
        self._pending = ""
        self._hits: Counter[str] = Counter()
        self._phi_patterns = [
            (item.label, re.compile(item.pattern, item.flags)) for item in _SAFE_HARBOR_PATTERNS
        ]

    @property
    def retained_chars(self) -> int:
        return len(self._pending)

    @property
    def stats(self) -> StreamRedactionStats:
        return StreamRedactionStats(entity_hits=dict(self._hits))

    def feed(self, text: str) -> str:
        """Accept logical text and return the safe settled prefix."""
        if not text:
            return ""
        if not self.enable_phi and not self.enable_pci:
            return text
        self._pending += text
        if len(self._pending) <= self.window_chars:
            return ""
        cutoff = len(self._pending) - self.window_chars
        self._reject_overlong_open_candidate(cutoff)
        output, consumed = self._redact_prefix(self._pending, cutoff)
        self._pending = self._pending[consumed:]
        if len(self._pending) > self.window_chars * 2:
            raise StreamingDeidentificationError(
                "stream privacy holdback exceeded its deterministic bound"
            )
        return output

    def flush(self) -> str:
        """Redact and release the final suffix at normal termination."""
        if not self.enable_phi and not self.enable_pci:
            return ""
        self._reject_overlong_open_candidate(len(self._pending), final=True)
        output, consumed = self._redact_prefix(self._pending, len(self._pending))
        if consumed != len(self._pending):
            raise StreamingDeidentificationError("unable to settle final privacy suffix")
        self._pending = ""
        return output

    def _reject_overlong_open_candidate(self, cutoff: int, *, final: bool = False) -> None:
        """Fail closed for the established unbounded URL/track grammars."""
        if cutoff <= 0:
            return
        lower = self._pending.lower()
        starts = [
            lower.rfind("http://", 0, cutoff),
            lower.rfind("https://", 0, cutoff),
            self._pending.rfind("%B", 0, cutoff),
            self._pending.rfind(";", 0, cutoff),
        ]
        for start in starts:
            if start < 0:
                continue
            candidate = self._pending[start:]
            if len(candidate) <= self.window_chars:
                continue
            if candidate.startswith(("http://", "https://")):
                if not re.search(r"[\s\"'<>)\]]", candidate):
                    raise StreamingDeidentificationError("overlong open URL candidate")
            elif candidate.startswith(("%B", ";")) and "?" not in candidate:
                raise StreamingDeidentificationError("overlong open track-data candidate")
        token_start = (
            max(
                self._pending.rfind(" ", 0, cutoff),
                self._pending.rfind("\n", 0, cutoff),
                self._pending.rfind("\t", 0, cutoff),
            )
            + 1
        )
        open_token = self._pending[token_start:]
        if "@" in open_token and len(open_token) > self.window_chars:
            raise StreamingDeidentificationError("overlong open email candidate")
        address = re.search(r"(?:^|\b)\d{1,5}\s+[A-Za-z0-9 ]+$", self._pending)
        if address is not None and len(address.group(0)) > self.window_chars:
            raise StreamingDeidentificationError("overlong open address candidate")
        if final and len(self._pending) > self.window_chars * 2:
            raise StreamingDeidentificationError("final privacy suffix exceeds configured bound")

    def _collect_matches(self, text: str) -> list[_Match]:
        matches: list[_Match] = []
        priority = 0
        if self.enable_pci:
            for rx, label, replacement in (
                (_TRACK1, "TRACK_DATA", "[REDACTED:TRACK_DATA]"),
                (_TRACK2, "TRACK_DATA", "[REDACTED:TRACK_DATA]"),
                (_CVV, "CVV", "[REDACTED:CVV]"),
            ):
                for found in rx.finditer(text):
                    matches.append(_Match(found.start(), found.end(), replacement, label, priority))
                priority += 1
            for found in _PAN_CANDIDATE.finditer(text):
                digits = re.sub(r"[ -]", "", found.group(0))
                brand = detect_brand(digits) if luhn_valid(digits) else CardBrand.UNKNOWN
                if 13 <= len(digits) <= 19 and brand is not CardBrand.UNKNOWN:
                    matches.append(
                        _Match(
                            found.start(),
                            found.end(),
                            _mask_pan(digits),
                            "PAN",
                            priority,
                        )
                    )
            priority += 1
        if self.enable_phi:
            for label, rx in self._phi_patterns:
                for found in rx.finditer(text):
                    matches.append(
                        _Match(
                            found.start(),
                            found.end(),
                            f"[REDACTED:{label}]",
                            label,
                            priority,
                        )
                    )
                priority += 1
        return sorted(
            matches, key=lambda item: (item.start, item.priority, -(item.end - item.start))
        )

    def _redact_prefix(self, text: str, cutoff: int) -> tuple[str, int]:
        selected: list[_Match] = []
        occupied_until = -1
        for item in self._collect_matches(text):
            if item.start < occupied_until:
                continue
            if item.start >= cutoff:
                break
            selected.append(item)
            occupied_until = item.end

        parts: list[str] = []
        cursor = 0
        consumed = cutoff
        for item in selected:
            parts.append(text[cursor : item.start])
            parts.append(item.replacement)
            self._hits[item.label] += 1
            cursor = item.end
            if item.end > consumed:
                consumed = item.end
        parts.append(text[cursor:consumed])
        return "".join(parts), consumed
