# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.pci_detector — PCI-DSS v4.0 cardholder-data detection & masking.

Detects and redacts cardholder data (CHD) and sensitive authentication data (SAD)
in free text before it is forwarded to an upstream model, analogous to the PHI
de-identification path:

* **PAN** (Primary Account Number) — 13–19 digit card numbers that pass the
  **Luhn check** and match a known issuer IIN range (Visa, Mastercard, Amex,
  Discover, Diners, JCB). The Luhn + IIN gate keeps false positives low (a random
  16-digit order number will almost never validate).
* **CVV/CVC** — 3–4 digit card verification values appearing in a card-security
  context (``cvv: 123``). Per PCI-DSS, CVV must **never** be stored — it is always
  fully redacted, never masked.
* **Track data** — magnetic-stripe Track 1/Track 2 patterns (SAD). Always fully
  redacted.

Masking follows PCI-DSS §3.4: a detected PAN is replaced with a token that
exposes at most the last four digits (``[PAN-****1111]``); CVV and track data are
replaced with ``[REDACTED:CVV]`` / ``[REDACTED:TRACK_DATA]`` (no residual digits).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class CardBrand(StrEnum):
    VISA = "visa"
    MASTERCARD = "mastercard"
    AMEX = "amex"
    DISCOVER = "discover"
    DINERS = "diners"
    JCB = "jcb"
    UNKNOWN = "unknown"


# Candidate PAN: 13–19 digits with optional single space/hyphen separators.
_PAN_CANDIDATE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# CVV only in an explicit card-security context (avoids matching any 3-digit number).
_CVV = re.compile(r"\b(?:cvv|cvc|cvv2|cvc2|cid|cav2)\b\s*[:#=]?\s*(\d{3,4})\b", re.IGNORECASE)

# Track 1 (starts %B…?) and Track 2 (;PAN=…?) magnetic-stripe data.
_TRACK1 = re.compile(r"%B\d{12,19}\^[^^]{2,26}\^\d{4,}[^?]*\?", re.IGNORECASE)
_TRACK2 = re.compile(r";\d{12,19}=\d{4,}[^?]*\?")


def luhn_valid(digits: str) -> bool:
    """Return True if *digits* (a bare digit string) passes the Luhn checksum."""
    if not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_brand(pan: str) -> CardBrand:
    """Classify a bare-digit PAN by issuer identification number (IIN) + length."""
    n = len(pan)
    if pan.startswith("4") and n in (13, 16, 19):
        return CardBrand.VISA
    if n == 15 and pan[:2] in ("34", "37"):
        return CardBrand.AMEX
    if n == 16:
        two = int(pan[:2])
        four = int(pan[:4])
        if 51 <= two <= 55 or 2221 <= four <= 2720:
            return CardBrand.MASTERCARD
        if pan.startswith("6011") or pan[:2] == "65" or 644 <= int(pan[:3]) <= 649:
            return CardBrand.DISCOVER
        if 3528 <= four <= 3589:
            return CardBrand.JCB
    if n == 14 and (pan[:2] in ("36", "38") or 300 <= int(pan[:3]) <= 305):
        return CardBrand.DINERS
    return CardBrand.UNKNOWN


def _mask_pan(pan: str) -> str:
    """PCI-DSS §3.4 masking — expose at most the last four digits."""
    last4 = pan[-4:]
    return f"[PAN-****{last4}]"


@dataclass
class PCIScanResult:
    """Result of scanning text for cardholder / sensitive-authentication data."""

    text: str  # masked/redacted output text
    pan_count: int = 0
    cvv_count: int = 0
    track_count: int = 0
    brands: list[CardBrand] = field(default_factory=list)

    @property
    def chd_detected(self) -> bool:
        """True when any cardholder or sensitive-authentication data was found."""
        return bool(self.pan_count or self.cvv_count or self.track_count)

    @property
    def total_hits(self) -> int:
        return self.pan_count + self.cvv_count + self.track_count

    def to_dict(self) -> dict[str, object]:
        return {
            "chd_detected": self.chd_detected,
            "pan_count": self.pan_count,
            "cvv_count": self.cvv_count,
            "track_count": self.track_count,
            "brands": [b.value for b in self.brands],
            "total_hits": self.total_hits,
        }


class PCIScrubber:
    """Detect and mask PCI cardholder data before forwarding text upstream.

    Detection favours precision for PANs (Luhn + IIN) so legitimate long numbers
    (order IDs, timestamps) are not over-redacted, while SAD (CVV, track data) is
    matched in context and always fully redacted.
    """

    def scan(self, text: str) -> PCIScanResult:
        if not text:
            return PCIScanResult(text=text)

        brands: list[CardBrand] = []
        track_count = 0

        # 1. Track data first (it embeds a PAN; redact whole-stripe before PAN pass).
        def _redact_track(_m: re.Match[str]) -> str:
            nonlocal track_count
            track_count += 1
            return "[REDACTED:TRACK_DATA]"

        current = _TRACK1.sub(_redact_track, text)
        current = _TRACK2.sub(_redact_track, current)

        # 2. CVV in card-security context — always fully redacted (never stored).
        cvv_count = 0

        def _redact_cvv(_m: re.Match[str]) -> str:
            nonlocal cvv_count
            cvv_count += 1
            return "[REDACTED:CVV]"

        current = _CVV.sub(_redact_cvv, current)

        # 3. PAN candidates — only mask those that pass Luhn (and a known brand).
        pan_count = 0

        def _mask_candidate(m: re.Match[str]) -> str:
            nonlocal pan_count
            raw = m.group(0)
            digits = re.sub(r"[ -]", "", raw)
            if not (13 <= len(digits) <= 19) or not luhn_valid(digits):
                return raw  # not a real PAN — leave untouched
            brand = detect_brand(digits)
            if brand is CardBrand.UNKNOWN:
                return raw  # Luhn-valid but no known issuer — avoid false positive
            pan_count += 1
            brands.append(brand)
            return _mask_pan(digits)

        current = _PAN_CANDIDATE.sub(_mask_candidate, current)

        if pan_count or cvv_count or track_count:
            logger.info(
                "PCI scrub: redacted %d PAN, %d CVV, %d track-data hit(s)",
                pan_count,
                cvv_count,
                track_count,
            )

        return PCIScanResult(
            text=current,
            pan_count=pan_count,
            cvv_count=cvv_count,
            track_count=track_count,
            brands=brands,
        )
