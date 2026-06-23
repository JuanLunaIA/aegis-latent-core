# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.decode_pipeline — Iterative multi-layer decode pipeline for WAF evasion resistance.

Attackers bypass pattern-matching WAFs by encoding payloads in Base64,
URL percent-encoding, or HTML entity encoding — sometimes stacking multiple
layers.  This module iteratively decodes up to ``max_depth`` layers of:

* **Base64** — standard (RFC 4648) and URL-safe alphabets; padding tolerant.
* **URL percent-encoding** — ``%XX`` and ``%uXXXX`` (Microsoft IIS variant).
* **HTML entity encoding** — named (``&lt;``, ``&amp;``), decimal (``&#60;``),
  and hex (``&#x3C;``) entities.

Usage::

    pipeline = DecodePipeline(max_depth=5)
    result = pipeline.decode("aHR0cHM6Ly9leGFtcGxlLmNvbQ==")
    # result.fully_decoded == "https://example.com"
    # result.depth_reached == 1
    # result.layers == ["base64"]

    # Get all forms for WAF scanning
    all_forms = pipeline.all_forms("aHR0cHM%3A%2F%2Fle")
    # Returns a list of strings to scan against WAF patterns

Integration with the WAF
------------------------
The WAF should call :meth:`DecodePipeline.all_forms` on each request field
and scan all returned strings.  If any form triggers a WAF rule, the request
is blocked.  This closes the encoding-bypass gap where an attacker submits
a Base64-encoded jailbreak that survives NFKC normalization.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import urllib.parse
from dataclasses import dataclass, field

# Minimum printable ratio: if decoded bytes contain < this fraction of
# printable ASCII or valid UTF-8, skip that decode layer.
_MIN_PRINTABLE_RATIO = 0.70

# Regex to detect if text contains any encoding indicators
_HAS_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}|%u[0-9A-Fa-f]{4}")
_HAS_HTML_ENTITY = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);")
# Base64 heuristic: long runs of base64 chars with optional '=' padding
_HAS_BASE64 = re.compile(r"[A-Za-z0-9+/\-_]{16,}={0,2}")


@dataclass
class DecodeLayer:
    """A single decode operation in the pipeline."""

    depth: int
    layer_type: str  # "base64" | "url" | "html" | "none"
    input_text: str
    output_text: str
    changed: bool = False


@dataclass
class DecodePipelineResult:
    """Outcome of iterative decoding.

    Attributes
    ----------
    original:
        The input text before any decoding.
    fully_decoded:
        The text after all decode layers have been applied.
    layers:
        Ordered list of layer types applied (e.g. ``["url", "base64"]``).
    depth_reached:
        Number of productive decode layers applied (``0`` if no encoding found).
    all_forms:
        All intermediate decoded forms (original + each layer output), for
        WAF scanning coverage.
    """

    original: str
    fully_decoded: str
    layers: list[str] = field(default_factory=list)
    depth_reached: int = 0
    all_forms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "original_length": len(self.original),
            "fully_decoded_length": len(self.fully_decoded),
            "layers": list(self.layers),
            "depth_reached": self.depth_reached,
            "form_count": len(self.all_forms),
        }


class DecodePipeline:
    """Iterative multi-layer decoder for WAF evasion resistance.

    Parameters
    ----------
    max_depth:
        Maximum number of decode iterations.  Default ``5`` — stacks deeper
        than this are impractical for real payloads and likely indicate data
        corruption rather than evasion.
    min_printable_ratio:
        Minimum fraction of printable UTF-8 characters in the decoded output
        to accept the layer as valid.  Filters out binary false-positive base64
        decodes.  Default ``0.70``.
    """

    def __init__(
        self,
        max_depth: int = 5,
        min_printable_ratio: float = _MIN_PRINTABLE_RATIO,
    ) -> None:
        if max_depth < 1:
            raise ValueError(f"max_depth must be ≥ 1, got {max_depth!r}")
        if not 0.0 <= min_printable_ratio <= 1.0:
            raise ValueError(f"min_printable_ratio must be in [0, 1], got {min_printable_ratio!r}")
        self._max_depth = max_depth
        self._min_printable_ratio = min_printable_ratio

    # ── Public API ────────────────────────────────────────────────────────────

    def decode(self, text: str) -> DecodePipelineResult:
        """Iteratively decode *text* through all recognized encoding layers.

        Returns a :class:`DecodePipelineResult` with all intermediate forms.
        """
        forms: list[str] = [text]
        layers: list[str] = []
        current = text

        for _ in range(self._max_depth):
            decoded, layer_type = self._try_decode_once(current)
            if decoded is None or decoded == current:
                break
            forms.append(decoded)
            layers.append(layer_type)
            current = decoded

        return DecodePipelineResult(
            original=text,
            fully_decoded=current,
            layers=layers,
            depth_reached=len(layers),
            all_forms=list(dict.fromkeys(forms)),  # deduplicate, preserve order
        )

    def all_forms(self, text: str) -> list[str]:
        """Return all decoded forms of *text* for WAF pattern scanning.

        Convenience wrapper around :meth:`decode` — returns
        ``result.all_forms``.
        """
        return self.decode(text).all_forms

    # ── Layer detection / decode ──────────────────────────────────────────────

    def _try_decode_once(self, text: str) -> tuple[str, str] | tuple[None, str]:
        """Try each decode type in priority order.

        Priority: HTML entity → URL percent → Base64.

        Returns ``(decoded_text, layer_type)`` on success, ``(None, "")`` if
        no applicable encoding is detected.
        """
        # 1. HTML entities first (lowest ambiguity, clearest signal)
        if _HAS_HTML_ENTITY.search(text):
            decoded = html.unescape(text)
            if decoded != text:
                return decoded, "html"

        # 2. URL percent-encoding (very common in web attack payloads)
        if _HAS_PERCENT.search(text):
            decoded = self._url_decode(text)
            if decoded != text:
                return decoded, "url"

        # 3. Base64 (highest ambiguity — apply last with printability check)
        candidate = self._try_base64(text)
        if candidate is not None:
            return candidate, "base64"

        return None, ""

    def _url_decode(self, text: str) -> str:
        """Decode percent-encoding including ``%uXXXX`` (IIS variant)."""

        # Expand %uXXXX → %XX%XX (approximate; decode as UTF-16 → UTF-8)
        def expand_iis(m: re.Match[str]) -> str:
            codepoint = int(m.group(1), 16)
            try:
                return chr(codepoint)
            except (ValueError, OverflowError):
                return m.group(0)

        text = re.sub(r"%u([0-9A-Fa-f]{4})", expand_iis, text)
        try:
            return urllib.parse.unquote(text, encoding="utf-8", errors="replace")
        except Exception:
            return text

    def _try_base64(self, text: str) -> str | None:
        """Try to decode *text* as standard or URL-safe Base64.

        Rejects the decoded output if it does not pass the printability check.
        Returns the decoded string on success, or ``None``.
        """
        if not _HAS_BASE64.search(text):
            return None

        stripped = text.strip()
        # Try standard alphabet (may have '=' padding)
        for alphabet in ("standard", "urlsafe"):
            try:
                if alphabet == "standard":
                    missing_pad = len(stripped) % 4
                    padded = stripped + "=" * (4 - missing_pad) if missing_pad else stripped
                    raw = base64.b64decode(padded, validate=False)
                else:
                    missing_pad = len(stripped) % 4
                    padded = stripped + "=" * (4 - missing_pad) if missing_pad else stripped
                    raw = base64.urlsafe_b64decode(padded)

                decoded_str = raw.decode("utf-8", errors="replace")
                if self._is_printable(decoded_str):
                    return decoded_str
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue

        return None

    def _is_printable(self, text: str) -> bool:
        """Return True if the printable character ratio exceeds the threshold."""
        if not text:
            return False
        printable_count = sum(
            1 for ch in text if (ch.isprintable() and ch != "�") or ch in "\n\r\t"
        )
        return (printable_count / len(text)) >= self._min_printable_ratio
