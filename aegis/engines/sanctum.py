# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Sanctum engine — streaming de-identification and request scanning.

Wraps :class:`~aegis.core.streaming_deidentifier.StreamingDeidentifier` and
:class:`~aegis.proxy.waf.AegisWAF` so a pipeline that is not an Aegis proxy can
still redact across chunk boundaries and scan prompts:

    engine = SanctumEngine()
    for clean in engine.deidentify_stream(provider_chunks):
        yield clean
    verdict = engine.scan_prompt(user_text)

Why a holdback exists at all
----------------------------

A streaming redactor cannot release every byte it receives: an identifier can
straddle a chunk boundary, so a bounded tail is withheld until enough context
arrives to settle it. :meth:`deidentify_stream` therefore emits *less* than it
has consumed until :meth:`finalize` — a caller that forwards chunks without
finalising will truncate its own output.

Boundaries carried over unchanged
---------------------------------

- Redaction is **finite pattern matching**, not de-identification in the HIPAA
  Safe Harbor or Expert Determination sense (``CLM-016``, ``CLM-057``). Do not
  describe its output as de-identified data.
- Bounded quantifiers make the holdback a real bound, and the price is
  one-directional: an evasion padding whitespace past the bound is not matched.
- The holdback is checked against the ceiling ``specs/aegis_stream_buffer.smt2``
  declares, ``R_max = 4W + Q + E + P``, computed by
  :class:`aegis.core.stream_bounds.StreamRetentionBounds`. In-process there is
  no queue, no canonical SSE event and no evidence preview, so ``Q``, ``E`` and
  ``P`` are zero and the ceiling is ``4W``. This bounds **one engine's
  holdback**, not process memory: nothing here limits how many engines a caller
  runs concurrently.
- When a candidate cannot settle inside the window the stream **fails closed**
  with ``StreamingDeidentificationError`` rather than emitting text it could
  not finish inspecting.
- The WAF operates on the application-visible representation after parsing. It
  establishes no guarantee against prompt injection (``CLM-024``), and its
  measured corpus result is bounded to that corpus.
- Redaction protects the *evidence record*, not the upstream provider: the
  request still reaches the provider as the caller sent it.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from aegis.core.stream_bounds import (
    UTF8_MAX_BYTES_PER_CHAR,
    StreamBoundsError,
    StreamRetentionBounds,
    require_window_in_domain,
)
from aegis.core.streaming_deidentifier import (
    StreamingDeidentificationError,
    StreamingDeidentifier,
)
from aegis.engines import require_module
from aegis.licensing.model import LicenseEntitlement
from aegis.proxy.waf import AegisWAF

_MODULE_NAME = "sanctum"


@dataclass(frozen=True, slots=True)
class ScanVerdict:
    """A WAF decision, flattened to what a caller acts on."""

    allowed: bool
    reason: str
    score: float
    shadow_blocked: bool


class SanctumEngine:
    """Streaming redaction and prompt scanning as a library."""

    def __init__(
        self,
        *,
        window_chars: int = 128,
        enable_phi: bool = True,
        enable_pci: bool = True,
        strict_mode: bool = True,
        shadow_mode: bool = False,
        entitlement: LicenseEntitlement | None = None,
    ) -> None:
        self._entitlement = require_module(_MODULE_NAME, entitlement=entitlement)
        self._window_chars = require_window_in_domain(window_chars)
        self._bounds = StreamRetentionBounds.in_process(self._window_chars)
        self._enable_phi = enable_phi
        self._enable_pci = enable_pci
        self._waf = AegisWAF(strict_mode=strict_mode, shadow_mode=shadow_mode)

    @property
    def entitlement(self) -> LicenseEntitlement | None:
        return self._entitlement

    @property
    def bounds(self) -> StreamRetentionBounds:
        """The declared retained-byte bounds this engine redacts under."""

        return self._bounds

    @property
    def retained_bytes_ceiling(self) -> int:
        """``R_max`` for this engine, in bytes.

        In-process there is no queue, no canonical event and no evidence
        preview, so ``Q``, ``E`` and ``P`` are zero and the ceiling is ``4W``.
        See :class:`aegis.core.stream_bounds.StreamRetentionBounds`.
        """

        return self._bounds.max_retained_bytes

    def _new_deidentifier(self) -> StreamingDeidentifier:
        return StreamingDeidentifier(
            window_chars=self._window_chars,
            enable_phi=self._enable_phi,
            enable_pci=self._enable_pci,
        )

    def _require_within_bounds(self, deidentifier: StreamingDeidentifier) -> None:
        """Fail closed if the holdback ever exceeds the declared ceiling.

        The redactor already bounds its own holdback and raises when it cannot
        settle a candidate. This is the independent check: it reads the same
        retention the bound is written about and compares it against ``R_max``
        computed from the spec's expression, so a future change that widens the
        holdback stops the stream instead of quietly invalidating the bound.
        """

        self._bounds.require_admits(
            deidentifier.retained_chars * UTF8_MAX_BYTES_PER_CHAR,
            what="sanctum de-identification holdback",
        )

    # ── streaming ───────────────────────────────────────────────────────

    def deidentify_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        """Redact across chunk boundaries, yielding only settled text.

        The final flush is emitted when the source is exhausted, so consuming
        this iterator to completion covers every byte fed in. Abandoning it
        early discards whatever was still inside the holdback — which is the
        safe direction, since that text was never inspected.
        """

        deidentifier = self._new_deidentifier()
        for chunk in chunks:
            settled = deidentifier.feed(chunk)
            self._require_within_bounds(deidentifier)
            if settled:
                yield settled
        tail = deidentifier.flush()
        if tail:
            yield tail

    def deidentify_text(self, raw_text: str) -> str:
        """Redact a complete string. Equivalent to feeding it as one chunk."""

        deidentifier = self._new_deidentifier()
        settled = deidentifier.feed(raw_text)
        self._require_within_bounds(deidentifier)
        return settled + deidentifier.flush()

    # ── scanning ────────────────────────────────────────────────────────

    def scan_prompt(self, prompt: str) -> ScanVerdict:
        """Run the request WAF over a prompt string."""

        return self.scan_payload({"prompt": prompt})

    def scan_payload(self, payload: object) -> ScanVerdict:
        """Run the request WAF over a parsed request body."""

        result = self._waf.inspect_payload(payload)
        return ScanVerdict(
            allowed=bool(result.allowed),
            reason=str(result.reason),
            score=float(result.score),
            shadow_blocked=bool(result.shadow_blocked),
        )


__all__ = [
    "SanctumEngine",
    "ScanVerdict",
    "StreamBoundsError",
    "StreamRetentionBounds",
    "StreamingDeidentificationError",
]
