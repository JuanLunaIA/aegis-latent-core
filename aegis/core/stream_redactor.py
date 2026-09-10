# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Composition of the two streaming redactors, and the choice between them.

The gateway has two streaming redactors and until now used one of them.

:class:`~aegis.core.streaming_deidentifier.StreamingDeidentifier` carries the
Safe Harbor identifier set — seventeen PHI labels plus ``PAN``, ``CVV`` and
``TRACK_DATA`` — and is what the proxy has always run.
:class:`~aegis.core.streaming_safety_engine.GrammarFrontierAutomaton` carries
four rules, two of which the deidentifier does not have at all:
``INSTR_OVERRIDE`` and ``SYS_LEAK``, which match instruction-override and
system-prompt-disclosure phrasing in model output.

Why this composes rather than replaces
--------------------------------------

Swapping the deidentifier out for the automaton would put four detectors on
the evidence path where twenty were, dropping ``EMAIL``, ``ADDRESS``, ``MRN``,
``URL``, ``TRACK_DATA``, ``CVV`` and the Luhn-and-brand-validated ``PAN``
among others. The automaton's four rules are not a superset of anything; they
are a different, smaller set aimed at a different class of content.

So both run, deidentifier first. Their overlap is harmless: the automaton's
``PHI_SSN`` and ``PCI_PAN`` see text the deidentifier has already rewritten to
``[REDACTED:SSN]``, so they simply do not match.

Redaction off means off
-----------------------

With both PHI and PCI detector families disabled the deidentifier is a
pass-through that withholds nothing, and the frontier stage does not run
either. Running it there would turn "no redaction" into "some redaction plus a
28-character holdback", changing both the bytes a deployment emits and when it
emits them, for an operator who switched redaction off. The frontier rules are
part of response redaction and follow the same switch.

Where redaction is on, the deidentifier's window — 128 characters by default —
already dominates the 28-character frontier, so the added holdback is a small
fraction of one already in place.

The composite's retained holdback is the sum of both stages, and it says so
through :attr:`retained_chars` and :attr:`window_chars`, so the per-stream
ceiling in :mod:`aegis.core.stream_bounds` stays a true bound rather than one
that quietly stopped covering everything the stream holds.

What this does not establish
----------------------------

Nothing about coverage. Every boundary on the wrapped components applies
unchanged: this is finite pattern matching, not de-identification in the HIPAA
Safe Harbor or Expert Determination sense (``CLM-016``, ``CLM-057``), and it
establishes no guarantee against prompt injection (``CLM-024``). The two
frontier rules match declared phrasings and nothing else — a paraphrase, a
translation, or an encoding they have no pattern for passes through. Adding a
stage adds patterns; it does not add understanding.
"""

from __future__ import annotations

from typing import Final, Literal, Protocol

from aegis.core.streaming_deidentifier import (
    StreamingDeidentifier,
    StreamRedactionStats,
)
from aegis.core.streaming_safety_engine import FRONTIER, GrammarFrontierAutomaton

#: Engine selector values for ``AEGIS_STREAMING_ENGINE``.
ENGINE_GRAMMAR_FRONTIER: Final[str] = "grammar_frontier"
ENGINE_DEIDENTIFIER: Final[str] = "deidentifier"

StreamingEngine = Literal["grammar_frontier", "deidentifier"]


class StreamRedactor(Protocol):
    """What the proxy needs from a streaming redactor.

    Both the plain deidentifier and the composite satisfy it, so the proxy
    holds one of these and does not branch on which.
    """

    @property
    def retained_chars(self) -> int: ...

    @property
    def window_chars(self) -> int: ...

    @property
    def stats(self) -> StreamRedactionStats: ...

    def feed(self, text: str) -> str: ...

    def flush(self) -> str: ...


class CompositeStreamRedactor:
    """Safe Harbor redaction followed by the grammar-frontier rules.

    Text flows through the deidentifier first and whatever it settles is fed to
    the automaton, so each stage sees only text the one before it has finished
    with. Both hold back a bounded tail, and the composite's holdback is the
    sum.
    """

    def __init__(
        self,
        *,
        window_chars: int = 128,
        enable_phi: bool = True,
        enable_pci: bool = True,
    ) -> None:
        self._deidentifier = StreamingDeidentifier(
            window_chars=window_chars,
            enable_phi=enable_phi,
            enable_pci=enable_pci,
        )
        # Response redaction off means off. With both detector families
        # disabled the deidentifier is a pass-through that withholds nothing,
        # and adding a frontier stage there would turn "no redaction" into
        # "some redaction plus a 28-character holdback" — changing both the
        # bytes and the delivery latency of a deployment that asked for
        # neither. The frontier rules are part of response redaction, so they
        # follow the same switch.
        #
        # FRONTIER is the smallest legal holdback and the sound bound for these
        # rules; anything larger withholds text for no reason and widens the
        # per-stream ceiling for nothing.
        self._automaton: GrammarFrontierAutomaton | None = (
            GrammarFrontierAutomaton(max_holdback=FRONTIER) if (enable_phi or enable_pci) else None
        )
        self._finalized = False

    @property
    def frontier_rules_active(self) -> bool:
        """Whether the grammar-frontier stage is running for this stream."""

        return self._automaton is not None

    @property
    def retained_chars(self) -> int:
        """Characters held across **both** stages.

        Summing rather than reporting the larger is what keeps the ceiling
        honest: the two holdbacks hold different text at the same time, so the
        stream really is retaining both.
        """

        held = self._deidentifier.retained_chars
        if self._automaton is not None:
            held += self._automaton.retained_chars
        return held

    @property
    def window_chars(self) -> int:
        """The effective ``W`` for the retained-byte ceiling.

        The deidentifier's window plus the automaton's frontier, when the
        frontier stage is running. Reporting only the deidentifier's window
        would leave ``R_max`` understating what the stream holds by
        ``4 * FRONTIER`` bytes.
        """

        window = self._deidentifier.window_chars
        if self._automaton is not None:
            window += self._automaton.max_holdback
        return window

    @property
    def stats(self) -> StreamRedactionStats:
        """Merged hit counters from both stages.

        The label sets are disjoint by construction — the automaton prefixes
        its rules ``PHI_``/``PCI_`` or names them for the class they match — so
        a merge cannot silently combine two different detectors under one name.
        """

        merged = dict(self._deidentifier.stats.entity_hits)
        if self._automaton is not None:
            for label, hits in self._automaton.redaction_counts.items():
                merged[label] = merged.get(label, 0) + hits
        return StreamRedactionStats(entity_hits=merged)

    def feed(self, text: str) -> str:
        """Redact a chunk and return the text both stages have settled."""

        settled = self._deidentifier.feed(text)
        if not settled or self._automaton is None:
            return settled
        return "".join(self._automaton.feed(settled))

    def flush(self) -> str:
        """Flush both holdbacks, in order.

        The deidentifier's tail is fed through the automaton before the
        automaton is finalized, so the last bytes of a stream are inspected by
        both stages rather than bypassing the second one.
        """

        if self._finalized:
            return ""
        self._finalized = True
        tail_from_deidentifier = self._deidentifier.flush()
        if self._automaton is None:
            return tail_from_deidentifier
        released = "".join(self._automaton.feed(tail_from_deidentifier))
        tail, _digest, _emitted = self._automaton.finalize()
        return released + tail


def build_stream_redactor(
    engine: str,
    *,
    window_chars: int = 128,
    enable_phi: bool = True,
    enable_pci: bool = True,
) -> StreamRedactor:
    """Return the redactor named by ``engine``, failing closed on an unknown name.

    An unrecognized value raises rather than falling back to a default. A
    silent fallback here would mean an operator who typed the engine name
    wrongly gets redaction they did not ask for, or loses redaction they did,
    and finds out from the output bytes.
    """

    if engine == ENGINE_GRAMMAR_FRONTIER:
        return CompositeStreamRedactor(
            window_chars=window_chars,
            enable_phi=enable_phi,
            enable_pci=enable_pci,
        )
    if engine == ENGINE_DEIDENTIFIER:
        return StreamingDeidentifier(
            window_chars=window_chars,
            enable_phi=enable_phi,
            enable_pci=enable_pci,
        )
    raise ValueError(
        f"unknown streaming engine {engine!r}; expected one of "
        f"{sorted((ENGINE_GRAMMAR_FRONTIER, ENGINE_DEIDENTIFIER))}"
    )


__all__ = [
    "ENGINE_DEIDENTIFIER",
    "ENGINE_GRAMMAR_FRONTIER",
    "CompositeStreamRedactor",
    "StreamRedactor",
    "StreamingEngine",
    "build_stream_redactor",
]
