# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Grammar-frontier automaton for streaming redaction.

A streaming redactor cannot release every byte it receives: a pattern may
straddle a chunk boundary, so some tail must be withheld until enough context
arrives to settle it. This module withholds exactly one bound — the *frontier*
— computed from the patterns themselves.

Why the quantifiers are bounded
-------------------------------

The frontier is only a real bound if every pattern has a finite maximum match
length. With ``\\s+`` between words a match is arbitrarily long, so no fixed
holdback is sound and "frontier" would be a heuristic wearing a proof's
clothing. Each pattern therefore bounds its runs, and
``test_streaming_safety_engine.py`` asserts every declared frontier against the
longest string its own pattern can match.

The cost is real and one-directional, exactly as it is for the ``ADDRESS``
bound in :mod:`aegis.core.phi_deidentifier`: an evasion that pads whitespace
past the bound is not matched. Bounding trades that recall for a holdback that
cannot be overrun. It is a deterministic pattern matcher, not a guarantee
against prompt injection — see ``CLM-024``.

What this does not do
---------------------

It matches the patterns it declares and nothing else. It establishes no
guarantee that adversarial text is absent, no semantic understanding, and no
protection against an encoding it has no pattern for.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from typing import Final, NamedTuple

# Longest whitespace run tolerated *inside* a pattern. Bounding this is what
# makes every frontier below finite; see the module docstring.
_WS: Final[str] = r"\s{1,4}"

_REDACTION_TEMPLATE: Final[str] = "[REDACTED:{name}]"

# Guards against a replacement that could itself re-trigger a pattern. No
# current replacement can — they are bracketed uppercase — but a future pattern
# could, and an unbounded rewrite loop in the streaming path is worse than a
# missed redaction.
_MAX_REDACTION_ROUNDS: Final[int] = 8


class _Rule(NamedTuple):
    """One pattern plus the lookahead needed to settle it."""

    name: str
    pattern: re.Pattern[str]
    #: Characters that must be withheld for this rule. Must be at least the
    #: longest string ``pattern`` can match, plus one for the trailing ``\b``.
    frontier: int


RULES: Final[tuple[_Rule, ...]] = (
    _Rule(
        "INSTR_OVERRIDE",
        re.compile(rf"(?i)\b(?:ignore|override|bypass){_WS}all{_WS}previous\b"),
        # max: "override"(8) + 4 + "all"(3) + 4 + "previous"(8) = 27, +1 for \b
        28,
    ),
    _Rule(
        "SYS_LEAK",
        re.compile(
            rf"(?i)\b(?:reveal|output|print|show){_WS}"
            rf"(?:system{_WS}prompt|instructions)\b"
        ),
        # max: "reveal"(6) + 4 + "system"(6)+4+"prompt"(6) = 26, +1 for \b
        27,
    ),
    _Rule("PHI_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 12),
    _Rule("PCI_PAN", re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"), 17),
)

#: Withheld tail. One bound for every rule: holding the per-rule frontier would
#: mean tracking which rule is viable at the tail, and getting that wrong fails
#: open. The maximum is never wrong and costs a few dozen characters.
FRONTIER: Final[int] = max(rule.frontier for rule in RULES)


class GrammarFrontierAutomaton:
    """Redact across chunk boundaries while releasing settled text.

    ``feed`` yields only text that no declared pattern can still extend into.
    ``finalize`` flushes the rest. Together they cover every byte fed in, and
    the rolling digest is taken over exactly the bytes yielded.
    """

    def __init__(self, max_holdback: int = 128) -> None:
        if max_holdback < FRONTIER:
            raise ValueError(
                f"max_holdback must be at least the frontier ({FRONTIER}); "
                f"a smaller window cannot settle every pattern"
            )
        self.max_holdback = max_holdback
        self._buffer = ""
        self._hasher = hashlib.sha256()
        self._emitted_bytes = 0
        self._redactions: dict[str, int] = {}

    @property
    def emitted_bytes(self) -> int:
        return self._emitted_bytes

    @property
    def redaction_counts(self) -> dict[str, int]:
        """How many times each rule fired, for evidence rather than display."""

        return dict(self._redactions)

    def _redact_settled(self) -> None:
        """Replace every complete match in the buffer.

        Runs every rule to fixpoint rather than stopping at the first hit. The
        original formulation redacted one match, then released the whole
        buffer with a zero frontier — so a second pattern sitting in the tail
        escaped unredacted. Redacting all of them, and only then computing the
        frontier over what is left, is what closes that.
        """

        for _ in range(_MAX_REDACTION_ROUNDS):
            changed = False
            for rule in RULES:
                replacement = _REDACTION_TEMPLATE.format(name=rule.name)
                redacted, hits = rule.pattern.subn(replacement, self._buffer)
                if hits:
                    self._buffer = redacted
                    self._redactions[rule.name] = self._redactions.get(rule.name, 0) + hits
                    changed = True
            if not changed:
                return

    def _emit(self, text: str) -> str:
        encoded = text.encode("utf-8")
        self._hasher.update(encoded)
        self._emitted_bytes += len(encoded)
        return text

    def feed(self, chunk: str) -> Iterator[str]:
        """Consume a chunk and yield whatever has settled."""

        self._buffer += chunk

        while len(self._buffer) > self.max_holdback:
            self._redact_settled()

            # The frontier is computed against the buffer *after* redaction,
            # so a match that has just been replaced no longer inflates it and
            # a partial match left in the tail is still covered.
            cutoff = len(self._buffer) - FRONTIER
            if cutoff <= 0:
                return

            releasable, self._buffer = self._buffer[:cutoff], self._buffer[cutoff:]
            yield self._emit(releasable)

    def finalize(self) -> tuple[str, str, int]:
        """Flush the holdback.

        Returns the trailing text, the SHA-256 of every byte emitted across the
        whole stream, and that byte count.
        """

        self._redact_settled()
        tail, self._buffer = self._buffer, ""
        emitted = self._emit(tail)
        return emitted, self._hasher.hexdigest(), self._emitted_bytes


__all__ = ["FRONTIER", "RULES", "GrammarFrontierAutomaton"]
