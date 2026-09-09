# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Regex denial of service against the two engines that see attacker text.

Both the PHI de-identifier and the streaming safety engine run pattern sets
over model output — text an attacker influences directly by asking for it. A
pattern with nested or adjacent unbounded quantifiers turns that into a CPU
exhaustion primitive: one request, one core, until a timeout that may not
exist. Because these run *inside* the evidence path, the failure is not a slow
response, it is a stalled gateway.

The payloads below are the standard shapes that expose catastrophic
backtracking — long runs that almost match, alternations that force the engine
to try every split, and near-misses that fail at the final character so the
engine must exhaust the search space before giving up.

Scaling is what is asserted, not a wall-clock number. A raw millisecond budget
turns into a flaky test on a loaded CI runner. Backtracking blowup is
super-linear by nature: doubling the input multiplies the work. So each test
feeds two sizes and asserts the larger one did not cost disproportionately
more, with a generous constant to absorb scheduling noise.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from aegis.core.phi_deidentifier import PHIDeidentifier
from aegis.core.streaming_safety_engine import GrammarFrontierAutomaton

#: A hard ceiling that any linear-time implementation clears by orders of
#: magnitude. It exists to fail a truly exponential case fast rather than hang
#: the suite; the scaling assertions are the real check.
ABSOLUTE_CEILING_SECONDS = 10.0

#: Doubling the input may cost more than twice as much — cache behaviour and
#: allocation are not perfectly linear — but a backtracking blowup costs
#: orders of magnitude more. This separates the two without being brittle.
MAX_SCALING_FACTOR = 12.0

#: Below this, timing is dominated by interpreter overhead and the ratio is
#: meaningless.
TIMING_FLOOR_SECONDS = 0.002


def _time(operation: Callable[[], object]) -> float:
    start = time.perf_counter()
    operation()
    return time.perf_counter() - start


def _assert_scales_linearly(
    build: Callable[[int], str], run: Callable[[str], object], base: int
) -> None:
    """Feed n and 2n; fail if the second cost disproportionately more."""

    small = _time(lambda: run(build(base)))
    large = _time(lambda: run(build(base * 2)))

    assert large < ABSOLUTE_CEILING_SECONDS, (
        f"processing {base * 2} characters took {large:.2f}s, which is not a bounded-time result"
    )
    if small < TIMING_FLOOR_SECONDS:
        return
    assert large / small < MAX_SCALING_FACTOR, (
        f"doubling the input multiplied the cost by {large / small:.1f}x "
        f"({small:.4f}s -> {large:.4f}s), which is the signature of "
        "catastrophic backtracking rather than linear scanning"
    )


#: Each payload is a shape that defeats a naive pattern. The lambda takes a
#: size so the same shape can be measured at n and 2n.
REDOS_SHAPES: dict[str, Callable[[int], str]] = {
    # A long digit run that could be an SSN, a phone number or an account
    # number, and is none of them.
    "digit_run": lambda n: "1" * n,
    # Separator storms: every position is a candidate group boundary.
    "separator_storm": lambda n: "-" * n,
    "mixed_separators": lambda n: "1-" * (n // 2),
    # Near-miss SSN: correct shape, wrong length, so it fails at the end.
    "near_miss_ssn": lambda n: "123-45-678" * (n // 10),
    # Address bait: a street-number prefix followed by an enormous name that
    # never terminates in a street suffix.
    "address_bait": lambda n: "123 " + "A" * n,
    # Email bait: unbounded local part and unbounded domain, no TLD.
    "email_bait": lambda n: "a" * (n // 2) + "@" + "b" * (n // 2),
    # Unbalanced phone opening: every paren is a candidate group start.
    "open_parens": lambda n: "(" * n,
    # Whitespace between candidate tokens, the classic `(\s+)+` trigger.
    "space_runs": lambda n: "123" + " " * n + "456",
    # Repeated real matches: the engine does the most work when it succeeds.
    "dense_matches": lambda n: "123-45-6789 " * (n // 12),
}


class TestPhiDeidentifierIsBounded:
    @pytest.mark.parametrize("shape", sorted(REDOS_SHAPES))
    def test_scrubbing_scales_linearly(self, shape: str) -> None:
        deidentifier = PHIDeidentifier()
        _assert_scales_linearly(
            REDOS_SHAPES[shape], lambda text: deidentifier.scrub(text), base=20_000
        )

    def test_a_large_hostile_document_completes(self) -> None:
        """All shapes concatenated, which is what a real hostile input looks like."""

        deidentifier = PHIDeidentifier()
        document = "\n".join(build(5_000) for build in REDOS_SHAPES.values())
        elapsed = _time(lambda: deidentifier.scrub(document))
        assert elapsed < ABSOLUTE_CEILING_SECONDS, (
            f"a {len(document)}-character hostile document took {elapsed:.2f}s"
        )

    def test_scrubbing_still_works_on_the_hostile_document(self) -> None:
        """Bounded time is worthless if the payload also defeats detection."""

        deidentifier = PHIDeidentifier()
        hostile = "-" * 10_000 + " 123-45-6789 " + "A" * 10_000
        result = deidentifier.scrub(hostile)
        assert result.phi_detected, "padding must not hide an SSN from the scrubber"
        assert "123-45-6789" not in result.text


class TestStreamingEngineIsBounded:
    def _drain(self, text: str, chunk_size: int = 512) -> None:
        automaton = GrammarFrontierAutomaton()
        for start in range(0, len(text), chunk_size):
            for _ in automaton.feed(text[start : start + chunk_size]):
                pass
        automaton.finalize()

    @pytest.mark.parametrize("shape", sorted(REDOS_SHAPES))
    def test_streaming_scales_linearly(self, shape: str) -> None:
        _assert_scales_linearly(REDOS_SHAPES[shape], self._drain, base=20_000)

    def test_a_single_token_split_across_every_chunk_boundary(self) -> None:
        """One byte per chunk is the worst case for a hold-back frontier.

        The automaton buffers an unsettled suffix so a pattern split across a
        chunk boundary is still caught. Feeding one character at a time forces
        that path on every single byte, which is where an accidental
        quadratic — re-scanning the whole buffer per chunk — would show up.
        """

        text = "123-45-6789 patient record " * 400
        automaton = GrammarFrontierAutomaton()

        start = time.perf_counter()
        for character in text:
            for _ in automaton.feed(character):
                pass
        automaton.finalize()
        elapsed = time.perf_counter() - start

        assert elapsed < ABSOLUTE_CEILING_SECONDS, (
            f"byte-at-a-time streaming of {len(text)} characters took {elapsed:.2f}s"
        )

    def test_the_holdback_buffer_does_not_grow_without_bound(self) -> None:
        """A frontier that never settles would buffer the whole stream.

        Memory is the other half of a denial-of-service budget: an attacker who
        can keep the automaton from ever settling can make it hold the entire
        response in memory.
        """

        automaton = GrammarFrontierAutomaton(max_holdback=64)
        emitted = 0
        for _ in range(2_000):
            for piece in automaton.feed("1" * 32):
                emitted += len(piece)
        tail, _, _ = automaton.finalize()[:3]

        total_fed = 2_000 * 32
        assert emitted + len(tail) <= total_fed
        # Nearly everything must have been released as the stream progressed;
        # if the frontier never settled, emitted would be ~0 and the tail huge.
        assert emitted > total_fed * 0.5, (
            f"only {emitted} of {total_fed} characters were released during "
            "streaming; the hold-back buffer is retaining the stream"
        )
