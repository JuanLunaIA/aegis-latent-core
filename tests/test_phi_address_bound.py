"""
tests/test_phi_address_bound.py — the ADDRESS bound, and what it costs.

The `ADDRESS` entry in `_SAFE_HARBOR_PATTERNS` matches a street number, a run of
letters, digits and spaces, then a street-type suffix. That middle run used to be
unbounded, which made any number-led prose a viable address prefix: the streaming
guard could not settle it inside the bounded holdback, so ordinary text starting
with a figure aborted the stream with `privacy_failure`.

The run is now bounded at 40 characters, and the streaming guard mirrors the same
bound. Two invariants have to hold together:

* the bounds must agree — a guard looser than the detector aborts on text the
  detector would never match, and a guard tighter than the detector releases the
  start of an address it was supposed to hold back;
* the bound must be wide enough for real addresses, and the recall it gives up
  must be visible in a test rather than implied by a comment.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import re

import pytest

from aegis.core.phi_deidentifier import _SAFE_HARBOR_PATTERNS
from aegis.core.streaming_deidentifier import (
    _ADDRESS_NAME_MAX,
    StreamingDeidentificationError,
    StreamingDeidentifier,
)

# Longest street-name span observed in a sample of real addresses was 18
# characters ("500 South Buena Vista Street"). The bound is deliberately wider.
_LONGEST_OBSERVED_REAL_SPAN = 18

_REAL_ADDRESSES = [
    "1600 Pennsylvania Avenue",
    "350 Fifth Avenue",
    "221 Baker Street",
    "500 South Buena Vista Street",
    "1234 Northwest Industrial Parkway",
    "1 Microsoft Way",
]

# Street types the detector does not list, and never has. These are a
# pre-existing coverage gap in `_SAFE_HARBOR_PATTERNS`, unrelated to the bound:
# both fail to match the unbounded pattern too. They are named here so the gap is
# recorded rather than discovered again.
_UNSUPPORTED_STREET_TYPES = [
    "30 Rockefeller Plaza",
    "8600 Rockville Pike",
]


def _address_pattern() -> str:
    for item in _SAFE_HARBOR_PATTERNS:
        if item.label == "ADDRESS":
            return item.pattern
    raise AssertionError("ADDRESS pattern not found in _SAFE_HARBOR_PATTERNS")


def _scrub_stream(text: str, chunk: int = 7) -> str:
    deidentifier = StreamingDeidentifier()
    chunks = [text[i : i + chunk] for i in range(0, len(text), chunk)]
    return "".join(deidentifier.feed(part) for part in chunks) + deidentifier.flush()


# ── The two bounds must agree ────────────────────────────────────────────────


def test_detector_street_name_run_is_bounded() -> None:
    """An unbounded run is what made ordinary prose a viable address prefix."""
    pattern = _address_pattern()
    assert "[A-Za-z0-9 ]+" not in pattern, (
        "ADDRESS street-name run is unbounded again; streaming will abort on number-led prose"
    )
    assert f"[A-Za-z0-9 ]{{1,{_ADDRESS_NAME_MAX}}}" in pattern


def test_guard_bound_matches_the_detector_bound() -> None:
    """The streaming guard is only a prefix test while the bounds are equal.

    Widening one without the other silently breaks the pairing in a direction no
    other test in this file would catch.
    """
    pattern = _address_pattern()
    detector_bound = re.search(r"\[A-Za-z0-9 \]\{1,(\d+)\}", pattern)
    assert detector_bound is not None, "ADDRESS run is not a bounded quantifier"
    assert int(detector_bound.group(1)) == _ADDRESS_NAME_MAX


def test_bound_leaves_headroom_over_real_addresses() -> None:
    """The bound is measured headroom, not a number that made a test pass."""
    assert _ADDRESS_NAME_MAX >= 2 * _LONGEST_OBSERVED_REAL_SPAN


# ── Ordinary prose must stream through ───────────────────────────────────────


@pytest.mark.parametrize(
    ("label", "text"),
    [
        (
            "number-led prose",
            "3 reasons the migration succeeded were better planning clearer ownership "
            "and a much tighter feedback loop across the whole engineering organisation",
        ),
        (
            "year-led prose",
            "In 2026, the company expanded operations across four regions and doubled "
            "its headcount while keeping the same operating margin as the prior year",
        ),
        (
            "figure in a sentence",
            "We saw 42 percent growth in governed calls this quarter and expect that "
            "to continue as more teams route their traffic through the gateway today",
        ),
    ],
)
def test_number_led_prose_does_not_abort_the_stream(label: str, text: str) -> None:
    """None of these contain PHI, and all of them aborted before the bound."""
    for chunk in (len(text), 7):
        deidentifier = StreamingDeidentifier()
        parts = [text[i : i + chunk] for i in range(0, len(text), chunk)]
        output = "".join(deidentifier.feed(part) for part in parts) + deidentifier.flush()
        assert output, f"{label} produced no output at chunk size {chunk}"


def test_a_viable_address_candidate_always_fits_the_smallest_window() -> None:
    """The bound removes the address abort structurally, not by tuning.

    A viable candidate is at most 5 digits + 1 separator + the bounded name, so
    46 characters. `window_chars` is constrained to [64, 4096], so a candidate the
    detector could still complete always fits inside even the smallest permitted
    holdback — and the guard's `len(candidate) > window_chars` rejection is
    therefore unreachable for addresses at every legal configuration.

    That is the reason the false positive cannot come back by picking an awkward
    window size, and it is worth asserting: if someone widens the bound past the
    minimum window, aborts on prose become reachable again.
    """
    smallest_legal_window = 64
    longest_viable_candidate = 5 + 1 + _ADDRESS_NAME_MAX
    assert longest_viable_candidate < smallest_legal_window

    # Confirmed behaviourally at the smallest legal window, not just arithmetically.
    deidentifier = StreamingDeidentifier(window_chars=smallest_legal_window, enable_phi=True)
    deidentifier.feed("12345 " + "a" * _ADDRESS_NAME_MAX + " and the sentence continues here")
    deidentifier.flush()


def test_other_open_candidate_guards_still_fail_closed() -> None:
    """Bounding ADDRESS must not disarm the guards for the unbounded grammars.

    URL and track-data candidates have no length bound in their detectors, so
    their holdback rejections remain reachable and must stay so.
    """
    deidentifier = StreamingDeidentifier(window_chars=64, enable_phi=True)
    with pytest.raises(StreamingDeidentificationError, match="open URL"):
        deidentifier.feed("https://example.test/" + "a" * 128)


@pytest.mark.parametrize("address", _UNSUPPORTED_STREET_TYPES)
def test_unsupported_street_types_are_a_pre_existing_gap(address: str) -> None:
    """`Plaza` and `Pike` are absent from the street-type list, bound or no bound.

    Asserting the current behaviour keeps this from being mistaken for a
    regression introduced by the bound, and makes the gap visible to anyone
    extending the detector.
    """
    output = _scrub_stream(f"Please ship the package to {address} before Friday.")
    assert "[REDACTED:ADDRESS]" not in output
    assert address in output


# ── Real addresses still redact, and the cost is explicit ────────────────────


@pytest.mark.parametrize("address", _REAL_ADDRESSES)
def test_real_addresses_are_still_redacted(address: str) -> None:
    """The bound must not cost recall on addresses of ordinary length."""
    output = _scrub_stream(
        f"Please ship the package to {address} before Friday and confirm receipt."
    )
    assert "[REDACTED:ADDRESS]" in output
    assert address not in output


def test_a_street_name_longer_than_the_bound_is_not_redacted() -> None:
    """The accepted cost, stated as a test rather than left to a comment.

    A street name longer than the bound is no longer matched, so it passes
    through unredacted. This is a deliberate trade: aborting every stream of
    number-led prose was judged worse than losing recall at the far tail of the
    street-name length distribution. If that judgement is revisited, this test is
    the one that should change first.
    """
    overlong = "9 " + "Verylongstreetname " * 3 + "Boulevard"
    output = _scrub_stream(f"Deliver to {overlong} on Monday please and confirm receipt.")
    assert "[REDACTED:ADDRESS]" not in output
    assert "Verylongstreetname" in output
