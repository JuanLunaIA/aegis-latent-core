# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""The retained-byte ceiling: the expression, its domain, and its limits.

``R_max = 4W + Q + E + P`` is declared in ``specs/aegis_stream_buffer.smt2``
and computed in :mod:`aegis.core.stream_bounds`. Two things are worth testing
about that pairing, and one thing is worth *not* claiming.

Worth testing: that the constants here are the constants the spec file
declares — a drift between them would leave the code enforcing a bound nobody
proved anything about — and that the expression is monotone, since the
in-process reduction to ``4W`` relies on it.

Not claimed: that any of this proves the proxy's memory use. The Z3 check is an
arithmetic tautology over declared ranges. These tests check that the code
agrees with it, which is a smaller statement than "the bound holds".

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegis.core.stream_bounds import (
    EVENT_BYTES_MIN,
    PREVIEW_BYTES_MAX,
    PREVIEW_BYTES_MIN,
    QUEUE_BYTES_MAX,
    QUEUE_BYTES_MIN,
    UTF8_MAX_BYTES_PER_CHAR,
    WINDOW_CHARS_MAX,
    WINDOW_CHARS_MIN,
    StreamBoundsError,
    StreamRetentionBounds,
    require_window_in_domain,
)

SPEC = Path(__file__).resolve().parents[1] / "specs" / "aegis_stream_buffer.smt2"


def _spec_range(name: str) -> tuple[int, int]:
    """Read the declared ``[lo, hi]`` for one SMT constant out of the spec file.

    Reading the numbers rather than restating them is the point: a test that
    hardcodes both sides passes when the spec and the code drift apart
    together, which is exactly the failure this file exists to catch.
    """

    text = SPEC.read_text(encoding="utf-8")
    pattern = rf"\(>= {name} (-?\d+)\).*?\(<= {name} (-?\d+)\)"
    found = re.search(pattern, text, re.DOTALL)
    if found is None:  # pragma: no cover - only on a spec edit that breaks the pairing
        raise AssertionError(f"no declared range for {name!r} in {SPEC}")
    return int(found.group(1)), int(found.group(2))


class TestSpecAgreement:
    def test_declared_ranges_match_the_smt_file(self) -> None:
        assert _spec_range("window_chars") == (WINDOW_CHARS_MIN, WINDOW_CHARS_MAX)
        assert _spec_range("queue_bytes") == (QUEUE_BYTES_MIN, QUEUE_BYTES_MAX)
        assert _spec_range("preview_bytes") == (PREVIEW_BYTES_MIN, PREVIEW_BYTES_MAX)

    def test_event_lower_bound_matches_the_smt_file(self) -> None:
        # event_bytes is bounded above by queue_bytes rather than a constant,
        # so only its floor is a literal in the spec.
        text = SPEC.read_text(encoding="utf-8")
        assert f"(>= event_bytes {EVENT_BYTES_MIN})" in text

    def test_the_expression_is_the_one_the_spec_asserts(self) -> None:
        text = SPEC.read_text(encoding="utf-8")
        expression = (
            f"(+ (* {UTF8_MAX_BYTES_PER_CHAR} window_chars) queue_bytes event_bytes preview_bytes)"
        )
        assert expression in text


class TestExpression:
    def test_r_max_is_four_w_plus_q_plus_e_plus_p(self) -> None:
        bounds = StreamRetentionBounds(
            window_chars=128, queue_bytes=4096, event_bytes=1024, preview_bytes=512
        )
        assert bounds.max_retained_bytes == 4 * 128 + 4096 + 1024 + 512

    @pytest.mark.parametrize(
        "field", ["window_chars", "queue_bytes", "event_bytes", "preview_bytes"]
    )
    def test_the_ceiling_never_decreases_when_a_term_grows(self, field: str) -> None:
        base = StreamRetentionBounds(
            window_chars=128, queue_bytes=4096, event_bytes=1024, preview_bytes=512
        )
        grown = StreamRetentionBounds(
            **{**{f: getattr(base, f) for f in base.__slots__}, field: getattr(base, field) + 1}
        )
        assert grown.max_retained_bytes > base.max_retained_bytes

    def test_admits_is_inclusive_at_the_ceiling(self) -> None:
        bounds = StreamRetentionBounds(
            window_chars=64, queue_bytes=1024, event_bytes=256, preview_bytes=0
        )
        ceiling = bounds.max_retained_bytes
        assert bounds.admits(ceiling)
        assert not bounds.admits(ceiling + 1)

    def test_require_admits_names_every_term_when_it_fails(self) -> None:
        bounds = StreamRetentionBounds(
            window_chars=64, queue_bytes=1024, event_bytes=256, preview_bytes=0
        )
        with pytest.raises(StreamBoundsError) as raised:
            bounds.require_admits(bounds.max_retained_bytes + 1, what="unit test")
        message = str(raised.value)
        assert "unit test" in message
        for term in ("W=64", "Q=1024", "E=256", "P=0"):
            assert term in message


class TestDomain:
    def test_a_default_gateway_configuration_is_inside_the_domain(self) -> None:
        bounds = StreamRetentionBounds(
            window_chars=128, queue_bytes=1_048_576, event_bytes=65_536, preview_bytes=65_536
        )
        assert bounds.in_declared_domain

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("window_chars", WINDOW_CHARS_MIN - 1),
            ("window_chars", WINDOW_CHARS_MAX + 1),
            ("queue_bytes", QUEUE_BYTES_MIN - 1),
            ("queue_bytes", QUEUE_BYTES_MAX + 1),
            ("event_bytes", EVENT_BYTES_MIN - 1),
            ("preview_bytes", PREVIEW_BYTES_MAX + 1),
        ],
    )
    def test_an_out_of_range_parameter_leaves_the_domain(self, field: str, value: int) -> None:
        # event_bytes stays at its floor so that shrinking queue_bytes below
        # its own floor still leaves a structurally coherent configuration —
        # the point of this case is the declared range, not the queue/event
        # relation, which has its own test.
        fields = {
            "window_chars": 128,
            "queue_bytes": 1_048_576,
            "event_bytes": EVENT_BYTES_MIN,
            "preview_bytes": 65_536,
        }
        fields[field] = value
        bounds = StreamRetentionBounds(**fields)
        assert not bounds.in_declared_domain

    def test_leaving_the_domain_is_reported_not_raised(self) -> None:
        # Reporting rather than raising is what keeps the accessor from
        # rejecting a stream the previous release admitted.
        bounds = StreamRetentionBounds(
            window_chars=8, queue_bytes=16, event_bytes=8, preview_bytes=0
        )
        assert not bounds.in_declared_domain
        assert bounds.max_retained_bytes == 4 * 8 + 16 + 8


class TestStructuralValidation:
    def test_an_event_larger_than_its_queue_is_refused(self) -> None:
        with pytest.raises(StreamBoundsError, match="never be enqueued"):
            StreamRetentionBounds(
                window_chars=128, queue_bytes=1024, event_bytes=2048, preview_bytes=0
            )

    @pytest.mark.parametrize(
        "field", ["window_chars", "queue_bytes", "event_bytes", "preview_bytes"]
    )
    def test_a_negative_budget_is_refused(self, field: str) -> None:
        fields = {
            "window_chars": 128,
            "queue_bytes": 1024,
            "event_bytes": 256,
            "preview_bytes": 0,
        }
        fields[field] = -1
        with pytest.raises(StreamBoundsError, match="must not be negative"):
            StreamRetentionBounds(**fields)

    def test_a_boolean_budget_is_refused(self) -> None:
        # bool is an int subclass, so an unguarded isinstance check accepts it
        # and True silently becomes a one-byte budget.
        with pytest.raises(StreamBoundsError, match="must be an integer"):
            StreamRetentionBounds(
                window_chars=128,
                queue_bytes=True,  # type: ignore[arg-type]
                event_bytes=0,
                preview_bytes=0,
            )

    def test_a_zero_window_is_refused(self) -> None:
        with pytest.raises(StreamBoundsError, match="must be positive"):
            StreamRetentionBounds(
                window_chars=0, queue_bytes=1024, event_bytes=256, preview_bytes=0
            )

    def test_bounds_are_frozen(self) -> None:
        bounds = StreamRetentionBounds(
            window_chars=128, queue_bytes=1024, event_bytes=256, preview_bytes=0
        )
        with pytest.raises(AttributeError):
            bounds.window_chars = 4096  # type: ignore[misc]


class TestInProcess:
    def test_the_in_process_ceiling_is_four_w(self) -> None:
        bounds = StreamRetentionBounds.in_process(128)
        assert bounds.max_retained_bytes == 4 * 128

    def test_the_in_process_case_reports_itself_outside_the_declared_domain(self) -> None:
        # The spec models a proxied stream, which always has a queue. Saying so
        # is better than inventing a queue budget to stay nominally in range.
        bounds = StreamRetentionBounds.in_process(128)
        assert not bounds.in_declared_domain

    def test_the_in_process_ceiling_is_never_larger_than_a_proxied_one(self) -> None:
        window = 256
        in_process = StreamRetentionBounds.in_process(window)
        proxied = StreamRetentionBounds(
            window_chars=window,
            queue_bytes=QUEUE_BYTES_MIN,
            event_bytes=EVENT_BYTES_MIN,
            preview_bytes=PREVIEW_BYTES_MIN,
        )
        assert in_process.max_retained_bytes <= proxied.max_retained_bytes


class TestWindowDomain:
    @pytest.mark.parametrize("window", [WINDOW_CHARS_MIN, 128, WINDOW_CHARS_MAX])
    def test_an_in_range_window_passes_through_unchanged(self, window: int) -> None:
        assert require_window_in_domain(window) == window

    @pytest.mark.parametrize("window", [0, -1, WINDOW_CHARS_MIN - 1, WINDOW_CHARS_MAX + 1])
    def test_an_out_of_range_window_is_refused(self, window: int) -> None:
        with pytest.raises(StreamBoundsError, match="window_chars must be in"):
            require_window_in_domain(window)

    def test_a_boolean_window_is_refused(self) -> None:
        with pytest.raises(StreamBoundsError, match="must be an integer"):
            require_window_in_domain(True)  # type: ignore[arg-type]

    def test_the_error_is_a_value_error(self) -> None:
        # Callers that already handled the ValueError StreamingDeidentifier
        # raises for a bad window keep catching this one.
        assert issubclass(StreamBoundsError, ValueError)
