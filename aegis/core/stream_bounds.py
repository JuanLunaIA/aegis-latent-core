# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""The per-stream retained-byte ceiling, in one place.

``specs/aegis_stream_buffer.smt2`` declares a ceiling on what one active stream
may retain:

.. code-block:: text

    R_max = 4W + Q + E + P

where ``W`` is the de-identification holdback in characters, ``Q`` the
byte-accounted queue budget, ``E`` the largest single canonical SSE event, and
``P`` the retained response preview. The four terms and their declared ranges
are tabulated in ``docs/institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md`` §4.4.

Until now that expression existed only in the spec file and the prose. Two
callers retain stream state — :class:`aegis.proxy.streaming.BoundedStreamProxy`
on the gateway path and :class:`aegis.engines.sanctum.SanctumEngine` in-process
— and neither computed the ceiling, so nothing connected the declared bound to
the running code. This module is that connection: one expression, one set of
declared ranges, used by both.

What this does and does not establish
-------------------------------------

The Z3 check in ``specs/aegis_stream_buffer.smt2`` is an arithmetic
consistency check — it asserts the retained-byte expression and then asserts
that the same expression exceeds itself, and ``unsat`` says only that no
assignment inside the declared ranges does so. It is not a refinement proof of
this module, of the proxy, of CPython's allocator, or of process memory.
``docs/formal/FORMAL_VERIFICATION_LIMITS.md`` records that boundary and it is
unchanged here.

What this module adds is narrower and checkable: the ceiling the code enforces
is now computed from the same expression the spec declares, and a configuration
outside the spec's declared ranges can be detected rather than silently
accepted. Aggregate memory across concurrent streams remains outside every one
of these bounds; it is a deployment admission-control property.

The ``4W`` term is conservative in the right direction. ``W`` bounds the
holdback in *characters* and four is the maximum UTF-8 byte length of one code
point, so ``4W`` is an over-estimate for any text that is not entirely
four-byte code points. It bounds the holdback observed between calls to
:meth:`~aegis.core.streaming_deidentifier.StreamingDeidentifier.feed`, which is
where the retained-byte accessors read it; within a single ``feed`` the pending
buffer transiently also holds the chunk being processed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: Maximum bytes one Unicode code point occupies in UTF-8.
UTF8_MAX_BYTES_PER_CHAR: Final[int] = 4

#: ``W`` range declared by ``specs/aegis_stream_buffer.smt2`` line 10, matching
#: ``StreamingDeidentifier`` and ``AegisSettings.stream_deidentifier_window_chars``.
WINDOW_CHARS_MIN: Final[int] = 64
WINDOW_CHARS_MAX: Final[int] = 4096

#: ``Q`` range declared by ``specs/aegis_stream_buffer.smt2`` line 11.
QUEUE_BYTES_MIN: Final[int] = 1_024
QUEUE_BYTES_MAX: Final[int] = 16_777_216

#: ``E`` lower bound declared by ``specs/aegis_stream_buffer.smt2`` line 12. Its
#: upper bound is ``Q``, so it is checked relationally rather than as a constant.
EVENT_BYTES_MIN: Final[int] = 256

#: ``P`` range declared by ``specs/aegis_stream_buffer.smt2`` line 13.
PREVIEW_BYTES_MIN: Final[int] = 0
PREVIEW_BYTES_MAX: Final[int] = 65_536


class StreamBoundsError(ValueError):
    """A stream configuration or observation violates the declared ceiling.

    Subclasses ``ValueError`` so that callers which already handle the
    ``ValueError`` raised by ``StreamingDeidentifier`` for an out-of-range
    window keep catching it.
    """


@dataclass(frozen=True, slots=True)
class StreamRetentionBounds:
    """One stream's declared retained-byte ceiling: ``R_max = 4W + Q + E + P``.

    Construct it with the configuration a stream actually runs under. The
    parameters are validated structurally — no negative budget, and no event
    larger than the queue that must hold it — because those are the shapes that
    make the expression meaningless rather than merely unusual. Whether the
    configuration also sits inside the ranges the spec declares is reported by
    :attr:`in_declared_domain` and enforced only where a caller asks for it.
    """

    window_chars: int
    queue_bytes: int
    event_bytes: int
    preview_bytes: int

    def __post_init__(self) -> None:
        for name in ("window_chars", "queue_bytes", "event_bytes", "preview_bytes"):
            value = getattr(self, name)
            # bool is an int subclass; a boolean budget is a caller error.
            if isinstance(value, bool) or not isinstance(value, int):
                raise StreamBoundsError(f"{name} must be an integer, got {type(value).__name__}")
            if value < 0:
                raise StreamBoundsError(f"{name} must not be negative, got {value}")
        if self.window_chars < 1:
            raise StreamBoundsError("window_chars must be positive")
        if self.queue_bytes and self.event_bytes > self.queue_bytes:
            raise StreamBoundsError(
                f"event_bytes ({self.event_bytes}) exceeds queue_bytes ({self.queue_bytes}); "
                "a single event that cannot fit the queue can never be enqueued"
            )

    @classmethod
    def in_process(cls, window_chars: int) -> StreamRetentionBounds:
        """Bounds for a caller that redacts in-process, with no SSE machinery.

        An in-process consumer holds no queue, assembles no canonical SSE
        event, and retains no evidence preview, so ``Q``, ``E`` and ``P`` are
        genuinely zero and the ceiling reduces to ``4W``. Those zeros sit
        *outside* the ranges the spec declares — the spec models a proxied
        stream, where a queue always exists — so :attr:`in_declared_domain` is
        ``False`` for these bounds and says so rather than pretending a queue
        that is not there. The expression is non-decreasing in each term, so
        this ceiling is no larger than the ceiling of any declared-domain
        configuration with the same ``W``; that is arithmetic stated here, not
        a result the Z3 run establishes.
        """

        return cls(window_chars=window_chars, queue_bytes=0, event_bytes=0, preview_bytes=0)

    @property
    def max_retained_bytes(self) -> int:
        """``R_max`` in bytes, exactly as ``specs/aegis_stream_buffer.smt2`` writes it."""

        return (
            UTF8_MAX_BYTES_PER_CHAR * self.window_chars
            + self.queue_bytes
            + self.event_bytes
            + self.preview_bytes
        )

    @property
    def in_declared_domain(self) -> bool:
        """Whether all four parameters sit inside the spec's declared ranges."""

        return (
            WINDOW_CHARS_MIN <= self.window_chars <= WINDOW_CHARS_MAX
            and QUEUE_BYTES_MIN <= self.queue_bytes <= QUEUE_BYTES_MAX
            and EVENT_BYTES_MIN <= self.event_bytes <= self.queue_bytes
            and PREVIEW_BYTES_MIN <= self.preview_bytes <= PREVIEW_BYTES_MAX
        )

    def admits(self, retained_bytes: int) -> bool:
        """Whether an observed retention is within :attr:`max_retained_bytes`."""

        return retained_bytes <= self.max_retained_bytes

    def require_admits(self, retained_bytes: int, *, what: str = "stream") -> None:
        """Fail closed when an observed retention exceeds the ceiling."""

        if not self.admits(retained_bytes):
            raise StreamBoundsError(
                f"{what} retained {retained_bytes} bytes, over its declared ceiling of "
                f"{self.max_retained_bytes} (R_max = 4W + Q + E + P with W={self.window_chars}, "
                f"Q={self.queue_bytes}, E={self.event_bytes}, P={self.preview_bytes})"
            )


def require_window_in_domain(window_chars: int) -> int:
    """Validate ``W`` against the declared range, returning it unchanged.

    Separate from :attr:`StreamRetentionBounds.in_declared_domain` because
    ``W`` is the one parameter every retaining caller has, including the
    in-process one that has no queue to place inside the declared ranges.
    """

    if isinstance(window_chars, bool) or not isinstance(window_chars, int):
        raise StreamBoundsError(
            f"window_chars must be an integer, got {type(window_chars).__name__}"
        )
    if not WINDOW_CHARS_MIN <= window_chars <= WINDOW_CHARS_MAX:
        raise StreamBoundsError(
            f"window_chars must be in [{WINDOW_CHARS_MIN}, {WINDOW_CHARS_MAX}], got {window_chars}"
        )
    return window_chars


__all__ = [
    "EVENT_BYTES_MIN",
    "PREVIEW_BYTES_MAX",
    "PREVIEW_BYTES_MIN",
    "QUEUE_BYTES_MAX",
    "QUEUE_BYTES_MIN",
    "UTF8_MAX_BYTES_PER_CHAR",
    "WINDOW_CHARS_MAX",
    "WINDOW_CHARS_MIN",
    "StreamBoundsError",
    "StreamRetentionBounds",
    "require_window_in_domain",
]
