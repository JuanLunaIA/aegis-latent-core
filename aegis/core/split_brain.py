# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.split_brain — Domain 4.1 split-brain prevention via fencing tokens.

Implements the fencing-token pattern (Kleppmann, 2016) to ensure WAL write
safety on network partitions.  A partitioned stale leader always holds a lower
fencing token than the newly elected leader; any write attempt by the stale
leader is rejected before it reaches the WAL.

References:
  - Kleppmann, M. (2016). "How to do distributed locking."
    https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# ── Exceptions ────────────────────────────────────────────────────────────────


class SplitBrainError(Exception):
    """Base class for split-brain safety violations."""


class StaleLeaseError(SplitBrainError):
    """Raised when a write is attempted with an expired or superseded lease."""


class FencingTokenError(SplitBrainError):
    """Raised when a token acquisition is rejected due to a stale token value."""


# ── Fencing token ─────────────────────────────────────────────────────────────


@dataclass
class FencingToken:
    """Monotonically increasing fencing token.

    A higher token value means a more recent lease holder.  Any storage backend
    that enforces monotonically increasing token values at write time will
    correctly reject writes from partitioned stale leaders.

    Attributes:
        value:      Monotonically increasing token value (integer).
        issued_at:  UNIX timestamp when this token was created.
        node_id:    Identifier of the node that acquired this lease.
        expires_at: UNIX timestamp after which the lease is invalid.
    """

    value: int
    issued_at: float
    node_id: str
    expires_at: float

    def is_valid(self) -> bool:
        """True if the lease has not yet expired."""
        return time.time() < self.expires_at

    def supersedes(self, other: FencingToken) -> bool:
        """True if this token is strictly more recent than *other*.

        A token supersedes another when its value is strictly greater.
        Nodes holding a superseded token must not perform writes.
        """
        return self.value > other.value

    def __repr__(self) -> str:
        remaining = max(0.0, self.expires_at - time.time())
        return (
            f"FencingToken(value={self.value}, node_id={self.node_id!r}, "
            f"valid={self.is_valid()}, ttl_remaining={remaining:.2f}s)"
        )


# ── Distributed lock ──────────────────────────────────────────────────────────


class LeaseBasedLock:
    """Fencing-token-based distributed lock for WAL write safety.

    Before any WAL write on a network partition, the writer must hold a valid
    lease with a token value higher than any previously seen token.  This
    prevents split-brain: a partitioned old leader's token will be lower than
    the new leader's, so its writes will be rejected.

    This implementation is a single-process model of the fencing protocol.
    In a multi-process or multi-host deployment, the ``_max_seen_token_value``
    must be stored in a durable, shared store (e.g. database row with
    optimistic locking) that all writers consult atomically.

    Parameters
    ----------
    node_id : str
        Identifier of the node holding this lock manager.
    lease_ttl_seconds : float
        Time-to-live for issued leases.  Writers must renew before expiry.
    """

    def __init__(self, node_id: str, lease_ttl_seconds: float = 30.0) -> None:
        self._node_id = node_id
        self._ttl = lease_ttl_seconds
        self._current_token: FencingToken | None = None
        self._max_seen_token_value: int = 0

    # ── Public API ────────────────────────────────────────────────────────

    def acquire_lease(self, token_value: int) -> FencingToken:
        """Issue a new FencingToken for this node.

        Parameters
        ----------
        token_value : int
            The proposed token value (typically supplied by the consensus
            leader-election outcome, e.g. the Raft term number).

        Returns
        -------
        FencingToken
            A valid token that can be presented to ``check_fence`` and
            ``gate_wal_write``.

        Raises
        ------
        FencingTokenError
            If ``token_value`` is not strictly greater than the highest
            previously seen token value, indicating a stale leader.
        """
        if token_value <= self._max_seen_token_value:
            raise FencingTokenError(
                f"Token value {token_value} is not greater than max seen "
                f"{self._max_seen_token_value}; stale leader rejected"
            )
        now = time.time()
        token = FencingToken(
            value=token_value,
            issued_at=now,
            node_id=self._node_id,
            expires_at=now + self._ttl,
        )
        self._max_seen_token_value = token_value
        self._current_token = token
        return token

    def check_fence(self, token: FencingToken) -> None:
        """Verify that *token* is still valid and not superseded.

        Parameters
        ----------
        token : FencingToken
            Token presented by the writer requesting WAL access.

        Raises
        ------
        StaleLeaseError
            If the token has expired or its value is lower than the
            highest token value seen by this lock manager.
        """
        if not token.is_valid():
            raise StaleLeaseError(
                f"Fencing token {token.value} has expired "
                f"(expired at {token.expires_at:.3f}, now={time.time():.3f})"
            )
        if token.value < self._max_seen_token_value:
            raise StaleLeaseError(
                f"Fencing token {token.value} is stale: max seen token is "
                f"{self._max_seen_token_value}"
            )

    def gate_wal_write(self, token: FencingToken, write_fn: Callable[[], Any]) -> Any:
        """Check the fence and, if valid, call *write_fn*.

        Parameters
        ----------
        token : FencingToken
            Token the caller holds.  Must pass ``check_fence`` before
            ``write_fn`` is invoked.
        write_fn : callable
            Zero-argument callable that performs the WAL write.

        Returns
        -------
        Any
            The return value of ``write_fn()``.

        Raises
        ------
        StaleLeaseError
            Before calling ``write_fn`` if ``check_fence`` fails.
        """
        self.check_fence(token)
        return write_fn()

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def current_lease_valid(self) -> bool:
        """True if this node currently holds a valid (non-expired) lease."""
        return self._current_token is not None and self._current_token.is_valid()

    @property
    def max_seen_token(self) -> int:
        """Highest token value observed by this lock manager."""
        return self._max_seen_token_value
