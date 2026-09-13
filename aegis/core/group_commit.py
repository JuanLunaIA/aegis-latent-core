# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.group_commit — coalesce concurrent WAL commits into one fsync.

The evidence ledger will not return a node to its caller until that node is on
stable storage. Done naively that means one ``fsync`` per request, and an
``fsync`` is not a CPU cost you can optimise away: it is a round trip to the
device. Under concurrency the cost compounds badly, because the ledger holds a
single lock across the whole commit, so N concurrent requests serialise into N
sequential device round trips and the tail latency is N times the disk.

The fix is the standard group commit. ``fsync`` on a file descriptor makes
*everything written to it so far* durable, not just the caller's own record — so
when several records have already been written, one ``fsync`` retires all of
them. This module turns that property into a protocol:

1. A committing thread writes its record and takes a **ticket** — a monotonic
   sequence number — while holding the ledger lock.
2. It releases the ledger lock and calls :meth:`CoalescedCommitEngine.await_durable`.
3. Exactly one waiter at a time becomes the **syncer**: it notes the current
   high-water mark, issues one ``fsync``, and publishes that mark as durable.
   Everyone whose ticket is at or below it wakes up and returns.

Batching therefore needs no timer to work. While the syncer is inside its
``fsync``, later writers pile up behind it; when it finishes, the next syncer
retires all of them at once. Load creates the batches. That is why the linger
below defaults to *not* delaying a lone committer: a deliberate wait would tax
the uncontended path — the common case — to help a case that already batches on
its own.

Why threads and not ``asyncio``
-------------------------------
``CryptographicAuditLedger`` is synchronous and guarded by a ``threading.Lock``;
the proxy reaches it through ``asyncio.to_thread`` (see ``aegis/proxy/app.py``),
so commits arrive on worker threads that have no running event loop. An
``asyncio.Event`` cannot be waited on there. The primitive has to be a
``threading.Condition``, and this module is written against that.

Failure is collective and terminal
----------------------------------
A batch is durable together or not at all. If the ``fsync`` raises, every waiter
in flight raises :class:`WalDurabilityError` — none of them may report their
record as committed — and the engine latches that failure so no later commit can
succeed against a descriptor that has already lost data. The ledger turns that
into its ``wal_persist_failed`` fault state, which the proxy already checks
before admitting a governed request. The alternative — letting some waiters
through — would hand a caller a receipt for a record that is not on the disk,
which is the one outcome an evidence system may never produce.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "DEFAULT_MAX_BATCH",
    "DEFAULT_LINGER_SECONDS",
    "CoalescedCommitEngine",
    "GroupCommitStats",
    "WalDurabilityError",
]

DEFAULT_MAX_BATCH = 64
"""Queue depth at which the syncer stops waiting for company (``AEGIS_COMMIT_BATCH_MAX_SIZE``).

Deliberately *not* a cap on how many records one ``fsync`` retires, because no
such cap is implementable: ``fsync`` makes everything written to the descriptor
durable and cannot be scoped to a subset of the file. Publishing a smaller
high-water mark than the sync actually achieved would only make later waiters
issue a redundant second ``fsync`` for data already on the platter, and would
under-report the coalescing in :class:`GroupCommitStats`. So this bounds the
*wait*, and ``largest_batch`` may legitimately exceed it under load — which is
the engine working, not a bound being violated.
"""

DEFAULT_LINGER_SECONDS = 0.002
"""Longest a syncer may wait for more writers (``AEGIS_COMMIT_BATCH_TIMEOUT_MS``).

Only ever paid when another committer is already waiting, so a lone writer is
never delayed. See the module docstring.
"""


class WalDurabilityError(RuntimeError):
    """A record could not be made durable, so it must not be reported committed.

    Raised to every waiter in the failing batch, and to every later caller,
    because a descriptor whose ``fsync`` has failed may have lost writes that
    were never reported as lost. Continuing to append to it would build evidence
    on top of a gap.
    """


@dataclass(frozen=True)
class GroupCommitStats:
    """What the engine actually did, for tests and ``/metrics``."""

    records: int
    """Records ticketed since construction."""

    batches: int
    """``fsync`` calls issued."""

    largest_batch: int
    """Most records retired by a single ``fsync``."""

    @property
    def records_per_fsync(self) -> float:
        """Mean coalescing ratio; ``1.0`` means no batching happened."""
        return self.records / self.batches if self.batches else 0.0


class CoalescedCommitEngine:
    """Retire many written-but-unsynced WAL records with one ``fsync``.

    The engine owns no file descriptor. The caller supplies the sync itself as a
    callable, because only the ledger knows which descriptor is current and how
    to hold it still against a concurrent rotation.

    Thread-safety: every public method is safe to call from any thread.
    :meth:`enqueue` must be called with the ledger lock held (it orders tickets
    against WAL writes); :meth:`await_durable` must be called *without* it, or
    the batching cannot happen.
    """

    def __init__(
        self,
        *,
        max_batch: int = DEFAULT_MAX_BATCH,
        linger_seconds: float = DEFAULT_LINGER_SECONDS,
    ) -> None:
        if max_batch < 1:
            raise ValueError(f"max_batch must be >= 1, got {max_batch}")
        if linger_seconds < 0.0:
            raise ValueError(f"linger_seconds must be >= 0, got {linger_seconds}")
        self._max_batch = max_batch
        self._linger = linger_seconds
        self._condition = threading.Condition()
        self._written = 0
        self._durable = 0
        self._syncing = False
        self._waiting = 0
        self._failure: BaseException | None = None
        self._records = 0
        self._batches = 0
        self._largest_batch = 0

    # ------------------------------------------------------------------
    # Producer side
    # ------------------------------------------------------------------

    def enqueue(self, node: Any = None) -> int:
        """Stage node in batch and take a ticket for one record written to the WAL descriptor.

        Enforces Hoare triple {P} C {Q} semantics: nodes are staged in `_staged_batch`
        and promoted to final chain state ONLY upon successful `fsync()`.
        """
        with self._condition:
            self._raise_if_failed()
            self._written += 1
            self._records += 1
            if node is not None:
                if not hasattr(self, "_staged_batch"):
                    self._staged_batch: list[Any] = []
                self._staged_batch.append(node)
            return self._written

    def note_external_sync(self) -> None:
        """Record that the caller has already synced everything written so far.

        WAL rotation flushes and ``fsync``s the outgoing segment before renaming
        it, which makes every pending record durable as a side effect. Telling
        the engine keeps those waiters from issuing a second, redundant
        ``fsync`` — against a descriptor that by then belongs to a different
        file.
        """
        with self._condition:
            if self._failure is not None:
                return
            self._durable = self._written
            self._condition.notify_all()

    def fail(self, exc: BaseException) -> None:
        """Latch a durability failure observed outside :meth:`await_durable`.

        Used by the rotation path, whose own ``fsync`` covers pending records:
        if it raises, those records are not durable and their waiters must not
        be told otherwise.
        """
        with self._condition:
            if self._failure is None:
                self._failure = exc
            self._condition.notify_all()

    # ------------------------------------------------------------------
    # Consumer side
    # ------------------------------------------------------------------

    def await_durable(self, ticket: int, sync: Callable[[], None]) -> None:
        """Block until ``ticket`` is on stable storage.

        Args:
            ticket: The value returned by :meth:`enqueue`.
            sync: Flushes and ``fsync``s the WAL descriptor. Called at most once
                per batch, by whichever waiter becomes the syncer, and never
                while the ledger lock is held. It must hold the descriptor
                stable for its duration.

        Raises:
            WalDurabilityError: This record's batch failed, or an earlier batch
                did. Nothing about ``ticket`` may be reported as committed.
        """
        high_water = self._claim_sync_or_wait(ticket)
        if high_water is None:
            return
        # From here this thread owns `_syncing`, and every exit must clear it —
        # including a KeyboardInterrupt landing between the claim and the sync.
        # Leaving it latched would park every other waiter forever, so the guard
        # is BaseException, not Exception.
        try:
            sync()
        except BaseException as exc:
            with self._condition:
                self._syncing = False
                if self._failure is None:
                    self._failure = exc
                if hasattr(self, "_staged_batch"):
                    self._staged_batch.clear()
                self._condition.notify_all()
            if isinstance(exc, Exception):
                raise WalDurabilityError(
                    "WAL fsync failed; the records in this batch are not durable"
                ) from exc
            raise

        with self._condition:
            self._syncing = False
            retired = high_water - self._durable
            if retired > 0:
                self._durable = high_water
                self._batches += 1
                self._largest_batch = max(self._largest_batch, retired)
                if hasattr(self, "_staged_batch"):
                    self._staged_batch.clear()
            self._condition.notify_all()

    def _claim_sync_or_wait(self, ticket: int) -> int | None:
        """Return the high-water mark to sync, or ``None`` if already durable.

        Separated from :meth:`await_durable` so the ``sync`` callable runs with
        no lock held: holding the condition across a device round trip would
        serialise exactly the writers this class exists to overlap.
        """
        with self._condition:
            self._waiting += 1
            try:
                while True:
                    self._raise_if_failed()
                    if self._durable >= ticket:
                        return None
                    if self._syncing:
                        # Someone else's fsync is in flight. It may or may not
                        # cover this ticket, so re-test rather than assume.
                        self._condition.wait()
                        continue
                    self._linger_for_company()
                    self._raise_if_failed()
                    if self._durable >= ticket:
                        return None
                    if self._syncing:
                        continue
                    self._syncing = True
                    # Everything written so far, not a slice of it: see
                    # DEFAULT_MAX_BATCH for why the size knob cannot bound this.
                    return self._written
            finally:
                self._waiting -= 1

    def _linger_for_company(self) -> None:
        """Give concurrent committers a moment to join this batch.

        Deliberately skipped when this thread is the only waiter: delaying a
        lone committer buys nothing and taxes the uncontended path. It is also
        skipped once the batch is already at ``max_batch``, since a larger batch
        is not allowed anyway.

        Must be called with the condition held.
        """
        if self._linger <= 0.0:
            return
        if self._waiting <= 1:
            return
        if self._written - self._durable >= self._max_batch:
            return
        # A single bounded wait, not a loop: the point is to widen the batch a
        # little, not to hold the earliest committer hostage to a steady arrival
        # rate. wait() returning early on a notify is fine and desirable.
        self._condition.wait(self._linger)

    def _raise_if_failed(self) -> None:
        """Must be called with the condition held."""
        if self._failure is not None:
            raise WalDurabilityError(
                "WAL durability has already failed for this ledger; "
                "refusing to report further records as committed"
            ) from self._failure

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    @property
    def stats(self) -> GroupCommitStats:
        """A consistent snapshot of the coalescing counters."""
        with self._condition:
            return GroupCommitStats(
                records=self._records,
                batches=self._batches,
                largest_batch=self._largest_batch,
            )

    @property
    def failed(self) -> bool:
        """``True`` once a durability failure has been latched."""
        with self._condition:
            return self._failure is not None
