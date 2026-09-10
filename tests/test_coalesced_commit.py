# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Concurrent commits share one fsync, and share its failure.

The ledger will not hand back a node until that node is on stable storage. Done
per-record that is one device round trip per request, taken while the ledger
lock is held, so N concurrent requests become N sequential disk waits.
`aegis.core.group_commit` coalesces them: an `fsync` makes everything already
written to the descriptor durable, so one call can retire a whole burst.

The property that has to survive is durability, not speed. These tests therefore
drive the batching hard enough to prove it happens, and then spend most of their
length on the ways it could quietly stop being safe:

- a caller must never receive a node whose record is not on the disk;
- a batch that fails must fail *every* commit in it, not just the syncer's;
- a ledger that has lost a write must refuse to accept more.

Disk latency is simulated by an injected `fsync_fn` rather than by real I/O, so
the tests are deterministic and fast. Calls with side effects are assigned
before being asserted on, never called inside the ``assert`` itself (``python
-O`` strips asserts; CodeQL flags this as py/side-effect-in-assert).
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.group_commit import CoalescedCommitEngine, WalDurabilityError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pathlib import Path

WRITERS = 100


class _SlowDisk:
    """An ``fsync`` that takes a while and counts how often it is called."""

    def __init__(self, delay: float = 0.02) -> None:
        self.delay = delay
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, fd: int) -> None:
        with self._lock:
            self.calls += 1
        time.sleep(self.delay)


class _FailingDisk:
    """An ``fsync`` that works until it is armed, then always raises."""

    def __init__(self) -> None:
        self.armed = threading.Event()
        self.calls = 0

    def __call__(self, fd: int) -> None:
        self.calls += 1
        if self.armed.is_set():
            raise OSError(28, "No space left on device")


def _ledger(tmp_path: Path, fsync: Any, **kwargs: Any) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        str(tmp_path / "audit.jsonl"),
        signing_key="test-key",
        fsync_fn=fsync,
        **kwargs,
    )


def _commit(ledger: CryptographicAuditLedger, index: int) -> str:
    node = ledger.commit_forensic(
        state_id=f"req-{index:04d}",
        request_bytes=f"request-{index}".encode(),
        response_bytes=f"response-{index}".encode(),
        tenant_id="tenant-a",
    )
    return node.state_id


def _wal_state_ids(path: Path) -> list[str]:
    import json

    return [
        json.loads(line)["state_id"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TestConcurrentCommitsAreDurable:
    def test_a_hundred_concurrent_commits_all_land_exactly_once(self, tmp_path: Path) -> None:
        """The order's headline case, driven for real against a slow disk."""
        disk = _SlowDisk()
        ledger = _ledger(tmp_path, disk)
        try:
            with ThreadPoolExecutor(max_workers=32) as pool:
                returned = sorted(pool.map(lambda i: _commit(ledger, i), range(WRITERS)))

            expected = sorted(f"req-{i:04d}" for i in range(WRITERS))
            on_disk = _wal_state_ids(tmp_path / "audit.jsonl")
            intact, broken_at = ledger.verify_integrity()

            assert returned == expected
            assert sorted(on_disk) == expected, "every returned commit must be in the WAL"
            assert len(on_disk) == WRITERS, "no duplicates"
            assert intact is True
            assert broken_at is None
            assert len(ledger.chain) == WRITERS
        finally:
            ledger.close()

    def test_the_fsync_count_is_far_below_the_commit_count(self, tmp_path: Path) -> None:
        """Without coalescing this is 100 fsyncs; the whole point is that it is not.

        The exact ratio depends on scheduling, so this asserts a wide margin
        rather than a number: the claim is 'batching happens', not 'batching
        achieves N'.
        """
        disk = _SlowDisk()
        ledger = _ledger(tmp_path, disk)
        try:
            with ThreadPoolExecutor(max_workers=32) as pool:
                list(pool.map(lambda i: _commit(ledger, i), range(WRITERS)))
            stats = ledger.group_commit_stats

            assert stats.records == WRITERS
            assert stats.batches < WRITERS, "no coalescing happened at all"
            assert stats.largest_batch > 1, "no batch ever retired more than one record"
            # Generous: 32 pool workers against a 20 ms fsync should coalesce
            # far better than 2:1, but scheduling on a loaded CI box is not
            # something a correctness test should depend on.
            assert stats.records_per_fsync > 2.0
        finally:
            ledger.close()

    def test_a_lone_committer_is_not_delayed_waiting_for_company(self, tmp_path: Path) -> None:
        """The linger must not tax the uncontended path.

        A group commit that always waits `AEGIS_COMMIT_BATCH_TIMEOUT_MS` would
        add that to every single-threaded commit. Ten sequential commits with a
        2 ms linger would cost at least 20 ms of pure waiting; this asserts they
        do not.
        """
        ledger = _ledger(tmp_path, lambda fd: None, commit_batch_timeout_ms=50.0)
        try:
            started = time.perf_counter()
            for index in range(10):
                _commit(ledger, index)
            elapsed = time.perf_counter() - started
            stats = ledger.group_commit_stats

            assert stats.batches == 10, "each solo commit should sync on its own"
            assert elapsed < 0.25, (
                f"10 solo commits took {elapsed:.3f}s with a 50 ms linger; "
                "the linger is being paid when nobody else is waiting"
            )
        finally:
            ledger.close()

    def test_commits_keep_working_across_a_wal_rotation(self, tmp_path: Path) -> None:
        """Rotation fsyncs and replaces the descriptor a syncer may be inside.

        It has to hand the pending batch over rather than strand it, so this
        drives concurrent commits with a rotation threshold small enough to fire
        repeatedly during the run.
        """
        disk = _SlowDisk(delay=0.005)
        ledger = _ledger(tmp_path, disk, max_wal_bytes=4096)
        try:
            with ThreadPoolExecutor(max_workers=16) as pool:
                returned = sorted(pool.map(lambda i: _commit(ledger, i), range(WRITERS)))
            intact, _ = ledger.verify_integrity()
            segments = sorted(tmp_path.glob("audit.jsonl.*"))

            assert returned == sorted(f"req-{i:04d}" for i in range(WRITERS))
            assert intact is True
            assert segments, "the threshold was too high to exercise rotation"
        finally:
            ledger.close()


class TestABatchFailsClosedTogether:
    def test_no_commit_returns_once_the_disk_stops_accepting_writes(self, tmp_path: Path) -> None:
        """Fail-closed is the point: a failed fsync must not yield a receipt."""
        disk = _FailingDisk()
        ledger = _ledger(tmp_path, disk)
        try:
            _commit(ledger, 0)  # healthy, proves the harness works
            disk.armed.set()

            with ThreadPoolExecutor(max_workers=8) as pool:
                outcomes = list(
                    pool.map(
                        lambda i: _outcome(ledger, i),
                        range(1, 9),
                    )
                )

            assert all(o == "failed" for o in outcomes), outcomes
            assert ledger._fault_state == "wal_persist_failed"
        finally:
            ledger.close()

    def test_the_ledger_refuses_further_commits_after_a_durability_failure(
        self, tmp_path: Path
    ) -> None:
        """A descriptor that lost a write may have lost it silently.

        Appending past that point builds evidence on top of a gap nobody can
        see, so the engine latches and every later commit is refused too.
        """
        disk = _FailingDisk()
        ledger = _ledger(tmp_path, disk)
        try:
            _commit(ledger, 0)
            disk.armed.set()
            with pytest.raises(WalDurabilityError):
                _commit(ledger, 1)

            # The disk "recovers" — the ledger must not.
            disk.armed.clear()
            with pytest.raises(WalDurabilityError):
                _commit(ledger, 2)
        finally:
            ledger.close()

    def test_a_failed_commit_is_reported_as_a_failure_not_a_missing_node(
        self, tmp_path: Path
    ) -> None:
        """The caller must learn the record is not durable, by exception.

        Returning normally and quietly omitting the node would be the worst
        outcome available: the proxy would emit a response with no evidence
        behind it.
        """
        disk = _FailingDisk()
        ledger = _ledger(tmp_path, disk)
        try:
            disk.armed.set()
            with pytest.raises(WalDurabilityError):
                _commit(ledger, 0)
        finally:
            ledger.close()


def _outcome(ledger: CryptographicAuditLedger, index: int) -> str:
    try:
        _commit(ledger, index)
    except WalDurabilityError:
        return "failed"
    except Exception as exc:  # pragma: no cover - would be a different defect
        return f"unexpected:{type(exc).__name__}:{exc}"
    return "returned"


class TestTheEngineInIsolation:
    """Properties of the engine that the ledger tests cannot pin down directly."""

    def test_one_sync_retires_every_ticket_written_before_it(self) -> None:
        engine = CoalescedCommitEngine(linger_seconds=0.0)
        first = engine.enqueue()
        second = engine.enqueue()
        third = engine.enqueue()
        calls = 0

        def sync() -> None:
            nonlocal calls
            calls += 1

        engine.await_durable(third, sync)
        # Already durable: the sync above covered the whole file.
        engine.await_durable(first, sync)
        engine.await_durable(second, sync)

        assert calls == 1
        assert engine.stats.largest_batch == 3

    def test_a_failing_sync_raises_for_every_later_caller(self) -> None:
        engine = CoalescedCommitEngine(linger_seconds=0.0)
        ticket = engine.enqueue()

        def boom() -> None:
            raise OSError("device is gone")

        with pytest.raises(WalDurabilityError):
            engine.await_durable(ticket, boom)
        with pytest.raises(WalDurabilityError):
            engine.enqueue()
        assert engine.failed is True

    def test_an_external_sync_releases_pending_tickets(self) -> None:
        """What WAL rotation relies on: it syncs, so nobody else needs to."""
        engine = CoalescedCommitEngine(linger_seconds=0.0)
        ticket = engine.enqueue()
        engine.note_external_sync()

        def must_not_run() -> None:  # pragma: no cover - asserted not to run
            raise AssertionError("a second fsync was issued for durable data")

        engine.await_durable(ticket, must_not_run)

    def test_an_external_failure_fails_pending_tickets(self) -> None:
        engine = CoalescedCommitEngine(linger_seconds=0.0)
        ticket = engine.enqueue()
        engine.fail(OSError("rotation could not fsync"))

        with pytest.raises(WalDurabilityError):
            engine.await_durable(ticket, lambda: None)

    def test_rejects_a_nonsensical_configuration(self) -> None:
        with pytest.raises(ValueError, match="max_batch"):
            CoalescedCommitEngine(max_batch=0)
        with pytest.raises(ValueError, match="linger_seconds"):
            CoalescedCommitEngine(linger_seconds=-1.0)
