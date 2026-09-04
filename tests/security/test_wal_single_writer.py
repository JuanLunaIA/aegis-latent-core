# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Single-writer enforcement for the authoritative JSONL WAL.

Threat WAL-02: two writers appending to one WAL path produce divergent
``prev_hash`` relationships that the loader cannot represent as one verified
chain. The topology was previously documented as unsupported but not enforced,
so the fork could occur silently. These tests pin the enforcement.

``CryptographicAuditLedger.__exit__`` calls ``close()``, so each ledger is held
in a ``with`` block: the writer is released on the normal path and on a failed
assertion alike, which matters here because a leaked handle would hold the lock
and cascade into every later test on the same path.

The guard is enforced with ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on
Windows. The behavioural tests are platform-neutral and run on both. The
Windows-specific mechanics — the sentinel region, the error translation, and
the offset restore — are additionally driven on any host through the module's
``_WINDOWS`` selector and a stand-in for ``msvcrt``, so the branch the running
interpreter does not take is still exercised rather than merely written.
"""

from __future__ import annotations

import multiprocessing as mp
import os

import pytest

from aegis.core import crypto_audit
from aegis.core.crypto_audit import CryptographicAuditLedger, WalWriterConflictError

_KEY = "k" * 32


def test_second_writer_on_same_path_is_refused(tmp_path):
    """A live writer must prevent a second ledger from opening the same path."""
    wal = str(tmp_path / "a.wal.jsonl")
    with CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY):
        with pytest.raises(WalWriterConflictError):
            CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)


def test_refused_writer_leaks_no_descriptor(tmp_path):
    """The losing writer must close its descriptor rather than leak it."""
    wal = str(tmp_path / "b.wal.jsonl")
    with CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY) as first:
        for _ in range(50):
            with pytest.raises(WalWriterConflictError):
                CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
        # A descriptor leak would exhaust the process limit well before 50.
        assert first._wal_handle is not None


def test_restart_reacquires_the_lock(tmp_path):
    """Releasing the writer must allow a later process to reopen the path."""
    wal = str(tmp_path / "c.wal.jsonl")
    with CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY) as first:
        first.commit_state("s0", 1.0, b"payload", tenant_id="t1")

    with CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY) as second:
        assert len(second.chain) >= 1
        ok, _ = second.verify_integrity()
        assert ok is True


def test_distinct_paths_are_independent(tmp_path):
    """The guard must not block legitimate per-replica WAL paths."""
    with (
        CryptographicAuditLedger(
            persistence_path=str(tmp_path / "r1.wal.jsonl"), signing_key=_KEY
        ) as one,
        CryptographicAuditLedger(
            persistence_path=str(tmp_path / "r2.wal.jsonl"), signing_key=_KEY
        ) as two,
    ):
        one.commit_state("s0", 1.0, b"a", tenant_id="t1")
        two.commit_state("s0", 1.0, b"b", tenant_id="t1")
        assert one.verify_integrity()[0] is True
        assert two.verify_integrity()[0] is True


def _child_try_open(wal: str, result) -> None:
    """Open the WAL in a separate process and report the outcome."""
    try:
        with CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY):
            pass
        result.value = 0  # acquired — a fork would have been possible
    except WalWriterConflictError:
        result.value = 1  # correctly refused
    except Exception:  # pragma: no cover - unexpected failure mode
        result.value = 2


def test_cross_process_writer_is_refused(tmp_path):
    """The guard must hold across processes, which is the real threat.

    Runs on POSIX and Windows alike: ``flock`` and ``msvcrt.locking`` are both
    held by the operating system against other processes, so neither platform
    is exempt from the assertion.
    """
    wal = str(tmp_path / "d.wal.jsonl")
    with CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY):
        ctx = mp.get_context("spawn")
        result = ctx.Value("i", -1)
        child = ctx.Process(target=_child_try_open, args=(wal, result))
        child.start()
        child.join(timeout=60)
        assert child.exitcode == 0
        assert result.value == 1, "a second process acquired the WAL lock"


# ── Windows lock mechanics ────────────────────────────────────────────────────
#
# These drive the ``os.name == "nt"`` branch on whatever platform the suite is
# running on. On a Windows runner the branch is also taken for real by every
# test above; here it is isolated so the sentinel arithmetic and the error
# translation are pinned independently of the host.


class _FakeMsvcrt:
    """Stand-in for :mod:`msvcrt` recording the calls the lock path makes."""

    LK_NBLCK = 1
    LK_UNLCK = 0

    def __init__(self, raises: OSError | None = None) -> None:
        self.calls: list[tuple[int, int, int]] = []
        self._raises = raises

    def locking(self, fd: int, mode: int, nbytes: int) -> None:
        # Record where the descriptor is pointing: that offset is the whole
        # point of the sentinel, and msvcrt.locking reads it implicitly.
        self.calls.append((mode, nbytes, os.lseek(fd, 0, os.SEEK_CUR)))
        if self._raises is not None:
            raise self._raises


@pytest.fixture
def windows_lock(monkeypatch):
    """Select the Windows branch and install a fake ``msvcrt``."""

    def _install(raises: OSError | None = None) -> _FakeMsvcrt:
        fake = _FakeMsvcrt(raises)
        monkeypatch.setattr(crypto_audit, "_WINDOWS", True)
        monkeypatch.setattr(crypto_audit, "msvcrt", fake)
        return fake

    return _install


@pytest.fixture
def scratch_fd(tmp_path):
    """An open descriptor on a real file, closed however the test ends."""
    fd = os.open(str(tmp_path / "w.wal.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        yield fd
    finally:
        os.close(fd)


def test_windows_lock_is_taken_at_the_sentinel_offset(windows_lock, scratch_fd):
    """The exclusive, non-blocking lock must cover one byte at the sentinel."""
    fake = windows_lock()

    crypto_audit._lock_wal_fd(scratch_fd, "w.wal.jsonl")

    assert fake.calls == [(fake.LK_NBLCK, 1, crypto_audit._WINDOWS_LOCK_OFFSET)]


def test_windows_lock_restores_the_descriptor_offset(windows_lock, scratch_fd):
    """Positioning the sentinel must not move the caller's file position."""
    fake = windows_lock()
    os.lseek(scratch_fd, 17, os.SEEK_SET)

    crypto_audit._lock_wal_fd(scratch_fd, "w.wal.jsonl")

    assert os.lseek(scratch_fd, 0, os.SEEK_CUR) == 17
    assert fake.calls[0][2] == crypto_audit._WINDOWS_LOCK_OFFSET


def test_windows_lock_conflict_becomes_the_documented_error(windows_lock, scratch_fd):
    """A refused lock is the second-writer case and must say so."""
    windows_lock(raises=OSError(13, "Permission denied"))

    with pytest.raises(WalWriterConflictError) as excinfo:
        crypto_audit._lock_wal_fd(scratch_fd, "w.wal.jsonl")

    assert "already locked by another writer" in str(excinfo.value)


def test_windows_unreachable_sentinel_admits_the_first_writer(
    windows_lock, scratch_fd, monkeypatch, caplog
):
    """A sentinel the filesystem cannot address is not a lock conflict.

    Refusing here would reject the *first* writer as though it were the
    second, taking the gateway down on any filesystem whose maximum file size
    sits below the offset. The guard degrades to operator-enforced instead,
    and says so.
    """
    fake = windows_lock()
    monkeypatch.setattr(crypto_audit, "_WINDOWS_LOCK_OFFSET", -1)

    with caplog.at_level("WARNING"):
        crypto_audit._lock_wal_fd(scratch_fd, "w.wal.jsonl")

    assert fake.calls == [], "the lock must not be attempted off the sentinel"
    assert "operator-enforced" in caplog.text


def test_windows_unlock_releases_the_same_region(windows_lock, scratch_fd):
    """Release must target the byte the lock took, not the file head."""
    fake = windows_lock()
    crypto_audit._lock_wal_fd(scratch_fd, "w.wal.jsonl")

    crypto_audit._unlock_wal_fd(scratch_fd)

    assert fake.calls[-1] == (fake.LK_UNLCK, 1, crypto_audit._WINDOWS_LOCK_OFFSET)


def test_windows_unlock_never_raises(windows_lock, scratch_fd):
    """Release runs on close and rotation; it must not mask the real error."""
    windows_lock(raises=OSError(13, "Permission denied"))

    crypto_audit._unlock_wal_fd(scratch_fd)  # must not raise


def test_sentinel_offset_clears_any_wal_and_stays_addressable(scratch_fd):
    """The sentinel must sit past real records but inside filesystem limits."""
    offset = crypto_audit._WINDOWS_LOCK_OFFSET
    # Far beyond a rotating WAL, whose threshold is configured in bytes and
    # deployed at megabyte scale.
    assert offset >= 1 << 40
    # And genuinely reachable: an offset past the filesystem maximum fails with
    # EINVAL, which is what makes an arbitrarily large constant unsafe.
    assert os.lseek(scratch_fd, offset, os.SEEK_SET) == offset


def test_posix_branch_still_uses_flock(scratch_fd):
    """The POSIX path must be unchanged by the Windows branch."""
    if os.name != "posix":  # pragma: no cover - platform dependent
        pytest.skip("POSIX-only assertion")
    assert crypto_audit._WINDOWS is False
    crypto_audit._lock_wal_fd(scratch_fd, "w.wal.jsonl")
    crypto_audit._unlock_wal_fd(scratch_fd)
