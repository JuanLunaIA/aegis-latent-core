# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Barrier ordering and externally latched group-commit failure regressions."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.group_commit import CoalescedCommitEngine, WalDurabilityError


def test_external_failure_during_sync_prevents_success() -> None:
    engine = CoalescedCommitEngine(linger_seconds=0)
    ticket = engine.enqueue()

    def sync() -> None:
        engine.fail(OSError("concurrent descriptor/rotation failure"))

    with pytest.raises(WalDurabilityError):
        engine.await_durable(ticket, sync)
    assert engine.stats.batches == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory fsync contract")
@pytest.mark.parametrize("directory_failure", [False, True])
def test_rotation_names_are_durable_before_ticket_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, directory_failure: bool
) -> None:
    events: list[str] = []
    wal = tmp_path / "audit.jsonl"
    ledger = CryptographicAuditLedger(str(wal), signing_key="fixture", max_wal_bytes=1)
    original_rename = os.rename
    original_publish = ledger._commit_engine.note_external_sync

    def rename(source, target):
        result = original_rename(source, target)
        events.append("rename")
        return result

    def sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            events.append("directory_sync")
            if directory_failure:
                raise OSError("injected directory sync failure")
        else:
            events.append("file_sync")
        os.fsync(fd)

    def publish():
        events.append("publish")
        original_publish()

    # Checkpoint optimization has its own fsync; exclude it so the test
    # observes only the authoritative segment rename/create barrier.
    monkeypatch.setattr(ledger, "_save_mmr_state", lambda *args: False)
    monkeypatch.setattr(ledger, "_fsync", sync)
    monkeypatch.setattr(os, "rename", rename)
    monkeypatch.setattr(ledger._commit_engine, "note_external_sync", publish)
    try:
        if directory_failure:
            with pytest.raises((OSError, WalDurabilityError)):
                ledger.commit_state("one", 0.0, b"payload")
            assert ledger._fault_state == "wal_persist_failed"
            assert "publish" not in events
        else:
            ledger.commit_state("one", 0.0, b"payload")
            assert "directory_sync" in events
            assert events.index("rename") < events.index("directory_sync") < events.index("publish")
    finally:
        ledger.close()
