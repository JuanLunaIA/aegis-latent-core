# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""The ledger refuses to extend its chain while a fault is latched.

``specs/aegis_invariants.tla`` checks that every record a caller was told is
committed can be read back by replay (``CommittedReplayable``). With
``LedgerGatesCommits = FALSE`` (``aegis_invariants_ungated.cfg``) TLC finds a
three-step counterexample, and it was the real behaviour of
``CryptographicAuditLedger``:

1. request A's WAL write tears part-way through a line and latches
   ``wal_persist_failed``;
2. request B, admitted by the gateway before the latch, commits anyway: its
   line lands after the torn bytes, and the caller is told it is durable;
3. replay stops at the torn line, so B is never read back. If B's bytes ran
   into A's partial line, ``tools/wal_repair.py`` truncates that merged line as
   a torn tail and discards B; if anything follows B, the damage is interior
   and repair refuses.

The gateway reads the latch before it forwards a request, but that read and the
commit are not atomic, so it cannot close the window. The check under the
ledger lock does: every writer that latches holds or takes that lock.

These tests pin the property on the real class: each commit entry point
refuses while faulted, nothing reaches the WAL or the MMR when it does, and
after a torn write every node the ledger returned is still replayable once the
torn tail is repaired.
"""

from __future__ import annotations

import importlib.util
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger, LedgerFaultedError

_SPEC = importlib.util.spec_from_file_location(
    "wal_repair", Path(__file__).resolve().parents[1] / "tools" / "wal_repair.py"
)
assert _SPEC is not None
assert _SPEC.loader is not None
wal_repair = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(wal_repair)

FAULTS = [
    "signing_failed",
    "wal_persist_failed",
    "wal_corrupt",
    "mmr_scheme_mismatch",
    "mmr_replay_mismatch",
]


def _ledger(wal: Path) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(str(wal), signing_key="fault-gate-test-key")


def _replayed_ids(wal: Path) -> list[str]:
    ledger = _ledger(wal)
    try:
        assert ledger._fault_state == "healthy"
        ok, bad_index = ledger.verify_integrity()
        assert ok, f"replayed chain does not verify at index {bad_index}"
        return [node.state_id for node in ledger.chain]
    finally:
        ledger.close()


class _TearingWrite:
    """Wrap a WAL handle's ``write`` so that one chosen call tears.

    The torn call writes the first half of its line - no newline, exactly what
    a process sees when the device fills mid-write - and raises ``OSError``.
    Every other call goes through. The ledger calls ``write`` under its lock,
    so the counter needs no lock of its own.
    """

    def __init__(self, original: Any, tear_on_call: int) -> None:
        self._original = original
        self._tear_on_call = tear_on_call
        self.calls = 0

    def __call__(self, line: str) -> int:
        self.calls += 1
        if self.calls == self._tear_on_call:
            self._original(line[: len(line) // 2])
            raise OSError(28, "No space left on device")
        result: int = self._original(line)
        return result


def _install_tear(ledger: CryptographicAuditLedger, tear_on_call: int) -> _TearingWrite:
    handle = ledger._wal_handle
    assert handle is not None
    tear = _TearingWrite(handle.write, tear_on_call)
    handle.write = tear  # type: ignore[method-assign]
    return tear


class TestEveryEntryPointIsGated:
    @pytest.mark.parametrize("fault", FAULTS)
    def test_nothing_is_written_while_a_fault_is_latched(self, tmp_path: Path, fault: str) -> None:
        wal = tmp_path / "audit.jsonl"
        ledger = _ledger(wal)
        try:
            ledger.commit_state("before", 0.0, b"payload")
            ledger._fault_state = fault
            wal_before = wal.read_bytes()
            leaves_before = ledger._mmr.get_leaf_count()
            chain_before = [node.state_id for node in ledger.chain]

            attempts = {
                "commit_state": lambda: ledger.commit_state("s", 0.0, b"payload"),
                "commit_forensic": lambda: ledger.commit_forensic(
                    state_id="f", request_bytes=b"req", response_bytes=b"resp"
                ),
                "commit_rejection": lambda: ledger.commit_rejection(
                    request_bytes=b"req", rejection_code=403, reason_category="waf"
                ),
                "commit_forensic_summary": lambda: ledger.commit_forensic_summary(
                    state_id="sum",
                    request_bytes=b"req",
                    response_hash="0" * 64,
                    response_size=0,
                    response_preview=b"",
                    terminal_outcome="complete",
                    final_marker_included=True,
                    token_count=0,
                    elapsed_seconds=0.0,
                ),
            }
            for name, attempt in attempts.items():
                with pytest.raises(LedgerFaultedError) as refused:
                    attempt()
                assert refused.value.fault_state == fault, name

            assert wal.read_bytes() == wal_before
            assert ledger._mmr.get_leaf_count() == leaves_before
            assert [node.state_id for node in ledger.chain] == chain_before
            assert ledger._fault_state == fault
        finally:
            ledger.close()

    def test_a_healthy_ledger_is_not_refused(self, tmp_path: Path) -> None:
        # The gate is not a blanket refusal: the same calls succeed while healthy.
        ledger = _ledger(tmp_path / "audit.jsonl")
        try:
            node = ledger.commit_rejection(
                request_bytes=b"req", rejection_code=403, reason_category="waf"
            )
            assert node.node_hash
            assert ledger._fault_state == "healthy"
        finally:
            ledger.close()

    def test_a_signing_failure_refuses_every_later_commit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ledger = _ledger(tmp_path / "audit.jsonl")
        try:
            ledger.commit_state("s1", 0.0, b"payload")
            original = ledger._sign_bound

            def broken(*args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("HSM unavailable")

            monkeypatch.setattr(ledger, "_sign_bound", broken)
            with pytest.raises(RuntimeError, match="HSM unavailable"):
                ledger.commit_state("s2", 0.0, b"payload")

            # The signer comes back; the ledger still refuses until restart.
            monkeypatch.setattr(ledger, "_sign_bound", original)
            with pytest.raises(LedgerFaultedError):
                ledger.commit_state("s3", 0.0, b"payload")
            assert [node.state_id for node in ledger.chain] == ["s1"]
        finally:
            ledger.close()


class TestCommittedRecordsStayReplayable:
    def test_a_commit_after_a_torn_write_is_refused(self, tmp_path: Path) -> None:
        wal = tmp_path / "audit.jsonl"
        ledger = _ledger(wal)
        returned: list[str] = []
        try:
            returned.append(ledger.commit_state("s1", 0.0, b"payload").state_id)
            tear = _install_tear(ledger, tear_on_call=1)
            with pytest.raises(OSError, match="No space left"):
                ledger.commit_state("s2", 0.0, b"payload")
            assert ledger._fault_state == "wal_persist_failed"

            # The disk accepts writes again. Without the gate this commit
            # returned a node whose line ran into the torn bytes.
            with pytest.raises(LedgerFaultedError):
                ledger.commit_state("s3", 0.0, b"payload")
            assert tear.calls == 1, "the refused commit must not reach the WAL"
        finally:
            ledger.close()

        # Only the torn tail is damaged, so the supported repair applies, and
        # every node the ledger returned replays and verifies.
        assert wal_repair.repair(wal, apply=True, backup=tmp_path / "audit.bak") == 0
        assert _replayed_ids(wal) == returned

    def test_concurrent_commits_around_a_torn_write_lose_nothing_returned(
        self, tmp_path: Path
    ) -> None:
        wal = tmp_path / "audit.jsonl"
        ledger = _ledger(wal)
        returned: list[str] = []
        guard = threading.Lock()
        start = threading.Barrier(16)

        def commit(index: int) -> str:
            start.wait()
            try:
                node = ledger.commit_state(f"req-{index:02d}", 0.0, b"payload")
            except (OSError, LedgerFaultedError) as exc:
                return type(exc).__name__
            with guard:
                returned.append(node.state_id)
            return "committed"

        try:
            ledger.commit_state("seed", 0.0, b"payload")
            returned.append("seed")
            _install_tear(ledger, tear_on_call=6)
            with ThreadPoolExecutor(max_workers=16) as pool:
                outcomes = list(pool.map(commit, range(16)))
        finally:
            ledger.close()

        # Five commits land before the tear, one tears, and every commit that
        # takes the lock afterwards is refused rather than written behind it.
        assert outcomes.count("committed") == 5, outcomes
        assert outcomes.count("OSError") == 1, outcomes
        assert outcomes.count("LedgerFaultedError") == 10, outcomes

        assert wal_repair.repair(wal, apply=True, backup=tmp_path / "audit.bak") == 0
        assert set(_replayed_ids(wal)) == set(returned)
