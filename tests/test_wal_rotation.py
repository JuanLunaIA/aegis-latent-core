# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""WAL segment rotation & archival (ROADMAP Domain 3.3).

Verifies that a size-bounded WAL rotates into immutable, owner-only archived
segments, that the full append-only audit chain is reconstructable across every
segment on restart, and that rotation is disabled by default (non-breaking).
"""

import os
import stat
from unittest.mock import patch

from aegis.core.crypto_audit import CryptographicAuditLedger

_AUDIT_KEY = "unit-test-signing-key-do-not-use-in-prod"


def _commit_n(ledger, n, *, prefix="s", size=512):
    """Commit n nodes with reasonably large payloads to force rotation."""
    payload = b"x" * size
    for i in range(n):
        ledger.commit_state(f"{prefix}{i:04d}", 1.0, payload)


def test_rotation_disabled_by_default(tmp_path):
    """max_wal_bytes=0 (default) must never create archived segments."""
    wal = str(tmp_path / "noroll.wal.jsonl")
    ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY)
    try:
        _commit_n(ledger, 50, size=1024)
        assert ledger.archived_segments == []
        # Everything is in the single active WAL.
        assert os.path.exists(wal)
    finally:
        ledger.close()


def test_wal_rotates_when_threshold_exceeded(tmp_path):
    """Crossing max_wal_bytes must archive the active WAL and open a fresh one."""
    wal = str(tmp_path / "roll.wal.jsonl")
    # Small cap so each handful of commits triggers a rotation.
    ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=2048)
    try:
        _commit_n(ledger, 40, size=512)
        segments = ledger.archived_segments
        assert len(segments) >= 2, f"expected multiple segments, got {segments}"
        # Active WAL still present after rotation.
        assert os.path.exists(wal)
        # Segments are numbered, ascending, contiguous from 1.
        seqs = [int(p.rsplit(".", 1)[1]) for p in segments]
        assert seqs == sorted(seqs)
        assert seqs[0] == 1
    finally:
        ledger.close()


def test_archived_segments_are_owner_only(tmp_path):
    """Every archived segment must carry 0o600 (no group/other access)."""
    wal = str(tmp_path / "perms.wal.jsonl")
    ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=2048)
    try:
        _commit_n(ledger, 40, size=512)
        segments = ledger.archived_segments
        assert segments, "rotation should have produced at least one segment"
        for seg in segments:
            mode = stat.S_IMODE(os.stat(seg).st_mode)
            assert mode & 0o077 == 0, f"segment too permissive: {seg} {oct(mode)}"
    finally:
        ledger.close()


def test_full_chain_reconstructed_across_segments(tmp_path):
    """After many rotations, a fresh ledger must replay the COMPLETE chain."""
    wal = str(tmp_path / "replay.wal.jsonl")
    total = 60
    with patch("aegis.core.crypto_audit.RUST_AVAILABLE", False):
        ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=1500)
        try:
            _commit_n(ledger, total, size=400)
            assert len(ledger.archived_segments) >= 2
            committed_hashes = [n.node_hash for n in ledger.chain]
            assert len(committed_hashes) == total
        finally:
            ledger.close()

        # Reopen against the same path: must reconstruct from all segments + active.
        reopened = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=1500)
    try:
        assert len(reopened.chain) == total, "every node must survive rotation"
        # Order and content preserved exactly.
        assert [n.node_hash for n in reopened.chain] == committed_hashes
        assert [n.state_id for n in reopened.chain] == [f"s{i:04d}" for i in range(total)]
        # The reconstructed chain is cryptographically intact.
        is_valid, idx = reopened.verify_integrity()
        assert is_valid is True, f"integrity failed at index {idx}"
    finally:
        reopened.close()


def test_rotation_preserves_commit_order(tmp_path):
    """state_ids must come back in strict commit order across segment boundaries."""
    wal = str(tmp_path / "order.wal.jsonl")
    ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=1024)
    try:
        _commit_n(ledger, 30, size=300)
    finally:
        ledger.close()

    reopened = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=1024)
    try:
        ids = [n.state_id for n in reopened.chain]
        assert ids == [f"s{i:04d}" for i in range(30)]
    finally:
        reopened.close()


def test_segment_sequence_continues_after_restart(tmp_path):
    """Reopening a rotated WAL must continue numbering, not overwrite segments."""
    wal = str(tmp_path / "seq.wal.jsonl")
    ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=1024)
    try:
        _commit_n(ledger, 20, prefix="a", size=300)
        first_round = set(ledger.archived_segments)
        assert first_round
    finally:
        ledger.close()

    reopened = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY, max_wal_bytes=1024)
    try:
        _commit_n(reopened, 20, prefix="b", size=300)
        all_segments = set(reopened.archived_segments)
        # Original segments are retained (never clobbered) and new ones added.
        assert first_round.issubset(all_segments)
        assert len(all_segments) > len(first_round)
    finally:
        reopened.close()
