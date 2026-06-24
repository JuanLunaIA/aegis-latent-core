# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.state_snapshotter — AtomicSnapshotManager."""

from __future__ import annotations

from aegis.core.state_snapshotter import AtomicSnapshotManager, SystemSnapshot


class TestCaptureState:
    def test_returns_snapshot_id(self):
        mgr = AtomicSnapshotManager()
        sid = mgr.capture_state({"key": "value"})
        assert isinstance(sid, str)
        assert len(sid) == 36  # UUID4

    def test_snapshot_stored_in_history(self):
        mgr = AtomicSnapshotManager()
        sid = mgr.capture_state({"a": 1})
        assert sid in mgr._history

    def test_merkle_root_is_sha256_hex(self):
        mgr = AtomicSnapshotManager()
        sid = mgr.capture_state({"x": 42})
        snap = mgr._history[sid]
        assert len(snap.merkle_root) == 64
        assert all(c in "0123456789abcdef" for c in snap.merkle_root)

    def test_state_is_deep_copy(self):
        original = {"nested": {"val": 10}}
        mgr = AtomicSnapshotManager()
        sid = mgr.capture_state(original)
        original["nested"]["val"] = 99
        assert mgr._history[sid].state_data["nested"]["val"] == 10

    def test_latest_snapshot_id_updated(self):
        mgr = AtomicSnapshotManager()
        sid1 = mgr.capture_state({"a": 1})
        sid2 = mgr.capture_state({"b": 2})
        assert mgr.get_latest_snapshot_id() == sid2
        assert sid1 != sid2

    def test_no_simulation_comment_in_docstring(self):
        doc = AtomicSnapshotManager.capture_state.__doc__ or ""
        assert "In a real" not in doc
        assert "SIMULATION" not in doc


class TestRollbackTo:
    def test_successful_rollback_returns_state(self):
        mgr = AtomicSnapshotManager()
        sid = mgr.capture_state({"config": "prod"})
        restored = mgr.rollback_to(sid)
        assert restored == {"config": "prod"}

    def test_unknown_snapshot_id_returns_none(self):
        mgr = AtomicSnapshotManager()
        result = mgr.rollback_to("nonexistent-id")
        assert result is None

    def test_corrupted_merkle_root_returns_none(self):
        mgr = AtomicSnapshotManager()
        sid = mgr.capture_state({"x": 1})
        mgr._history[sid].merkle_root = "deadbeef" * 8
        result = mgr.rollback_to(sid)
        assert result is None

    def test_rollback_does_not_remove_snapshot(self):
        mgr = AtomicSnapshotManager()
        sid = mgr.capture_state({"y": 2})
        mgr.rollback_to(sid)
        assert sid in mgr._history


class TestPurgeOldSnapshots:
    def test_purge_keeps_last_n(self):
        mgr = AtomicSnapshotManager()
        for i in range(10):
            mgr.capture_state({"i": i})
        mgr.purge_old_snapshots(keep_last=5)
        assert len(mgr._history) == 5

    def test_purge_below_limit_is_noop(self):
        mgr = AtomicSnapshotManager()
        for i in range(3):
            mgr.capture_state({"i": i})
        mgr.purge_old_snapshots(keep_last=10)
        assert len(mgr._history) == 3


class TestSystemSnapshotDataclass:
    def test_fields(self):
        snap = SystemSnapshot(
            snapshot_id="abc",
            timestamp=1.0,
            state_data={"k": "v"},
            merkle_root="aa" * 32,
            is_verified=True,
        )
        assert snap.snapshot_id == "abc"
        assert snap.is_verified is True
