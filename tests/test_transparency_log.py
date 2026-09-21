# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.transparency_log — TransparencyLogManager."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from aegis.core.transparency_log import TransparencyLogManager, compute_entry_hash


class TestTransparencyLogManagerInit:
    def test_starts_empty(self):
        mgr = TransparencyLogManager()
        assert len(mgr._ledger) == 0

    def test_storage_path_none_by_default(self):
        mgr = TransparencyLogManager()
        assert mgr._storage_path is None

    def test_storage_path_set_when_provided(self, tmp_path):
        mgr = TransparencyLogManager(storage_path=tmp_path / "log.jsonl")
        assert mgr._storage_path is not None


class TestPublishBinaryHash:
    def test_returns_hex_string(self):
        mgr = TransparencyLogManager()
        h = mgr.publish_binary_hash("abc123", "1.0.0")
        assert isinstance(h, str)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_entry_added_to_ledger(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("deadbeef", "2.0.0")
        assert len(mgr._ledger) == 1

    def test_first_entry_prev_hash_is_zeros(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("abc", "1.0")
        assert mgr._ledger[0].prev_hash == "0" * 64

    def test_second_entry_prev_hash_links_to_first(self):
        mgr = TransparencyLogManager()
        h1 = mgr.publish_binary_hash("aaa", "1.0")
        mgr.publish_binary_hash("bbb", "2.0")
        assert mgr._ledger[1].prev_hash == h1

    def test_indices_increment(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("a", "1.0")
        mgr.publish_binary_hash("b", "2.0")
        assert mgr._ledger[0].index == 0
        assert mgr._ledger[1].index == 1

    def test_different_hashes_produce_different_entries(self):
        mgr = TransparencyLogManager()
        h1 = mgr.publish_binary_hash("aaa", "1.0")
        h2 = mgr.publish_binary_hash("bbb", "1.0")
        assert h1 != h2


class TestVerifyBinaryPresence:
    def test_present_hash_returns_true(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("cafebabe", "1.0")
        assert mgr.verify_binary_presence("cafebabe") is True

    def test_absent_hash_returns_false(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("cafebabe", "1.0")
        assert mgr.verify_binary_presence("deadbeef") is False

    def test_empty_ledger_returns_false(self):
        mgr = TransparencyLogManager()
        assert mgr.verify_binary_presence("anything") is False


class TestVerifyLedgerIntegrity:
    def test_empty_ledger_is_valid(self):
        mgr = TransparencyLogManager()
        assert mgr.verify_ledger_integrity() is True

    def test_single_entry_is_valid(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("a", "1.0")
        assert mgr.verify_ledger_integrity() is True

    def test_multi_entry_chain_is_valid(self):
        mgr = TransparencyLogManager()
        for i in range(5):
            mgr.publish_binary_hash(f"hash{i}", f"{i}.0")
        assert mgr.verify_ledger_integrity() is True

    def test_tampered_prev_hash_breaks_chain(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("a", "1.0")
        mgr.publish_binary_hash("b", "2.0")
        mgr._ledger[1].prev_hash = "00" * 32
        assert mgr.verify_ledger_integrity() is False


class TestGetMerkleRoot:
    def test_empty_returns_zeros(self):
        mgr = TransparencyLogManager()
        assert mgr.get_merkle_root() == "0" * 64

    def test_returns_last_entry_hash(self):
        mgr = TransparencyLogManager()
        mgr.publish_binary_hash("x", "1.0")
        h = mgr.publish_binary_hash("y", "2.0")
        assert mgr.get_merkle_root() == h


class TestFilePersistence:
    def test_entries_written_to_jsonl(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        mgr = TransparencyLogManager(storage_path=path)
        mgr.publish_binary_hash("deadbeef", "1.0")
        assert path.exists()
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["binary_hash"] == "deadbeef"

    def test_replay_on_new_instance(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        mgr1 = TransparencyLogManager(storage_path=path)
        mgr1.publish_binary_hash("cafebabe", "2.0")
        mgr1.publish_binary_hash("deadbeef", "3.0")

        mgr2 = TransparencyLogManager(storage_path=path)
        assert len(mgr2._ledger) == 2
        assert mgr2._ledger[0].binary_hash == "cafebabe"
        assert mgr2._ledger[1].binary_hash == "deadbeef"

    def test_chain_intact_after_replay(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        mgr1 = TransparencyLogManager(storage_path=path)
        for i in range(3):
            mgr1.publish_binary_hash(f"h{i}", f"{i}.0")

        mgr2 = TransparencyLogManager(storage_path=path)
        assert mgr2.verify_ledger_integrity() is True

    def test_presence_check_works_after_replay(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        mgr1 = TransparencyLogManager(storage_path=path)
        mgr1.publish_binary_hash("targetbinary", "1.0")

        mgr2 = TransparencyLogManager(storage_path=path)
        assert mgr2.verify_binary_presence("targetbinary") is True

    def test_appends_do_not_overwrite(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        mgr1 = TransparencyLogManager(storage_path=path)
        mgr1.publish_binary_hash("first", "1.0")

        mgr2 = TransparencyLogManager(storage_path=path)
        mgr2.publish_binary_hash("second", "2.0")

        mgr3 = TransparencyLogManager(storage_path=path)
        assert len(mgr3._ledger) == 2

    def test_malformed_line_is_skipped(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        path.write_text(
            '{"index": 0, "binary_hash": "good", "version": "1.0", "timestamp": 1.0, "prev_hash": "'
            + "0" * 64
            + '", "entry_hash": "'
            + "a" * 64
            + '"}\nNOT_JSON\n'
        )
        mgr = TransparencyLogManager(storage_path=path)
        assert len(mgr._ledger) == 1


# ── AUD-11: the verifier recomputes, and the append is durable ───────────────


def _chain(count: int = 3) -> TransparencyLogManager:
    mgr = TransparencyLogManager()
    for n in range(count):
        mgr.publish_binary_hash(chr(ord("a") + n) * 64, f"1.0.{n}")
    return mgr


class TestTamperDetectionRecomputesEntryHashes:
    """The pre-fix verifier compared linkage only; these pin the recompute.

    Before AUD-11 every case below returned True: the stored entry_hash was
    compared against the successor's prev_hash and never re-derived from the
    entry's own fields, so an in-place edit kept the graph intact and
    `verify_binary_presence` then confirmed the substituted binary.
    """

    def test_edit_of_a_non_tail_entry_is_detected(self):
        mgr = _chain()
        mgr._ledger[1].binary_hash = "f" * 64
        assert mgr.verify_ledger_integrity() is False

    def test_edit_of_a_tail_entry_is_detected(self):
        mgr = _chain()
        mgr._ledger[2].binary_hash = "f" * 64
        assert mgr.verify_ledger_integrity() is False

    def test_version_edit_is_detected(self):
        mgr = _chain()
        mgr._ledger[1].version = "9.9.9"
        assert mgr.verify_ledger_integrity() is False

    def test_timestamp_edit_is_detected(self):
        mgr = _chain()
        mgr._ledger[1].timestamp += 1.0
        assert mgr.verify_ledger_integrity() is False

    def test_edit_with_a_recomputed_hash_and_repaired_linkage_is_detected(self):
        """The edit that linkage alone cannot see: entry 1 is rehashed and entry
        2's prev_hash follows it, so every link still matches. Verification
        catches it because entry 2's stored hash no longer recomputes."""
        mgr = _chain()
        entry = mgr._ledger[1]
        entry.binary_hash = "f" * 64
        entry.entry_hash = compute_entry_hash(
            entry.index, entry.binary_hash, entry.version, entry.timestamp, entry.prev_hash
        )
        mgr._ledger[2].prev_hash = entry.entry_hash
        assert mgr.verify_ledger_integrity() is False

    def test_reordering_is_detected(self):
        mgr = _chain()
        mgr._ledger[1], mgr._ledger[2] = mgr._ledger[2], mgr._ledger[1]
        assert mgr.verify_ledger_integrity() is False

    def test_a_substituted_binary_hash_is_not_confirmed(self):
        mgr = _chain()
        mgr._ledger[1].binary_hash = "a" * 64  # pretend the audited binary was entry 1
        assert mgr._ledger[1].binary_hash == "a" * 64
        assert mgr.verify_binary_presence("a" * 64) is False

    def test_a_clean_ledger_still_verifies(self):
        mgr = _chain()
        assert mgr.verify_ledger_integrity() is True
        assert mgr.verify_binary_presence("a" * 64) is True
        assert mgr.verify_binary_presence("z" * 64) is False
        assert TransparencyLogManager().verify_ledger_integrity() is True

    def test_an_edit_on_disk_is_detected_after_replay(self, tmp_path):
        path = tmp_path / "log.jsonl"
        mgr = TransparencyLogManager(storage_path=path)
        for n in range(3):
            mgr.publish_binary_hash(chr(ord("a") + n) * 64, f"1.0.{n}")
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        record = json.loads(lines[1])
        record["binary_hash"] = "f" * 64
        lines[1] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        replayed = TransparencyLogManager(storage_path=path)
        assert replayed._ledger[1].binary_hash == "f" * 64
        assert replayed.verify_ledger_integrity() is False

    def test_a_deleted_line_is_detected_after_replay(self, tmp_path):
        path = tmp_path / "log.jsonl"
        mgr = TransparencyLogManager(storage_path=path)
        for n in range(3):
            mgr.publish_binary_hash(chr(ord("a") + n) * 64, f"1.0.{n}")
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
        replayed = TransparencyLogManager(storage_path=path)
        assert replayed.verify_ledger_integrity() is False

    def test_a_full_suffix_rewrite_is_the_published_limit(self):
        """UC-061, pinned: the chain is unkeyed.

        An author who edits an entry *and* recomputes every hash after it
        produces a ledger this module cannot distinguish from an honest one.
        Asserted so the boundary is not implied to be stronger than it is.
        """
        mgr = _chain()
        mgr._ledger[1].binary_hash = "f" * 64
        for index in (1, 2):
            entry = mgr._ledger[index]
            if index == 2:
                entry.prev_hash = mgr._ledger[1].entry_hash
            entry.entry_hash = compute_entry_hash(
                entry.index, entry.binary_hash, entry.version, entry.timestamp, entry.prev_hash
            )
        assert mgr.verify_ledger_integrity() is True


class TestAppendDurability:
    def test_publish_fsyncs_before_returning_the_hash(self, tmp_path):
        path = Path(tmp_path) / "log.jsonl"
        calls: list[int] = []
        with patch("os.fsync", side_effect=lambda fd: calls.append(fd)):
            mgr = TransparencyLogManager(storage_path=path)
            mgr.publish_binary_hash("cafebabe", "1.0.0")
        assert len(calls) == 1
        assert len(TransparencyLogManager(storage_path=path)._ledger) == 1

    def test_a_failed_fsync_does_not_report_a_published_entry(self, tmp_path):
        path = Path(tmp_path) / "log.jsonl"
        with patch("os.fsync", side_effect=OSError("no space left on device")):
            mgr = TransparencyLogManager(storage_path=path)
            try:
                mgr.publish_binary_hash("cafebabe", "1.0.0")
            except OSError as exc:
                assert "no space left" in str(exc)
            else:
                raise AssertionError("publish_binary_hash returned despite a failed fsync")
        # Disk first, memory second: no entry is claimed that the file lacks.
        assert len(mgr._ledger) == 0
        assert mgr.verify_ledger_integrity() is True
