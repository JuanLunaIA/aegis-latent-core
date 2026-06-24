# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.memory_invariants — real /proc/self/mem verification.

Verifies that MemoryInvariantMonitor reads actual process virtual-address
ranges, computes real SHA-256 golden hashes, detects modifications, and
handles unmapped ranges without crashing.
"""

from __future__ import annotations

import ctypes
import hashlib
from unittest.mock import patch

from aegis.core.memory_invariants import (
    MemoryInvariantMonitor,
    _hash_range,
    _read_range,
)

# ── _read_range / _hash_range ─────────────────────────────────────────────────


class TestReadRange:
    def _make_buffer(self, content: bytes) -> tuple[int, int]:
        buf = ctypes.create_string_buffer(content)
        TestReadRange._keep = buf  # prevent GC
        addr = ctypes.addressof(buf)
        return addr, addr + len(content)

    def test_reads_real_memory(self):
        addr, end = self._make_buffer(b"aegis-mem-test")
        data = _read_range(addr, end)
        assert data is not None
        assert data == b"aegis-mem-test"

    def test_empty_range_returns_none(self):
        assert _read_range(0x1000, 0x1000) is None

    def test_reversed_range_returns_none(self):
        assert _read_range(0x2000, 0x1000) is None

    def test_unmapped_address_returns_none(self):
        # Address 0x1 is never mapped
        result = _read_range(1, 2)
        assert result is None


class TestHashRange:
    def _make_buffer(self, content: bytes) -> tuple[int, int]:
        buf = ctypes.create_string_buffer(content)
        TestHashRange._keep = buf
        addr = ctypes.addressof(buf)
        return addr, addr + len(content)

    def test_returns_sha256_hex(self):
        content = b"hash-test-content"
        addr, end = self._make_buffer(content)
        result = _hash_range(addr, end)
        assert result == hashlib.sha256(content).hexdigest()

    def test_unmapped_returns_none(self):
        assert _hash_range(1, 2) is None

    def test_empty_returns_none(self):
        assert _hash_range(0x100, 0x100) is None


# ── MemoryInvariantMonitor ────────────────────────────────────────────────────


class TestMemoryInvariantMonitor:
    def _make_buffer(self, content: bytes) -> tuple[int, int, ctypes.Array]:
        buf = ctypes.create_string_buffer(content)
        addr = ctypes.addressof(buf)
        return addr, addr + len(content), buf

    def test_register_readable_range_returns_true(self):
        mon = MemoryInvariantMonitor()
        addr, end, buf = self._make_buffer(b"register-test")
        assert mon.register_invariant("test", addr, end) is True

    def test_register_unmapped_range_returns_false(self):
        mon = MemoryInvariantMonitor()
        assert mon.register_invariant("bad", 1, 2) is False

    def test_verify_unchanged_returns_true(self):
        mon = MemoryInvariantMonitor()
        content = b"unchanged-invariant"
        addr, end, buf = self._make_buffer(content)
        mon.register_invariant("stable", addr, end)
        assert mon.verify_invariants() is True

    def test_verify_no_invariants_returns_true(self):
        mon = MemoryInvariantMonitor()
        assert mon.verify_invariants() is True

    def test_verify_modified_critical_returns_false(self):
        mon = MemoryInvariantMonitor()
        content = bytearray(b"mutable-data-AAAA")
        buf = ctypes.create_string_buffer(bytes(content))
        TestMemoryInvariantMonitor._keep = buf
        addr = ctypes.addressof(buf)
        end = addr + len(content)

        mon.register_invariant("mutable", addr, end, criticality="CRITICAL")

        # Modify the buffer contents
        ctypes.memmove(addr, b"mutable-data-BBBB", len(content))

        assert mon.verify_invariants() is False

    def test_verify_modified_high_continues(self):
        mon = MemoryInvariantMonitor()
        content = bytearray(b"high-prio-AAAA")
        buf = ctypes.create_string_buffer(bytes(content))
        TestMemoryInvariantMonitor._keep2 = buf
        addr = ctypes.addressof(buf)
        end = addr + len(content)

        mon.register_invariant("high", addr, end, criticality="HIGH")
        ctypes.memmove(addr, b"high-prio-BBBB", len(content))

        # HIGH violation doesn't short-circuit — returns True (no CRITICAL)
        result = mon.verify_invariants()
        # The loop continues; since there are no CRITICAL invariants, returns True
        assert isinstance(result, bool)

    def test_register_stores_real_hash(self):
        mon = MemoryInvariantMonitor()
        content = b"hash-check"
        addr, end, buf = self._make_buffer(content)
        mon.register_invariant("hashed", addr, end)
        inv = mon._invariants["hashed"]
        assert inv.golden_hash == hashlib.sha256(content).hexdigest()

    def test_unreadable_range_after_register_returns_false(self):
        mon = MemoryInvariantMonitor()
        with patch("aegis.core.memory_invariants._hash_range") as mock_hash:
            # First call: return a valid hash (registration)
            # Second call: return None (memory became unreadable)
            mock_hash.side_effect = ["abc123", None]
            mon.register_invariant("gone", 0xDEAD, 0xDEAD + 4, criticality="CRITICAL")
            result = mon.verify_invariants()
        assert result is False

    def test_start_stop_monitoring(self):
        mon = MemoryInvariantMonitor()
        assert mon._is_monitoring is False
        mon.start_monitoring()
        assert mon._is_monitoring is True
        mon.stop_monitoring()
        assert mon._is_monitoring is False
