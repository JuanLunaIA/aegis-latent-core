# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.cfi_manager — real ELF CFI inspection.

Verifies that CFIManager reads actual binary content rather than returning
a hardcoded True, and that it handles edge cases gracefully.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aegis.core.cfi_manager import (
    _FEAT1_IBT,
    _FEAT1_SHSTK,
    _GNU_PROP_X86_FEAT1_TYPE,
    CFIManager,
    CFIReport,
    _parse_gnu_property,
)

# Path to the compiled Rust extension — it has .eh_frame but no LLVM CFI
_RUST_SO = (
    Path(__file__).parent.parent / "aegis_rust_v2" / "target" / "release" / "libaegis_rust.so"
)
_RUST_SO_AVAILABLE = _rust_so = pytest.mark.skipif(
    not _RUST_SO.is_file(),
    reason="Rust release binary not built",
)


class TestCFIReport:
    def test_empty_report_has_no_cfi(self):
        r = CFIReport("/fake")
        assert not r.has_llvm_cfi
        assert not r.has_eh_frame
        assert not r.has_intel_cet
        assert not r.has_any_cfi
        assert r.summary() == "no-cfi-markers"

    def test_llvm_cfi_propagates(self):
        r = CFIReport("/fake")
        r.llvm_cfi.append("__cfi_check")
        assert r.has_llvm_cfi
        assert r.has_any_cfi
        assert "llvm-cfi" in r.summary()

    def test_eh_frame_propagates(self):
        r = CFIReport("/fake")
        r.eh_frame.append(".eh_frame")
        assert r.has_eh_frame
        assert r.has_any_cfi
        assert "basic-cfi" in r.summary()

    def test_intel_cet_ibt_propagates(self):
        r = CFIReport("/fake")
        r.intel_cet_ibt = True
        assert r.has_intel_cet
        assert "intel-cet:ibt" in r.summary()

    def test_intel_cet_shstk_propagates(self):
        r = CFIReport("/fake")
        r.intel_cet_shadow_stack = True
        assert r.has_intel_cet
        assert "intel-cet:shadow-stack" in r.summary()

    def test_error_in_summary(self):
        r = CFIReport("/fake")
        r.error = "File not found"
        assert "failed" in r.summary()


class TestGnuPropertyParser:
    def _make_note(self, feat1_val: int) -> bytes:
        """Build a minimal .note.gnu.property byte blob with GNU_PROPERTY_X86_FEATURE_1_AND."""
        # property: type(4) + datasz(4) + data(4) padded to 8 bytes
        prop_type = _GNU_PROP_X86_FEAT1_TYPE
        prop_datasz = 4
        prop_data = struct.pack("<I", feat1_val)
        # pad to 8-byte boundary
        prop_entry = struct.pack("<II", prop_type, prop_datasz) + prop_data + b"\x00" * 4

        # note header: namesz, descsz, type=5(NT_GNU_PROPERTY_TYPE_0)
        name = b"GNU\x00"
        namesz = len(name)
        descsz = len(prop_entry)
        note_hdr = struct.pack("<III", namesz, descsz, 5)
        return note_hdr + name + prop_entry

    def test_ibt_flag_detected(self):
        data = self._make_note(_FEAT1_IBT)
        r = CFIReport("/fake")
        _parse_gnu_property(data, r)
        assert r.intel_cet_ibt
        assert not r.intel_cet_shadow_stack

    def test_shstk_flag_detected(self):
        data = self._make_note(_FEAT1_SHSTK)
        r = CFIReport("/fake")
        _parse_gnu_property(data, r)
        assert r.intel_cet_shadow_stack
        assert not r.intel_cet_ibt

    def test_both_flags_detected(self):
        data = self._make_note(_FEAT1_IBT | _FEAT1_SHSTK)
        r = CFIReport("/fake")
        _parse_gnu_property(data, r)
        assert r.intel_cet_ibt
        assert r.intel_cet_shadow_stack

    def test_no_flags_sets_nothing(self):
        data = self._make_note(0)
        r = CFIReport("/fake")
        _parse_gnu_property(data, r)
        assert not r.intel_cet_ibt
        assert not r.intel_cet_shadow_stack

    def test_truncated_data_does_not_raise(self):
        r = CFIReport("/fake")
        _parse_gnu_property(b"\x00" * 4, r)  # too short — no crash


class TestCFIManagerMissingFile:
    def test_nonexistent_path_returns_false(self):
        mgr = CFIManager()
        ok, msg = mgr.verify_binary_cfi("/nonexistent/path/binary")
        assert not ok
        assert "not found" in msg.lower() or "failed" in msg.lower()

    def test_non_elf_file_returns_false(self, tmp_path):
        p = tmp_path / "notelf.bin"
        p.write_bytes(b"This is not an ELF binary at all.")
        mgr = CFIManager()
        ok, msg = mgr.verify_binary_cfi(str(p))
        assert not ok

    def test_empty_file_returns_false(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        mgr = CFIManager()
        ok, msg = mgr.verify_binary_cfi(str(p))
        assert not ok


@_RUST_SO_AVAILABLE
class TestCFIManagerRealBinary:
    def test_rust_so_has_eh_frame(self):
        """The release Rust .so has .eh_frame / .eh_frame_hdr (unwind CFI)."""
        mgr = CFIManager()
        report = mgr.audit(str(_RUST_SO))
        assert not report.error, f"Audit error: {report.error}"
        assert report.has_eh_frame, "Expected .eh_frame in Rust binary"

    def test_rust_so_verify_returns_true(self):
        """verify_binary_cfi returns True because eh_frame is present."""
        mgr = CFIManager()
        ok, msg = mgr.verify_binary_cfi(str(_RUST_SO))
        assert ok, f"Expected ok=True, got msg={msg!r}"
        assert "basic-cfi" in msg

    def test_rust_so_no_hardcoded_true(self):
        """A non-existent path must return False — prove we read real content."""
        mgr = CFIManager()
        ok_real, _ = mgr.verify_binary_cfi(str(_RUST_SO))
        ok_fake, _ = mgr.verify_binary_cfi("/nonexistent")
        # Real binary → some CFI; fake path → no CFI
        assert ok_real is True
        assert ok_fake is False

    def test_audit_no_llvm_cfi_on_unoptimised_build(self):
        """Rust debug/release without -Zsanitize=cfi has no __cfi_check."""
        mgr = CFIManager()
        report = mgr.audit(str(_RUST_SO))
        assert not report.has_llvm_cfi, "Unexpected LLVM CFI symbols — build flags may have changed"


class TestRecommendedFlags:
    def test_returns_list_of_strings(self):
        flags = CFIManager.get_recommended_build_flags()
        assert isinstance(flags, list)
        assert all(isinstance(f, str) for f in flags)
        assert any("cfi" in f.lower() or "cf-protection" in f for f in flags)
