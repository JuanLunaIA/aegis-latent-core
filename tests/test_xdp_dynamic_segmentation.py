# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.xdp_dynamic_segmentation — real firewall enforcement.

Verifies the firewall backend detection, IP validation, block/unblock
idempotency, zone management, and the application-layer fallback path when
kernel tools are unavailable.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.xdp_dynamic_segmentation import (
    XDPDynamicSegmenter,
    _FirewallBackend,
    _validate_ip,
)

# ── _validate_ip ─────────────────────────────────────────────────────────────


class TestValidateIp:
    def test_valid_ipv4(self):
        assert _validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert _validate_ip("::1") == "::1"

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            _validate_ip("not-an-ip")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            _validate_ip("")


# ── _FirewallBackend detection ────────────────────────────────────────────────


class TestFirewallBackendDetection:
    def test_detects_nftables_when_available(self):
        with patch("shutil.which", side_effect=lambda x: "/usr/sbin/nft" if x == "nft" else None):
            with patch("subprocess.run", return_value=MagicMock(returncode=0)):
                backend = _FirewallBackend()
        assert backend.backend_name == _FirewallBackend.NFTABLES

    def test_falls_back_to_iptables_when_nft_absent(self):
        def which_no_nft(x):
            return "/usr/sbin/iptables" if x == "iptables" else None

        with patch("shutil.which", side_effect=which_no_nft):
            with patch("subprocess.run", return_value=MagicMock(returncode=0)):
                backend = _FirewallBackend()
        assert backend.backend_name == _FirewallBackend.IPTABLES

    def test_falls_back_to_none_when_both_absent(self):
        with patch("shutil.which", return_value=None):
            backend = _FirewallBackend()
        assert backend.backend_name == _FirewallBackend.NONE

    def test_none_backend_block_returns_false(self):
        with patch("shutil.which", return_value=None):
            backend = _FirewallBackend()
        assert backend.block("1.2.3.4") is False

    def test_none_backend_unblock_returns_false(self):
        with patch("shutil.which", return_value=None):
            backend = _FirewallBackend()
        assert backend.unblock("1.2.3.4") is False


# ── XDPDynamicSegmenter (application-layer fallback) ─────────────────────────


def _segmenter_no_kernel() -> XDPDynamicSegmenter:
    """Return a segmenter backed by the 'none' backend (no kernel tools)."""
    with patch("shutil.which", return_value=None):
        return XDPDynamicSegmenter()


class TestSegmenterNoKernel:
    def test_backend_is_none(self):
        seg = _segmenter_no_kernel()
        assert seg.backend == _FirewallBackend.NONE

    def test_block_ip_immediately_adds_to_blocklist(self):
        seg = _segmenter_no_kernel()
        seg.block_ip_immediately("10.0.0.1")
        assert "10.0.0.1" in seg.get_blocked_ips()

    def test_block_ip_returns_false_without_kernel(self):
        seg = _segmenter_no_kernel()
        result = seg.block_ip_immediately("10.0.0.1")
        assert result is False  # application-layer only

    def test_block_invalid_ip_returns_false(self):
        seg = _segmenter_no_kernel()
        result = seg.block_ip_immediately("not-an-ip")
        assert result is False
        assert "not-an-ip" not in seg.get_blocked_ips()

    def test_unblock_removes_from_blocklist(self):
        seg = _segmenter_no_kernel()
        seg.block_ip_immediately("10.0.0.2")
        seg.unblock_ip("10.0.0.2")
        assert "10.0.0.2" not in seg.get_blocked_ips()

    def test_block_is_idempotent(self):
        seg = _segmenter_no_kernel()
        seg.block_ip_immediately("10.0.0.3")
        seg.block_ip_immediately("10.0.0.3")
        assert seg.get_blocked_ips().count if False else len(seg.get_blocked_ips()) == 1

    def test_teardown_clears_blocklist(self):
        seg = _segmenter_no_kernel()
        seg.block_ip_immediately("10.0.0.4")
        seg.teardown()
        assert not seg.get_blocked_ips()

    def test_define_zone_validates_ips(self):
        seg = _segmenter_no_kernel()
        with pytest.raises(ValueError):
            seg.define_zone("bad", ["not-an-ip"])

    def test_define_zone_and_query_segmentation(self):
        seg = _segmenter_no_kernel()
        seg.define_zone("trusted", ["192.168.1.1", "192.168.1.2"])
        result = seg.get_current_segmentation()
        assert "trusted" in result
        assert result["trusted"] == "ACTIVE"

    def test_shift_zone_to_blackhole_blocks_all_zone_ips(self):
        seg = _segmenter_no_kernel()
        seg.define_zone("hostile", ["10.1.0.1", "10.1.0.2"])
        seg.shift_zone_status("hostile", "BLACKHOLE")
        blocked = seg.get_blocked_ips()
        assert "10.1.0.1" in blocked
        assert "10.1.0.2" in blocked
        assert seg.get_current_segmentation()["hostile"] == "BLACKHOLE"

    def test_shift_zone_to_active_unblocks_ips(self):
        seg = _segmenter_no_kernel()
        seg.define_zone("zone", ["10.2.0.1"])
        seg.shift_zone_status("zone", "BLACKHOLE")
        seg.shift_zone_status("zone", "ACTIVE")
        assert "10.2.0.1" not in seg.get_blocked_ips()

    def test_shift_unknown_zone_is_noop(self):
        seg = _segmenter_no_kernel()
        seg.shift_zone_status("nonexistent", "BLACKHOLE")  # must not raise

    def test_get_blocked_ips_returns_frozenset(self):
        seg = _segmenter_no_kernel()
        result = seg.get_blocked_ips()
        assert isinstance(result, frozenset)


# ── XDPDynamicSegmenter with mocked nftables backend ─────────────────────────


class TestSegmenterNftBackend:
    def _make_segmenter(self):
        """Build a segmenter with nft mocked to succeed."""
        with (
            patch("shutil.which", side_effect=lambda x: f"/usr/sbin/{x}" if x == "nft" else None),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            return XDPDynamicSegmenter()

    def test_backend_is_nftables(self):
        seg = self._make_segmenter()
        assert seg.backend == _FirewallBackend.NFTABLES

    def test_block_ip_calls_nft_add_element(self):
        seg = self._make_segmenter()
        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
            ok = seg.block_ip_immediately("5.6.7.8")
        assert ok is True
        # Verify nft was called with 'add element'
        calls_str = " ".join(str(c) for c in mock_run.call_args_list)
        assert "add" in calls_str
        assert "5.6.7.8" in calls_str

    def test_unblock_ip_calls_nft_delete_element(self):
        seg = self._make_segmenter()
        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
            seg.block_ip_immediately("5.6.7.8")
            seg.unblock_ip("5.6.7.8")
        calls_str = " ".join(str(c) for c in mock_run.call_args_list)
        assert "delete" in calls_str

    def test_block_idempotent_no_duplicate_kernel_call(self):
        seg = self._make_segmenter()
        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
            seg.block_ip_immediately("1.2.3.4")
            first_call_count = mock_run.call_count
            seg.block_ip_immediately("1.2.3.4")  # second call — idempotent
        assert mock_run.call_count == first_call_count  # no extra kernel call

    def test_kernel_failure_returns_false(self):
        seg = self._make_segmenter()
        with patch("subprocess.run", side_effect=subprocess.SubprocessError):
            ok = seg.block_ip_immediately("9.9.9.9")
        assert ok is False
        # Still tracked in-process
        assert "9.9.9.9" in seg.get_blocked_ips()
