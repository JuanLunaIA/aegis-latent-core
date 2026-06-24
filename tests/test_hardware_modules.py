# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for hardware-gated modules: ebpf_monitor, enclave_provider, tee_manager, dpdk_engine."""

from __future__ import annotations

from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.dpdk_engine import DPKPEngine
from aegis.core.ebpf_monitor import EBPFProbe, IntegrityMonitor
from aegis.core.enclave_provider import EnclavePQCProvider
from aegis.core.tee_manager import AttestationReport, TEEManager


def _make_cp(returncode: int) -> CompletedProcess:
    cp = MagicMock(spec=CompletedProcess)
    cp.returncode = returncode
    return cp


# ─── EBPFProbe ────────────────────────────────────────────────────────────────


class TestEBPFProbeLoad:
    def test_inactive_by_default(self):
        p = EBPFProbe("test", "read")
        assert p._active is False

    def test_returns_false_when_bpftool_absent(self):
        p = EBPFProbe("test", "read")
        with patch("aegis.core.ebpf_monitor.shutil.which", return_value=None):
            result = p.load()
        assert result is False
        assert p._active is False

    def test_returns_false_when_bpftool_prog_list_fails(self):
        p = EBPFProbe("test", "read")
        with (
            patch("aegis.core.ebpf_monitor.shutil.which", return_value="/usr/sbin/bpftool"),
            patch("aegis.core.ebpf_monitor.subprocess.run", return_value=_make_cp(1)),
        ):
            result = p.load()
        assert result is False
        assert p._active is False

    def test_returns_true_when_bpftool_succeeds(self):
        p = EBPFProbe("test", "read")
        with (
            patch("aegis.core.ebpf_monitor.shutil.which", return_value="/usr/sbin/bpftool"),
            patch("aegis.core.ebpf_monitor.subprocess.run", return_value=_make_cp(0)),
        ):
            result = p.load()
        assert result is True
        assert p._active is True


class TestEBPFProbePollEvents:
    def test_inactive_probe_returns_empty(self):
        p = EBPFProbe("test", "read")
        assert p.poll_events() == []

    def test_active_probe_returns_empty_without_bpf_programs(self):
        p = EBPFProbe("test", "read")
        with (
            patch("aegis.core.ebpf_monitor.shutil.which", return_value="/usr/sbin/bpftool"),
            patch("aegis.core.ebpf_monitor.subprocess.run", return_value=_make_cp(0)),
        ):
            p.load()
        events = p.poll_events()
        assert events == []

    def test_no_random_events_generated(self):
        p = EBPFProbe("test", "read")
        for _ in range(20):
            assert p.poll_events() == []


class TestIntegrityMonitor:
    def test_has_six_probes(self):
        monitor = IntegrityMonitor()
        assert len(monitor.probes) == 6

    def test_default_latency_threshold(self):
        monitor = IntegrityMonitor()
        assert monitor.latency_threshold_us == 1000.0


# ─── EnclavePQCProvider ──────────────────────────────────────────────────────


class TestEnclavePQCProvider:
    def test_not_initialized_by_default(self):
        provider = EnclavePQCProvider()
        assert provider._is_initialized is False

    def test_initialize_returns_false_when_no_device(self):
        provider = EnclavePQCProvider()
        with patch("aegis.core.enclave_provider.os.path.exists", return_value=False):
            result = provider.initialize_enclave()
        assert result is False
        assert provider._is_initialized is False

    def test_initialize_returns_true_when_device_found(self):
        provider = EnclavePQCProvider()

        def fake_exists(path):
            return path == "/dev/sgx_enclave"

        with patch("aegis.core.enclave_provider.os.path.exists", side_effect=fake_exists):
            result = provider.initialize_enclave()
        assert result is True
        assert provider._is_initialized is True

    def test_sign_raises_when_not_initialized(self):
        provider = EnclavePQCProvider()
        with pytest.raises(RuntimeError, match="not initialized"):
            provider.sign_in_enclave(b"data", 0)

    def test_sign_raises_not_implemented_when_initialized(self):
        provider = EnclavePQCProvider()
        with patch("aegis.core.enclave_provider.os.path.exists", return_value=True):
            provider.initialize_enclave()
        with pytest.raises(NotImplementedError):
            provider.sign_in_enclave(b"data", 0)

    def test_attestation_raises_when_not_initialized(self):
        provider = EnclavePQCProvider()
        with pytest.raises(RuntimeError, match="not initialized"):
            provider.get_attestation_quote()

    def test_attestation_raises_not_implemented_when_initialized(self):
        provider = EnclavePQCProvider()
        with patch("aegis.core.enclave_provider.os.path.exists", return_value=True):
            provider.initialize_enclave()
        with pytest.raises(NotImplementedError):
            provider.get_attestation_quote()

    def test_no_fake_salt_signature_generated(self):
        """Confirm ENCLAVE_SECRET_SALT pattern is not present in the module."""
        import inspect

        import aegis.core.enclave_provider as mod

        source = inspect.getsource(mod)
        assert "ENCLAVE_SECRET_SALT" not in source


# ─── TEEManager ──────────────────────────────────────────────────────────────


class TestTEEManager:
    def test_not_active_by_default(self):
        mgr = TEEManager()
        assert mgr._is_enclave_active is False

    def test_initialize_returns_false_when_no_device(self):
        mgr = TEEManager()
        with patch("aegis.core.tee_manager.os.path.exists", return_value=False):
            result = mgr.initialize_enclave()
        assert result is False

    def test_initialize_returns_true_when_device_found(self):
        mgr = TEEManager()

        def fake_exists(path):
            return path == "/dev/sgx_enclave"

        with patch("aegis.core.tee_manager.os.path.exists", side_effect=fake_exists):
            result = mgr.initialize_enclave()
        assert result is True
        assert mgr._is_enclave_active is True

    def test_generate_quote_raises_when_inactive(self):
        mgr = TEEManager()
        with pytest.raises(RuntimeError, match="not active"):
            mgr.generate_attestation_quote()

    def test_generate_quote_raises_not_implemented_when_active(self):
        mgr = TEEManager()
        with patch("aegis.core.tee_manager.os.path.exists", return_value=True):
            mgr.initialize_enclave()
        with pytest.raises(NotImplementedError):
            mgr.generate_attestation_quote()

    def test_verify_remote_attestation_genuine_passes(self):
        mgr = TEEManager()
        report = AttestationReport(
            enclave_id="x",
            measurement="abc123",
            signer_id="def456",
            is_genuine=True,
            timestamp=0.0,
        )
        assert mgr.verify_remote_attestation(report) is True

    def test_verify_remote_attestation_not_genuine_fails(self):
        mgr = TEEManager()
        report = AttestationReport(
            enclave_id="x",
            measurement="abc123",
            signer_id="def456",
            is_genuine=False,
            timestamp=0.0,
        )
        assert mgr.verify_remote_attestation(report) is False

    def test_verify_remote_attestation_empty_measurement_fails(self):
        mgr = TEEManager()
        report = AttestationReport(
            enclave_id="x",
            measurement="",
            signer_id="def456",
            is_genuine=True,
            timestamp=0.0,
        )
        assert mgr.verify_remote_attestation(report) is False

    def test_no_hardcoded_measurement_in_source(self):
        import inspect

        import aegis.core.tee_manager as mod

        source = inspect.getsource(mod)
        assert "a8f7e6d5c4b3a2f1" not in source


# ─── DPKPEngine ──────────────────────────────────────────────────────────────


class TestDPKPEngine:
    def test_not_initialized_by_default(self):
        engine = DPKPEngine()
        assert engine._is_initialized is False
        assert engine._hugepages_configured is False

    def test_setup_hugepages_returns_false_when_sysfs_absent(self, tmp_path):
        engine = DPKPEngine()
        with patch("aegis.core.dpdk_engine.Path") as MockPath:
            MockPath.return_value.exists.return_value = False
            result = engine.setup_hugepages()
        assert result is False

    def test_setup_hugepages_returns_false_when_count_zero(self, tmp_path):
        engine = DPKPEngine()
        hp_file = tmp_path / "nr_hugepages"
        hp_file.write_text("0\n")

        def mock_path(p):
            if "hugepages" in str(p):
                return hp_file
            from pathlib import Path

            return Path(p)

        original_path = __import__("pathlib").Path
        with patch(
            "aegis.core.dpdk_engine.Path",
            side_effect=lambda p: hp_file if "hugepages" in str(p) else original_path(p),
        ):
            result = engine.setup_hugepages()
        assert result is False

    def test_bind_interfaces_fails_when_hugepages_not_configured(self):
        engine = DPKPEngine()
        assert engine.bind_interfaces() is False

    def test_bind_interfaces_fails_when_devbind_absent(self):
        engine = DPKPEngine()
        engine._hugepages_configured = True
        with patch("aegis.core.dpdk_engine.shutil.which", return_value=None):
            result = engine.bind_interfaces()
        assert result is False

    def test_bind_interfaces_succeeds_when_devbind_found(self):
        engine = DPKPEngine()
        engine._hugepages_configured = True
        with patch("aegis.core.dpdk_engine.shutil.which", return_value="/usr/bin/dpdk-devbind"):
            result = engine.bind_interfaces()
        assert result is True
        assert engine._is_initialized is True

    def test_poll_packets_raises_when_not_initialized(self):
        engine = DPKPEngine()
        with pytest.raises(RuntimeError, match="not initialized"):
            engine.poll_packets()

    def test_poll_packets_returns_empty_not_fake(self):
        engine = DPKPEngine()
        engine._is_initialized = True
        packets = engine.poll_packets(batch_size=32)
        assert packets == []

    def test_transmit_packet_returns_false_when_not_initialized(self):
        engine = DPKPEngine()
        assert engine.transmit_packet(b"data") is False

    def test_transmit_packet_returns_false_even_when_initialized(self):
        engine = DPKPEngine()
        engine._is_initialized = True
        assert engine.transmit_packet(b"data") is False

    def test_is_active_reflects_initialized(self):
        engine = DPKPEngine()
        assert engine.is_active() is False
        engine._is_initialized = True
        assert engine.is_active() is True
