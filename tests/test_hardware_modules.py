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
from aegis.core.tee_manager import (
    AttestationPolicy,
    AttestationReport,
    AttestationUnavailableError,
    TEEManager,
    VerifiedAttestationClaims,
)


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
    _NONCE = b"0123456789abcdef"
    _REPORT_DATA = b"workload-binding"

    class _Verifier:
        def __init__(self, claims: VerifiedAttestationClaims | Exception) -> None:
            self.claims = claims
            self.calls = 0

        def verify(self, evidence: bytes, nonce: bytes) -> VerifiedAttestationClaims:
            assert evidence == b"vendor-evidence"
            assert nonce == TestTEEManager._NONCE
            self.calls += 1
            if isinstance(self.claims, Exception):
                raise self.claims
            return self.claims

    @classmethod
    def _claims(cls, **changes: object) -> VerifiedAttestationClaims:
        values: dict[str, object] = {
            "tee_type": "SGX",
            "enclave_id": "enclave-1",
            "measurement": "mrenclave-1",
            "signer_id": "mrsigner-1",
            "nonce": cls._NONCE,
            "issued_at": 95.0,
            "debug": False,
            "tcb_status": "OK",
            "report_data": cls._REPORT_DATA,
        }
        values.update(changes)
        return VerifiedAttestationClaims(**values)  # type: ignore[arg-type]

    @staticmethod
    def _policy() -> AttestationPolicy:
        return AttestationPolicy(
            tee_type="SGX",
            allowed_measurements=frozenset({"mrenclave-1"}),
            allowed_signers=frozenset({"mrsigner-1"}),
            max_age_seconds=10.0,
        )

    def test_not_active_by_default(self):
        mgr = TEEManager()
        assert mgr._is_enclave_active is False

    def test_initialize_returns_false_when_no_device(self):
        mgr = TEEManager()
        with patch("aegis.core.tee_manager.os.path.exists", return_value=False):
            result = mgr.initialize_enclave()
        assert result is False

    def test_device_presence_is_discovery_only(self):
        mgr = TEEManager()

        def fake_exists(path):
            return path == "/dev/sgx_enclave"

        with patch("aegis.core.tee_manager.os.path.exists", side_effect=fake_exists):
            result = mgr.initialize_enclave()
        assert result is False
        assert mgr._is_enclave_active is False
        assert mgr.device_path == "/dev/sgx_enclave"

    def test_generate_quote_is_unavailable(self):
        mgr = TEEManager()
        with pytest.raises(AttestationUnavailableError, match="unavailable"):
            mgr.generate_attestation_quote()

    def test_device_presence_does_not_enable_quote_generation(self):
        mgr = TEEManager()
        with patch("aegis.core.tee_manager.os.path.exists", return_value=True):
            mgr.initialize_enclave()
        with pytest.raises(AttestationUnavailableError):
            mgr.generate_attestation_quote()

    def test_legacy_caller_controlled_report_is_always_rejected(self):
        mgr = TEEManager()
        report = AttestationReport(
            enclave_id="x",
            measurement="abc123",
            signer_id="def456",
            is_genuine=True,
            timestamp=0.0,
        )
        assert mgr.verify_remote_attestation(report) is False

    def test_authenticated_claims_must_match_exact_policy(self):
        verifier = self._Verifier(self._claims())
        mgr = TEEManager(
            verifier=verifier,
            policy=self._policy(),
            clock=lambda: 100.0,
        )
        assert mgr.verify_evidence(
            b"vendor-evidence",
            nonce=self._NONCE,
            expected_report_data=self._REPORT_DATA,
        )
        assert mgr.attestation_verified is True
        assert mgr.is_protected() is False
        assert verifier.calls == 1

    @pytest.mark.parametrize(
        "changes",
        [
            {"measurement": "wrong"},
            {"signer_id": "wrong"},
            {"nonce": b"fedcba9876543210"},
            {"issued_at": 80.0},
            {"issued_at": 101.0},
            {"debug": True},
            {"tcb_status": "REVOKED"},
            {"report_data": b"wrong-binding"},
        ],
    )
    def test_policy_mismatch_fails_closed(self, changes: dict[str, object]) -> None:
        mgr = TEEManager(
            verifier=self._Verifier(self._claims(**changes)),
            policy=self._policy(),
            clock=lambda: 100.0,
        )
        assert not mgr.verify_evidence(
            b"vendor-evidence",
            nonce=self._NONCE,
            expected_report_data=self._REPORT_DATA,
        )
        assert mgr.attestation_verified is False

    def test_backend_error_clears_previous_verified_state(self) -> None:
        verifier = self._Verifier(self._claims())
        mgr = TEEManager(verifier=verifier, policy=self._policy(), clock=lambda: 100.0)
        assert mgr.verify_evidence(
            b"vendor-evidence",
            nonce=self._NONCE,
            expected_report_data=self._REPORT_DATA,
        )
        verifier.claims = RuntimeError("rejected")
        assert not mgr.verify_evidence(
            b"vendor-evidence",
            nonce=self._NONCE,
            expected_report_data=self._REPORT_DATA,
        )
        assert mgr.attestation_verified is False

    @pytest.mark.parametrize(
        "changes",
        [
            {"issued_at": "95"},
            {"issued_at": True},
            {"measurement": 42},
            {"measurement": "x" * 4097},
            {"nonce": "0123456789abcdef"},
            {"nonce": b"short"},
            {"report_data": "binding"},
            {"report_data": b""},
            {"debug": "false"},
        ],
    )
    def test_malformed_normalized_claim_types_fail_closed(self, changes: dict[str, object]) -> None:
        mgr = TEEManager(
            verifier=self._Verifier(self._claims(**changes)),
            policy=self._policy(),
            clock=lambda: 100.0,
        )
        assert not mgr.verify_evidence(
            b"vendor-evidence",
            nonce=self._NONCE,
            expected_report_data=self._REPORT_DATA,
        )

    @pytest.mark.parametrize("clock_value", ["100", True, float("nan"), float("inf")])
    def test_malformed_clock_value_fails_closed(self, clock_value: object) -> None:
        mgr = TEEManager(
            verifier=self._Verifier(self._claims()),
            policy=self._policy(),
            clock=lambda: clock_value,  # type: ignore[return-value]
        )
        assert not mgr.verify_evidence(
            b"vendor-evidence",
            nonce=self._NONCE,
            expected_report_data=self._REPORT_DATA,
        )

    def test_clock_exception_fails_closed(self) -> None:
        def broken_clock() -> float:
            raise RuntimeError("clock unavailable")

        mgr = TEEManager(
            verifier=self._Verifier(self._claims()),
            policy=self._policy(),
            clock=broken_clock,
        )
        assert not mgr.verify_evidence(
            b"vendor-evidence",
            nonce=self._NONCE,
            expected_report_data=self._REPORT_DATA,
        )

    def test_missing_backend_raises_unavailable(self) -> None:
        with pytest.raises(AttestationUnavailableError, match="must both be configured"):
            TEEManager().verify_evidence(
                b"vendor-evidence",
                nonce=self._NONCE,
                expected_report_data=self._REPORT_DATA,
            )

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
