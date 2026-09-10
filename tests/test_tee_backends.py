# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Attestation backend behaviour, including that a replay cannot become attestation.

No test here asserts that any quote was verified, because nothing in this
repository can verify one. What is asserted is the shape of the refusals and the
fact that the policy evaluator rejects a replayed document under production
conditions.
"""

from __future__ import annotations

import pytest

from aegis.core.tee_backends import (
    NitroBackend,
    RecordedAttestationBackend,
    SevSnpBackend,
)
from aegis.core.tee_manager import (
    AttestationPolicy,
    AttestationUnavailableError,
    TEEManager,
    VerifiedAttestationClaims,
)

RECORDED_NONCE = b"recorded-nonce-0123"
RECORDED_AT = 1_000.0
REPORT_DATA = b"workload-binding"


def recorded_claims(**changes: object) -> VerifiedAttestationClaims:
    values: dict[str, object] = {
        "tee_type": "SEV-SNP",
        "enclave_id": "guest-1",
        "measurement": "measurement-1",
        "signer_id": "vcek-1",
        "nonce": RECORDED_NONCE,
        "issued_at": RECORDED_AT,
        "debug": False,
        "tcb_status": "OK",
        "report_data": REPORT_DATA,
    }
    values.update(changes)
    return VerifiedAttestationClaims(**values)  # type: ignore[arg-type]


def policy(**changes: object) -> AttestationPolicy:
    values: dict[str, object] = {
        "tee_type": "SEV-SNP",
        "allowed_measurements": frozenset({"measurement-1"}),
        "allowed_signers": frozenset({"vcek-1"}),
        "max_age_seconds": 30.0,
    }
    values.update(changes)
    return AttestationPolicy(**values)  # type: ignore[arg-type]


class TestPlatformBackendsRefuse:
    """Neither platform adapter may ever return claims in this tree."""

    @pytest.mark.parametrize("backend_cls", [NitroBackend, SevSnpBackend])
    def test_absent_device_refuses_and_names_the_device(self, backend_cls, tmp_path) -> None:
        backend = backend_cls(device_path=str(tmp_path / "not-here"))
        assert backend.device_present() is False
        with pytest.raises(AttestationUnavailableError, match="not.*present|not running under"):
            backend.verify(b"evidence", b"0123456789abcdef")

    @pytest.mark.parametrize("backend_cls", [NitroBackend, SevSnpBackend])
    def test_present_device_still_refuses(self, backend_cls, tmp_path) -> None:
        """Device presence is discovery evidence, never attestation.

        This is the failure worth catching: a workload genuinely running on the
        platform, whose device node exists, must not be reported as attested
        merely because the node is there.
        """
        device = tmp_path / "device"
        device.write_bytes(b"")
        backend = backend_cls(device_path=str(device))
        assert backend.device_present() is True
        with pytest.raises(AttestationUnavailableError, match="no .* is integrated"):
            backend.verify(b"evidence", b"0123456789abcdef")

    @pytest.mark.parametrize("backend_cls", [NitroBackend, SevSnpBackend])
    def test_default_device_path_is_the_real_platform_node(self, backend_cls) -> None:
        assert backend_cls().device_path == backend_cls.DEVICE

    def test_platform_backends_are_marked_live_and_recorded_is_not(self) -> None:
        assert NitroBackend.LIVE is True
        assert SevSnpBackend.LIVE is True
        assert RecordedAttestationBackend.LIVE is False

    @pytest.mark.parametrize("backend_cls", [NitroBackend, SevSnpBackend])
    def test_manager_fails_closed_when_backend_refuses(self, backend_cls, tmp_path) -> None:
        """A refusing backend must make verify_evidence return False, not raise."""
        manager = TEEManager(
            "SEV-SNP",
            verifier=backend_cls(device_path=str(tmp_path / "not-here")),
            policy=policy(),
            clock=lambda: RECORDED_AT,
        )
        assert (
            manager.verify_evidence(
                b"vendor-evidence",
                nonce=RECORDED_NONCE,
                expected_report_data=REPORT_DATA,
            )
            is False
        )
        assert manager.attestation_verified is False


class TestRecordedBackendCannotBecomeAttestation:
    """The replay is refused by the freshness check, not by convention."""

    def test_a_fresh_nonce_defeats_the_replay(self) -> None:
        """Production challenges with a fresh nonce; the recorded one is frozen.

        This is the property that makes the recorded backend safe to ship: it
        does not depend on anybody remembering not to configure it.
        """
        manager = TEEManager(
            "SEV-SNP",
            verifier=RecordedAttestationBackend(recorded_claims()),
            policy=policy(),
            clock=lambda: RECORDED_AT,
        )
        assert (
            manager.verify_evidence(
                b"vendor-evidence",
                nonce=b"a-freshly-issued-nonce",
                expected_report_data=REPORT_DATA,
            )
            is False
        )

    def test_a_real_clock_defeats_the_replay(self) -> None:
        """Even replayed against its own nonce, the document ages out."""
        manager = TEEManager(
            "SEV-SNP",
            verifier=RecordedAttestationBackend(recorded_claims()),
            policy=policy(),
            clock=lambda: RECORDED_AT + 10_000.0,
        )
        assert (
            manager.verify_evidence(
                b"vendor-evidence",
                nonce=RECORDED_NONCE,
                expected_report_data=REPORT_DATA,
            )
            is False
        )

    def test_it_passes_only_with_the_recorded_nonce_and_a_pinned_clock(self) -> None:
        """The one shape that works is a test, which is the point.

        Passing here means the policy path executed end to end. It does not mean
        a quote was verified: nothing was authenticated, and the claims came out
        of a fixture.
        """
        backend = RecordedAttestationBackend(recorded_claims())
        manager = TEEManager(
            "SEV-SNP",
            verifier=backend,
            policy=policy(),
            clock=lambda: RECORDED_AT + 1.0,
        )
        assert (
            manager.verify_evidence(
                b"vendor-evidence",
                nonce=RECORDED_NONCE,
                expected_report_data=REPORT_DATA,
            )
            is True
        )
        assert manager.attestation_verified is True
        assert backend.calls == 1

    def test_verified_evidence_still_does_not_make_the_host_protected(self) -> None:
        """No enclave is loaded, so is_protected stays False regardless."""
        manager = TEEManager(
            "SEV-SNP",
            verifier=RecordedAttestationBackend(recorded_claims()),
            policy=policy(),
            clock=lambda: RECORDED_AT + 1.0,
        )
        manager.verify_evidence(
            b"vendor-evidence",
            nonce=RECORDED_NONCE,
            expected_report_data=REPORT_DATA,
        )
        assert manager.is_protected() is False


class TestRecordedBackendMechanics:
    def test_rejects_a_non_claims_argument(self) -> None:
        with pytest.raises(TypeError, match="VerifiedAttestationClaims"):
            RecordedAttestationBackend({"tee_type": "SEV-SNP"})  # type: ignore[arg-type]

    def test_evidence_bytes_are_ignored_entirely(self) -> None:
        backend = RecordedAttestationBackend(recorded_claims())
        assert backend.verify(b"anything", RECORDED_NONCE) == recorded_claims()
        assert backend.verify(b"something else", RECORDED_NONCE) == recorded_claims()

    @pytest.mark.parametrize(
        "changes",
        [
            {"measurement": "unexpected-measurement"},
            {"signer_id": "unexpected-signer"},
            {"tcb_status": "OUT_OF_DATE"},
            {"tee_type": "SGX"},
            {"debug": True},
        ],
        ids=["measurement", "signer", "tcb_status", "tee_type", "debug"],
    )
    def test_bind_nonce_exposes_policy_rejection_without_nonce_masking(
        self, changes: dict[str, object]
    ) -> None:
        """With the nonce check satisfied, each policy field must still reject.

        Without `bind_nonce` every one of these would fail on the nonce instead,
        and the test would pass while proving nothing about the policy field it
        names.
        """
        manager = TEEManager(
            "SEV-SNP",
            verifier=RecordedAttestationBackend(recorded_claims(**changes), bind_nonce=True),
            policy=policy(),
            clock=lambda: RECORDED_AT + 1.0,
        )
        assert (
            manager.verify_evidence(
                b"vendor-evidence",
                nonce=b"a-freshly-issued-nonce",
                expected_report_data=REPORT_DATA,
            )
            is False
        )

    def test_bind_nonce_accepts_an_otherwise_valid_document(self) -> None:
        """The control for the parametrized rejections above."""
        manager = TEEManager(
            "SEV-SNP",
            verifier=RecordedAttestationBackend(recorded_claims(), bind_nonce=True),
            policy=policy(),
            clock=lambda: RECORDED_AT + 1.0,
        )
        assert (
            manager.verify_evidence(
                b"vendor-evidence",
                nonce=b"a-freshly-issued-nonce",
                expected_report_data=REPORT_DATA,
            )
            is True
        )
