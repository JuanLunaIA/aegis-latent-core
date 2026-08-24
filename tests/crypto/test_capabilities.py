# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Focused honesty-contract tests for :mod:`aegis.crypto`."""

from __future__ import annotations

import importlib

import aegis.crypto as crypto
from aegis.core.mmr import MerkleMountainRange, MMRInclusionProofV1
from aegis.core.pqc_signer import PQCSigner
from aegis.core.zk_proof import ZKProver
from aegis.crypto.capabilities import capability_report, collect_capabilities


def _capabilities_by_name() -> dict[str, crypto.CryptoCapability]:
    return {capability.name: capability for capability in collect_capabilities()}


def test_facade_reexports_existing_types_without_wrapping() -> None:
    assert crypto.MerkleMountainRange is MerkleMountainRange
    assert crypto.MMRInclusionProofV1 is MMRInclusionProofV1
    assert crypto.PQCSigner is PQCSigner
    assert crypto.ZKProver is ZKProver


def test_report_distinguishes_all_required_statuses() -> None:
    statuses = {capability.status for capability in collect_capabilities()}
    assert statuses == {
        "implemented",
        "optional-runtime",
        "stub",
        "external-validation-required",
    }


def test_mmr_is_implemented_with_logarithmic_proof_complexity() -> None:
    mmr = _capabilities_by_name()["mmr_sha256"]
    assert mmr.status == "implemented"
    assert mmr.available is True
    assert mmr.real is True
    assert mmr.proof_complexity == "O(log n)"


def test_pqc_availability_matches_owning_runtime_modules() -> None:
    capabilities = _capabilities_by_name()
    signer = capabilities["ml_dsa_65_signing"]
    ml_kem = capabilities["ml_kem_1024_session_bootstrap"]

    from aegis.core.mlkem_session import HAS_MLKEM
    from aegis.core.pqc_signer import backend_available

    assert signer.status == "optional-runtime"
    assert signer.available is backend_available()
    assert signer.real is signer.available
    assert ml_kem.status == "optional-runtime"
    assert ml_kem.available is HAS_MLKEM
    assert ml_kem.real is ml_kem.available


def test_zk_is_explicitly_non_real_stub() -> None:
    zk = _capabilities_by_name()["zk_audit_proofs"]
    assert zk.status == "stub"
    assert zk.available is True
    assert zk.real is False
    assert "no zero-knowledge" in zk.detail


def test_no_fips_validation_is_claimed() -> None:
    capabilities = collect_capabilities()
    validation = _capabilities_by_name()["fips_module_validation"]

    assert all(capability.fips_validated is False for capability in capabilities)
    assert validation.status == "external-validation-required"
    assert validation.available is False
    assert validation.real is False
    assert validation.external_validation_required is True
    assert "No FIPS" in validation.detail


def test_serialized_report_is_json_compatible_and_stably_ordered() -> None:
    report = capability_report()
    assert isinstance(report, tuple)
    assert [record["name"] for record in report] == [
        "mmr_sha256",
        "ml_dsa_65_signing",
        "ml_kem_1024_session_bootstrap",
        "zk_audit_proofs",
        "fips_module_validation",
    ]
    assert report[0]["proof_complexity"] == "O(log n)"
    assert report[3]["real"] is False


def test_every_capability_module_locator_is_importable() -> None:
    for capability in collect_capabilities():
        assert importlib.import_module(capability.module) is not None
