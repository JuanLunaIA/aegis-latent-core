# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.zk_proof — ZK-SNARK/STARK proof stubs."""

from __future__ import annotations

import base64

import pytest

from aegis.core.zk_proof import (
    HAS_ZK_NATIVE,
    ProofSystem,
    ZKProofRequest,
    ZKProofResult,
    ZKProver,
    ZKVerificationResult,
    ZKVerifier,
    _derive_proof_bytes,
)

# ── ProofSystem enum ──────────────────────────────────────────────────────────


def test_proof_system_groth16_value():
    assert ProofSystem.GROTH16.value == "groth16"


def test_proof_system_plonk_value():
    assert ProofSystem.PLONK.value == "plonk"


def test_proof_system_stark_value():
    assert ProofSystem.STARK.value == "stark"


def test_proof_system_is_str_subclass():
    assert isinstance(ProofSystem.GROTH16, str)


def test_proof_system_all_members():
    members = {m.value for m in ProofSystem}
    assert members == {"groth16", "plonk", "stark"}


# ── HAS_ZK_NATIVE ─────────────────────────────────────────────────────────────


def test_has_zk_native_is_false():
    assert HAS_ZK_NATIVE is False


# ── ZKProofRequest ────────────────────────────────────────────────────────────


def test_proof_request_fields():
    req = ZKProofRequest(
        proof_system=ProofSystem.GROTH16,
        audit_node_hash="ab" * 32,
        chain_root="cd" * 32,
    )
    assert req.proof_system is ProofSystem.GROTH16
    assert req.audit_node_hash == "ab" * 32
    assert req.chain_root == "cd" * 32
    assert req.include_node_content is False


def test_proof_request_include_node_content():
    req = ZKProofRequest(
        proof_system=ProofSystem.STARK,
        audit_node_hash="aa" * 32,
        chain_root="bb" * 32,
        include_node_content=True,
    )
    assert req.include_node_content is True


def test_proof_request_is_frozen():
    req = ZKProofRequest(
        proof_system=ProofSystem.PLONK,
        audit_node_hash="aa" * 32,
        chain_root="bb" * 32,
    )
    with pytest.raises((AttributeError, TypeError)):
        req.proof_system = ProofSystem.STARK  # type: ignore[misc]


# ── ZKProver.generate_proof ───────────────────────────────────────────────────


@pytest.fixture
def prover() -> ZKProver:
    return ZKProver()


@pytest.fixture
def verifier() -> ZKVerifier:
    return ZKVerifier()


@pytest.fixture
def basic_request() -> ZKProofRequest:
    return ZKProofRequest(
        proof_system=ProofSystem.GROTH16,
        audit_node_hash="a" * 64,
        chain_root="b" * 64,
    )


def test_generate_proof_returns_result(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert isinstance(result, ZKProofResult)


def test_generate_proof_correct_proof_system(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert result.proof_system is ProofSystem.GROTH16


def test_generate_proof_bytes_are_bytes(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert isinstance(result.proof_bytes, bytes)


def test_generate_proof_bytes_are_32_bytes(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert len(result.proof_bytes) == 32  # SHA-256 digest


def test_generate_proof_public_inputs_length(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert len(result.public_inputs) == 3


def test_generate_proof_public_inputs_node_hash(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert result.public_inputs[0] == basic_request.audit_node_hash


def test_generate_proof_public_inputs_chain_root(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert result.public_inputs[1] == basic_request.chain_root


def test_generate_proof_public_inputs_timestamp_is_hex(prover, basic_request):
    result = prover.generate_proof(basic_request)
    ts_hex = result.public_inputs[2]
    assert ts_hex.startswith("0x")
    assert int(ts_hex, 16) > 0


def test_generate_proof_generated_at_is_float(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert isinstance(result.generated_at, float)
    assert result.generated_at > 0.0


def test_generate_proof_vk_hash_format(prover, basic_request):
    result = prover.generate_proof(basic_request)
    assert len(result.verification_key_hash) == 64
    int(result.verification_key_hash, 16)  # must be valid hex


def test_generate_proof_deterministic_same_inputs(prover):
    req = ZKProofRequest(
        proof_system=ProofSystem.PLONK,
        audit_node_hash="dead" * 16,
        chain_root="beef" * 16,
    )
    r1 = prover.generate_proof(req)
    r2 = prover.generate_proof(req)
    assert r1.proof_bytes == r2.proof_bytes


def test_generate_proof_different_node_hash(prover):
    req_a = ZKProofRequest(
        proof_system=ProofSystem.GROTH16,
        audit_node_hash="aa" * 32,
        chain_root="cc" * 32,
    )
    req_b = ZKProofRequest(
        proof_system=ProofSystem.GROTH16,
        audit_node_hash="bb" * 32,
        chain_root="cc" * 32,
    )
    assert prover.generate_proof(req_a).proof_bytes != prover.generate_proof(req_b).proof_bytes


def test_generate_proof_different_chain_root(prover):
    req_a = ZKProofRequest(
        proof_system=ProofSystem.STARK,
        audit_node_hash="aa" * 32,
        chain_root="cc" * 32,
    )
    req_b = ZKProofRequest(
        proof_system=ProofSystem.STARK,
        audit_node_hash="aa" * 32,
        chain_root="dd" * 32,
    )
    assert prover.generate_proof(req_a).proof_bytes != prover.generate_proof(req_b).proof_bytes


def test_generate_proof_different_proof_system(prover):
    req_g = ZKProofRequest(
        proof_system=ProofSystem.GROTH16, audit_node_hash="aa" * 32, chain_root="bb" * 32
    )
    req_s = ZKProofRequest(
        proof_system=ProofSystem.STARK, audit_node_hash="aa" * 32, chain_root="bb" * 32
    )
    assert prover.generate_proof(req_g).proof_bytes != prover.generate_proof(req_s).proof_bytes


def test_prover_is_stub(prover):
    assert prover.is_stub is True


def test_require_real_raises_without_native_backend():
    import pytest

    from aegis.core.zk_proof import HAS_ZK_NATIVE, ZKProofUnavailableError, ZKProver

    # The stub backend must refuse to operate when a caller demands real proofs.
    assert HAS_ZK_NATIVE is False
    with pytest.raises(ZKProofUnavailableError, match="not sound"):
        ZKProver(require_real=True)


def test_default_prover_does_not_require_real():
    from aegis.core.zk_proof import ZKProver

    # Default construction stays usable as an explicit, labelled stub.
    assert ZKProver().is_stub is True


# ── to_dict / to_base64 ───────────────────────────────────────────────────────


def test_to_dict_has_required_keys(prover, basic_request):
    result = prover.generate_proof(basic_request)
    d = result.to_dict()
    assert "proof_bytes_hex" in d
    assert "proof_system" in d
    assert "public_inputs" in d
    assert "verification_key_hash" in d
    assert "generated_at" in d


def test_to_dict_proof_system_is_string(prover, basic_request):
    d = prover.generate_proof(basic_request).to_dict()
    assert d["proof_system"] == "groth16"


def test_to_dict_proof_bytes_hex_roundtrip(prover, basic_request):
    result = prover.generate_proof(basic_request)
    d = result.to_dict()
    assert bytes.fromhex(d["proof_bytes_hex"]) == result.proof_bytes


def test_to_base64_encodes_proof_bytes(prover, basic_request):
    result = prover.generate_proof(basic_request)
    b64 = result.to_base64()
    decoded = base64.b64decode(b64)
    assert decoded == result.proof_bytes


# ── generate_batch_proof ──────────────────────────────────────────────────────


def test_generate_batch_proof_empty(prover):
    assert prover.generate_batch_proof([]) == []


def test_generate_batch_proof_correct_length(prover):
    requests = [
        ZKProofRequest(
            proof_system=ProofSystem.GROTH16, audit_node_hash=f"{i:064x}", chain_root="0" * 64
        )
        for i in range(5)
    ]
    results = prover.generate_batch_proof(requests)
    assert len(results) == 5


def test_generate_batch_proof_order_preserved(prover):
    requests = [
        ZKProofRequest(
            proof_system=ProofSystem.STARK,
            audit_node_hash=f"{i:064x}",
            chain_root="0" * 64,
        )
        for i in range(3)
    ]
    results = prover.generate_batch_proof(requests)
    for req, res in zip(requests, results, strict=True):
        expected = _derive_proof_bytes(req.audit_node_hash, req.chain_root, req.proof_system)
        assert res.proof_bytes == expected


# ── ZKVerifier.verify ─────────────────────────────────────────────────────────


def test_verify_valid_proof(prover, verifier, basic_request):
    result = prover.generate_proof(basic_request)
    vr = verifier.verify(result)
    assert isinstance(vr, ZKVerificationResult)
    assert vr.valid is True


def test_verify_valid_reason(prover, verifier, basic_request):
    result = prover.generate_proof(basic_request)
    vr = verifier.verify(result)
    assert "stub" in vr.reason.lower()


def test_verify_correct_proof_system(prover, verifier, basic_request):
    result = prover.generate_proof(basic_request)
    vr = verifier.verify(result)
    assert vr.proof_system is ProofSystem.GROTH16


def test_verify_tampered_proof_bytes(prover, verifier, basic_request):
    result = prover.generate_proof(basic_request)
    tampered = ZKProofResult(
        proof_bytes=b"\xff" * 32,
        proof_system=result.proof_system,
        public_inputs=result.public_inputs,
        verification_key_hash=result.verification_key_hash,
        generated_at=result.generated_at,
    )
    vr = verifier.verify(tampered)
    assert vr.valid is False


def test_verify_tampered_reason_non_empty(prover, verifier, basic_request):
    result = prover.generate_proof(basic_request)
    tampered = ZKProofResult(
        proof_bytes=b"\x00" * 32,
        proof_system=result.proof_system,
        public_inputs=result.public_inputs,
        verification_key_hash=result.verification_key_hash,
        generated_at=result.generated_at,
    )
    vr = verifier.verify(tampered)
    assert len(vr.reason) > 0


def test_verify_verified_at_is_float(prover, verifier, basic_request):
    result = prover.generate_proof(basic_request)
    vr = verifier.verify(result)
    assert isinstance(vr.verified_at, float)
    assert vr.verified_at > 0.0


def test_verify_result_to_dict(prover, verifier, basic_request):
    result = prover.generate_proof(basic_request)
    vr = verifier.verify(result)
    d = vr.to_dict()
    assert "valid" in d
    assert "proof_system" in d
    assert "verified_at" in d
    assert "reason" in d


def test_verify_batch_length(prover, verifier):
    requests = [
        ZKProofRequest(
            proof_system=ProofSystem.PLONK,
            audit_node_hash=f"{i:064x}",
            chain_root="f" * 64,
        )
        for i in range(4)
    ]
    results = prover.generate_batch_proof(requests)
    vrs = verifier.verify_batch(results)
    assert len(vrs) == 4


def test_verify_batch_all_valid(prover, verifier):
    requests = [
        ZKProofRequest(
            proof_system=ProofSystem.GROTH16,
            audit_node_hash=f"{i:064x}",
            chain_root="e" * 64,
        )
        for i in range(3)
    ]
    results = prover.generate_batch_proof(requests)
    vrs = verifier.verify_batch(results)
    assert all(vr.valid for vr in vrs)


def test_verify_missing_public_inputs(verifier):
    result = ZKProofResult(
        proof_bytes=b"\x00" * 32,
        proof_system=ProofSystem.STARK,
        public_inputs=["only_one"],
        verification_key_hash="a" * 64,
        generated_at=1.0,
    )
    vr = verifier.verify(result)
    assert vr.valid is False
