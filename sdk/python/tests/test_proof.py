# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from aegis_sdk.proof import (
    AegisProofError,
    InclusionProof,
    canonical_proof_json,
    verify_inclusion,
    verify_proof_headers,
)

VECTORS = Path(__file__).parents[2] / "shared" / "mmr-inclusion-v1.json"


def _vectors() -> dict[str, Any]:
    value = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_every_shared_vector_verifies() -> None:
    for case in _vectors()["cases"]:
        root = case["root"]
        for leaf_hex, raw_proof in zip(case["leaves_hex"], case["proofs"], strict=True):
            proof = InclusionProof.from_mapping(raw_proof)
            leaf = bytes.fromhex(leaf_hex)
            assert verify_inclusion(leaf, proof, root)
            assert InclusionProof.from_mapping(json.loads(canonical_proof_json(proof))) == proof


def test_tampering_fails_closed() -> None:
    case = _vectors()["cases"][4]
    leaf = bytes.fromhex(case["leaves_hex"][2])
    proof = InclusionProof.from_mapping(case["proofs"][2])
    assert not verify_inclusion(b"tampered", proof, case["root"])
    assert not verify_inclusion(leaf, replace(proof, leaf_index=3), case["root"])
    assert not verify_inclusion(leaf, proof, "0" * 64)


def test_response_headers_decode_and_verify() -> None:
    case = _vectors()["cases"][2]
    leaf = bytes.fromhex(case["leaves_hex"][2])
    proof = InclusionProof.from_mapping(case["proofs"][2])
    headers = {
        "X-Aegis-MMR-Leaf": hashlib.sha256(leaf).hexdigest(),
        "X-Aegis-MMR-Proof": base64.urlsafe_b64encode(canonical_proof_json(proof))
        .decode()
        .rstrip("="),
        "X-Aegis-MMR-Root": case["root"],
    }
    assert verify_proof_headers(headers, case["root"]) == proof
    with pytest.raises(AegisProofError, match="trusted root"):
        verify_proof_headers(headers, "0" * 64)


def test_schema_rejects_unknown_fields() -> None:
    case = _vectors()["cases"][0]
    proof = dict(case["proofs"][0])
    proof["extra"] = True
    with pytest.raises(AegisProofError, match="fields"):
        InclusionProof.from_mapping(proof)
