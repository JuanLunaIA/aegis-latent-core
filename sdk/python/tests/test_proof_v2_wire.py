# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""SDK round-trip + strictness, mirroring the core tests."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from aegis_sdk import InclusionProof, verify_inclusion
from aegis_sdk.proof import AegisProofError

V2 = {
    "version": "aegis-mmr-inclusion-v2",
    "algorithm": "sha256-binary-domain-separated",
}


def _tree():
    from aegis.core.mmr import HASH_SCHEME_V2, MerkleMountainRange

    m = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    payloads = [f"record {i}".encode() for i in range(9)]
    for p in payloads:
        m.add_leaf(p)
    return m, payloads, m.get_root_hash()


def test_sdk_reserialises_v2_to_base64url():
    m, payloads, root = _tree()
    wire = json.loads(json.dumps(m.get_portable_inclusion_proof(3).to_dict()))
    again = InclusionProof.from_mapping(wire).to_mapping()
    assert again == wire
    assert len(again["root"]) == 43
    assert verify_inclusion(payloads[3], InclusionProof.from_mapping(again), root)


def _differing():
    for i in range(500):
        c = hashlib.sha256(b"seed%d" % i).digest()
        if base64.b64encode(c).decode().rstrip("=") != base64.urlsafe_b64encode(c).decode().rstrip(
            "="
        ):
            return c
    raise AssertionError


def test_sdk_refuses_standard_base64():
    m, _, _ = _tree()
    wire = json.loads(json.dumps(m.get_portable_inclusion_proof(3).to_dict()))
    wire["root"] = base64.b64encode(_differing()).decode().rstrip("=")
    with pytest.raises(AegisProofError, match="base64url alphabet"):
        InclusionProof.from_mapping(wire)


def test_sdk_refuses_non_canonical_encoding():
    raw = _differing()
    canon = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    alt = next(
        c
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        if c != canon[-1] and base64.urlsafe_b64decode(canon[:-1] + c + "=") == raw
    )
    m, _, _ = _tree()
    wire = json.loads(json.dumps(m.get_portable_inclusion_proof(3).to_dict()))
    wire["root"] = canon[:-1] + alt
    with pytest.raises(AegisProofError, match="canonically encoded"):
        InclusionProof.from_mapping(wire)
