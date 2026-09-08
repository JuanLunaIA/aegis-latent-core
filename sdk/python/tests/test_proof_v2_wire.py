# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""v2 wire-form handling in the SDK verifier.

Driven from a committed fixture the *core* implementation issued, never by
importing the core. The SDK is a standalone zero-dependency verifier and its
CI job installs only the SDK, so a test that reaches for ``aegis.core`` does
not fail honestly — it fails with ``ModuleNotFoundError`` and says nothing
about the verifier. The TypeScript suite pins the same artifact for the same
reason.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from aegis_sdk import InclusionProof, verify_inclusion
from aegis_sdk.proof import AegisProofError

_FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "mmr_v2_python_issued.json").read_text()
)


def _proof(index: int = 3) -> dict:
    return copy.deepcopy(_FIXTURE["proofs"][index])


def _differing_digest() -> bytes:
    """A digest whose standard and url-safe base64 forms differ."""
    for seed in range(500):
        candidate = hashlib.sha256(b"seed%d" % seed).digest()
        if base64.b64encode(candidate).decode().rstrip("=") != base64.urlsafe_b64encode(
            candidate
        ).decode().rstrip("="):
            return candidate
    raise AssertionError("no differing digest found")


def test_core_issued_v2_proofs_verify():
    """The baseline: the SDK agrees with the implementation that issued these."""
    for index, leaf in enumerate(_FIXTURE["leaves"]):
        proof = InclusionProof.from_mapping(_FIXTURE["proofs"][index])
        assert proof.version == "aegis-mmr-inclusion-v2"
        assert verify_inclusion(leaf.encode(), proof, _FIXTURE["root"])


def test_sdk_reserialises_v2_to_base64url():
    """A parsed v2 proof must re-serialise to the form it arrived in.

    Emitting the internal hex would yield a document every v2 parser rejects —
    a proof that survives one round trip but not two.
    """
    original = _proof()
    again = InclusionProof.from_mapping(original).to_mapping()
    assert again == original
    assert len(again["root"]) == 43
    assert verify_inclusion(
        _FIXTURE["leaves"][3].encode(), InclusionProof.from_mapping(again), _FIXTURE["root"]
    )


def test_sdk_refuses_standard_base64():
    """``+`` and ``/`` are outside the declared wire alphabet.

    Accepting them would let one document parse here and fail in TypeScript,
    which checks the alphabet by regex.
    """
    document = _proof()
    document["root"] = base64.b64encode(_differing_digest()).decode().rstrip("=")
    with pytest.raises(AegisProofError, match="base64url alphabet"):
        InclusionProof.from_mapping(document)


def test_sdk_refuses_non_canonical_encoding():
    """43 characters carry 258 bits for a 256-bit digest.

    The two spare bits in the final character are free, so distinct strings
    decode to identical bytes. Without a canonicality check a v2 digest would
    be malleable on the wire.
    """
    raw = _differing_digest()
    canonical = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    alternative = next(
        character
        for character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        if character != canonical[-1]
        and base64.urlsafe_b64decode(canonical[:-1] + character + "=") == raw
    )
    document = _proof()
    document["root"] = canonical[:-1] + alternative
    with pytest.raises(AegisProofError, match="canonically encoded"):
        InclusionProof.from_mapping(document)
