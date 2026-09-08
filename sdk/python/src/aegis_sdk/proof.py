# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Stateless verification of Aegis MMR inclusion proof headers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class AegisProofError(ValueError):
    """A proof is missing, malformed, or cryptographically inconsistent."""


@dataclass(frozen=True)
class ProofStep:
    sibling_hash: str
    direction: str


MMR_PROOF_VERSION_V1 = "aegis-mmr-inclusion-v1"
MMR_PROOF_VERSION_V2 = "aegis-mmr-inclusion-v2"
MMR_ALGORITHM_V1 = "sha256-asciihex"
MMR_ALGORITHM_V2 = "sha256-binary-domain-separated"

_DOMAIN_LEAF = b"\x00"
_DOMAIN_NODE = b"\x01"
_DOMAIN_ROOT = b"\x02"


def _v2_leaf_hash(payload: bytes) -> str:
    """``SHA-256(0x00 || payload)`` as lowercase hex."""
    return hashlib.sha256(_DOMAIN_LEAF + payload).hexdigest()


def _v2_node_hash(left: str, right: str) -> str:
    """``SHA-256(0x01 || left || right)`` over the raw 32-byte digests."""
    return hashlib.sha256(_DOMAIN_NODE + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _v2_bagged_root(peak_hashes: list[str]) -> str:
    """``SHA-256(0x02 || peak_1 || ... || peak_k)`` over raw 32-byte digests."""
    return hashlib.sha256(
        _DOMAIN_ROOT + b"".join(bytes.fromhex(value) for value in peak_hashes)
    ).hexdigest()


def _b64u_to_hex(value: str) -> str:
    """Decode a v2 wire digest (43-char unpadded base64url) to lowercase hex."""
    if len(value) != 43:
        raise AegisProofError("v2 proof digests must be 43-character unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error) as exc:
        raise AegisProofError("v2 proof digest is not valid base64url") from exc
    if len(raw) != 32:
        raise AegisProofError("v2 proof digests must decode to 32 bytes")
    return raw.hex()


@dataclass(frozen=True)
class Peak:
    height: int
    hash: str


@dataclass(frozen=True)
class InclusionProof:
    version: str
    algorithm: str
    leaf_index: int
    leaf_count: int
    peak_index: int
    path: tuple[ProofStep, ...]
    peaks: tuple[Peak, ...]
    root: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> InclusionProof:
        required = {
            "version",
            "algorithm",
            "leaf_index",
            "leaf_count",
            "peak_index",
            "path",
            "peaks",
            "root",
        }
        if set(value) != required:
            raise AegisProofError("proof fields do not match the aegis-mmr-inclusion schema")
        try:
            path_raw = value["path"]
            peaks_raw = value["peaks"]
            if not isinstance(path_raw, list) or not isinstance(peaks_raw, list):
                raise TypeError("path and peaks must be arrays")
            decode = (
                _b64u_to_hex
                if _require_string(value, "version") == MMR_PROOF_VERSION_V2
                else (lambda digest: digest)
            )
            path = tuple(
                ProofStep(
                    sibling_hash=decode(_require_string(item, "sibling_hash")),
                    direction=_require_string(item, "direction"),
                )
                for item in path_raw
            )
            peaks = tuple(
                Peak(
                    height=_require_int(item, "height"),
                    hash=decode(_require_string(item, "hash")),
                )
                for item in peaks_raw
            )
            return cls(
                version=_require_string(value, "version"),
                algorithm=_require_string(value, "algorithm"),
                leaf_index=_require_int(value, "leaf_index"),
                leaf_count=_require_int(value, "leaf_count"),
                peak_index=_require_int(value, "peak_index"),
                path=path,
                peaks=peaks,
                root=decode(_require_string(value, "root")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AegisProofError("invalid proof field types") from exc

    def to_mapping(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "leaf_count": self.leaf_count,
            "leaf_index": self.leaf_index,
            "path": [
                {"direction": step.direction, "sibling_hash": step.sibling_hash}
                for step in self.path
            ],
            "peak_index": self.peak_index,
            "peaks": [{"hash": peak.hash, "height": peak.height} for peak in self.peaks],
            "root": self.root,
            "version": self.version,
        }


def _require_string(value: Mapping[str, Any], key: str) -> str:
    result = value[key]
    if not isinstance(result, str):
        raise TypeError(f"{key} must be a string")
    return result


def _require_int(value: Mapping[str, Any], key: str) -> int:
    result = value[key]
    if not isinstance(result, int) or isinstance(result, bool):
        raise TypeError(f"{key} must be an integer")
    return result


def _valid_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def canonical_proof_json(proof: InclusionProof) -> bytes:
    return json.dumps(
        proof.to_mapping(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def verify_inclusion(leaf: bytes, proof: InclusionProof, trusted_root: str) -> bool:
    """Verify a v1 or v2 inclusion proof over raw leaf bytes.

    The leaf digest is computed under the scheme the *proof* declares, so a
    proof of one version can never be replayed against the other's digest.
    """
    if proof.version == MMR_PROOF_VERSION_V2:
        return verify_inclusion_hash(_v2_leaf_hash(leaf), proof, trusted_root)
    return verify_inclusion_hash(hashlib.sha256(leaf).hexdigest(), proof, trusted_root)


def verify_inclusion_hash(leaf_hash: str, proof: InclusionProof, trusted_root: str) -> bool:
    if proof.version == MMR_PROOF_VERSION_V2:
        if proof.algorithm != MMR_ALGORITHM_V2:
            return False
        v2 = True
    elif proof.version == MMR_PROOF_VERSION_V1:
        if proof.algorithm != MMR_ALGORITHM_V1:
            return False
        v2 = False
    else:
        return False
    if proof.leaf_count < 1 or not 0 <= proof.leaf_index < proof.leaf_count:
        return False
    if not _valid_hash(trusted_root) or proof.root != trusted_root:
        return False
    if len(proof.peaks) != proof.leaf_count.bit_count():
        return False
    if not 0 <= proof.peak_index < len(proof.peaks):
        return False
    heights = [
        bit
        for bit in range(proof.leaf_count.bit_length() - 1, -1, -1)
        if proof.leaf_count & (1 << bit)
    ]
    if [peak.height for peak in proof.peaks] != heights:
        return False
    if any(not _valid_hash(peak.hash) for peak in proof.peaks):
        return False

    mountain_start = sum(1 << height for height in heights[: proof.peak_index])
    mountain_height = heights[proof.peak_index]
    if not mountain_start <= proof.leaf_index < mountain_start + (1 << mountain_height):
        return False
    local_index = proof.leaf_index - mountain_start
    if len(proof.path) != mountain_height:
        return False

    if not _valid_hash(leaf_hash):
        return False
    current = leaf_hash
    for level, step in enumerate(proof.path):
        if not _valid_hash(step.sibling_hash) or step.direction not in {"L", "R"}:
            return False
        expected = "R" if ((local_index >> level) & 1) == 0 else "L"
        if step.direction != expected:
            return False
        left, right = (
            (current, step.sibling_hash) if step.direction == "R" else (step.sibling_hash, current)
        )
        current = (
            _v2_node_hash(left, right)
            if v2
            else hashlib.sha256((left + right).encode("ascii")).hexdigest()
        )
    if current != proof.peaks[proof.peak_index].hash:
        return False
    root = (
        _v2_bagged_root([peak.hash for peak in proof.peaks])
        if v2
        else hashlib.sha256("".join(peak.hash for peak in proof.peaks).encode("ascii")).hexdigest()
    )
    return root == trusted_root


def decode_proof_header(value: str) -> InclusionProof:
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(value + padding)
        decoded = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise AegisProofError("X-Aegis-MMR-Proof is not valid base64url JSON") from exc
    if not isinstance(decoded, dict):
        raise AegisProofError("X-Aegis-MMR-Proof must encode a JSON object")
    return InclusionProof.from_mapping(decoded)


def verify_proof_headers(headers: Mapping[str, str], trusted_root: str) -> InclusionProof:
    normalized = {key.lower(): value for key, value in headers.items()}
    leaf_value = normalized.get("x-aegis-mmr-leaf")
    proof_value = normalized.get("x-aegis-mmr-proof")
    root_value = normalized.get("x-aegis-mmr-root")
    if leaf_value is None or proof_value is None or root_value is None:
        raise AegisProofError("Aegis proof headers are required but missing")
    if root_value != trusted_root:
        raise AegisProofError("gateway MMR root does not match the trusted root")
    if not _valid_hash(leaf_value):
        raise AegisProofError("X-Aegis-MMR-Leaf must be a lowercase SHA-256 digest")
    proof = decode_proof_header(proof_value)
    if not verify_inclusion_hash(leaf_value, proof, trusted_root):
        raise AegisProofError("MMR inclusion verification failed")
    return proof
