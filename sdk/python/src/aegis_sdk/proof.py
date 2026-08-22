# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Stateless verification of Aegis MMR inclusion proof headers."""

from __future__ import annotations

import base64
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
            raise AegisProofError("proof fields do not match aegis-mmr-inclusion-v1")
        try:
            path_raw = value["path"]
            peaks_raw = value["peaks"]
            if not isinstance(path_raw, list) or not isinstance(peaks_raw, list):
                raise TypeError("path and peaks must be arrays")
            path = tuple(
                ProofStep(
                    sibling_hash=_require_string(item, "sibling_hash"),
                    direction=_require_string(item, "direction"),
                )
                for item in path_raw
            )
            peaks = tuple(
                Peak(
                    height=_require_int(item, "height"),
                    hash=_require_string(item, "hash"),
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
                root=_require_string(value, "root"),
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
    return verify_inclusion_hash(hashlib.sha256(leaf).hexdigest(), proof, trusted_root)


def verify_inclusion_hash(leaf_hash: str, proof: InclusionProof, trusted_root: str) -> bool:
    if proof.version != "aegis-mmr-inclusion-v1":
        return False
    if proof.algorithm != "sha256-asciihex":
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
        combined = (
            current + step.sibling_hash if step.direction == "R" else step.sibling_hash + current
        )
        current = hashlib.sha256(combined.encode("ascii")).hexdigest()
    if current != proof.peaks[proof.peak_index].hash:
        return False
    root = hashlib.sha256("".join(peak.hash for peak in proof.peaks).encode("ascii")).hexdigest()
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
