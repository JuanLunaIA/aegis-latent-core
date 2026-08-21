#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Build the 2026-08-20 execution provenance envelope.

Dependencies: cbor2>=5.9.0 (generation only)
Exposed artifacts: manifest.json, manifest.cbor, manifest.sha256, manifest.cid
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import unicodedata
import uuid
from pathlib import Path

import cbor2

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "evidence" / "execution_2026-08-20"
MANIFEST_JSON = OUTPUT_DIR / "manifest.json"
MANIFEST_CBOR = OUTPUT_DIR / "manifest.cbor"
MANIFEST_SHA256 = OUTPUT_DIR / "manifest.sha256"
MANIFEST_CID = OUTPUT_DIR / "manifest.cid"
EXECUTION_TIMESTAMP = "2026-08-21T02:00:00.000Z"
SOURCE_ZIP_SHA256 = "be46695cf76523e69e794b47c8bb464ca9fa57b5e8daff401e2f275824415308"


def canonical_text(value: str) -> str:
    """Return Unicode NFC with LF line endings."""
    return unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(*command: str) -> str:
    # Callers supply only fixed Git subcommands defined in this module; no user
    # input or manifest content reaches the executable or argument vector.
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def staged_paths() -> list[Path]:
    output = run("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    excluded = {
        MANIFEST_JSON.relative_to(ROOT).as_posix(),
        MANIFEST_CBOR.relative_to(ROOT).as_posix(),
        MANIFEST_SHA256.relative_to(ROOT).as_posix(),
        MANIFEST_CID.relative_to(ROOT).as_posix(),
    }
    paths = []
    for raw_path in output.splitlines():
        normalized = canonical_text(raw_path)
        if normalized and normalized not in excluded:
            paths.append(ROOT / normalized)
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def artifact_record(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {
        "path": canonical_text(path.relative_to(ROOT).as_posix()),
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
    }


def merkle_root(records: list[dict[str, object]]) -> str:
    if not records:
        return sha256_bytes(b"\x00")
    level = []
    for record in records:
        path = str(record["path"]).encode("utf-8")
        digest = bytes.fromhex(str(record["sha256"]))
        level.append(hashlib.sha256(b"\x00" + path + b"\x00" + digest).digest())
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"\x01" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def jcs_bytes(value: object) -> bytes:
    # The envelope uses only JSON strings, integers, booleans, arrays, and maps;
    # this avoids implementation-dependent floating-point rendering.
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return canonical_text(text).encode("utf-8")


def cid_v1_dag_cbor(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    # CIDv1 (0x01), dag-cbor multicodec (0x71), sha2-256 multihash (0x12, 0x20).
    raw = bytes((0x01, 0x71, 0x12, 0x20)) + digest
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def main() -> None:
    records = [artifact_record(path) for path in staged_paths()]
    parent_commit = run("git", "rev-parse", "HEAD")
    root_hash = merkle_root(records)
    artifact_uuid = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"urn:aegis:execution:{parent_commit}:{root_hash}",
    )

    envelope: dict[str, object] = {
        "artifact_id": f"urn:uuid:{artifact_uuid}",
        "artifacts": records,
        "causal_derivation_graph": {
            "edges": [
                {"from": "uploaded_zip", "rule": "content comparison", "to": "git_baseline"},
                {"from": "git_baseline", "rule": "verified patch", "to": "execution_artifacts"},
                {
                    "from": "execution_artifacts",
                    "rule": "domain-separated Merkle aggregation",
                    "to": "merkle_root",
                },
            ],
            "nodes": ["uploaded_zip", "git_baseline", "execution_artifacts", "merkle_root"],
        },
        "epistemic_evaluation": {
            "claim_scope": "formal tags apply only to executed solver artifacts and finite model bounds",
            "primary_tag": "[ESTABLISHED_EMPIRICAL]",
            "residual_risk": "no implementation-to-model refinement proof and no target-filesystem power-loss proof",
        },
        "inputs": {
            "repository": "JuanLunaIA/aegis-latent-core",
            "source_commit": parent_commit,
            "source_zip_sha256": SOURCE_ZIP_SHA256,
        },
        "integrity": {
            "leaf_domain_prefix_hex": "00",
            "merkle_root_sha256": root_hash,
            "node_domain_prefix_hex": "01",
        },
        "reproducibility": {
            "formal_gate": "passed",
            "python_suite": {"passed": 5442, "skipped": 37, "warnings": 47},
            "rust_suite": {"passed": 28, "failed": 0},
            "wheel_sha256": "71040c5b81b306f07bc70661e9ab74225f75898f192e25f0b45ae3eb7a96f7a7",
        },
        "schema": "aegis-execution-provenance-v1",
        "timestamp_utc": EXECUTION_TIMESTAMP,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest_json = jcs_bytes(envelope)
    manifest_cbor = cbor2.dumps(envelope, canonical=True)
    MANIFEST_JSON.write_bytes(manifest_json)
    MANIFEST_CBOR.write_bytes(manifest_cbor)
    MANIFEST_SHA256.write_text(sha256_bytes(manifest_json) + "\n", encoding="ascii")
    MANIFEST_CID.write_text(cid_v1_dag_cbor(manifest_cbor) + "\n", encoding="ascii")

    print(f"artifacts={len(records)}")
    print(f"merkle_root={envelope['integrity']['merkle_root_sha256']}")
    print(f"manifest_sha256={sha256_bytes(manifest_json)}")
    print(f"manifest_cid={cid_v1_dag_cbor(manifest_cbor)}")


if __name__ == "__main__":
    main()
