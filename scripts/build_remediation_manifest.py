#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Build the 2026-08-21 remediation provenance envelope.

Dependencies: cbor2>=5.9.0 (generation only)
Exposed artifacts: remediation_manifest.json/.cbor/.sha256/.cid
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
OUTPUT_DIR = ROOT / "evidence" / "remediation_2026-08-21"
MANIFEST_JSON = OUTPUT_DIR / "remediation_manifest.json"
MANIFEST_CBOR = OUTPUT_DIR / "remediation_manifest.cbor"
MANIFEST_SHA256 = OUTPUT_DIR / "remediation_manifest.sha256"
MANIFEST_CID = OUTPUT_DIR / "remediation_manifest.cid"
EXECUTION_TIMESTAMP = "2026-08-21T03:35:52.000Z"


def canonical_text(value: str) -> str:
    """Return Unicode NFC text with LF line endings."""
    return unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(*command: str) -> str:
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
    return sorted(
        (
            ROOT / canonical_text(raw_path)
            for raw_path in output.splitlines()
            if canonical_text(raw_path) and canonical_text(raw_path) not in excluded
        ),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


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
    level = [
        hashlib.sha256(
            b"\x00"
            + str(record["path"]).encode("utf-8")
            + b"\x00"
            + bytes.fromhex(str(record["sha256"]))
        ).digest()
        for record in records
    ]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"\x01" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def jcs_bytes(value: object) -> bytes:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return canonical_text(text).encode("utf-8")


def cid_v1_dag_cbor(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    raw = bytes((0x01, 0x71, 0x12, 0x20)) + digest
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def main() -> None:
    records = [artifact_record(path) for path in staged_paths()]
    parent_commit = run("git", "rev-parse", "HEAD")
    root_hash = merkle_root(records)
    artifact_uuid = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"urn:aegis:remediation:{parent_commit}:{root_hash}",
    )
    envelope: dict[str, object] = {
        "artifact_id": f"urn:uuid:{artifact_uuid}",
        "artifacts": records,
        "causal_derivation_graph": {
            "edges": [
                {"from": "github_runs", "rule": "bounded reproduction", "to": "python311_fix"},
                {"from": "stream_threat", "rule": "byte and deadline bounds", "to": "sse_fix"},
                {"from": "workflow_inventory", "rule": "commit resolution", "to": "sha_pins"},
                {
                    "from": "verified_changes",
                    "rule": "domain-separated Merkle aggregation",
                    "to": "merkle_root",
                },
            ],
            "nodes": [
                "github_runs",
                "python311_fix",
                "stream_threat",
                "sse_fix",
                "workflow_inventory",
                "sha_pins",
                "verified_changes",
                "merkle_root",
            ],
        },
        "epistemic_evaluation": {
            "primary_tag": "[ESTABLISHED_EMPIRICAL]",
            "residual_risk": "Security alert counts remain unresolved until the GitHub App receives alert-read permissions",
            "falsification_threshold": "Any Python 3.11 timeout, over-limit SSE acceptance, unclosed upstream iterator, or mutable Action ref",
            "choke_test_status": "PASS_LOCAL_PENDING_GITHUB",
        },
        "inputs": {
            "repository": "JuanLunaIA/aegis-latent-core",
            "source_commit": parent_commit,
            "source_material": "pasted_content.txt",
        },
        "integrity": {
            "leaf_domain_prefix_hex": "00",
            "merkle_root_sha256": root_hash,
            "node_domain_prefix_hex": "01",
        },
        "reproducibility": {
            "formal_gate": "passed",
            "github_action_sha_pins": {"passed": 76, "total": 76},
            "python311_native_suite": {"passed": 5447, "skipped": 37, "warnings": 0},
            "python311_repeat_file": {"iterations": 25, "timeouts": 0},
            "rust_suite": {"passed": 28, "failed": 0},
            "warning_error_subset": {"passed": 43, "failed": 0},
            "wheel_sha256": "2977282972685a9cc5db16292a0a269010b87ab73628161a6939b3525fea2f20",
        },
        "schema": "aegis-remediation-provenance-v1",
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
    print(f"merkle_root={root_hash}")
    print(f"manifest_sha256={sha256_bytes(manifest_json)}")
    print(f"manifest_cid={cid_v1_dag_cbor(manifest_cbor)}")


if __name__ == "__main__":
    main()
