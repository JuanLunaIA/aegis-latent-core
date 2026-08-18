# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis_server.crypto.keyring import RotatingHMACSigner

KEY_OLD = "o" * 64
KEY_NEW = "n" * 64


def write_snapshot(path: Path, *, active_key_id: str) -> None:
    if active_key_id == "key-old":
        keys = [{"key_id": "key-old", "secret": KEY_OLD, "state": "active"}]
    else:
        keys = [
            {
                "key_id": "key-old",
                "secret": KEY_OLD,
                "state": "verify",
                "expires_at": time.time() + 60.0,
            },
            {"key_id": "key-new", "secret": KEY_NEW, "state": "active"},
        ]
    payload = {"version": 1, "active_key_id": active_key_id, "keys": keys}
    fd, temporary = tempfile.mkstemp(prefix="keyring.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exercise three independent keyring signers through an atomic rotation."
    )
    parser.add_argument("--duration-s", type=float, default=0.5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.duration_s <= 0 or args.duration_s > 30:
        raise ValueError("duration-s must be between 0 and 30 seconds")

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="aegis-key-rotation-") as directory:
        keyring_path = Path(directory) / "hmac-keyring.json"
        write_snapshot(keyring_path, active_key_id="key-old")
        signers = [RotatingHMACSigner(str(keyring_path), reload_interval_s=0.0) for _ in range(3)]
        records: list[dict[str, Any]] = []
        failures: list[str] = []
        lock = threading.Lock()
        stop_at = started + args.duration_s
        rotation_at = started + min(args.duration_s / 3.0, 0.25)
        rotated = False

        def worker(replica_index: int) -> None:
            nonlocal rotated
            sequence = 0
            while time.monotonic() < stop_at:
                if not rotated and time.monotonic() >= rotation_at:
                    with lock:
                        if not rotated:
                            write_snapshot(keyring_path, active_key_id="key-new")
                            rotated = True
                payload = f"replica={replica_index};sequence={sequence}".encode()
                try:
                    signature, key_id = asyncio.run(
                        signers[replica_index].sign_payload_with_metadata(payload)
                    )
                except Exception as exc:  # pragma: no cover - defensive harness boundary
                    with lock:
                        failures.append(f"replica={replica_index}: {type(exc).__name__}")
                    sequence += 1
                    continue
                with lock:
                    records.append(
                        {
                            "replica": replica_index,
                            "sequence": sequence,
                            "key_id": key_id,
                            "payload": payload,
                            "signature": signature,
                        }
                    )
                sequence += 1

        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="aegis-replica") as pool:
            list(pool.map(worker, range(3)))

        verification_failures = 0
        for record in records:
            payload = record["payload"]
            signature = record["signature"]
            if not any(async_verify(signer, payload, signature) for signer in signers):
                verification_failures += 1
        counts = {
            key_id: sum(record["key_id"] == key_id for record in records)
            for key_id in ("key-old", "key-new")
        }
        report = {
            "schema": "aegis-key-rotation-report-v1",
            "generated_at_utc": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "repository": "JuanLunaIA/aegis-latent-core",
            "scope": "three independent local signer instances; atomic keyring replacement; no Kubernetes or secret-manager claim",
            "replicas": 3,
            "duration_s": args.duration_s,
            "records": len(records),
            "failed_commits": len(failures),
            "unverifiable_records": verification_failures,
            "key_ids_observed": counts,
            "rotation_observed": rotated,
            "keyring_mode": oct(keyring_path.stat().st_mode & 0o777),
            "keyring_sha256": sha256_file(keyring_path),
            "gate": {
                "passed": bool(records)
                and rotated
                and not failures
                and verification_failures == 0
                and counts["key-new"] > 0,
                "zero_failed_commits": not failures,
                "zero_unverifiable_records": verification_failures == 0,
                "deployment_boundary": "LOCAL_ONLY; three process replicas, secret-manager propagation, clock skew, and orchestrator restart are NOT_EXECUTED",
            },
            "failures": failures,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=lambda value: value.decode() if isinstance(value, bytes) else value,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "passed": report["gate"]["passed"],
                "records": report["records"],
                "failed_commits": report["failed_commits"],
                "unverifiable_records": report["unverifiable_records"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report["gate"]["passed"] else 1


def async_verify(signer: RotatingHMACSigner, payload: bytes, signature: str) -> bool:
    import asyncio

    return asyncio.run(signer.verify(payload, signature))


if __name__ == "__main__":
    raise SystemExit(main())
