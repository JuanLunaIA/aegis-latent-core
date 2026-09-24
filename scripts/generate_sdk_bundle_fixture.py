# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Write the gateway-issued forensic bundle the Python SDK's tests verify.

The SDK's CI job installs only the SDK, so it cannot build a bundle itself; this
script builds one with the gateway's own ``build_forensic_bundle`` from real
ledger commits and writes it beside its public key under ``sdk/shared/``.

The output is not byte-reproducible (commit timestamps differ per run); re-run
it when the bundle format changes, and ``tests/test_sdk_bundle_contract.py``
fails when a freshly built bundle's shape drifts from the committed one.

The signing key is derived from a public constant. It authenticates nothing and
must never sign anything but this fixture.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.forensic_bundle import build_forensic_bundle

OUTPUT_DIR = Path("sdk/shared")
BUNDLE = OUTPUT_DIR / "forensic-bundle-v1.zip"
# Hex, not PEM: the repository ignores *.pem so that no key file is ever
# committed by accident, and a public key needs no exception to that rule.
PUBLIC_KEY = OUTPUT_DIR / "forensic-bundle-v1.pub.hex"

#: Public by construction — see the module docstring.
FIXTURE_SIGNING_SEED = hashlib.sha256(
    b"aegis-latent-sdk forensic-bundle-v1 test fixture; public, authenticates nothing"
).digest()
GENERATED_AT = datetime(2026, 9, 24, tzinfo=UTC)


def fixture_public_key_hex() -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(FIXTURE_SIGNING_SEED).public_key()
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex().encode("ascii") + b"\n"


def build_fixture_bundle(workdir: Path, *, signed: bool = True) -> bytes:
    """Three committed nodes, exported exactly as the export endpoint would."""
    ledger = CryptographicAuditLedger(
        persistence_path=str(workdir / "audit.jsonl"),
        signing_key="sdk-bundle-fixture-hmac-key",
    )
    try:
        nodes = [
            ledger.commit_forensic(
                state_id=f"fixture-{index}",
                request_bytes=f'{{"prompt":"fixture request {index}"}}'.encode(),
                response_bytes=f'{{"answer":"fixture response {index}"}}'.encode(),
                tenant_id="tenant-fixture",
                model="fixture-model",
                endpoint="chat.completions",
            )
            for index in range(3)
        ]
    finally:
        ledger.close()
    return build_forensic_bundle(
        nodes,
        operator="sdk-fixture",
        acquisition_reason="aegis-latent-sdk verify fixture",
        generated_at=GENERATED_AT,
        manifest_signing_key=FIXTURE_SIGNING_SEED if signed else None,
    )


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as scratch:
        BUNDLE.write_bytes(build_fixture_bundle(Path(scratch)))
    PUBLIC_KEY.write_bytes(fixture_public_key_hex())
    sys.stdout.write(f"wrote {BUNDLE} and {PUBLIC_KEY}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
