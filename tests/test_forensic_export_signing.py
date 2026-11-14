# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""F-01: the HTTP forensic export is signed, and strict mode refuses to serve it unsigned.

``build_forensic_bundle`` could already sign ``manifest.json``, but
``POST /v1/audit/forensics/export`` never passed a key, so every bundle
downloaded over HTTP was unsigned. Its digests then only detected corruption:
whoever could rewrite the archive could rewrite the digests too. These tests
download a bundle through the endpoint and verify it with the offline SDK
verifier, using a public key the test holds and the bundle does not carry.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from pydantic import ValidationError

from aegis.auth.principal import Principal, Role
from aegis.auth.scopes import SCOPE_AUDIT_EXPORT, SCOPE_AUDIT_READ
from aegis.config import AegisSettings
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.proxy.audit_api import build_audit_router

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"))
from aegis_sdk.bundle import verify_bundle  # noqa: E402

SEED = bytes(range(32))


async def _export(tmp_path: Path, **router_kwargs: object) -> httpx.Response:
    async def auth() -> Principal:
        return Principal(
            subject="examiner",
            tenant_id="tenant-a",
            roles=frozenset({Role.ADMIN}),
            scopes=frozenset({SCOPE_AUDIT_READ, SCOPE_AUDIT_EXPORT}),
            auth_method="test",
        )

    now = datetime.now(UTC)
    with CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.jsonl"), signing_key="test-signing-key"
    ) as ledger:
        ledger.commit_forensic(
            state_id="export-1",
            request_bytes=b"request",
            response_bytes=b"response",
            tenant_id="tenant-a",
        )
        app = FastAPI()
        app.include_router(build_audit_router(ledger, auth, **router_kwargs), prefix="/v1/audit")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.post(
                "/v1/audit/forensics/export",
                json={
                    "start_time": (now - timedelta(minutes=1)).isoformat(),
                    "end_time": (now + timedelta(minutes=1)).isoformat(),
                    "operator": "Examiner A",
                    "acquisition_reason": "Authorized test",
                },
            )


@pytest.mark.asyncio
async def test_strict_export_is_signed_and_verifies_offline(tmp_path):
    response = await _export(tmp_path, bundle_signing_key=SEED, require_signed_bundle=True)

    assert response.status_code == 200
    assert response.headers["x-aegis-bundle-signed"] == "true"
    public_key = (
        Ed25519PrivateKey.from_private_bytes(SEED)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    report = verify_bundle(response.content, public_key=public_key)
    assert report.result == "verified", report.to_mapping()

    wrong_key = (
        Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    assert verify_bundle(response.content, public_key=wrong_key).result == "failed"


@pytest.mark.asyncio
async def test_strict_export_without_a_key_is_refused(tmp_path):
    response = await _export(tmp_path, require_signed_bundle=True)

    assert response.status_code == 503
    assert "AEGIS_FORENSIC_BUNDLE_SIGNING_KEY" in response.json()["detail"]


@pytest.mark.asyncio
async def test_development_export_without_a_key_is_marked_unsigned(tmp_path):
    response = await _export(tmp_path)

    assert response.status_code == 200
    assert response.headers["x-aegis-bundle-signed"] == "false"
    assert verify_bundle(response.content).result == "incomplete"


def test_signing_key_setting_accepts_only_32_hex_bytes():
    assert AegisSettings(forensic_bundle_signing_key="").forensic_bundle_signing_seed() is None
    assert (
        AegisSettings(forensic_bundle_signing_key=SEED.hex()).forensic_bundle_signing_seed() == SEED
    )
    for bad in ("ab" * 31, "zz" * 32, "cd" * 33):
        with pytest.raises(ValidationError) as excinfo:
            AegisSettings(forensic_bundle_signing_key=bad)
        # A mistyped seed is nearly the real one: it must not reach startup logs.
        assert bad[:8] not in str(excinfo.value)
