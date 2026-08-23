# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from aegis.config import AegisSettings
from aegis.core import crypto_audit as crypto_audit_module
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.ratelimiter import DistributedRateLimiter, RateLimitBackendUnavailable
from aegis.proxy.app import RequestBodyLimitMiddleware


def test_strict_runtime_rejects_missing_production_controls(tmp_path: Path) -> None:
    cfg = AegisSettings(
        security_enforcement_mode="strict",
        rate_limit_backend="memory",
        signing_key="",
        api_keys="",
        wal_path=tmp_path / "audit.wal",
    )
    with pytest.raises(ValueError, match="rate_limit_backend"):
        cfg.validate_runtime_invariants()


def test_strict_runtime_accepts_explicit_controls(tmp_path: Path) -> None:
    key = "test-key"
    digest = hashlib.sha256(key.encode()).hexdigest()
    cfg = AegisSettings(
        security_enforcement_mode="strict",
        rate_limit_backend="redis",
        signing_key="a" * 64,
        api_keys=key,
        auth_identity_hmac_key="i" * 32,
        api_key_principals_json=json.dumps(
            {
                digest: {
                    "subject": "p0-gate",
                    "tenant_id": "tenant-p0",
                    "roles": ["proxy_user"],
                }
            }
        ),
        wal_path=tmp_path / "audit.wal",
    )
    cfg.validate_runtime_invariants()


def test_strong_ledger_rejects_ephemeral_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(crypto_audit_module, "RUST_AVAILABLE", False)
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "strict.wal"),
        signing_key="",
        require_strong_signing=True,
    )
    with pytest.raises(RuntimeError, match="strong signing required"):
        ledger.commit_forensic(state_id="r1", request_bytes=b"{}", response_bytes=b"{}")
    ledger.close()


def test_distributed_rate_limit_never_fails_open() -> None:
    limiter = DistributedRateLimiter("redis://localhost:6379")
    limiter.redis.eval = AsyncMock(side_effect=ConnectionError("redis down"))
    with pytest.raises(RateLimitBackendUnavailable):
        asyncio.run(limiter.check_limit("tenant"))
    asyncio.run(limiter.close())


@pytest.mark.anyio
async def test_request_body_limit_rejects_declared_oversize() -> None:
    app = Mock()
    middleware = RequestBodyLimitMiddleware(app, max_body_bytes=64)
    request = Mock()
    request.headers = {"content-length": "65"}
    response = await middleware.dispatch(request, AsyncMock())
    assert response.status_code == 413
