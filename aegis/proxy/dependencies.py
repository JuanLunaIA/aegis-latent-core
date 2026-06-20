"""
aegis.proxy.dependencies — Shared FastAPI dependencies for the Aegis proxy.

FIX-DEP-01: mTLS 401 silent fallback.

Original behaviour: when state.mtls_auth is set and the client raises a 401
(missing/invalid certificate), the exception was silently swallowed and the
request fell through to API-key authentication.  This nulified mTLS:
any caller who knew a valid API key could bypass certificate enforcement by
simply omitting the client cert.

Fix: behaviour is now governed by ``settings.mtls_required``.

  mtls_required=True  (hardened / production):
    401 from mTLS propagates — no fallback.  A missing or invalid cert is
    an unconditional rejection, regardless of whether the caller presents
    a valid API key.

  mtls_required=False (default / transitional):
    Original fallback is preserved — mTLS is attempted but API-key auth
    is accepted when the cert is absent.  Useful during mTLS roll-out.
    The warning log makes the degraded posture explicit in the audit trail.

Mechanism of the original bypass:
  mTLSAuth.validate_request raises HTTP 401 when X-Forwarded-Client-Cert
  is absent.  dependencies.py caught that 401 and executed ``pass``,
  continuing to the ProxyKeyAuth branch.  An attacker with a valid API key
  and knowledge of this fallback could therefore present no certificate and
  still authenticate, making mTLS configuration a no-op from a security
  perspective.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from aegis.auth.apikey import AuditKeyAuth, ProxyKeyAuth

logger = logging.getLogger(__name__)


async def validate_proxy_auth(request: Request) -> str:
    """Validate proxy access via mTLS (SPIFFE) with optional API-key fallback.

    The fallback behaviour is controlled by ``settings.mtls_required``:
      - True  → mTLS 401 propagates; no API-key fallback (production posture).
      - False → mTLS is attempted; API-key fallback on cert absence (transitional).
    """
    state = request.app.state.aegis
    mtls_required: bool = getattr(state.settings, "mtls_required", False)

    if getattr(state, "mtls_auth", None) is not None:
        try:
            return await state.mtls_auth.validate_request(request)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_401_UNAUTHORIZED:
                if mtls_required:
                    # FIX-DEP-01: hard enforcement — no fallback in hardened mode.
                    logger.warning(
                        "mTLS auth failed and mtls_required=True: rejecting request "
                        "(no API-key fallback). detail=%s",
                        exc.detail,
                    )
                    raise
                # Transitional mode: log the degraded posture clearly.
                logger.warning(
                    "mTLS auth returned 401 (mtls_required=False); "
                    "falling back to API-key authentication. "
                    "Set AEGIS_MTLS_REQUIRED=true to enforce mTLS in production."
                )
            else:
                # Non-401 errors (403 bad cert, 500 internal) always propagate.
                raise

    auth: ProxyKeyAuth = state.proxy_auth
    return await auth.validate_request(request)


async def validate_audit_auth(request: Request) -> str:
    """Validate audit-endpoint access via mTLS (SPIFFE) with optional API-key fallback.

    Shares the same mtls_required enforcement logic as validate_proxy_auth.
    """
    state = request.app.state.aegis
    mtls_required: bool = getattr(state.settings, "mtls_required", False)

    if getattr(state, "mtls_auth", None) is not None:
        try:
            return await state.mtls_auth.validate_request(request)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_401_UNAUTHORIZED:
                if mtls_required:
                    logger.warning(
                        "mTLS audit auth failed and mtls_required=True: rejecting request. "
                        "detail=%s",
                        exc.detail,
                    )
                    raise
                logger.warning(
                    "mTLS audit auth returned 401 (mtls_required=False); "
                    "falling back to audit API-key authentication."
                )
            else:
                raise

    auth: AuditKeyAuth = state.audit_auth
    return await auth.validate_request(request)
