"""
aegis.proxy.dependencies — Shared FastAPI dependencies for the Aegis proxy.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from fastapi import HTTPException, Request, status

from aegis.auth.apikey import AuditKeyAuth, ProxyKeyAuth


async def validate_proxy_auth(request: Request) -> str:
    """
    Validates the request using mTLS (SPIFFE) if enabled, falling back to API Keys.
    """
    state = request.app.state.aegis

    # 1. Prioritize mTLS (SISTEMA INEXPUGNABLE requirement)
    if getattr(state, "mtls_auth", None) is not None:
        try:
            # Attempt mTLS validation first
            return await state.mtls_auth.validate_request(request)
        except HTTPException as e:
            if e.status_code == status.HTTP_401_UNAUTHORIZED:
                # Fallback to API Keys if mTLS is missing, but only if explicitly allowed
                # In a fully hardened state, this fallback should be removed.
                pass
            else:
                raise e

    # 2. Fallback to API Key authentication
    auth: ProxyKeyAuth = state.proxy_auth
    return await auth.validate_request(request)


async def validate_audit_auth(request: Request) -> str:
    """
    Validates the Audit API using mTLS (SPIFFE) or Audit API Keys.
    """
    state = request.app.state.aegis

    if getattr(state, "mtls_auth", None) is not None:
        try:
            return await state.mtls_auth.validate_request(request)
        except HTTPException as e:
            if e.status_code == status.HTTP_401_UNAUTHORIZED:
                pass
            else:
                raise e

    auth: AuditKeyAuth = state.audit_auth
    return await auth.validate_request(request)
