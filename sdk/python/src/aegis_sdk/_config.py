# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import re
import secrets
import uuid
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit

_HASH = re.compile(r"^[0-9a-f]{64}$")


def normalize_gateway_url(value: str, *, openai: bool) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("gateway_url must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("gateway_url must not contain credentials")
    base_path = parsed.path.rstrip("/")
    if openai and not base_path.endswith("/v1"):
        base_path += "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, base_path + "/", "", ""))


def build_headers(
    *,
    tenant_id: str,
    session_id: str | None,
    trace_context: str | None,
    caller_headers: Mapping[str, str] | None,
) -> dict[str, str]:
    if not tenant_id.strip():
        raise ValueError("tenant_id must not be empty")
    sid = session_id or str(uuid.uuid4())
    if not sid.strip():
        raise ValueError("session_id must not be empty")
    trace = trace_context or f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01"
    headers = dict(caller_headers or {})
    headers.update(
        {
            "X-Aegis-Tenant-ID": tenant_id,
            "X-Aegis-Session-ID": sid,
            "X-Aegis-Trace-Context": trace,
        }
    )
    return headers


def require_trusted_root(verify_proof: bool, trusted_mmr_root: str | None) -> str | None:
    if not verify_proof:
        return trusted_mmr_root
    if trusted_mmr_root is None or _HASH.fullmatch(trusted_mmr_root) is None:
        raise ValueError("verify_proof=True requires a lowercase 64-hex trusted_mmr_root")
    return trusted_mmr_root
