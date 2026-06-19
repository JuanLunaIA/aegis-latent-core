"""Helpers for optional Rust acceleration (aegis_rust).

This module centralises runtime detection of the Rust extension and exposes
lightweight helpers that other modules can import without raising on import
if the Rust extension is not installed.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from typing import Any

try:
    import aegis_rust  # type: ignore

    _HAS_RUST = True
except Exception:
    _HAS_RUST = False


def has_rust() -> bool:
    """Return True if the aegis_rust extension is importable."""
    return _HAS_RUST


def new_rust_forwarder(
    base_url: str,
    api_key: str,
    timeout_seconds: int | None = None,
    connect_timeout_seconds: int | None = None,
) -> Any | None:
    """Create and return a RustForwarder instance when available, or None.

    The returned object is a PyO3 bound object exposing the same convenience
    methods as the Rust implementation (forward_json_sync, etc.).
    """
    if not _HAS_RUST:
        return None
    try:
        # RustForwarder.new may raise on invalid args; surface the exception to caller
        return aegis_rust.RustForwarder.new(
            base_url, api_key, timeout_seconds, connect_timeout_seconds
        )
    except Exception:
        return None


def generate_pqc_keypair() -> bytes | None:
    """Generate a PQC keypair using the Rust backend, if present.

    Returns the public key bytes (caller can decide how to store keys).
    """
    if not _HAS_RUST:
        return None
    try:
        kp = aegis_rust.generate_pqc_keypair()
        # kp has .public_key attribute exposed as PyBytes; access python-level
        return bytes(kp.public_key)
    except Exception:
        return None


def verify_pqc_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a PQC signature via Rust if available; return False otherwise."""
    if not _HAS_RUST:
        return False
    try:
        return bool(aegis_rust.verify_pqc_signature(data, signature, public_key))
    except Exception:
        return False
