"""Tier-4 Rust acceleration bridge for Aegis Latent Core.

This module is the single point of contact between the Python control plane
and the aegis_rust PyO3 extension.  All seven Rust tiers are exposed here
with safe fallback stubs when the extension is not compiled.

Import order:
    aegis.core.rust_integration  ← this file
    ↳ aegis_rust (optional PyO3 extension)

Tier mapping:
    1. RustForwarder     — async HTTP with persistent connection pool
    2. RustWaf           — Aho-Corasick SIMD multi-pattern WAF
    3. RustRateLimiter   — lock-free atomic token bucket per tenant
    4. RustSessionStore  — DashMap sharded concurrent session registry
    5. AuditRingBuffer   — MPSC lock-free ring buffer for audit events
    6. RustWal           — mmap Write-Ahead Log (replaces os.fsync)
    7. BLAKE3 / ML-DSA   — fast hashing + post-quantum signing
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    import aegis_rust  # type: ignore[import]

    _HAS_RUST = True
    logger.info(
        "aegis_rust v%s loaded — all Tier-4 accelerators active",
        getattr(aegis_rust, "__version__", "unknown"),
    )
except Exception as _exc:
    aegis_rust = None  # type: ignore[assignment]
    _HAS_RUST = False
    logger.debug("aegis_rust extension not available (%s); using Python fallbacks", _exc)


# ── Runtime probe ─────────────────────────────────────────────────────────────


def has_rust() -> bool:
    """Return True if the aegis_rust extension is importable and loaded."""
    return _HAS_RUST


# ── Tier 1: Async HTTP Forwarder ─────────────────────────────────────────────


def new_rust_forwarder(
    base_url: str,
    api_key: str,
    timeout_seconds: int | None = None,
    connect_timeout_seconds: int | None = None,
) -> Any | None:
    """Create a RustForwarder (persistent async connection pool) or None."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.RustForwarder.new(
            base_url, api_key, timeout_seconds, connect_timeout_seconds
        )
    except Exception as e:
        logger.warning("RustForwarder init failed: %s", e)
        return None


# ── Tier 2: Aho-Corasick WAF ─────────────────────────────────────────────────


def new_rust_waf() -> Any | None:
    """Create a RustWaf instance or None when Rust is unavailable."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.RustWaf()
    except Exception as e:
        logger.warning("RustWaf init failed: %s", e)
        return None


def rust_waf_scan(waf: Any, text: str) -> dict[str, Any]:
    """Scan `text` with RustWaf. Returns dict with keys blocked/reason/soft_score."""
    try:
        result = waf.scan(text)
        return {
            "blocked": result.blocked,
            "reason": result.reason,
            "soft_score": result.soft_score,
            "matched_patterns": result.matched_patterns,
        }
    except Exception as e:
        logger.warning("RustWaf scan error: %s", e)
        return {"blocked": False, "reason": "", "soft_score": 0.0, "matched_patterns": []}


def rust_waf_scan_messages(waf: Any, messages: list[str]) -> dict[str, Any]:
    """Scan a list of message content strings."""
    try:
        result = waf.scan_messages(messages)
        return {
            "blocked": result.blocked,
            "reason": result.reason,
            "soft_score": result.soft_score,
            "matched_patterns": result.matched_patterns,
        }
    except Exception as e:
        logger.warning("RustWaf scan_messages error: %s", e)
        return {"blocked": False, "reason": "", "soft_score": 0.0, "matched_patterns": []}


# ── Tier 3: Lock-free Rate Limiter ───────────────────────────────────────────


def new_rust_rate_limiter(capacity: int, refill_rate: int) -> Any | None:
    """Create a RustRateLimiter or None.

    Args:
        capacity: Burst capacity in tokens.
        refill_rate: Sustained rate in tokens/second.
    """
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.RustRateLimiter(capacity, refill_rate)
    except Exception as e:
        logger.warning("RustRateLimiter init failed: %s", e)
        return None


# ── Tier 4: Concurrent Session Store ─────────────────────────────────────────


def new_rust_session_store(
    max_sessions: int = 4096,
    evict_after_secs: int = 3600,
) -> Any | None:
    """Create a RustSessionStore or None."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.RustSessionStore(max_sessions, evict_after_secs)
    except Exception as e:
        logger.warning("RustSessionStore init failed: %s", e)
        return None


# ── Tier 5: Audit Ring Buffer ─────────────────────────────────────────────────


def new_audit_ring_buffer(capacity: int = 65536) -> Any | None:
    """Create an AuditRingBuffer or None."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.AuditRingBuffer(capacity)
    except Exception as e:
        logger.warning("AuditRingBuffer init failed: %s", e)
        return None


# ── Tier 6: Memory-Mapped WAL ────────────────────────────────────────────────


def new_rust_wal(path: str, capacity_bytes: int | None = None) -> Any | None:
    """Open or create a RustWal at `path` or None."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.RustWal.open(path, capacity_bytes)
    except Exception as e:
        logger.warning("RustWal open failed (path=%s): %s", path, e)
        return None


# ── Tier 7: BLAKE3 + ML-DSA PQC ─────────────────────────────────────────────


def blake3_hash(data: bytes) -> str | None:
    """BLAKE3 hex digest of `data`, or None when Rust unavailable."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.blake3_hash(data)
    except Exception:
        return None


def blake3_keyed_hash(key: bytes, data: bytes) -> str | None:
    """BLAKE3 keyed-hash (32-byte key). Returns hex digest or None."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.blake3_keyed_hash(key, data)
    except Exception:
        return None


def hash_audit_payload(
    prev_hash: str,
    state_id: str,
    timestamp: str,
    merkle_root: str,
    request_hash: str,
    response_hash: str,
) -> str | None:
    """Canonical BLAKE3 audit-payload hash or None."""
    if not _HAS_RUST:
        return None
    try:
        return aegis_rust.hash_audit_payload(
            prev_hash, state_id, timestamp, merkle_root, request_hash, response_hash
        )
    except Exception:
        return None


def generate_pqc_keypair() -> bytes | None:
    """Generate an ML-DSA-65 keypair via Rust. Returns public key bytes or None."""
    if not _HAS_RUST:
        return None
    try:
        kp = aegis_rust.generate_pqc_keypair()
        return bytes(kp.public_key)
    except Exception as e:
        logger.warning("PQC keypair generation failed: %s", e)
        return None


def verify_pqc_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Returns False when Rust unavailable."""
    if not _HAS_RUST:
        return False
    try:
        return bool(aegis_rust.verify_pqc_signature(data, signature, public_key))
    except Exception:
        return False


# ── Rust metrics snapshot ─────────────────────────────────────────────────────


def rust_metrics(
    *,
    ring_buffer: Any | None = None,
    rate_limiter: Any | None = None,
    session_store: Any | None = None,
    wal: Any | None = None,
) -> dict[str, Any]:
    """Collect Rust-tier metrics for Prometheus / health endpoints."""
    metrics: dict[str, Any] = {"rust_available": _HAS_RUST}

    if ring_buffer is not None:
        try:
            metrics.update(
                {
                    "audit_ring_len": ring_buffer.len(),
                    "audit_ring_fill_ratio": ring_buffer.fill_ratio(),
                    "audit_enqueue_total": ring_buffer.enqueue_count(),
                    "audit_drop_total": ring_buffer.drop_count(),
                }
            )
        except Exception:
            pass

    if rate_limiter is not None:
        try:
            metrics["rate_limiter_buckets"] = rate_limiter.bucket_count()
        except Exception:
            pass

    if session_store is not None:
        try:
            metrics.update(
                {
                    "session_count": session_store.session_count(),
                    "session_evictions_total": session_store.total_evictions(),
                    "session_oldest_age_secs": session_store.oldest_session_age_secs(),
                }
            )
        except Exception:
            pass

    if wal is not None:
        try:
            metrics.update(
                {
                    "wal_write_pos": wal.write_pos(),
                    "wal_capacity": wal.capacity(),
                    "wal_remaining": wal.remaining(),
                }
            )
        except Exception:
            pass

    return metrics
